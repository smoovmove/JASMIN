---
title: HTB Sherlock: Tick Tock
url: https://0xdf.gitlab.io/2023/12/14/htb-sherlock-tick-tock.html
date: 2023-12-14T10:00:00+00:00
difficulty: Medium
tags: ctf, dfir, forensics, sherlock-tick-tock, sherlock-cat-dfir, hackthebox, kape, teamviewer, event-logs, evtxecmd, time-stomping, merlin-c2, defender, mft, mftecmd, htb-sherlock
---

![tick tock](/icons/sherlock-tick-tock.png)

A new employee gets a call from the “IT department”, who is actually a malicious actor. They get a TeamViewer connection and launch a Merlin C2 agent. I’ll see through the logs the processes it runs, where Defender catches it, and how it tries to mess with forensics by constantly changing the system time.

## Challenge Info

| Name | [Tick Tock](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2ftick+tock)  [Tick Tock](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2ftick+tock) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2ftick+tock) |
| --- | --- |
| Release Date | 2023-11-13 |
| Retire Date | 2023-12-14 |
| Difficulty | Medium |
| Category | DFIR DFIR |
| Creator | [blitztide blitztide](https://app.hackthebox.com/users/6893) |

## Background

### Scenario

> Gladys is a new joiner in the company, she has received an email informing her that the IT department is due to do some work on her PC, she is guided to call the IT team where they will inform her on how to allow them remote access. The IT team however are actually a group of hackers that are attempting to attack Forela.

From this scenario, I’ve made a few notes:
- The company under attack again is Forela, just like in [Knock Knock](/2023/12/04/htb-sherlock-knock-knock.html#scenario).
- There’s going to be some kind of remote access to Glady’s machine.

### Questions

To solve this challenge, I’ll need to answer the following 11 questions:
- What was the name of the executable that was uploaded as a C2 Agent?
- What was the session id for in the initial access?
- The attacker attempted to set a bitlocker password on the `C:` drive what was the password?
- What name was used by the attacker?
- What IP address did the C2 connect back to?
- What category did Windows Defender give to the C2 binary file?
- What was the filename of the powershell script the attackers used to manipulate time?
- What time did the initial access connection start?
- What is the SHA1 and SHA2 sum of the malicious binary?
- How many times did the powershell script change the time on the machine?
- What is the SID of the victim user?

### Data

The download unzips to a folder named `Collection`. In it are three Kape logs and a `C` directory, which has select files from a Windows file system (with some extra files):

```

oxdf@hacky$ ls Collection/
2023-05-04T11_51_06_5397121_ConsoleLog.txt  2023-05-04T11_51_06_5397121_CopyLog.csv  2023-05-04T11_51_06_5397121_SkipLog.csv.csv  C
oxdf@hacky$ ls Collection/C
'$Boot'  '$Extend'  '$LogFile'  '$MFT'  '$Recycle.Bin'  '$Secure_$SDS'   ProgramData   Users   Windows

```

### Strategy

On `C`, I’ll want to look at Gladys’ home directory, as well as the Windows event logs. The `$MFT` (master file table) could be useful as well.

## Glady’s Home Directory

### Overview

Gladys’ home directory doesn’t have any standard folders like `Documents`, `Pictures`, or `Desktop`. It looks like Kape only collected the registry hive-related files (`NTUSER.DAT` and logs), as well as the `AppData` directory:

```

oxdf@hacky$ ls C/Users/gladys/
AppData  NTUSER.DAT  ntuser.dat.LOG1  ntuser.dat.LOG2

```

In `AppData`, there’s `Local` and `Roaming`.

### Roaming

`Roaming` has a Firefox profile:

```

oxdf@hacky$ ls C/Users/gladys/AppData/Roaming/Mozilla/Firefox/Profiles/p2d7pcle.default-release/
cookies.sqlite   formhistory.sqlite  places.sqlite       sessionstore-backups
extensions.json  key4.db             prefs.js            sessionstore.jsonlz4
favicons.sqlite  permissions.sqlite  protections.sqlite

```

The `Roaming\Microsoft` directory has a `Recent` folder with links to recently run things, but much of it is forensics tools, and nothing jumps out as malicious:

```

oxdf@hacky$ ls C/Users/gladys/AppData/Roaming/Microsoft/Windows/Recent/
 ANTIVIRU.lnk            BSTRINGS.lnk         EVTXECMD.lnk   LOGS.lnk      SQLECMD.lnk        WSA.lnk
'APPS (2).lnk'          'CD Drive.lnk'        EZTOOLS.lnk    MAPS.lnk     'TARGETS (2).lnk'   WSL.lnk
 APPS.lnk                COMPOUND.lnk         GET_KAPE.lnk   MFTECMD.lnk   THOR_LIT.lnk
 AutomaticDestinations   CustomDestinations   KAPE.lnk       MODULES.lnk   THOR.lnk
 BATCHEXA.lnk            _DISABLE.lnk         KAPERESE.lnk   P2P.lnk       TZWORKS.lnk
 BIN.lnk                'DOCUMENT (2).lnk'    KAPESYNC.lnk   PLUGINS.lnk  'WINDOWS (2).lnk'
 BROWSERS.lnk            DOCUMENT.lnk         _LOCAL.lnk     RECMD.lnk     WINDOWS.lnk

```

There’s a PowerShell console history as well:

```

oxdf@hacky$ cat C/Users/gladys/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt 
set-executionpolicy bypass
cd ..
cd ..
cd .\Users\
cd .\gladys\Desktop\
dir
.\Invoke-TimeWizard.ps1

```

I don’t see what `Invoke-TimeWizard.ps1` is right away. It is the the answer to Task 7 (“What was the filename of the powershell script the attackers used to manipulate time?”).

### Local

`Local` has three directories:

```

oxdf@hacky$ ls C/Users/gladys/AppData/Local/
Microsoft  Packages  TeamViewer

```

`Microsoft` has some Microsoft stuff like an empty IE profile, some OneDrive log. `Packages` has what looks like an Edge profile:

```

oxdf@hacky$ ls C/Users/gladys/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/
AC  AppData  Microsoft.MicrosoftEdge_20.10240.17146.0_neutral__8wekyb3d8bbwe  Settings

```

But the most interesting is `TeamViewer`.

### TeamViewer

#### Overview

TeamViewer is a remote access software commonly used by IT and support teams. The directory has a SQLite db:

```

oxdf@hacky$ file C/Users/gladys/AppData/Local/TeamViewer/Database/tvchatfilecache.db 
C/Users/gladys/AppData/Local/TeamViewer/Database/tvchatfilecache.db: SQLite 3.x database, user version 1, last written using SQLite version 3031000, file counter 7, database pages 7, cookie 0x5, schema 4, UTF-8, version-valid-for 7

```

It’s basically empty.

There’s also a `Logs` directory:

```

oxdf@hacky$ ls C/Users/gladys/AppData/Local/TeamViewer/Logs/
TeamViewer15_Logfile.log  TVNetwork.log

```

And a `RemotePrint` directory with another database:

```

oxdf@hacky$ file C/Users/gladys/AppData/Local/TeamViewer/RemotePrinting/tvprint.db 
C/Users/gladys/AppData/Local/TeamViewer/RemotePrinting/tvprint.db: SQLite 3.x database, last written using SQLite version 3031000, file counter 9, database pages 9, cookie 0x6, schema 4, UTF-8, version-valid-for 9

```

It’s also basically empty.

#### TeamViewer15\_LogFile.log

Right at the top of the log file, there is a connection from an remote user into TeamViewer:

[![image-20231214130222258](/img/image-20231214130222258.png)*Click for full size image*](/img/image-20231214130222258.png)

The session id is -2102926010, which completes Task 2. The connection started at 2023/05/04 11:35:27 (Task 8).

While the session is being set up, it sets this session and saves the local participant as 1764218403:

```

2023/05/04 11:35:27.433  5716       5840 D3   SessionManagerDesktop::IncomingConnection: Connection incoming, sessionID = -2102926010
2023/05/04 11:35:27.433  5716       5840 D3   CParticipantManagerBase::SetMyParticipantIdentifier(): pid=[1764218403,-2102926010]

```

Four seconds later, there are two participants in the session:

```

2023/05/04 11:35:31.958  5716       2436 D3   CParticipantManagerBase participant DESKTOP-R30EAMH (ID [1764218403,-2102926010]) was added with the role 3
2023/05/04 11:35:31.958  5716       2436 D3   New Participant added in CParticipantManager DESKTOP-R30EAMH ([1764218403,-2102926010])
2023/05/04 11:35:31.958  5716       2436 D3   CParticipantManagerBase participant fritjof olfasson (ID [1761879737,-207968498]) was added with the role 6
2023/05/04 11:35:31.958  5716       2436 D3   New Participant added in CParticipantManager fritjof olfasson ([1761879737,-207968498])

```

The first is Gladys (likely hostname Desktop-R30EAMH, which is confirmed later in event logs), and the other is identified as fritjof olfasson (answer to Task 4).

Looks like the actor gets screenshots at 11:35:32 and again at 11:36:25:

```

2023/05/04 11:35:32.574  5716       2436 D3   Desktop grab succeeded.
2023/05/04 11:36:25.041  5716       2436 D3   Desktop grab succeeded.

```

At 11:21:30, there’s a file write:

```

2023/05/04 11:21:30.996  4428       6012 G3   Write file C:\Users\gladys\Desktop\merlin.exe
2023/05/04 11:21:34.398  4428       6012 G3   Download from "merlin.exe" to "C:\Users\gladys\Desktop\merlin.exe" (10.95 MB)

```

`merlin.exe` is written to Gladys’ Desktop folder. This is very interesting (and the answer to Task 1).

#### Time Issues

This timestamp on the file download is interesting, as it’s before the connection. In fact, while times are going up as the log file continues, there’s a point where it jumps back 15 minutes:

```

2023/05/04 11:36:25.041  5716       2436 D3   Desktop grab succeeded.
2023/05/04 11:36:25.044  5716       2436 D3   CScreenStreamSender::SendDisplayParams() 1024x768x32 on 23 to 3 (restartStream=0)
2023/05/04 11:21:05.708  4428       5292 G3!  Couldn't access Log-File since startup
2023/05/04 11:21:05.709  4428       5292 G3   IConnection[1]::~IConnection(): Count: 2
2023/05/04 11:21:05.729  4428       5292 G3   CTcpConnectionBase[5]::ConnectEndpoint(): Connecting to endpoint 217.146.23.145:5938

```

Later, it jumps again, this time forward just over an hour:

```

2023/05/04 11:22:37.403  4428       5292 G3   TcpProcessConnector::CloseConnection(): PID=5716
2023/05/04 11:22:37.434  4428       3208 G3   DesktopProcessControl::OnProcessTerminated: Process 5716 in session 3 has terminated
2023/05/04 12:27:32.813  4428       5292 G3   IConnection[6]::~IConnection(): Count: 1
2023/05/04 12:27:32.844  4428       5292 G3   CTcpConnectionBase[7]::ConnectEndpoint(): Connecting to endpoint 188.172.219.136:5938

```

There’s at least 4 or 5 more of these jumps. It seems like I can’t trust these timestamps.

## Event Logs

### Process

#### Identify

There’s a fair number of event log files in `C:\Windows\System32\winevt\logs`:

```

oxdf@hacky$ ls Windows/System32/winevt/logs/
 Application.evtx                                                                 Microsoft-Windows-Ntfs%4Operational.evtx
 Microsoft-Client-Licensing-Platform%4Admin.evtx                                  Microsoft-Windows-Ntfs%4WHC.evtx
 Microsoft-Windows-All-User-Install-Agent%4Admin.evtx                             Microsoft-Windows-PowerShell%4Operational.evtx
 Microsoft-Windows-Application-Experience%4Program-Compatibility-Assistant.evtx   Microsoft-Windows-PrintService%4Admin.evtx
 Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx                 Microsoft-Windows-PushNotification-Platform%4Operational.evtx
 Microsoft-Windows-ApplicationResourceManagementSystem%4Operational.evtx          Microsoft-Windows-Regsvr32%4Operational.evtx
 Microsoft-Windows-AppModel-Runtime%4Admin.evtx                                   Microsoft-Windows-Resource-Exhaustion-Detector%4Operational.evtx
 Microsoft-Windows-AppReadiness%4Admin.evtx                                       Microsoft-Windows-Resource-Exhaustion-Resolver%4Operational.evtx
 Microsoft-Windows-AppReadiness%4Operational.evtx                                 Microsoft-Windows-Security-SPP-UX-Notifications%4ActionCenter.evtx
 Microsoft-Windows-AppXDeployment%4Operational.evtx                               Microsoft-Windows-SettingSync%4Debug.evtx
 Microsoft-Windows-AppXDeploymentServer%4Operational.evtx                         Microsoft-Windows-Shell-Core%4Operational.evtx
 Microsoft-Windows-AppxPackaging%4Operational.evtx                                Microsoft-Windows-SmbClient%4Connectivity.evtx
 Microsoft-Windows-AssignedAccessBroker%4Admin.evtx                               Microsoft-Windows-SMBServer%4Operational.evtx
 Microsoft-Windows-BackgroundTaskInfrastructure%4Operational.evtx                 Microsoft-Windows-StateRepository%4Operational.evtx
 Microsoft-Windows-Bits-Client%4Operational.evtx                                  Microsoft-Windows-Storage-ClassPnP%4Operational.evtx
 Microsoft-Windows-CAPI2%4Operational.evtx                                        Microsoft-Windows-Store%4Operational.evtx
 Microsoft-Windows-Crypto-DPAPI%4Operational.evtx                                 Microsoft-Windows-Sysmon%4Operational.evtx
 Microsoft-Windows-DeviceSetupManager%4Admin.evtx                                 Microsoft-Windows-TaskScheduler%4Maintenance.evtx
 Microsoft-Windows-DeviceSetupManager%4Operational.evtx                           Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
 Microsoft-Windows-Diagnosis-DPS%4Operational.evtx                                Microsoft-Windows-TWinUI%4Operational.evtx
 Microsoft-Windows-Diagnostics-Performance%4Operational.evtx                      Microsoft-Windows-UAC-FileVirtualization%4Operational.evtx
 Microsoft-Windows-GroupPolicy%4Operational.evtx                                  Microsoft-Windows-UserPnp%4DeviceInstall.evtx
'Microsoft-Windows-HomeGroup Control Panel%4Operational.evtx'                    'Microsoft-Windows-User Profile Service%4Operational.evtx'
'Microsoft-Windows-HomeGroup Provider Service%4Operational.evtx'                  Microsoft-Windows-VolumeSnapshot-Driver%4Operational.evtx
 Microsoft-Windows-International%4Operational.evtx                                Microsoft-Windows-Wcmsvc%4Operational.evtx
 Microsoft-Windows-Kernel-Boot%4Operational.evtx                                 'Microsoft-Windows-Windows Defender%4Operational.evtx'
 Microsoft-Windows-Kernel-EventTracing%4Admin.evtx                               'Microsoft-Windows-Windows Defender%4WHC.evtx'
 Microsoft-Windows-Kernel-PnP%4Configuration.evtx                                'Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx'
 Microsoft-Windows-Kernel-ShimEngine%4Operational.evtx                            Microsoft-Windows-WindowsSystemAssessmentTool%4Operational.evtx
 Microsoft-Windows-Kernel-WHEA%4Operational.evtx                                  Microsoft-Windows-WindowsUpdateClient%4Operational.evtx
'Microsoft-Windows-Known Folders API Service.evtx'                                Microsoft-Windows-WinINet-Capture%4Analytic.evtx
 Microsoft-Windows-LanguagePackSetup%4Operational.evtx                            Microsoft-Windows-WMI-Activity%4Operational.evtx
 Microsoft-Windows-LiveId%4Operational.evtx                                       Microsoft-WS-Licensing%4Admin.evtx
 Microsoft-Windows-MUI%4Operational.evtx                                          Security.evtx
 Microsoft-Windows-NcdAutoSetup%4Operational.evtx                                 Setup.evtx
 Microsoft-Windows-NCSI%4Operational.evtx                                         System.evtx
 Microsoft-Windows-NetworkProfile%4Operational.evtx                              'Windows PowerShell.evtx'

```

There are a handful that jump out as interesting:
- Defender
- Sysmon (`Microsoft-Windows-Sysmon%40Operational.evtx`)
- Network (`Microsoft-Windows-NetworkProfile%4Operational.evtx`)
- Security
- Windows PowerShell

#### Parse

Before diving into individual logs, I’ll use `EvtxECmd` from [Zimmerman Tools](https://ericzimmerman.github.io/#!index.md) to parse the logs into a single large file I can search through. I’ll do this in a Windows VM, getting out JSON logs:

```

PS C:\Users\0xdf > C:\Tools\ZimmermanTools\EvtxeCmd\EvtxECmd.exe -d .\logs\ --json Z:\hackthebox-sherlocks\ticktock\
...[snip]...

```

The resulting file is:

```

oxdf@hacky$ ls
20231214172942_EvtxECmd_Output.json

```

I’ll rename them without the timestamps at the start for easy of working with.

### Invoke-TimeWizard.ps1

#### Creation

I’ll use `jq -c` to output the logs as one per line. Then I can `grep` for terms, getting the entire log back, and then use `jq` to pretty print them again. So to look for logs referencing `Invoke-TimeWizard.ps1`, I’ll run `jq -c . EvtxECmd_Output.json | grep "Invoke-TimeWizard" | jq .`. It finds two logs. The first Is the file creation:

```

{
  "PayloadData1": "ProcessID: 4428, ProcessGUID: 5080714d-8a4f-6453-d501-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "Image: C:\\Users\\gladys\\AppData\\Local\\Temp\\TeamViewer\\TeamViewer.exe",
  "PayloadData4": "TargetFilename: C:\\Users\\gladys\\Desktop\\Invoke-TimeWizard.ps1",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "MapDescription": "FileCreate",
  "ChunkNumber": 28,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:35:59.964\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8a4f-6453-d501-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"4428\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\AppData\\\\Local\\\\Temp\\\\TeamViewer\\\\TeamViewer.exe\"},{\"@Name\":\"TargetFilename\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\Invoke-TimeWizard.ps1\"},{\"@Name\":\"CreationUtcTime\",\"#text\":\"2023-05-04 10:35:59.962\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 11,
  "EventRecordId": "1866",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:35:59.9655497+00:00",
  "RecordNumber": 1866
}

```

These event logs seem to be one hour ahead (before any time changing shenanigans by the actor) of the TeamViewer logs. Given that the TeamViewer timestamp was accepted by HTB as the right answer, I’ll convert these times forward an hour. So while this log says 2023-05-04 10:35:59.964, that’s 11:35:59 in the timeline.

The second log shows the actor changing the creation time for this script, making it three minutes younger, before the actor connected:

```

{
  "PayloadData1": "ProcessID: 4428, ProcessGUID: 5080714d-8a4f-6453-d501-000000000700",
  "PayloadData2": "RuleName: T1099",
  "PayloadData3": "Image: C:\\Users\\gladys\\AppData\\Local\\Temp\\TeamViewer\\TeamViewer.exe",
  "PayloadData4": "TargetFilename: C:\\Users\\gladys\\Desktop\\Invoke-TimeWizard.ps1",
  "PayloadData5": "CreationTimeUTC: 2023-05-04 10:32:53.000",
  "PayloadData6": "PreviousCreationTimeUTC: 2023-05-04 10:35:59.962",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "MapDescription": "A process changed a file creation time",
  "ChunkNumber": 28,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"T1099\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:35:59.964\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8a4f-6453-d501-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"4428\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\AppData\\\\Local\\\\Temp\\\\TeamViewer\\\\TeamViewer.exe\"},{\"@Name\":\"TargetFilename\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\Invoke-TimeWizard.ps1\"},{\"@Name\":\"CreationUtcTime\",\"#text\":\"2023-05-04 10:32:53.000\"},{\"@Name\":\"PreviousCreationUtcTime\",\"#text\":\"2023-05-04 10:35:59.962\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 2,
  "EventRecordId": "1867",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:35:59.9665972+00:00",
  "RecordNumber": 1867
}

```

#### Time Changes

When the time is changed on a Windows machine, it creates a [4616 event](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4616). I’ll use `jq` to filter for these events. There are 2374 (with `-c` the output is one log per line, so I can just count with `wc -l`):

```

oxdf@hacky$ jq -c '.|select(.EventId == 4616)' EvtxECmd_Output.json  | wc -l
2374

```

If I want to know how many of these come from PowerShell, I can `grep` for that:

```

oxdf@hacky$ jq -c '.|select(.EventId == 4616)' EvtxECmd_Output.json  | grep -i powershell | wc -l
2371

```

This is the correct answer to Task 10. These events look like:

```

{
  "PayloadData1": "PreviousTime: 2023-05-04 10:38:32.5682816",
  "PayloadData2": "NewTime: 2023-05-04 11:49:32.5340000",
  "PayloadData3": "LogonId: 0x345D6D",
  "UserName": "DESKTOP-R30EAMH\\gladys (S-1-5-21-3720869868-2926106253-3446724670-1003)",
  "ExecutableInfo": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "MapDescription": "The system time was changed",
  "ChunkNumber": 4,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"SubjectUserSid\",\"#text\":\"S-1-5-21-3720869868-2926106253-3446724670-1003\"},{\"@Name\":\"SubjectUserName\",\"#text\":\"gladys\"},{\"@Name\":\"SubjectDomainName\",\"#text\":\"DESKTOP-R30EAMH\"},{\"@Name\":\"SubjectLogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"PreviousTime\",\"#text\":\"2023-05-04 10:38:32.5682816\"},{\"@Name\":\"NewTime\",\"#text\":\"2023-05-04 11:49:32.5340000\"},{\"@Name\":\"ProcessId\",\"#text\":\"0x1504\"},{\"@Name\":\"ProcessName\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"}]}}",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventId": 4616,
  "EventRecordId": "8905",
  "ProcessId": 4,
  "ThreadId": 156,
  "Level": "LogAlways",
  "Keywords": "Audit success",
  "SourceFile": ".\\logs\\Security.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T11:49:32.5370350+00:00",
  "RecordNumber": 8905
}

```

I can get the SID of the victim from here for Task 11, S-1-5-21-3720869868-2926106253-3446724670-1003.

Of the other three, two come from `SystemSettingsAdminFlows.exe`, and one from `C:\\W遀, 筕㨡,` . It’s not clear if these are malicious or not.

### merlin.exe

#### First merline.exe Process [1992]

There are 379 logs that mention `merlin.exe`:

```

oxdf@hacky$ jq -c . EvtxECmd_Output.json  | grep -i merlin.exe | wc -l
379

```

The first log shows it’s creation at the suspect time of 2023/05/04 11:21:30:

```

{
  "PayloadData1": "ProcessID: 4428, ProcessGUID: 5080714d-8a4f-6453-d501-000000000700",
  "PayloadData2": "RuleName: EXE",
  "PayloadData3": "Image: C:\\Users\\gladys\\AppData\\Local\\Temp\\TeamViewer\\TeamViewer.exe",
  "PayloadData4": "TargetFilename: C:\\Users\\gladys\\Desktop\\merlin.exe",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "MapDescription": "FileCreate",
  "ChunkNumber": 31,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"EXE\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:21:30.995\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8a4f-6453-d501-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"4428\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\AppData\\\\Local\\\\Temp\\\\TeamViewer\\\\TeamViewer.exe\"},{\"@Name\":\"TargetFilename\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"CreationUtcTime\",\"#text\":\"2023-05-04 10:21:30.994\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 11,
  "EventRecordId": "2063",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:21:30.9970072+00:00",
  "RecordNumber": 2063
}

```

The creation time on the file is modified (just like with the PowerShell script), and then the executable is run at 2023-05-04 11:21:42 with process id 1992:

```

{
  "PayloadData1": "ProcessID: 1992, ProcessGUID: 5080714d-8736-6453-4002-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=AED56DA95650B4895707A1638BC941EF,SHA256=42EC59F760D8B6A50BBC7187829F62C3B6B8E1B841164E7185F497EB7F3B4DB9,IMPHASH=9CBEFE68F395E67356E2A5D8D1B285C0",
  "PayloadData4": "ParentProcess: C:\\Windows\\explorer.exe",
  "PayloadData5": "ParentProcessID: 4780, ParentProcessGUID: 5080714d-427c-6452-6b01-000000000700",
  "PayloadData6": "ParentCommandLine: C:\\Windows\\Explorer.EXE",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "\"C:\\Users\\gladys\\Desktop\\merlin.exe\" ",
  "MapDescription": "Process creation",
  "ChunkNumber": 32,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:21:42.391\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8736-6453-4002-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"1992\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"-\"},{\"@Name\":\"Description\",\
"#text\":\"-\"},{\"@Name\":\"Product\",\"#text\":\"-\"},{\"@Name\":\"Company\",\"#text\":\"-\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"-\"},{\"@Name\":\"CommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\\\" \"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\"
:\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\"
,\"#text\":\"MD5=AED56DA95650B4895707A1638BC941EF,SHA256=42EC59F760D8B6A50BBC7187829F62C3B6B8E1B841164E7185F497EB7F3B4DB9,IMPHASH=9CBEFE68F395E67356E2A5D8D1B285C0\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"
5080714d-427c-6452-6b01-000000000700\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"4780\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Windows\\\\explorer.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"C:\
\\\Windows\\\\Explorer.EXE\"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2070",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:21:42.4707110+00:00",
  "RecordNumber": 2070
}

```

There are some registry writes, and then a network connection:

```

{
  "PayloadData1": "ProcessID: 1992, ProcessGUID: 5080714d-8736-6453-4002-000000000700",
  "PayloadData2": "RuleName: Usermode",
  "PayloadData3": "SourceHostname: DESKTOP-R30EAMH.forela.local",
  "PayloadData4": "SourceIp: 10.10.0.79",
  "PayloadData5": "DestinationHostname: ec2-52-56-142-81.eu-west-2.compute.amazonaws.com",
  "PayloadData6": "DestinationIp: 52.56.142.81",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "MapDescription": "Network connection",
  "ChunkNumber": 32,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"Usermode\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-03 11:24:24.445\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8736-6453-400
2-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"1992\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@
Name\":\"Protocol\",\"#text\":\"tcp\"},{\"@Name\":\"Initiated\",\"#text\":\"True\"},{\"@Name\":\"SourceIsIpv6\",\"#text\":\"False\"},{\"@Name\":\"SourceIp\",\"#text\":\"10.10.0.79\"},{\"@Name\":\"SourceHostname\",\"#text\":\"DESKTOP-R30EAMH.forela.local\"},{\"@Name\":\"SourcePort\",\"#text\":\"50538\"},{\"@Name\":\"SourcePortName\",\"#text\":\"-\"},{\"@Name\":\"DestinationIsIpv6\",\"#text\":\"False\"},{\"@Name\":\"Dest
inationIp\",\"#text\":\"52.56.142.81\"},{\"@Name\":\"DestinationHostname\",\"#text\":\"ec2-52-56-142-81.eu-west-2.compute.amazonaws.com\"},{\"@Name\":\"DestinationPort\",\"#text\":\"80\"},{\"@Name\":\"Destinatio
nPortName\",\"#text\":\"http\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 3,
  "EventRecordId": "2076",
  "ProcessId": 2980,
  "ThreadId": 472,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:21:47.2784488+00:00",
  "RecordNumber": 2076
}

```

The destination IP of 52.56.142.81 is the answer to Task 5. There’s a ton of these “Network Connection logs, all to the same IP. If I `grep` them out, there are only 22 left:

```

oxdf@hacky$ jq -c . EvtxECmd_Output.json  | grep -i merlin.exe | grep -v "Network connection" | wc -l
22

```

The process (1992) ends with a Process Terminated event at 2023/05/04 11:29:41.

#### Second merlin.exe [5768]

A second Merlin process is started a few minutes later, process id 5768, at 2023/05/04 11:32:46.

```

{
  "PayloadData1": "ProcessID: 5768, ProcessGUID: 5080714d-89ce-6453-c202-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=AED56DA95650B4895707A1638BC941EF,SHA256=42EC59F760D8B6A50BBC7187829F62C3B6B8E1B841164E7185F497EB7F3B4DB9,IMPHASH=9CBEFE68F395E67356E2A5D8D1B285C0",
  "PayloadData4": "ParentProcess: C:\\Windows\\explorer.exe",
  "PayloadData5": "ParentProcessID: 4780, ParentProcessGUID: 5080714d-427c-6452-6b01-000000000700",
  "PayloadData6": "ParentCommandLine: C:\\Windows\\Explorer.EXE",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "\"C:\\Users\\gladys\\Desktop\\merlin.exe\" ",
  "MapDescription": "Process creation",
  "ChunkNumber": 43,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:32:46.458\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-89ce-6453-c202-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"5768\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"-\"},{\"@Name\":\"Description\",\
"#text\":\"-\"},{\"@Name\":\"Product\",\"#text\":\"-\"},{\"@Name\":\"Company\",\"#text\":\"-\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"-\"},{\"@Name\":\"CommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\gladys\\
\\Desktop\\\\merlin.exe\\\" \"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\"
:\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\"
,\"#text\":\"MD5=AED56DA95650B4895707A1638BC941EF,SHA256=42EC59F760D8B6A50BBC7187829F62C3B6B8E1B841164E7185F497EB7F3B4DB9,IMPHASH=9CBEFE68F395E67356E2A5D8D1B285C0\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"
5080714d-427c-6452-6b01-000000000700\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"4780\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Windows\\\\explorer.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"C:\
\\\Windows\\\\Explorer.EXE\"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2880",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:32:46.4592084+00:00",
  "RecordNumber": 2880
}

```

It tries to run `cmd.exe` to create a directory at `C:temp`:

```

{
  "PayloadData1": "ProcessID: 5092, ProcessGUID: 5080714d-9aa0-6453-d402-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD",
  "PayloadData4": "ParentProcess: C:\\Users\\gladys\\Desktop\\merlin.exe",
  "PayloadData5": "ParentProcessID: 5768, ParentProcessGUID: 5080714d-89ce-6453-c202-000000000700",
  "PayloadData6": "ParentCommandLine: \"C:\\Users\\gladys\\Desktop\\merlin.exe\" ",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\system32\\cmd.exe /c mkdir C:temp",
  "MapDescription": "Process creation",
  "ChunkNumber": 44,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 11:44:32.862\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-9aa0-6453-d402-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"5092\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@N
ame\":\"Description\",\"#text\":\"Windows Command Processor\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"Cmd.Exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\system32\\\\cmd.exe /c mkdir C:temp\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Deskt
op\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"Ter
minalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4
EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"5080714d-89ce-6453-c202-000000000700\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"5768\"},{\"@Name\":\"Pa
rentImage\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\\\" \"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2932",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T11:44:32.8658890+00:00",
  "RecordNumber": 2932
}

```

The timestamp on this even is over an hour later at 2023/05/04 12:44:32, but it may have just jumped again.

#### Defender

There are a handful of Defender logs at the bottom of the logs. First it detects `merlin.exe` at 2023/05/04 10:29:22:

```

{
  "PayloadData1": "Malware name: VirTool:Win32/Myrddin.D",
  "PayloadData2": "Description: Tool (Severe)",
  "PayloadData3": "Detection Time: 2023-05-04T10:29:22.055Z",
  "PayloadData4": "Process (if real-time detection): C:\\Users\\gladys\\Desktop\\merlin.exe",
  "PayloadData5": "Detection ID: {54D38AAD-42D5-464A-865D-FF19F91744A5}",
  "UserName": "Detection User: NT AUTHORITY\\SYSTEM",
  "ExecutableInfo": "file:_C:\\Users\\gladys\\Desktop\\merlin.exe;process:_pid:1992,ProcessStart:133276693023911786",
  "MapDescription": "Detection - The antimalware platform detected malware or other potentially unwanted software",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"Product Name\",\"#text\":\"%%827\"},{\"@Name\":\"Product Version\",\"#text\":\"4.8.10240.17394\"},{\"@Name\":\"Detection ID\",\"#text\":\"{54D38AAD-42D5-464A-
865D-FF19F91744A5}\"},{\"@Name\":\"Detection Time\",\"#text\":\"2023-05-04T10:29:22.055Z\"},{\"@Name\":\"Unused\"},{\"@Name\":\"Unused2\"},{\"@Name\":\"Threat ID\",\"#text\":\"2147812764\"},{\"@Name\":\"Threat N
ame\",\"#text\":\"VirTool:Win32/Myrddin.D\"},{\"@Name\":\"Severity ID\",\"#text\":\"5\"},{\"@Name\":\"Severity Name\",\"#text\":\"Severe\"},{\"@Name\":\"Category ID\",\"#text\":\"34\"},{\"@Name\":\"Category Name
\",\"#text\":\"Tool\"},{\"@Name\":\"FWLink\",\"#text\":\"http://go.microsoft.com/fwlink/?linkid=37020&amp;name=VirTool:Win32/Myrddin.D&amp;threatid=2147812764&amp;enterprise=0\"},{\"@Name\":\"Status Code\",\"#text\":\"1\"},{\"@Name\":\"Status Description\"},{\"@Name\":\"State\",\"#text\":\"1\"},{\"@Name\":\"Source ID\",\"#text\":\"2\"},{\"@Name\":\"Source Name\",\"#text\":\"%%820\"},{\"@Name\":\"Process Name\",\"#text\
":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"Detection User\",\"#text\":\"NT AUTHORITY\\\\SYSTEM\"},{\"@Name\":\"Unused3\"},{\"@Name\":\"Path\",\"#text\":\"file:_C:\\\\Users\\\\gladys\\\\De
sktop\\\\merlin.exe;process:_pid:1992,ProcessStart:133276693023911786\"},{\"@Name\":\"Origin ID\",\"#text\":\"1\"},{\"@Name\":\"Origin Name\",\"#text\":\"%%845\"},{\"@Name\":\"Execution ID\",\"#text\":\"3\"},{\"
@Name\":\"Execution Name\",\"#text\":\"%%848\"},{\"@Name\":\"Type ID\",\"#text\":\"0\"},{\"@Name\":\"Type Name\",\"#text\":\"%%822\"},{\"@Name\":\"Pre Execution Status\",\"#text\":\"0\"},{\"@Name\":\"Action ID\"
,\"#text\":\"9\"},{\"@Name\":\"Action Name\",\"#text\":\"%%887\"},{\"@Name\":\"Unused4\"},{\"@Name\":\"Error Code\",\"#text\":\"0x00000000\"},{\"@Name\":\"Error Description\",\"#text\":\"The operation completed successfully. \"},{\"@Name\":\"Unused5\"},{\"@Name\":\"Post Clean Status\",\"#text\":\"0\"},{\"@Name\":\"Additional Actions ID\",\"#text\":\"0\"},{\"@Name\":\"Additional Actions String\",\"#text\":\"No additiona
l actions required\"},{\"@Name\":\"Remediation User\"},{\"@Name\":\"Unused6\"},{\"@Name\":\"Signature Version\",\"#text\":\"AV: 1.389.167.0, AS: 1.389.167.0, NIS: 0.0.0.0\"},{\"@Name\":\"Engine Version\",\"#text
\":\"AM: 1.1.20300.3, NIS: 0.0.0.0\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Windows Defender/Operational",
  "Provider": "Microsoft-Windows-Windows Defender",
  "EventId": 1116,
  "EventRecordId": "25",
  "ProcessId": 1936,
  "ThreadId": 3000,
  "Level": "Warning",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:29:22.0747342+00:00",
  "RecordNumber": 25
}

```

Then it takes action, presumbly quarantining it:

```

{
  "PayloadData1": "Malware name: VirTool:Win32/Myrddin.D",
  "PayloadData2": "Description: Tool (Severe)",
  "PayloadData3": "Detection Time: 2023-05-04T10:29:22.055Z",
  "PayloadData4": "Process (if real-time detection): C:\\Users\\gladys\\Desktop\\merlin.exe",
  "PayloadData5": "Detection ID: {54D38AAD-42D5-464A-865D-FF19F91744A5}",
  "UserName": "Detection User: NT AUTHORITY\\SYSTEM",
  "ExecutableInfo": "file:_C:\\Users\\gladys\\Desktop\\merlin.exe;process:_pid:1992,ProcessStart:133276693023911786",
  "MapDescription": "Detection - The antimalware platform performed an action to protect your system from malware or other potentially unwanted software",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"Product Name\",\"#text\":\"%%827\"},{\"@Name\":\"Product Version\",\"#text\":\"4.8.10240.17394\"},{\"@Name\":\"Detection ID\",\"#text\":\"{54D38AAD-42D5-464A-
865D-FF19F91744A5}\"},{\"@Name\":\"Detection Time\",\"#text\":\"2023-05-04T10:29:22.055Z\"},{\"@Name\":\"Unused\"},{\"@Name\":\"Unused2\"},{\"@Name\":\"Threat ID\",\"#text\":\"2147812764\"},{\"@Name\":\"Threat N
ame\",\"#text\":\"VirTool:Win32/Myrddin.D\"},{\"@Name\":\"Severity ID\",\"#text\":\"5\"},{\"@Name\":\"Severity Name\",\"#text\":\"Severe\"},{\"@Name\":\"Category ID\",\"#text\":\"34\"},{\"@Name\":\"Category Name
\",\"#text\":\"Tool\"},{\"@Name\":\"FWLink\",\"#text\":\"http://go.microsoft.com/fwlink/?linkid=37020&amp;name=VirTool:Win32/Myrddin.D&amp;threatid=2147812764&amp;enterprise=0\"},{\"@Name\":\"Status Code\",\"#te
xt\":\"3\"},{\"@Name\":\"Status Description\"},{\"@Name\":\"State\",\"#text\":\"2\"},{\"@Name\":\"Source ID\",\"#text\":\"2\"},{\"@Name\":\"Source Name\",\"#text\":\"%%820\"},{\"@Name\":\"Process Name\",\"#text\
":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"Detection User\",\"#text\":\"NT AUTHORITY\\\\SYSTEM\"},{\"@Name\":\"Unused3\"},{\"@Name\":\"Path\",\"#text\":\"file:_C:\\\\Users\\\\gladys\\\\De
sktop\\\\merlin.exe;process:_pid:1992,ProcessStart:133276693023911786\"},{\"@Name\":\"Origin ID\",\"#text\":\"1\"},{\"@Name\":\"Origin Name\",\"#text\":\"%%845\"},{\"@Name\":\"Execution ID\",\"#text\":\"3\"},{\"
@Name\":\"Execution Name\",\"#text\":\"%%848\"},{\"@Name\":\"Type ID\",\"#text\":\"0\"},{\"@Name\":\"Type Name\",\"#text\":\"%%822\"},{\"@Name\":\"Pre Execution Status\",\"#text\":\"3\"},{\"@Name\":\"Action ID\"
,\"#text\":\"2\"},{\"@Name\":\"Action Name\",\"#text\":\"%%809\"},{\"@Name\":\"Unused4\"},{\"@Name\":\"Error Code\",\"#text\":\"0x00000000\"},{\"@Name\":\"Error Description\",\"#text\":\"The operation completed 
successfully. \"},{\"@Name\":\"Unused5\"},{\"@Name\":\"Post Clean Status\",\"#text\":\"0\"},{\"@Name\":\"Additional Actions ID\",\"#text\":\"0\"},{\"@Name\":\"Additional Actions String\",\"#text\":\"No additiona
l actions required\"},{\"@Name\":\"Remediation User\",\"#text\":\"NT AUTHORITY\\\\SYSTEM\"},{\"@Name\":\"Unused6\"},{\"@Name\":\"Signature Version\",\"#text\":\"AV: 1.389.167.0, AS: 1.389.167.0, NIS: 0.0.0.0\"},
{\"@Name\":\"Engine Version\",\"#text\":\"AM: 1.1.20300.3, NIS: 0.0.0.0\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Windows Defender/Operational",
  "Provider": "Microsoft-Windows-Windows Defender",
  "EventId": 1117,
  "EventRecordId": "26",
  "ProcessId": 1936,
  "ThreadId": 3000,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:29:41.8497109+00:00",
  "RecordNumber": 26
}

```

It’s flagging `merlin.exe` as `VirTool:Win32/Myrddin.D` (the answer to Task 6). This “action” time is the same as when the first process terminates.

### Other Processes

#### All

Given the actor’s execution on this host, I’ll look for a list of all the process creation Sysmon events. I’ll use `jq` to filter on only events with the `.MapDescription` of “Process creation”, and then get just the `.ExcutableInfo` field, which is typically the fill command line for the process:

```

oxdf@hacky$ jq -r '. | select(.MapDescription == "Process creation") | .ExecutableInfo' EvtxECmd_Output.json | wc -l
296
oxdf@hacky$ jq -r '. | select(.MapDescription == "Process creation") | .ExecutableInfo' EvtxECmd_Output.json | head 
C:\Windows\Sysmon64.exe
C:\Windows\system32\wbem\unsecapp.exe -Embedding
"LogonUI.exe" /flags:0x0 /state0:0xa39b3855 /state1:0x41c64e6d
\SystemRoot\System32\smss.exe 000000c0 00000074 
%%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
winlogon.exe
"LogonUI.exe" /flags:0x0 /state0:0xa39b5055 /state1:0x41c64e6d
"dwm.exe"
vm3dservice.exe -n
C:\Windows\system32\userinit.exe

```

There’s 296 processes logged, and the output looks about right.

#### cmd.exe

I can scroll that entire list, but something to pay extra attention to is `cmd.exe` to run commands. There are seven events:

```

oxdf@hacky$ jq -r '. | select(.MapDescription == "Process creation") | .ExecutableInfo' EvtxECmd_Output.json | grep -i cmd.exe
"C:\Windows\System32\cmd.exe" /q /c del /q "C:\Users\gladys\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
"C:\Windows\System32\cmd.exe" /q /c del /q "C:\Users\gladys\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe"
C:\Windows\system32\cmd.exe /c .rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full
C:\Windows\system32\cmd.exe /c rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full
C:\Windows\system32\cmd.exe /c mkdir C:temp
"cmd.exe" /s /k pushd "C:\Users\gladys\Desktop\KAPE"
"C:\Windows\system32\cmd.exe" 

```

The first two appear benign, and the last two have to do with collection through Kape. The middle three are interesting. I’ll pull them in more details.

I’ll switch back to `grep` to get these logs, and actually find a fourth similar one with `jq -c . EvtxECmd_Output.json | grep -e lsass.dmp -e C:temp | jq .`. The first event shows running `cmd.exe` to try to run `rundll32.exe` to run `comsvcs.dll` to dump LSASS:

```

{
  "PayloadData1": "ProcessID: 4044, ProcessGUID: 5080714d-88e2-6453-9102-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD",
  "PayloadData4": "ParentProcess: -",
  "PayloadData5": "ParentProcessID: 1992, ParentProcessGUID: 00000000-0000-0000-0000-000000000000",
  "PayloadData6": "ParentCommandLine: -",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\system32\\cmd.exe /c .rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full",
  "MapDescription": "Process creation",
  "ChunkNumber": 42,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:28:50.652\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-88e2-6453-9102-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"4044\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@Name\":\"Description\",\"#text\":\"Windows Command Processor\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"Cmd.Exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\system32\\\\cmd.exe /c .rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"00000000-0000-0000-0000-000000000000\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"1992\"},{\"@Name\":\"ParentImage\",\"#text\":\"-\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"-\"},{\"@Name\":\"ParentUser\",\"#text\":\"-\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2829",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:28:50.6541476+00:00",
  "RecordNumber": 2829
}

```

The actor seems to not be escaping their `\` so they are missing here, and they are trying to call `.rundll32.exe` (with an extra leading dot), so it fails. The parent process is 1992, the `merlin.exe` process from above.

About a minute later they try basically the same thing again, fixing the leading dot but not the slashes:

```

{
  "PayloadData1": "ProcessID: 2392, ProcessGUID: 5080714d-8903-6453-a902-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD",
  "PayloadData4": "ParentProcess: -",
  "PayloadData5": "ParentProcessID: 1992, ParentProcessGUID: 00000000-0000-0000-0000-000000000000",
  "PayloadData6": "ParentCommandLine: -",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\system32\\cmd.exe /c rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full",
  "MapDescription": "Process creation",
  "ChunkNumber": 43,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:29:23.522\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8903-6453-a902-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"2392\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@N
ame\":\"Description\",\"#text\":\"Windows Command Processor\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"
OriginalFileName\",\"#text\":\"Cmd.Exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\system32\\\\cmd.exe /c rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full\"},{\"@Name\"
:\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=A6177D080759CF4A03EF837A3
8F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"00000000-0000-0000-0000-000000000000\"},{\
"@Name\":\"ParentProcessId\",\"#text\":\"1992\"},{\"@Name\":\"ParentImage\",\"#text\":\"-\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"-\"},{\"@Name\":\"ParentUser\",\"#text\":\"-\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2856",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:29:23.5244329+00:00",
  "RecordNumber": 2856
}

```

A `rundll32.exe` process does start:

```

{
  "PayloadData1": "ProcessID: 2644, ProcessGUID: 5080714d-8903-6453-ab02-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=5DED2A3F11AE916C8F2724947E736261,SHA256=35402466FE6D02CC85A27171F55D9F7FD0AAF018D3CC410E46F0B43DCE7EA080,IMPHASH=F5F0B1D26781FF501D89E94660255E9C",
  "PayloadData4": "ParentProcess: C:\\Windows\\System32\\cmd.exe",
  "PayloadData5": "ParentProcessID: 2392, ParentProcessGUID: 5080714d-8903-6453-a902-000000000700",
  "PayloadData6": "ParentCommandLine: C:\\Windows\\system32\\cmd.exe /c rundll32.exe C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "rundll32.exe  C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full",
  "MapDescription": "Process creation",
  "ChunkNumber": 43,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:29:23.564\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8903-6453-ab02-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"2644\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\rundll32.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},
{\"@Name\":\"Description\",\"#text\":\"Windows host process (Rundll32)\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\
"@Name\":\"OriginalFileName\",\"#text\":\"RUNDLL32.EXE\"},{\"@Name\":\"CommandLine\",\"#text\":\"rundll32.exe  C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full\"},{\"@Name\":\"CurrentDirectory\",\
"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=5DED2A3F11AE916C8F2724947E736261,SHA256=35402466
FE6D02CC85A27171F55D9F7FD0AAF018D3CC410E46F0B43DCE7EA080,IMPHASH=F5F0B1D26781FF501D89E94660255E9C\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"5080714d-8903-6453-a902-000000000700\"},{\"@Name\":\"ParentProces
sId\",\"#text\":\"2392\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"C:\\\\Windows\\\\system32\\\\cmd.exe /c rundll32.exe C:window
sSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full\"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2857",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:29:23.5673787+00:00",
  "RecordNumber": 2857
}

```

It’s right at this time that the `merlin.exe` gets detected by Defender.

The final `cmd.exe` comes from the second `merlin.exe` execution:

```

{
  "PayloadData1": "ProcessID: 5092, ProcessGUID: 5080714d-9aa0-6453-d402-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD",
  "PayloadData4": "ParentProcess: C:\\Users\\gladys\\Desktop\\merlin.exe",
  "PayloadData5": "ParentProcessID: 5768, ParentProcessGUID: 5080714d-89ce-6453-c202-000000000700",
  "PayloadData6": "ParentCommandLine: \"C:\\Users\\gladys\\Desktop\\merlin.exe\" ",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\system32\\cmd.exe /c mkdir C:temp",
  "MapDescription": "Process creation",
  "ChunkNumber": 44,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 11:44:32.862\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-9aa0-6453-d402-00000
0000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"5092\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@N
ame\":\"Description\",\"#text\":\"Windows Command Processor\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"
OriginalFileName\",\"#text\":\"Cmd.Exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\system32\\\\cmd.exe /c mkdir C:temp\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"Ter
minalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=A6177D080759CF4A03EF837A38F62401,SHA256=79D1FFABDD7841D9043D4DDF1F93721BCD35D823614411FD4
EAB5D2C16A86F35,IMPHASH=E9AF55CDA7F5BE2D9801D2640AB396FD\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"5080714d-89ce-6453-c202-000000000700\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"5768\"},{\"@Name\":\"Pa
rentImage\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\\\" \"},{\"@Name\":\"ParentUser\",\"#text
\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2932",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T11:44:32.8658890+00:00",
  "RecordNumber": 2932
}

```

#### Child Processes

I’ll look for events where processes start as children of the known `merlin.exe` processes. `jq '. | select(.PayloadData5 // "" | contains("ParentProcessID: 1992"))' EvtxECmd_Output.json` will filter on events that contain some `PayloadData5` and it has the string identifying the parent process id:

```

{
  "PayloadData1": "ProcessID: 1804, ProcessGUID: 5080714d-886e-6453-7102-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=64A1B725CD863CDFEAA03ED4C07A41B2,SHA256=70BE38AD675D7E85E6C18D1AC22097F100FECFCE4FA3E898FD044092186FEE46,IMPHASH=39B229051176141F00F2283D711B1D09",
  "PayloadData4": "ParentProcess: C:\\Users\\gladys\\Desktop\\merlin.exe",
  "PayloadData5": "ParentProcessID: 1992, ParentProcessGUID: 5080714d-8736-6453-4002-000000000700",
  "PayloadData6": "ParentCommandLine: \"C:\\Users\\gladys\\Desktop\\merlin.exe\" ",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "\"C:\\Windows\\System32\\WerFault.exe\"",
  "MapDescription": "Process creation",
  "ChunkNumber": 35,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 10:26:54.187\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-886e-6453-7102-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"1804\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WerFault.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@Name\":\"Description\",\"#text\":\"Windows Problem Reporting\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"WerFault.exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"\\\"C:\\\\Windows\\\\System32\\\\WerFault.exe\\\"\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=64A1B725CD863CDFEAA03ED4C07A41B2,SHA256=70BE38AD675D7E85E6C18D1AC22097F100FECFCE4FA3E898FD044092186FEE46,IMPHASH=39B229051176141F00F2283D711B1D09\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"5080714d-8736-6453-4002-000000000700\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"1992\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\gladys\\\\Desktop\\\\merlin.exe\\\" \"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2283",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T10:26:54.1920811+00:00",
  "RecordNumber": 2283
}

```

This is [definitely suspicious activity](https://www.elastic.co/guide/en/security/current/suspicious-werfault-child-process.html). The rest of the children of 1992 are the ones above.

5768 also has three child processes. The first is the failed `mkdir` noted above. The next two are both PowerShell commands running base64-encoded commands. The first is:

```

{
  "PayloadData1": "ProcessID: 3804, ProcessGUID: 5080714d-8150-6453-0d03-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=190E6E0CDBEF529941D9E5F8F979F5D9,SHA256=8787D4B624880012ABDB442532BE762DB0361DECE169FEF9E1E877A9DF9E00CB,IMPHASH=44B4867FED7460EEC45FBEE7804BB612",
  "PayloadData4": "ParentProcess: -",
  "PayloadData5": "ParentProcessID: 5768, ParentProcessGUID: 00000000-0000-0000-0000-000000000000",
  "PayloadData6": "ParentCommandLine: -",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e JABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgByAGUAYQBsAGwAeQBsAG8AbgBnAHAAYQBzAHMAdwBvAHIAZAAiACAALQBBAHMAUABsAGEAaQBuAFQAZQB4AHQAIAAtAEYAbwByAGMAZQAKAEUAbgBhAGIAbABlAC0AQgBpAHQATABvAGMAawBlAHIAIAAtAE0AbwB1AG4AdABQAG8AaQBuAHQAIAAiAEMAOgAiACAALQBFAG4AYwByAHkAcAB0AGkAbwBuAE0AZQB0AGgAbwBkACAAQQBlAHMAMgA1ADYAIAAtAFUAcwBlAGQAUwBwAGEAYwBlAE8AbgBsAHkAIAAtAFAAaQBuACAAJABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAC0AVABQAE0AYQBuAGQAUABpAG4AUAByAG8AdABlAGMAdABvAHIA",
  "MapDescription": "Process creation",
  "ChunkNumber": 45,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 09:56:32.836\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-8150-6453-0d03-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"3804\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@Name\":\"Description\",\"#text\":\"Windows PowerShell\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"PowerShell.EXE\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe -e JABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgByAGUAYQBsAGwAeQBsAG8AbgBnAHAAYQBzAHMAdwBvAHIAZAAiACAALQBBAHMAUABsAGEAaQBuAFQAZQB4AHQAIAAtAEYAbwByAGMAZQAKAEUAbgBhAGIAbABlAC0AQgBpAHQATABvAGMAawBlAHIAIAAtAE0AbwB1AG4AdABQAG8AaQBuAHQAIAAiAEMAOgAiACAALQBFAG4AYwByAHkAcAB0AGkAbwBuAE0AZQB0AGgAbwBkACAAQQBlAHMAMgA1ADYAIAAtAFUAcwBlAGQAUwBwAGEAYwBlAE8AbgBsAHkAIAAtAFAAaQBuACAAJABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAC0AVABQAE0AYQBuAGQAUABpAG4AUAByAG8AdABlAGMAdABvAHIA\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=190E6E0CDBEF529941D9E5F8F979F5D9,SHA256=8787D4B624880012ABDB442532BE762DB0361DECE169FEF9E1E877A9DF9E00CB,IMPHASH=44B4867FED7460EEC45FBEE7804BB612\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"00000000-0000-0000-0000-000000000000\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"5768\"},{\"@Name\":\"ParentImage\",\"#text\":\"-\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"-\"},{\"@Name\":\"ParentUser\",\"#text\":\"-\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "2967",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T09:56:32.8372435+00:00",
  "RecordNumber": 2967
}

```

The base64 decodes to:

```

$SecureString = ConvertTo-SecureString "reallylongpassword" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector

```

It’s trying to enable Bitlocker with the password “reallylongpassword” (this answers Task 3).

The second one is:

```

{
  "PayloadData1": "ProcessID: 2452, ProcessGUID: 5080714d-9398-6453-9004-000000000700",
  "PayloadData2": "RuleName: -",
  "PayloadData3": "MD5=190E6E0CDBEF529941D9E5F8F979F5D9,SHA256=8787D4B624880012ABDB442532BE762DB0361DECE169FEF9E1E877A9DF9E00CB,IMPHASH=44B4867FED7460EEC45FBEE7804BB612",
  "PayloadData4": "ParentProcess: -",
  "PayloadData5": "ParentProcessID: 5768, ParentProcessGUID: 00000000-0000-0000-0000-000000000000",
  "PayloadData6": "ParentCommandLine: -",
  "UserName": "DESKTOP-R30EAMH\\gladys",
  "ExecutableInfo": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e JABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgByAGUAYQBsAGwAeQBsAG8AbgBnAHAAYQBzAHMAdwBvAHIAZAAiACAALQBBAHMAUABsAGEAaQBuAFQAZQB4AHQAIAAtAEYAbwByAGMAZQAKAEUAbgBhAGIAbABlAC0AQgBpAHQATABvAGMAawBlAHIAIAAtAE0AbwB1AG4AdABQAG8AaQBuAHQAIAAiAEMAOgAiACAALQBFAG4AYwByAHkAcAB0AGkAbwBuAE0AZQB0AGgAbwBkACAAQQBlAHMAMgA1ADYAIAAtAFUAcwBlAGQAUwBwAGEAYwBlAE8AbgBsAHkAIAAtAFAAaQBuACAAJABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwA=",
  "MapDescription": "Process creation",
  "ChunkNumber": 48,
  "Computer": "DESKTOP-R30EAMH",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2023-05-04 11:14:32.703\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"5080714d-9398-6453-9004-000000000700\"},{\"@Name\":\"ProcessId\",\"#text\":\"2452\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"10.0.10240.16384 (th1.150709-1700)\"},{\"@Name\":\"Description\",\"#text\":\"Windows PowerShell\"},{\"@Name\":\"Product\",\"#text\":\"Microsoft® Windows® Operating System\"},{\"@Name\":\"Company\",\"#text\":\"Microsoft Corporation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"PowerShell.EXE\"},{\"@Name\":\"CommandLine\",\"#text\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe -e JABTAGUAYwB1AHIAZQ
BTAHQAcgBpAG4AZwAgAD0AIABDAG8AbgB2AGUAcgB0AFQAbwAtAFMAZQBjAHUAcgBlAFMAdAByAGkAbgBnACAAIgByAGUAYQBsAGwAeQBsAG8AbgBnAHAAYQBzAHMAdwBvAHIAZAAiACAALQBBAHMAUABsAGEAaQBuAFQAZQB4AHQAIAAtAEYAbwByAGMAZQAKAEUAbgBhAGIAbABlAC0AQgBpAHQATABvAGMAawBlAHIAIAAtAE0AbwB1AG4AdABQAG8AaQBuAHQAIAAiAEMAOgAiACAALQBFAG4AYwByAHkAcAB0AGkAbwBuAE0AZQB0AGgAbwBkACAAQQBlAHMAMgA1ADYAIAAtAFUAcwBlAGQAUwBwAGEAYwBlAE8AbgBsAHkAIAAtAFAAaQBuACAAJABTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwA=\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\gladys\\\\Desktop\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-R30EAMH\\\\gladys\"},{\"@Name\":\"LogonGuid\",\"#text\":\"5080714d-427b-6452-6d5d-340000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x345D6D\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"3\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"High\"},{\"@Name\":\"Hashes\",\"#text\":\"MD5=190E6E0CDBEF529941D9E5F8F979F5D9,SHA256=8787D4B624880012ABDB442532BE762DB0361DECE169FEF9E1E877A9DF9E00CB,IMPHASH=44B4867FED7460EEC45FBEE7804BB612\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"00000000-0000-0000-0000-000000000000\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"5768\"},{\"@Name\":\"ParentImage\",\"#text\":\"-\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"-\"},{\"@Name\":\"ParentUser\",\"#text\":\"-\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "3138",
  "ProcessId": 2980,
  "ThreadId": 4056,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-05-04T11:14:32.7042798+00:00",
  "RecordNumber": 3138
}

```

This decodes to a slightly different variation:

```

$SecureString = ConvertTo-SecureString "reallylongpassword" -AsPlainText -Force
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $SecureString

```

The timestamps on both of these attempts don’t fit the timeline at all.

## MFT

### Parse

The Master File Table is stored in `$MFT` in the collection. I’ll parse it with another [Zimmerman Tool](https://ericzimmerman.github.io/#!index.md), `MFTECmd.exe` in my Windows VM:

```

PS C:\Users\0xdf > C:\Tools\ZimmermanTools\MFTECmd.exe -f '$MFT' --json Z:\hackthebox-sherlocks\ticktock\
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f $MFT --json Z:\hackthebox-sherlocks\ticktock\

Warning: Administrator privileges not found!

File type: Mft

Processed $MFT in 1.8035 seconds

$MFT: FILE records found: 120,652 (Free records: 11,126) File size: 128.8MB
        JSON output will be saved to Z:\hackthebox-sherlocks\ticktock\20231214193248_MFTECmd_$MFT_Output.json

```

I’ll rename it without the timestamp.

### Invoke-TimeWizard

There’s a single entry in the results for `Invoke-TimeWizard.ps1`:

```

oxdf@hacky$ grep Invoke-TimeWizard MFTECmd_MFT_Output.json | jq .
{
  "EntryNumber": 89291,
  "SequenceNumber": 4,
  "ParentEntryNumber": 83197,
  "ParentSequenceNumber": 3,
  "InUse": true,
  "ParentPath": ".\\Users\\gladys\\Desktop",
  "FileName": "Invoke-TimeWizard.ps1",
  "Extension": ".ps1",
  "IsDirectory": false,
  "HasAds": false,
  "IsAds": false,
  "FileSize": 446,
  "Created0x10": "2023-05-04T10:32:53.0000000+00:00",
  "Created0x30": "2023-05-04T10:35:59.9622439+00:00",
  "LastModified0x10": "2023-05-04T10:32:53.0000000+00:00",
  "LastModified0x30": "2023-05-04T10:35:59.9622439+00:00",
  "LastRecordChange0x10": "2023-05-04T10:36:00.1482572+00:00",
  "LastRecordChange0x30": "2023-05-04T10:35:59.9622439+00:00",
  "LastAccess0x10": "2023-05-04T10:32:53.0000000+00:00",
  "LastAccess0x30": "2023-05-04T10:35:59.9622439+00:00",
  "UpdateSequenceNumber": 244447752,
  "LogfileSequenceNumber": 797127032,
  "SecurityId": 2704,
  "SiFlags": 32,
  "ReferenceCount": 1,
  "NameType": 1,
  "Timestomped": true,
  "uSecZeros": true,
  "Copied": false,
  "FnAttributeId": 2,
  "OtherAttributeId": 1
}

```

I’ll remember from above that it tried to change the creation time of this file. It only got one set of timestamps, shown as 0x10 (like `Created0x10`), as the 0x30 values still has the legit time (1 hour behind the times the timeline).

### merlin.exe

I can get the same data about `merlin.exe`:

```

oxdf@hacky$ grep merlin.exe MFTECmd_MFT_Output.json | jq .
{
  "EntryNumber": 89565,
  "SequenceNumber": 11,
  "ParentEntryNumber": 83197,
  "ParentSequenceNumber": 3,
  "InUse": true,
  "ParentPath": ".\\Users\\gladys\\Desktop",
  "FileName": "merlin.exe",
  "Extension": ".exe",
  "IsDirectory": false,
  "HasAds": false,
  "IsAds": false,
  "FileSize": 11482112,
  "Created0x10": "2023-05-04T10:32:10.0000000+00:00",
  "Created0x30": "2023-05-04T10:32:39.2903937+00:00",
  "LastModified0x10": "2023-05-04T10:32:10.0000000+00:00",
  "LastModified0x30": "2023-05-04T10:32:39.2903937+00:00",
  "LastRecordChange0x10": "2023-05-04T10:32:39.3997821+00:00",
  "LastRecordChange0x30": "2023-05-04T10:32:39.2903937+00:00",
  "LastAccess0x10": "2023-05-04T10:41:32.0000000+00:00",
  "LastAccess0x30": "2023-05-04T10:32:39.2903937+00:00",
  "UpdateSequenceNumber": 276407928,
  "LogfileSequenceNumber": 873425896,
  "SecurityId": 2704,
  "SiFlags": 32,
  "ReferenceCount": 1,
  "NameType": 3,
  "Timestomped": true,
  "uSecZeros": true,
  "Copied": false,
  "FnAttributeId": 2,
  "OtherAttributeId": 3
}

```

None of these timestamps really makes sense with my timeline, but given the time obfuscation in play, that isn’t that surprising.

## Windows Defender Logs

### Locate

Kape also collected the `ProgramData` folder, which contains a `Microsoft` directory with three directories:

```

oxdf@hacky$ ls C/ProgramData/Microsoft/
search/           Windows/          Windows Defender/ 

```

`Windows` has start menu short cuts. `search` has databases to do with search history:

```

oxdf@hacky$ ls C/ProgramData/Microsoft/search/data/applications/windows
edb00017.log  edb00018.log  edb.chk  edb.log  edbres00001.jrs  edbtmp.log  GatherLogs  tmp.edb  Windows.edb

```

I’m most interested in the logs for `Windows Defender`:

```

oxdf@hacky$ ls C/ProgramData/Microsoft/Windows\ Defender/Support/
MpCacheStats.log  MPDetection-05032023-114843.log  MPLog-07102015-052145.log  MpWppTracing-05032023-114843-00000003-ffffffff.bin  MpWppTracing-05032023-115142-00000003-ffffffff.bin

```

### Analysis

I can’t `grep` in these logs, as they are UTF-16, and that doesn’t play nicely with `grep`. Still, `MPLog-07102015-052145.log` has references to the binary, such as:

```

SDN:Issuing SDN query for \\?\C:\Users\gladys\Desktop\merlin.exe (\\?\C:\Users\gladys\Desktop\merlin.exe) (sha1=ac688f1ba6d4b23899750b86521331d7f7ccfb69, sha2=42ec59f760d8b6a50bbc7187829f62c3b6b8e1b841164e7185f497eb7f3b4db9)
2023-05-04T10:29:22.070Z DETECTIONEVENT VirTool:Win32/Myrddin.D file:C:\Users\gladys\Desktop\merlin.exe;process:pid:1992,ProcessStart:133276693023911786;
2023-05-04T10:29:22.070Z DETECTION_ADD VirTool:Win32/Myrddin.D file:C:\Users\gladys\Desktop\merlin.exe
2023-05-04T10:29:22.070Z DETECTION_ADD VirTool:Win32/Myrddin.D process:pid:1992,ProcessStart:133276693023911786

```

The first one gives the SHA1 and SHA2 hash for the file (Task 9).

## Results

### Timeline

Putting all that together makes the following timeline (\* shows after system time modification):

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023/05/04 11:35:27 | Connection over TeamViewer | TeamViewer |
| 2023/05/04 11:35:32 | TeamViewer Screenshot | TeamViewer |
| 2023-05-04 11:35:59 | `Invoke-TimeWizard.ps1` written | Event Logs, MFT |
| 2023/05/04 11:36:25 | TeamViewer Screenshot | TeamViewer |
| 2023/05/04 11:21:30\* | `merlin.exe` creation time | Event Logs |
| 2023/05/04 11:21:34\* | `merlin.exe` downloaded | TeamViewer |
| 2023/05/04 11:21:42\* | `merlin.exe` executed | Event Logs |
| 2023/05/04 11:21:47\* | `merlin.exe` connection to 52.56.142.81 | Event Logs |
| 2023/05/04 11:26:54\* | Attempt to execute `WerFault.exe` | Event Logs |
| 2023/05/04 11:28:50\* | First failed attempt to dump LSASS | Event Logs |
| 2023/05/04 11:29:22\* | Defender detects `merlin.exe` | Event Logs, Defender Logs |
| 2023/05/04 11:29:23\* | Second failed attempt to dump LSASS | Event Logs |
| 2023/05/04 11:29:41\* | Defender takes action on `merlin.exe` | Event Logs |
| 2023/05/04 11:29:41\* | `merlin.exe` ends | Event Logs |
| 2023/05/04 11:32:46\* | Second `merlin.exe` executed | Event Logs |
| 2023/05/04 12:44:32\* | Second `merlin.exe` tries to create `C:temp` | Event Logs |
| {:.timeline} |  |  |

### Question Answers
1. What was the name of the executable that was uploaded as a C2 Agent?

   `merlin.exe` - TeamViewer Logs
2. What was the session id for in the initial access?
   -2102926010 - TeamViewer Logs
3. The attacker attempted to set a bitlocker password on the `C:` drive what was the password?
4. What name was used by the attacker?

   fritjof olfasson - TeamViewer Logs
5. What IP address did the C2 connect back to?
   52.56.142.81 - EventLogs
6. What category did Windows Defender give to the C2 binary file?

   `VirTool:Win32/Myrddin.D` - EventLogs
7. What was the filename of the powershell script the attackers used to manipulate time?

   `Invoke-TimeWizard.ps1` - PowerShell History Log
8. What time did the initial access connection start?

   2023/05/04 11:35:27 - TeamViewer Log
9. What is the SHA1 and SHA2 sum of the malicious binary?

   ac688f1ba6d4b23899750b86521331d7f7ccfb69:42ec59f760d8b6a50bbc7187829f62c3b6b8e1b841164e7185f497eb7f3b4db9 - Defender Logs
10. How many times did the powershell script change the time on the machine?

    2371 - Event Logs
11. What is the SID of the victim user?

    S-1-5-21-3720869868-2926106253-3446724670-1003 - Event Logs