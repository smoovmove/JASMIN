---
title: HTB Sherlock: Logjammer
url: https://0xdf.gitlab.io/2024/05/16/htb-sherlock-logjammer.html
date: 2024-05-16T09:00:00+00:00
difficulty: Easy
tags: htb-sherlock, ctf, sherlock-logjammer, sherlock-cat-dfir, forensics, dfir, hackthebox, evtxecmd, windows, event-logs, win-event-4624, jq, win-event-2004, win-event-2005, win-event-2006, win-event-2010, win-event-2033, win-event-2051, win-event-4719, win-event-4698, win-event-1116, win-event-1117, win-event-4103, win-event-4104, win-event-1102, win-event-104
---

![Logjammer](/icons/sherlock-logjammer.png)

Logjammer is a neat look at some Windows event log analysis. I’ll start with five event logs, security, system, Defender, firewall, and PowerShell, and use EvtxECmd.exe to convert them to JSON. Then I’ll slice them using JQ and some Bash to answer 12 questions about a malicious user on the box, showing their logon, uploading Sharphound, modifying the firewall, creating a scheduled task, running a PowerShell script, and clearing some event logs.

## Challenge Info

| Name | [Logjammer](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2flogjammer)  [Logjammer](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2flogjammer) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2flogjammer) |
| --- | --- |
| Release Date | 13 November 2023 |
| Retire Date | 2024-05-16 |
| Difficulty | Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> You have been presented with the opportunity to work as a junior DFIR consultant for a big consultancy. However, they have provided a technical assessment for you to complete. The consultancy Forela-Security would like to gauge your knowledge of Windows Event Log Analysis. Please analyse and report back on the questions they have asked.

Notes from the scenario:
- I’ll expect Event Logs.
- Not much background here, more of a a follow the questions task.

### Questions

To solve this challenge, I’ll need to answer the following 12 questions:
1. When did user cyberjunkie successfully log into his computer? (UTC)
2. The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?
3. What’s the direction of the firewall rule?
4. The user changed audit policy of the computer. What’s the Subcategory of this changed policy?
5. The user “cyberjunkie” created a scheduled task. What’s the name of this task?
6. What’s the full path of the file which was scheduled for the task?
7. What are the arguments of the command?
8. The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?
9. What’s the full path of the malware which raised the alert?
10. What action was taken by the antivirus?
11. The user used Powershell to execute commands. What command was executed by the user?
12. We suspect the user deleted some event logs. Which Event log file was cleared?

### Artifact Background

I’m given five different event logs:
- `Powershell-Operational` - Records of PowerShell activity on the system, and can include commands executed, scripts run, and any errors or warnings generated during their execution.
- `Security` - Records related to security events on the system, including user authentication, privilege changes, account management, and security policy changes.
- `System` - Captures system-level events such as startup and shutdown processes, driver and service failures, hardware configuration changes, and system resource utilization.
- `Windows Defender-Operational.evtx` - Documents the activities and status of Windows Defender, including malware detections, scans, updates, and any other security-related events managed by Windows Defender.
- `Windows Firewall-Firewall` - Logs firewall-related events such as allowed and blocked network connections, rule changes, and firewall service startup and shutdown events.

Each of these will have many event ids within them.

### Tools

These Windows Event Log files are a binary format that I’ll need to either convert to something useful to work with, or log into the Windows Event Log Viewer. I much prefer working from the Linux command line, so I’ll use [EvtxECmd.exe](https://github.com/EricZimmerman/evtx) (a Zimmerman tool) to convert the logs from this binary format to JSON. Then I can work with `jq`, along with `grep` and other Bash utilities.

### Data

The given data has the five log files:

```

oxdf@hacky$ unzip -l logjammer.zip 
Archive:  logjammer.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2023-07-21 11:33   Event-Logs/
 12652544  2023-03-27 15:00   Event-Logs/Powershell-Operational.evtx
  1118208  2023-03-27 14:53   Event-Logs/Security.evtx
  2166784  2023-03-27 15:02   Event-Logs/System.evtx
  1118208  2023-03-27 14:53   Event-Logs/Windows Defender-Operational.evtx
  1118208  2023-03-27 14:53   Event-Logs/Windows Firewall-Firewall.evtx
---------                     -------
 18173952                     6 files

```

I’ll parse these to JSON with `EvtxeCmd.exe`:

```

PS Z:\hackthebox-sherlocks\logjammer > C:\Tools\ZimmermanTools\EvtxeCmd\EvtxECmd.exe -d .\Event-Logs\ --json .
EvtxECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/evtx

Command line: -d .\Event-Logs\ --json .

json output will be saved to .\20240511121627_EvtxECmd_Output.json

Maps loaded: 438
Looking for event log files in .\Event-Logs\

Processing .\Event-Logs\Windows Firewall-Firewall.evtx...
Chunk count: 15, Iterating records...
Record #: 233 (timestamp: 2023-01-31 13:10:29.7937028): Warning! Time just went backwards! Last seen time before change: 2023-02-01 02:10:27.0076844

Event log details
Flags: None
Chunk count: 15
Stored/Calculated CRC: E8ED6B41/E8ED6B41
Earliest timestamp: 2023-01-31 13:10:29.7937028
Latest timestamp:   2023-03-27 14:44:43.4157021
Total event log records found: 929

Records included: 929 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
2004            490
2005            76
2006            315
2010            32
2033            8
2051            8

Processing .\Event-Logs\Powershell-Operational.evtx...
Chunk count: 181, Iterating records...

Event log details
Flags: None
Chunk count: 181
Stored/Calculated CRC: FC7A8F01/FC7A8F01
Earliest timestamp: 2023-03-01 07:14:25.0242267
Latest timestamp:   2023-03-27 14:58:33.4117404
Total event log records found: 578

Records included: 578 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
4100            2
4103            11
4104            381
40961           60
40962           60
53504           64

Processing .\Event-Logs\Security.evtx...
Chunk count: 3, Iterating records...
Record # 2 (Event Record Id: 13021): In map for event 1100, Property /Event/UserData[@Name="ServiceShutdown"] not found! Replacing with empty string

Event log details
Flags: None
Chunk count: 3
Stored/Calculated CRC: CDDBD50B/CDDBD50B
Earliest timestamp: 2023-03-27 14:36:45.3077318
Latest timestamp:   2023-03-27 14:52:50.1101331
Total event log records found: 115

Records included: 115 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1100            1
1102            1
4616            1
4624            67
4648            8
4688            11
4696            1
4698            1
4702            22
4719            1
4826            1

Processing .\Event-Logs\Windows Defender-Operational.evtx...
Chunk count: 10, Iterating records...
Record # 17 (Event Record Id: 17): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 24 (Event Record Id: 24): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 24 (Event Record Id: 24): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 25 (Event Record Id: 25): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 25 (Event Record Id: 25): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 52 (Event Record Id: 52): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 54 (Event Record Id: 54): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 56 (Event Record Id: 56): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 58 (Event Record Id: 58): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 66 (Event Record Id: 66): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 66 (Event Record Id: 66): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 67 (Event Record Id: 67): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 67 (Event Record Id: 67): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 325 (Event Record Id: 325): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 325 (Event Record Id: 325): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 326 (Event Record Id: 326): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 326 (Event Record Id: 326): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 329 (Event Record Id: 329): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 331 (Event Record Id: 331): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 343 (Event Record Id: 343): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 343 (Event Record Id: 343): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 344 (Event Record Id: 344): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 344 (Event Record Id: 344): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 353 (Event Record Id: 353): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 355 (Event Record Id: 355): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 357 (Event Record Id: 357): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 359 (Event Record Id: 359): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 362 (Event Record Id: 362): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 368 (Event Record Id: 368): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 368 (Event Record Id: 368): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 369 (Event Record Id: 369): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 369 (Event Record Id: 369): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 380 (Event Record Id: 380): In map for event 1150, Property /Event/EventData/Data[@Name="Signature version"] not found! Replacing with empty string
Record # 391 (Event Record Id: 391): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 391 (Event Record Id: 391): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 392 (Event Record Id: 392): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 392 (Event Record Id: 392): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 410 (Event Record Id: 410): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 410 (Event Record Id: 410): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 411 (Event Record Id: 411): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 411 (Event Record Id: 411): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 421 (Event Record Id: 421): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 421 (Event Record Id: 421): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 422 (Event Record Id: 422): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 422 (Event Record Id: 422): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 432 (Event Record Id: 432): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 432 (Event Record Id: 432): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string
Record # 433 (Event Record Id: 433): In map for event 2000, Property /Event/EventData/Data[@Name="Current Signature Version"] not found! Replacing with empty string
Record # 433 (Event Record Id: 433): In map for event 2000, Property /Event/EventData/Data[@Name="Previous Signature Version"] not found! Replacing with empty string

Event log details
Flags: None
Chunk count: 10
Stored/Calculated CRC: 1DDD50DB/1DDD50DB
Earliest timestamp: 2023-02-01 00:40:19.3980452
Latest timestamp:   2023-03-27 14:42:48.3536643
Total event log records found: 444

Records included: 444 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1000            5
1001            5
1013            1
1116            139
1117            71
1150            13
1151            18
2000            18
2002            2
2010            11
2014            3
5000            3
5001            3
5007            152

Processing .\Event-Logs\System.evtx...
Chunk count: 19, Iterating records...
Record #: 3 (timestamp: 2023-02-01 00:40:06.5425652): Warning! Time just went backwards! Last seen time before change: 2023-02-01 00:40:18.3956821
Record #: 117 (timestamp: 2023-02-01 00:41:03.6533958): Warning! Time just went backwards! Last seen time before change: 2023-02-01 00:41:14.6046026
Record #: 213 (timestamp: 2023-01-31 13:10:29.4637069): Warning! Time just went backwards! Last seen time before change: 2023-02-01 02:10:28.0744357
Record #: 242 (timestamp: 2023-01-31 13:12:04.0451774): Warning! Time just went backwards! Last seen time before change: 2023-03-01 07:10:50.3770351
Record # 245 (Event Record Id: 245): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 373 (timestamp: 2023-03-01 07:17:57.4183388): Warning! Time just went backwards! Last seen time before change: 2023-03-01 07:18:11.0864265
Record # 374 (Event Record Id: 374): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 846 (timestamp: 2023-03-01 12:03:39.4382915): Warning! Time just went backwards! Last seen time before change: 2023-03-10 02:00:30.2111274
Record # 847 (Event Record Id: 847): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 1219 (timestamp: 2023-03-10 05:09:47.9674049): Warning! Time just went backwards! Last seen time before change: 2023-03-10 05:09:55.6181051
Record #: 1283 (timestamp: 2023-03-22 08:19:19.9528413): Warning! Time just went backwards! Last seen time before change: 2023-03-22 08:19:27.5835727
Record #: 1342 (timestamp: 2023-03-22 08:20:30.6934067): Warning! Time just went backwards! Last seen time before change: 2023-03-22 08:20:48.3740662
Record # 1345 (Event Record Id: 1345): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 1428 (timestamp: 2023-03-22 08:21:20.7696170): Warning! Time just went backwards! Last seen time before change: 2023-03-22 08:21:34.1470776
Record # 1430 (Event Record Id: 1430): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 1612 (timestamp: 2023-03-22 17:17:10.9183807): Warning! Time just went backwards! Last seen time before change: 2023-03-23 08:23:11.0344695
Record # 1613 (Event Record Id: 1613): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 1699 (timestamp: 2023-03-23 08:41:05.7591698): Warning! Time just went backwards! Last seen time before change: 2023-03-23 08:41:19.1591021
Record # 1700 (Event Record Id: 1700): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record error at offset 0xEFE58, record #: 1768 error: Not a valid Win32 FileTime. (Parameter 'fileTime')
System.ArgumentOutOfRangeException: Not a valid Win32 FileTime. (Parameter 'fileTime')
   at System.DateTime.FromFileTimeUtc(Int64 fileTime)
   at evtx.SubstitutionArrayEntry.GetDataAsString()
   at evtx.Tags.NormalSubstitution.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.Tags.OpenStartElementTag.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.Tags.OpenStartElementTag.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.Tags.TemplateInstance.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.Tags.OpenStartElementTag.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.Tags.TemplateInstance.AsXml(List`1 substitutionEntries, Int64 parentOffset)
   at evtx.EventRecord.ConvertPayloadToXml()
   at evtx.EventRecord.BuildProperties()
   at evtx.EventRecord..ctor(BinaryReader recordData, Int32 recordPosition, ChunkInfo chunk)
   at evtx.ChunkInfo..ctor(Byte[] chunkBytes, Int64 absoluteOffset, Int32 chunkNumber)
Record #: 1884 (timestamp: 2023-03-24 20:41:31.7497949): Warning! Time just went backwards! Last seen time before change: 2023-03-25 13:38:19.6921384
Record #: 1916 (timestamp: 2023-03-24 21:37:33.8666110): Warning! Time just went backwards! Last seen time before change: 2023-03-24 21:37:52.0806800
Record # 1917 (Event Record Id: 1917): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 1987 (timestamp: 2023-03-25 14:40:39.3077703): Warning! Time just went backwards! Last seen time before change: 2023-03-26 19:00:22.1439697
Record # 1988 (Event Record Id: 1988): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 2053 (timestamp: 2023-03-27 00:00:11.0192337): Warning! Time just went backwards! Last seen time before change: 2023-03-27 14:32:00.9388417
Record # 2055 (Event Record Id: 2055): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string
Record #: 2126 (timestamp: 2023-03-27 14:36:53.8512912): Warning! Time just went backwards! Last seen time before change: 2023-03-27 14:37:09.4616404
Record # 2127 (Event Record Id: 2127): In map for event 13, Property /Event/EventData/Data[@Name="BootMode"] not found! Replacing with empty string

Event log details
Flags: None
Chunk count: 19
Stored/Calculated CRC: 31D1F7FA/31D1F7FA
Earliest timestamp: 2023-01-31 13:10:29.4637069
Latest timestamp:   2023-03-27 15:01:56.5158362
Total event log records found: 2,185

Records included: 2,185 Errors: 1 Events dropped: 0

Errors
Record #1768: Error: Not a valid Win32 FileTime. (Parameter 'fileTime')

Metrics (including dropped events)
Event ID        Count
1               43
2               1
3               13
6               173
12              21
13              11
14              15
15              7
16              272
18              15
19              67
20              31
22              1
24              37
25              15
26              8
27              19
30              1
32              31
34              1
35              9
37              10
41              1
42              1
43              69
44              270
52              2
55              120
98              29
104             15
109             11
129             3
134             9
153             15
172             15
238             15
1014            92
1074            12
1500            4
1501            2
1502            3
3261            1
4107            7
6005            15
6006            11
6008            2
6009            15
6011            1
6013            16
7000            1
7001            13
7002            10
7023            1
7026            15
7030            1
7031            4
7040            66
7043            2
7045            104
10005           6
10010           6
10016           219
15007           8
15008           8
16962           15
16977           16
16983           15
20003           7
50036           15
50037           11
50103           15
50104           11
50105           11
50106           11
51046           15
51047           11
51057           11

Processed 5 files in 2.9078 seconds

Files with errors
.\Event-Logs\System.evtx error count: 1

```

This leaves a single file with 4251 logs:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c . | wc -l
4251

```

## Results

### Login (Task 1)

> When did the cyberjunkie user first successfully log into his computer? (UTC)

#### Filter 4624 Events

[Successful logon events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624) (or “An account was successfully logged on”) are event id 4624. I’ll look at the first log and see that the event id is stored in a field named `EventId`:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -s '.[0]' 
{
  "PayloadData1": ": @{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}",
  "PayloadData2": "",
  "PayloadData3": "Direction: Outbound",
  "PayloadData4": "Action: Block",
  "PayloadData5": "Protocol: All",
  "RemoteHost": "*: ",
  "MapDescription": "A rule has been added to the Windows Defender Firewall exception list",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleId\",\"#text\":\"{6B516114-A353-4DD8-8FC1-299BFCC1297C}\"},{\"@Name\":\"RuleName\",\"#text\":\"@{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}\"},{\"@Name\":\"Origin\",\"#text\":\"1\"},{\"@Name\":\"ApplicationPath\"},{\"@Name\":\"ServiceName\"},{\"@Name\":\"Direction\",\"#text\":\"2\"},{\"@Name\":\"Protocol\",\"#text\":\"256\"},{\"@Name\":\"LocalPorts\"},{\"@Name\":\"RemotePorts\"},{\"@Name\":\"Action\",\"#text\":\"2\"},{\"@Name\":\"Profiles\",\"#text\":\"2147483647\"},{\"@Name\":\"LocalAddresses\",\"#text\":\"*\"},{\"@Name\":\"RemoteAddresses\",\"#text\":\"*\"},{\"@Name\":\"RemoteMachineAuthorizationList\"},{\"@Name\":\"RemoteUserAuthorizationList\"},{\"@Name\":\"EmbeddedContext\",\"#text\":\"@{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}\"},{\"@Name\":\"Flags\",\"#text\":\"1\"},{\"@Name\":\"Active\",\"#text\":\"1\"},{\"@Name\":\"EdgeTraversal\",\"#text\":\"0\"},{\"@Name\":\"LooseSourceMapped\",\"#text\":\"0\"},{\"@Name\":\"SecurityOptions\",\"#text\":\"0\"},{\"@Name\":\"ModifyingUser\",\"#text\":\"S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052\"},{\"@Name\":\"ModifyingApplication\",\"#text\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\"},{\"@Name\":\"SchemaVersion\",\"#text\":\"542\"},{\"@Name\":\"RuleStatus\",\"#text\":\"65536\"},{\"@Name\":\"LocalOnlyMapped\",\"#text\":\"0\"}]}}",
  "UserId": "S-1-5-19",
  "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
  "Provider": "Microsoft-Windows-Windows Firewall With Advanced Security",
  "EventId": 2004,
  "EventRecordId": "192",
  "ProcessId": 2836,
  "ThreadId": 4100,
  "Level": "Info",
  "Keywords": "0x8000020000000000",
  "SourceFile": ".\\Event-Logs\\Windows Firewall-Firewall.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-02-01T00:59:07.7193859+00:00",
  "RecordNumber": 1
}

```

The records are stored as JSON lines. That means that each line has a even starting with `{` and ending with `}`. To read just one of these, I’m using `-s` with `jq`, which slurps these into a list of events, and then I can select the first one with `.[0]`.

Given that I want `EventId` to be 4624, I’ll use a `jq` keyword `select`:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c 'select(.EventId==4624)' | wc -l
67

```

This filters down to 67 logs (using `-c` to output one log per line so that `wc -l` will count logs).

#### Filter For CyberJunkie

I’ll check out the first log:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c 'select(.EventId==4624)' | head -1 | jq .
{
  "PayloadData1": "Target: NT AUTHORITY\\SYSTEM",
  "PayloadData2": "LogonType 0",
  "PayloadData3": "LogonId: 0x3E7",
  "PayloadData4": "AuthenticationPackageName: -",
  "PayloadData5": "LogonProcessName: -",
  "UserName": "-\\-",
  "RemoteHost": "- (-)",
  "ExecutableInfo": "",
  "MapDescription": "Successful logon",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"SubjectUserSid\",\"#text\":\"S-1-0-0\"},{\"@Name\":\"SubjectUserName\",\"#text\":\"-\"},{\"@Name\":\"SubjectDomainName\",\"#text\":\"-\"},{\"@Name\":\"SubjectLogonId\",\"#text\":\"0x0\"},{\"@Name\":\"TargetUserSid\",\"#text\":\"S-1-5-18\"},{\"@Name\":\"TargetUserName\",\"#text\":\"SYSTEM\"},{\"@Name\":\"TargetDomainName\",\"#text\":\"NT AUTHORITY\"},{\"@Name\":\"TargetLogonId\",\"#text\":\"0x3E7\"},{\"@Name\":\"LogonType\",\"#text\":\"0\"},{\"@Name\":\"LogonProcessName\",\"#text\":\"-\"},{\"@Name\":\"AuthenticationPackageName\",\"#text\":\"-\"},{\"@Name\":\"WorkstationName\",\"#text\":\"-\"},{\"@Name\":\"LogonGuid\",\"#text\":\"00000000-0000-0000-0000-000000000000\"},{\"@Name\":\"TransmittedServices\",\"#text\":\"-\"},{\"@Name\":\"LmPackageName\",\"#text\":\"-\"},{\"@Name\":\"KeyLength\",\"#text\":\"0\"},{\"@Name\":\"ProcessId\",\"#text\":\"0x4\"},{\"@Name\":\"ProcessName\"},{\"@Name\":\"IpAddress\",\"#text\":\"-\"},{\"@Name\":\"IpPort\",\"#text\":\"-\"},{\"@Name\":\"ImpersonationLevel\",\"#text\":\"-\"},{\"@Name\":\"RestrictedAdminMode\",\"#text\":\"-\"},{\"@Name\":\"TargetOutboundUserName\",\"#text\":\"-\"},{\"@Name\":\"TargetOutboundDomainName\",\"#text\":\"-\"},{\"@Name\":\"VirtualAccount\",\"#text\":\"%%1843\"},{\"@Name\":\"TargetLinkedLogonId\",\"#text\":\"0x0\"},{\"@Name\":\"ElevatedToken\",\"#text\":\"%%1842\"}]}}",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventId": 4624,
  "EventRecordId": "13036",
  "ProcessId": 780,
  "ThreadId": 784,
  "Level": "LogAlways",
  "Keywords": "Audit success",
  "SourceFile": ".\\Event-Logs\\Security.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-03-27T14:37:08.6008290+00:00",
  "RecordNumber": 17
}

```

The user logging in is a part of the `Payload` field. I’ll filter more to get logs where CyberJunkie is in that field with the `test` [function](https://jqlang.github.io/jq/manual/#test), which applies a regex and returns True or False:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c '. | select(.EventId== 4624 and (.Payload | test("cyberjunkie";"i")))' | wc -l
4

```

Awesome, it’s down to four logs. There are two different timestamps if I drop the fractional seconds:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq '. | select(.EventId== 4624 and (.Payload | test("cyberjunkie";"i"))) | .TimeCreated'
"2023-03-27T14:37:09.8798913+00:00"
"2023-03-27T14:37:09.8799405+00:00"
"2023-03-27T14:38:32.9374236+00:00"
"2023-03-27T14:38:32.9374588+00:00"

```

The first time CyberJunkie logged in was 27/03/2023 14:37:09.

### Firewall Manipulation (Tasks 2 - 3)

> The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?

> What’s the direction of the firewall rule?

#### Find Correct Event Id

I’ll grep the log lines for “firewall” (case insensitive) and look at the first log:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep -i firewall | head -1 | jq .
{
  "PayloadData1": ": @{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}",
  "PayloadData2": "",
  "PayloadData3": "Direction: Outbound",
  "PayloadData4": "Action: Block",
  "PayloadData5": "Protocol: All",
  "RemoteHost": "*: ",
  "MapDescription": "A rule has been added to the Windows Defender Firewall exception list",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleId\",\"#text\":\"{6B516114-A353-4DD8-8FC1-299BFCC1297C}\"},{\"@Name\":\"RuleName\",\"#text\":\"@{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}\"},{\"@Name\":\"Origin\",\"#text\":\"1\"},{\"@Name\":\"ApplicationPath\"},{\"@Name\":\"ServiceName\"},{\"@Name\":\"Direction\",\"#text\":\"2\"},{\"@Name\":\"Protocol\",\"#text\":\"256\"},{\"@Name\":\"LocalPorts\"},{\"@Name\":\"RemotePorts\"},{\"@Name\":\"Action\",\"#text\":\"2\"},{\"@Name\":\"Profiles\",\"#text\":\"2147483647\"},{\"@Name\":\"LocalAddresses\",\"#text\":\"*\"},{\"@Name\":\"RemoteAddresses\",\"#text\":\"*\"},{\"@Name\":\"RemoteMachineAuthorizationList\"},{\"@Name\":\"RemoteUserAuthorizationList\"},{\"@Name\":\"EmbeddedContext\",\"#text\":\"@{Windows.CBSPreview_10.0.19041.1023_neutral_neutral_cw5n1h2txyewy?ms-resource://Windows.CBSPreview/resources/DisplayName}\"},{\"@Name\":\"Flags\",\"#text\":\"1\"},{\"@Name\":\"Active\",\"#text\":\"1\"},{\"@Name\":\"EdgeTraversal\",\"#text\":\"0\"},{\"@Name\":\"LooseSourceMapped\",\"#text\":\"0\"},{\"@Name\":\"SecurityOptions\",\"#text\":\"0\"},{\"@Name\":\"ModifyingUser\",\"#text\":\"S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052\"},{\"@Name\":\"ModifyingApplication\",\"#text\":\"C:\\\\Windows\\\\System32\\\\svchost.exe\"},{\"@Name\":\"SchemaVersion\",\"#text\":\"542\"},{\"@Name\":\"RuleStatus\",\"#text\":\"65536\"},{\"@Name\":\"LocalOnlyMapped\",\"#text\":\"0\"}]}}",
  "UserId": "S-1-5-19",
  "Channel": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
  "Provider": "Microsoft-Windows-Windows Firewall With Advanced Security",
  "EventId": 2004,
  "EventRecordId": "192",
  "ProcessId": 2836,
  "ThreadId": 4100,
  "Level": "Info",
  "Keywords": "0x8000020000000000",
  "SourceFile": ".\\Event-Logs\\Windows Firewall-Firewall.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-02-01T00:59:07.7193859+00:00",
  "RecordNumber": 1
}

```

The `SourceFile` attribute seems like a good one to filter on. I’ll just use grep:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Firewall-Firewall.evtx" | jq '.EventId' | sort | uniq -c
    490 2004
     76 2005
    315 2006
     32 2010
      8 2033
      8 2051

```

I’ve got a handful of event ids to look up:
- 2004: [A rule has been added to the Windows Firewall exception list](https://kb.eventtracker.com/evtpass/evtPages/EventId_2004_Microsoft-Windows-WindowsFirewallwithAdvancedS_65673.asp).
- 2005: [A rule has been modified in the Windows Firewall exception list](https://kb.eventtracker.com/evtpass/evtPages/EventId_2005_Microsoft-Windows-WindowsFirewallwithAdvancedS_65674.asp).
- 2006: [A rule has been deleted in the Windows Firewall exception list](https://kb.eventtracker.com/evtpass/evtPages/EventId_2006_Microsoft-Windows-WindowsFirewallwithAdvancedS_65675.asp).
- 2010: [Network profile changed on an interface](https://kb.eventtracker.com/evtpass/evtpages/EventId_2010_Microsoft-Windows-WindowsFirewallwithAdvancedS_65677.asp)
- 2033: [All rules have been deleted from mthe Windows Firewall configuration on this computer](https://kb.eventtracker.com/evtpass/evtpages/EventId_2033_Microsoft-Windows-WindowsFirewallwithAdvancedS_65679.asp).
- 2051: Couldn’t find documentation on this one, but [this forum post](https://www.bleepingcomputer.com/forums/t/770694/windows-keeps-logging-event-2033-stating-all-firewall-rules-have-been-deleted/) suggests they come in pairs with the 2033.

#### Find Addition

Given that the user logged on and added a rule, I’m looking for a 2004 after 2023-03-27T14:37:09. I can filter both of those with `jq`:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Firewall-Firewall.evtx" | jq 'select(.EventId==2004 and .TimeCreated > "2023-03-27T14:37:09") | .TimeCreated'
"2023-03-27T14:37:35.4692787+00:00"
"2023-03-27T14:37:35.4701846+00:00"
"2023-03-27T14:44:43.4157021+00:00"

```

There’s only three logs left. A quick inspection of the format of the logs shows the data to pull:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Firewall-Firewall.evtx" | jq -c 'select(.EventId==2004 and .TimeCreated > "2023-03-27T14:37:09") | [.PayloadData1, .PayloadData3, .PayloadData4, .PayloadData5, .RemoteHost, .TimeCreated]'
[": Microsoft Edge","Direction: Inbound","Action: Block","Protocol: All","*: ","2023-03-27T14:37:35.4692787+00:00"]
[": Microsoft Edge","Direction: Outbound","Action: Block","Protocol: All","*: ","2023-03-27T14:37:35.4701846+00:00"]
[": Metasploit C2 Bypass","Direction: Outbound","Action: Allow","Protocol: TCP","*: 4444","2023-03-27T14:44:43.4157021+00:00"]

```

Task 2 is “Metasploit C2 Bypass”, and Task 3 is “Outbound”.

### Audit Policy (Task 4)

> The user changed audit policy of the computer. What’s the Subcategory of this changed policy?

The event log for [System audit policy was changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4719) is event id 4719. There’s only one of these:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c 'select(.EventId==4719)' | wc -l
1
oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq 'select(.EventId==4719)'
{
  "PayloadData1": "CategoryId: %%8274 SubcategoryId: %%12804",
  "PayloadData2": "SubcategoryGuid: 0cce9227-69ae-11d9-bed3-505054503030",
  "PayloadData3": "AuditPolicyChanges: %%8449",
  "UserName": "WORKGROUP\\DESKTOP-887GK2L$",
  "MapDescription": "System audit policy was changed",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"SubjectUserSid\",\"#text\":\"S-1-5-18\"},{\"@Name\":\"SubjectUserName\",\"#text\":\"DESKTOP-887GK2L$\"},{\"@Name\":\"SubjectDomainName\",\"#text\":\"WORKGROUP\"},{\"@Name\":\"SubjectLogonId\",\"#text\":\"0x3E7\"},{\"@Name\":\"CategoryId\",\"#text\":\"%%8274\"},{\"@Name\":\"SubcategoryId\",\"#text\":\"%%12804\"},{\"@Name\":\"SubcategoryGuid\",\"#text\":\"0cce9227-69ae-11d9-bed3-505054503030\"},{\"@Name\":\"AuditPolicyChanges\",\"#text\":\"%%8449\"}]}}",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventId": 4719,
  "EventRecordId": "13102",
  "ProcessId": 780,
  "ThreadId": 1488,
  "Level": "LogAlways",
  "Keywords": "Audit success",
  "SourceFile": ".\\Event-Logs\\Security.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-03-27T14:50:03.7218352+00:00",
  "RecordNumber": 83
}

```

`PayloadData2` gives “SubcategoryGuid: 0cce9227-69ae-11d9-bed3-505054503030”. Searching for that GUID returns [this Microsoft page](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d), which shows it as “Other Object Access Events”:

![image-20240511155212645](/img/image-20240511155212645.png)

I originally tried just Other Object Access, but the placeholder showed I needed one more word.

### Scheduled Task (Tasks 5 - 7)

> The user “cyberjunkie” created a scheduled task. What’s the name of this task?

> What’s the full path of the file which was scheduled for the task?

> What are the arguments of the command?

The event code for [A scheduled task was created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4698) is 4698. There’s only one of these in the dataset:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -c 'select(.EventId==4698)' | wc -l
1

```

The task name is available in `PayloadData1`, the answer to Task 5:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq 'select(.EventId==4698) | .PayloadData1'
"TaskName: \\HTB-AUTOMATION"

```

I can go further and get the XML for the scheduled task to include the script that’s run from `Payload` which then needs to be converted from JSON, pull out the `TakContent`, then get the `#text`, HTML decode, remove `,`, and lint with XML:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq -r 'select(.EventId==4698) | .Payload | fromjson | .EventData.Data | map(select(.["@Name"]=="TaskContent")) | .[]."#text" | @text' | recode html..ascii | tr -d ',' | xmllint --format - --recover

��<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task" version="1.2">
  <RegistrationInfo>
    <Date>2023-03-27T07:51:21.4599985</Date>
    <Author>DESKTOP-887GK2L\CyberJunkie</Author>
    <Description>practice</Description>
    <URI>\HTB-AUTOMATION</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2023-03-27T09:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
      <UserId>DESKTOP-887GK2L\CyberJunkie</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1</Command>
      <Arguments>-A cyberjunkie@hackthebox.eu</Arguments>
    </Exec>
  </Actions>
</Task>

```

The command is `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1` (Task 6), and the arguments are `-A cyberjunkie@hackthebox.eu` (Task 7).

### Defender (Tasks 8 - 10)

#### Isolate Defender Logs

One of the file names was `Windows Defender-Operational.evtx`. I’ll grep for that to just get those logs:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | wc -l
444

```

There are many different `EventId` values in these logs:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq '.EventId' | sort | uniq -c | sort -nk2
      5 1000
      5 1001
      1 1013
    139 1116
     71 1117
     13 1150
     18 1151
     18 2000
      2 2002
     11 2010
      3 2014
      3 5000
      3 5001
    152 5007

```

#### Filter By Time

There’s a lot of different log types there, so before I figure out what each of these are, I’m going to assume I’m still looking at events that happen after that first login. That reduces the logs to look at from 444 to 11:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09") | .EventId' | wc -l
11
oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09") | .EventId' | sort | uniq -c | sort -nk2
      2 1116
      2 1117
      7 5007

```

[This page](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus) documents all the event id values for Defender logs:
- 1116 - MALWAREPROTECTION\_STATE\_MALWARE\_DETECTED
- 1117 - MALWAREPROTECTION\_STATE\_MALWARE\_ACTION\_TAKEN
- 5007 - MALWAREPROTECTION\_CONFIG\_CHANGED

#### 1116

Starting with the 1116 logs, I’ll pull the interesting parts out of each:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId == 1116) | {"Name": .PayloadData1, "User": .UserName, "ExeInfo": .ExecutableInfo, "CreationTime": .TimeCreated}'
{
  "Name": "Malware name: HackTool:PowerShell/SharpHound.B",
  "User": "Detection User: DESKTOP-887GK2L\\CyberJunkie",
  "ExeInfo": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip-&gt;SharpHound.ps1; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20230327T144228Z&amp;X-Amz-Expires=300&amp;X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&amp;X-Amz-SignedHeaders=host&amp;actor_id=0&amp;key_id=0&amp;repo_id=385323486&amp;response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&amp;response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
  "CreationTime": "2023-03-27T14:42:34.2909353+00:00"
}
{
  "Name": "Malware name: HackTool:MSIL/SharpHound!MSR",
  "User": "Detection User: DESKTOP-887GK2L\\CyberJunkie",
  "ExeInfo": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip-&gt;SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20230327T144228Z&amp;X-Amz-Expires=300&amp;X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&amp;X-Amz-SignedHeaders=host&amp;actor_id=0&amp;key_id=0&amp;repo_id=385323486&amp;response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&amp;response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
  "CreationTime": "2023-03-27T14:42:34.2927169+00:00"
}

```

It’s two detections for the same binary, which is SharpHound (Task 8), detected as a Zip file at `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip` (Task 9).

#### 1117

Event Id 1117 is very similar to 1116, but this one has the action in the `.Payload`. To get to it, I’ll need to select it and then convert that `fromjson`, and process it more in a rather annoying way. The cheat is to just `grep`:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId == 1117) | .Payload | fromjson' | grep -a1 "Action Name" 
      {
        "@Name": "Action Name",
        "#text": "Quarantine"
--
      {
        "@Name": "Action Name",
        "#text": "Quarantine"

```

The action taken was quarantine (Task 10). A pretty `jq` way to do it is:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId == 1117) | .Payload | fromjson | .EventData.Data | map(select(.["@Name"]=="Action Name")) | .[]."#text"'
"Quarantine"
"Quarantine"

```

Or I can put it all together with:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep "Windows Defender-Operational.evtx" | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId == 1117) | {"Name": .PayloadData1, "User": .UserName, "ExeInfo": .ExecutableInfo, "Action": .Payload | fromjson | .EventData.Data | map(select(.["@Name"]=="Action Name")) | .[]."#text", "CreationTime": .TimeCreated}'
{
  "Name": "Malware name: HackTool:MSIL/SharpHound!MSR",
  "User": "Detection User: DESKTOP-887GK2L\\CyberJunkie",
  "ExeInfo": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip-&gt;SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20230327T144228Z&amp;X-Amz-Expires=300&amp;X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&amp;X-Amz-SignedHeaders=host&amp;actor_id=0&amp;key_id=0&amp;repo_id=385323486&amp;response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&amp;response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
  "Action": "Quarantine",
  "CreationTime": "2023-03-27T14:42:48.3526591+00:00"
}
{
  "Name": "Malware name: HackTool:MSIL/SharpHound!MSR",
  "User": "Detection User: DESKTOP-887GK2L\\CyberJunkie",
  "ExeInfo": "containerfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip; file:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip-&gt;SharpHound.exe; webfile:_C:\\Users\\CyberJunkie\\Downloads\\SharpHound-v1.1.0.zip|https://objects.githubusercontent.com/github-production-release-asset-2e65be/385323486/70d776cc-8f83-44d5-b226-2dccc4f7c1e3?X-Amz-Algorithm=AWS4-HMAC-SHA256&amp;X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230327%2Fus-east-1%2Fs3%2Faws4_request&amp;X-Amz-Date=20230327T144228Z&amp;X-Amz-Expires=300&amp;X-Amz-Signature=f969ef5ca3eec150dc1e23623434adc1e4a444ba026423c32edf5e85d881a771&amp;X-Amz-SignedHeaders=host&amp;actor_id=0&amp;key_id=0&amp;repo_id=385323486&amp;response-content-disposition=attachment%3B%20filename%3DSharpHound-v1.1.0.zip&amp;response-content-type=application%2Foctet-stream|pid:3532,ProcessStart:133244017530289775",
  "Action": "Quarantine",
  "CreationTime": "2023-03-27T14:42:48.3536643+00:00"
}

```

### PowerShell (Task 11)

> The user used Powershell to execute commands. What command was executed by the user?

#### Powershell Overview

There are 578 logs in the `Powershell-Operational.evtx` file with six different event ids:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | wc -l
578
oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq '.EventId' | sort | uniq -c
     60 40961
     60 40962
      2 4100
     11 4103
    381 4104
     64 53504

```

20 of those happen after the first login:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq -c 'select(.TimeCreated > "2023-03-27T14:37:09")' | wc -l
20
oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq -c 'select(.TimeCreated > "2023-03-27T14:37:09") | .EventId' | sort | uniq -c
      2 40961
      2 40962
     11 4103
      3 4104
      2 53504

```

#### 4103 / 4104

The 4103 logs the start of a PowerShell session, where 4104 logs the commands run. 4103 shows the start of sessions:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId==4103) | {"Script": .PayloadData3, "Payload": .PayloadData6}'
{
  "Script": "Script Name: C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadline\\2.0.0\\PSReadLine.psm1",
  "Payload": "Payload: CommandInvocation(Set-StrictMode): \"Set-StrictMode\", ParameterBinding(Set-StrictMode): name=\"Off\"; value=\"True\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(Get-Variable): \"Get-Variable\", ParameterBinding(Get-Variable): name=\"Name\"; value=\"host\", ParameterBinding(Get-Variable): name=\"ValueOnly\"; value=\"True\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(Resolve-Path): \"Resolve-Path\", ParameterBinding(Resolve-Path): name=\"ErrorAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"WarningAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"InformationAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"Verbose\"; value=\"False\", ParameterBinding(Resolve-Path): name=\"Debug\"; value=\"False\", ParameterBinding(Resolve-Path): name=\"Path\"; value=\"DE*\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(Resolve-Path): \"Resolve-Path\", ParameterBinding(Resolve-Path): name=\"ErrorAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"WarningAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"InformationAction\"; value=\"Ignore\", ParameterBinding(Resolve-Path): name=\"Verbose\"; value=\"False\", ParameterBinding(Resolve-Path): name=\"Debug\"; value=\"False\", ParameterBinding(Resolve-Path): name=\"Path\"; value=\".\\Desktop\\aU*\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(PSConsoleHostReadLine): \"PSConsoleHostReadLine\", "
}
{
  "Script": "Script Name: C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1",
  "Payload": "Payload: CommandInvocation(Resolve-Path): \"Resolve-Path\", ParameterBinding(Resolve-Path): name=\"Path\"; value=\".\\Desktop\\Automation-HTB.ps1\", CommandInvocation(ForEach-Object): \"ForEach-Object\", ParameterBinding(ForEach-Object): name=\"MemberName\"; value=\"ProviderPath\", ParameterBinding(ForEach-Object): name=\"InputObject\"; value=\"C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1\", "
}
{
  "Script": "Script Name: C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1",
  "Payload": "Payload: CommandInvocation(Test-Path): \"Test-Path\", ParameterBinding(Test-Path): name=\"LiteralPath\"; value=\"C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1\", ParameterBinding(Test-Path): name=\"PathType\"; value=\"Container\", "
}
{
  "Script": "Script Name: C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1",
  "Payload": "Payload: CommandInvocation(GetStreamHash): \"GetStreamHash\", ParameterBinding(GetStreamHash): name=\"InputStream\"; value=\"System.IO.FileStream\", ParameterBinding(GetStreamHash): name=\"RelatedPath\"; value=\"C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1\", ParameterBinding(GetStreamHash): name=\"Hasher\"; value=\"System.Security.Cryptography.MD5CryptoServiceProvider\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(Get-FileHash): \"Get-FileHash\", ParameterBinding(Get-FileHash): name=\"Algorithm\"; value=\"md5\", ParameterBinding(Get-FileHash): name=\"Path\"; value=\".\\Desktop\\Automation-HTB.ps1\", "
}
{
  "Script": "Script Name: ",
  "Payload": "Payload: CommandInvocation(Out-Default): \"Out-Default\", ParameterBinding(Out-Default): name=\"InputObject\"; value=\"@{Algorithm=MD5; Hash=36E606E249065E2BDFCA950DBB549C63; Path=C:\\Users\\CyberJunkie\\Desktop\\Automation-HTB.ps1}\", "
}
{
  "Script": "Script Name: C:\\Program Files\\WindowsPowerShell\\Modules\\PSReadline\\2.0.0\\PSReadLine.psm1",
  "Payload": "Payload: CommandInvocation(Set-StrictMode): \"Set-StrictMode\", ParameterBinding(Set-StrictMode): name=\"Off\"; value=\"True\", "
}

```

The second to last one, that runs `Automation-HTB.ps1` is most interesting.

I can pull the commands run from the 4103:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId==4104) | .Payload | fromjson | .EventData.Data | map(select(.["@Name"]=="ScriptBlockText")) | .[]."#text"'
"prompt"
"Get-FileHash -Algorithm md5 .\\Desktop\\Automation-HTB.ps1"
"prompt"

```

The middle one is the interesting one (Task 11). I’ll get the full log for the interesting one:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep Powershell-Operational.evtx | jq 'select(.TimeCreated > "2023-03-27T14:37:09" and .EventId==4104 and (.Payload | test("Get-FileHash")))'
{
  "PayloadData1": "Path: ",
  "PayloadData2": "ScriptBlockText: Get-FileHash -Algorithm md5 .\\Desktop\\Automation-HTB.ps1",
  "MapDescription": "Contains contents of scripts run",
  "ChunkNumber": 180,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"MessageNumber\",\"#text\":\"1\"},{\"@Name\":\"MessageTotal\",\"#text\":\"1\"},{\"@Name\":\"ScriptBlockText\",\"#text\":\"Get-FileHash -Algorithm md5 .\\\\Desktop\\\\Automation-HTB.ps1\"},{\"@Name\":\"ScriptBlockId\",\"#text\":\"b4fcf72f-abdc-4a84-923f-8e06a758000b\"},{\"@Name\":\"Path\"}]}}",
  "UserId": "S-1-5-21-3393683511-3463148672-371912004-1001",
  "Channel": "Microsoft-Windows-PowerShell/Operational",
  "Provider": "Microsoft-Windows-PowerShell",
  "EventId": 4104,
  "EventRecordId": "571",
  "ProcessId": 7152,
  "ThreadId": 2000,
  "Level": "Verbose",
  "Keywords": "0x0",
  "SourceFile": ".\\Event-Logs\\Powershell-Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-03-27T14:58:33.3647699+00:00",
  "RecordNumber": 571
}

```

### Log Clearing (Task 12)

> We suspect the user deleted some event logs. Which Event log file was cleared?

One common log for security event log being cleared is [1102](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102). There is one of those here:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | jq 'select(.EventId==1102)'
{
  "PayloadData1": "SID: (S-1-5-21-3393683511-3463148672-371912004-1001)",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "MapDescription": "Event log cleared",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"UserData\":{\"LogFileCleared\":{\"SubjectUserSid\":\"S-1-5-21-3393683511-3463148672-371912004-1001\",\"SubjectUserName\":\"CyberJunkie\",\"SubjectDomainName\":\"DESKTOP-887GK2L\",\"SubjectLogonId\":\"0x25235\"}}}",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Eventlog",
  "EventId": 1102,
  "EventRecordId": "13020",
  "ProcessId": 1320,
  "ThreadId": 9512,
  "Level": "Info",
  "Keywords": "0x4020000000000000",
  "SourceFile": ".\\Event-Logs\\Security.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-03-27T14:36:45.3077318+00:00",
  "RecordNumber": 1
}

```

It’s before the first login, and thus I think not of interest (at least it’s not the accepted answer).

The other log with the word “Cleared” in it is 104:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep -i cleared | jq .EventId | sort | uniq -c 
     15 104
      1 1102

```

If I add the filter for after the first login, there’s only one:

```

oxdf@hacky$ cat 20240511121627_EvtxECmd_Output.json | grep -i cleared | jq 'select(.EventId==104 and .TimeCreated > "2023-03-27T14:37:09")'
{
  "PayloadData1": "The Microsoft-Windows-Windows Firewall With Advanced Security/Firewall log file was cleared",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "MapDescription": "Event log cleared",
  "ChunkNumber": 18,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"UserData\":{\"LogFileCleared\":{\"SubjectUserName\":\"CyberJunkie\",\"SubjectDomainName\":\"DESKTOP-887GK2L\",\"Channel\":\"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\",\"BackupPath\":\"\"}}}",
  "UserId": "S-1-5-21-3393683511-3463148672-371912004-1001",
  "Channel": "System",
  "Provider": "Microsoft-Windows-Eventlog",
  "EventId": 104,
  "EventRecordId": "2186",
  "ProcessId": 1332,
  "ThreadId": 5332,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": ".\\Event-Logs\\System.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2023-03-27T15:01:56.5158362+00:00",
  "RecordNumber": 2186
}

```

The log cleared in this event is “Microsoft-Windows-Windows Firewall With Advanced Security/Firewall” (Task 12).

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023-03-27T14:37:09 | CyberJunkie first login | Security 4624 |
| 2023-03-27T14:38:32 | CyberJunkie second login | Security 4624 |
| 2023-03-27T14:42:34 | SharpHound zip detected | Defender 1116 |
| 2023-03-27T14:42:48 | SharpHound quarantined | Defender 1117 |
| 2023-03-27T14:44:43 | Firewall modified to allow Metasploit out | Firewall 2004 |
| 2023-03-27T14:50:03 | System audit policy changed | Audit 4719 |
| 2023-03-27T14:51:21 | Scheduled task created | Security 4698 |
| 2023-03-27T14:58:33 | Runs `Automation-HTB.ps1` | PowerShell 4104 |
| 2023-03-27T15:01:56 | Firewall event logs cleared | System 104 |

### Question Answers
1. When did the cyberjunkie user first successfully log into his computer? (UTC)

   27/03/2023 14:37:09
2. The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?

   Metasploit C2 Bypass
3. What’s the direction of the firewall rule?

   Outbound
4. The user changed audit policy of the computer. What’s the Subcategory of this changed policy?

   Other Object Access Events
5. The user “cyberjunkie” created a scheduled task. What’s the name of this task?

   HTB-AUTOMATION
6. What’s the full path of the file which was scheduled for the task?

   `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`
7. What are the arguments of the command?

   `-A cyberjunkie@hackthebox.eu`
8. The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?

   SharpHound
9. What’s the full path of the malware which raised the alert?

   `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`
10. What action was taken by the antivirus?

    Quarantine
11. The user used Powershell to execute commands. What command was executed by the user?

    `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1`
12. We suspect the user deleted some event logs. Which Event log file was cleared?

    Microsoft-Windows-Windows Firewall With Advanced Security/Firewall