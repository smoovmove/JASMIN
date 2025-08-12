---
title: HTB Sherlock: Unit42
url: https://0xdf.gitlab.io/2024/04/11/htb-sherlock-unit42.html
date: 2024-04-11T10:00:00+00:00
difficulty: Very Easy
tags: ctf, dfir, forensics, sherlock-unit42, sherlock-cat-dfir, hackthebox, htb-sherlock, event-logs, sysmon, jq, malware, time-stomping, evtxecmd
---

![unit42](/icons/sherlock-unit42.png)

Unit42 is based off a real malware campaign noted by Unit 42.I’ll work with Sysmon logs to see how the malware was downloaded through Firefox from Dropbox, run by the user, and proceeded to install itself using Windows tools. It makes network connections including DNS queries and connection to a probably malicious IP before killing itself.

## Challenge Info

| Name | [Unit42](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2funit42)  [Unit42](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2funit42) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2funit42) |
| --- | --- |
| Release Date | 4 April 2024 |
| Retire Date | 4 April 2024 |
| Difficulty | Very Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto’s Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

Notes from the scenario:
- Sysmon logs
- Exploited Windows machine
- Backdoored version of UltraVNC

### Questions

To solve this challenge, I’ll need to answer the following 8 questions:
1. How many Event logs are there with Event ID 11?
2. Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim’s system?
3. Which Cloud drive was used to distribute the malware?
4. The initial malicious file time-stamped (a defense evasion technique, where the file creation date is changed to make it appear old) many files it created on disk. What was the timestamp changed to for a PDF file?
5. The malicious file dropped a few files on disk. Where was “once.cmd” created on disk? Please answer with the full path along with the filename.
6. The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?
7. Which IP address did the malicious process try to reach out to?
8. The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

### Sysmon

#### Background

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is a extra service that can be installed on Windows systems to provide increased logging of activity on the system. It is particularly useful for collecting things like processes events with full command lines, the hashes of process images, network connections, and registry modifications. Sysmon is highly configurable, so exactly what kind of logs will be present on a given system will depend on it’s configuration (which doesn’t seem to be available for this case). A relatively [famous configuration](https://github.com/SwiftOnSecurity/sysmon-config) was created by [SwiftOnSecurity](https://twitter.com/SwiftOnSecurity), though most professional organizations will have to modify if for their environment.

#### EventIds

The EventIds Sysmon uses are well documented on the [Microsoft Sysmon page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). The ones that will come up in this investigation as:
- 1: Process creation
- 2: Change of file creation time
- 3: Network connection
- 5: Process terminated
- 11: File created
- 12: Registry object created or deleted
- 13: Registry value set
- 22: DNS query
- 23: File deleted (with archive)
- 26: File deleted (without archive)

### Tools

I’m going to work from a Windows VM here. This is very useful when working on Windows forensics investigations. Where I need to, I can drop into a Windows Subsystem for Linux Bash shell, or bound over to my Linux VM (but I’ll try to stay Windows to show the techniques).

Because I’ll be working with JSON data, I’ll be using one of my favorite tools, `jq` (check out [this 2018 post for background](/2018/12/19/jq.html)) . To install on Windows, as I’m already using Flare VM which uses `choco` for package management, I’ll just run `choco install jq`.

### Data

#### Overview

The download zip has a single files in it:

```

oxdf@hacky$ unzip -l unit42.zip 
Archive:  unit42.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1118208  2024-02-14 08:43   Microsoft-Windows-Sysmon-Operational.evtx
---------                     -------
  1118208                     1 file

```

These are the Sysmon logs from the target system. Once unzipped, the file is a Windows event log of 1.1MB:

```

oxdf@hacky$ file Microsoft-Windows-Sysmon-Operational.evtx 
Microsoft-Windows-Sysmon-Operational.evtx: MS Windows Vista Event Log, 3 chunks (no. 2 in use), next record no. 170
oxdf@hacky$ ls -lh Microsoft-Windows-Sysmon-Operational.evtx
-rwxrwx--- 1 root vboxsf 1.1M Feb 13 22:43 Microsoft-Windows-Sysmon-Operational.evtx

```

#### Process Logs

The best tool I know of for processing Windows Event Logs to a format I like to work with (JSON) is [EvtxeCmd.exe](https://github.com/EricZimmerman/evtx) from Eric Zimmerman. I’ll run it, giving it the logs and specifying the output with `--json [file]`:

```

PS > EvtxECmd.exe -f .\Microsoft-Windows-Sysmon-Operational.evtx --json .
EvtxECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)

Command line: -f .\Microsoft-Windows-Sysmon-Operational.evtx --json .

json output will be saved to .\20240408132435_EvtxECmd_Output.json

Maps loaded: 438

Processing \Microsoft-Windows-Sysmon-Operational.evtx...
Chunk count: 3, Iterating records...
Record # 4 (Event Record Id: 118750): In map for event 26, Property /Event/EventData/Data[@Name="Archived"] not found! Replacing with empty string
Record # 27 (Event Record Id: 118773): In map for event 10, Property /Event/EventData/Data[@Name="SourceProcessGuid"] not found! Replacing with empty string
Record # 27 (Event Record Id: 118773): In map for event 10, Property /Event/EventData/Data[@Name="TargetProcessGuid"] not found! Replacing with empty string
Record # 46 (Event Record Id: 118792): In map for event 26, Property /Event/EventData/Data[@Name="Archived"] not found! Replacing with empty string

Event log details
Flags: None
Chunk count: 3
Stored/Calculated CRC: 9B75E006/9B75E006
Earliest timestamp: 2024-02-14 03:41:26.4441194
Latest timestamp:   2024-02-14 03:43:26.8870662
Total event log records found: 169

Records included: 169 Errors: 0 Events dropped: 0

Metrics (including dropped events)
Event ID        Count
1               6
2               16
3               1
5               1
7               15
10              1
11              56
12              14
13              19
15              2
17              7
22              3
23              26
26              2

Processed 1 file in 0.6669 seconds

FLARE-VM 04/08/2024 09:24:35

```

At the bottom of the output, it gives a nice histogram of the types of logs it found. There are 56 logs with EventId 11 (Task 1).

#### Data Format

The resulting JSON is a series of logs each represented on a single line of JSON:

```

PS > cat .\20240408132435_EvtxECmd_Output.json | select -first 1
{"PayloadData1":"ProcessID: 4292, ProcessGUID: 817bddf3-3514-65cc-0802-000000001900","PayloadData2":"RuleName: -","PayloadData3":"Image: C:\\Program Files\\Mozilla Firefox\\firefox.exe","PayloadData4":"QueryName: uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com","PayloadData5":"QueryStatus: 0","PayloadData6":"QueryResults: type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d:4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;","UserName":"DESKTOP-887GK2L\\CyberJunkie","MapDescription":"DNSEvent (DNS query)","ChunkNumber":0,"Computer":"DESKTOP-887GK2L","Payload":"{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2024-02-14 03:41:25.269\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"817bddf3-3514-65cc-0802-000000001900\"},{\"@Name\":\"ProcessId\",\"#text\":\"4292\"},{\"@Name\":\"QueryName\",\"#text\":\"uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com\"},{\"@Name\":\"QueryStatus\",\"#text\":\"0\"},{\"@Name\":\"QueryResults\",\"#text\":\"type:  5 edge-block-www-env.dropbox-dns.com;::ffff:162.125.81.15;198.51.44.6;2620:4d:4000:6259:7:6:0:1;198.51.45.6;2a00:edc0:6259:7:6::2;198.51.44.70;2620:4d:4000:6259:7:6:0:3;198.51.45.70;2a00:edc0:6259:7:6::4;\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Program Files\\\\Mozilla Firefox\\\\firefox.exe\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"}]}}","UserId":"S-1-5-18","Channel":"Microsoft-Windows-Sysmon/Operational","Provider":"Microsoft-Windows-Sysmon","EventId":22,"EventRecordId":"118747","ProcessId":3028,"ThreadId":4452,"Level":"Info","Keywords":"Classic","SourceFile":"Z:\\hackthebox-sherlocks\\unit42\\Microsoft-Windows-Sysmon-Operational.evtx","ExtraDataOffset":0,"HiddenRecord":false,"TimeCreated":"2024-02-14T03:41:26.4441194+00:00","RecordNumber":1}

```

I could also get a similar histogram as what was logged in the processing using `jq` on the resulting JSON data:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -sc 'group_by(.EventId) | map({EventId: .[0].EventId, count: length}) |.[]'
{"EventId":1,"count":6}
{"EventId":2,"count":16}
{"EventId":3,"count":1}
{"EventId":5,"count":1}
{"EventId":7,"count":15}
{"EventId":10,"count":1}
{"EventId":11,"count":56}
{"EventId":12,"count":14}
{"EventId":13,"count":19}
{"EventId":15,"count":2}
{"EventId":17,"count":7}
{"EventId":22,"count":3}
{"EventId":23,"count":26}
{"EventId":26,"count":2}

```

To break that command down:
- `-s` tells `jq` to read the individual lines from the input file into a list (slurp).
- `group_by(.EventId)` creates a list of lists sorted by `EventId`.
- The result of that is piped into `map()`, which will take each list and create a new object from it.
- In the new object, the `EventId` key will be the first item (`.[0]`) in the list’s `EventId`. The `count` will be the length of the list.
- `-c` tells `jq` to print one object per line, rather than pretty printing each spaced out.
- Pipe into `.[]` loops over each item in the output of the map and outputs it. Without this, all the output would come on one line because `jq` outputs a single list.

## Processes

### Understanding the Data

The most obvious place to start is to look at the process events to see what is running on the victim host. To save having to filter on `EventId` in each query, I’ll save these events to a file:

```

PS > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 1)' > eventid1.json

```

Now I can look at just the first log to get a feel for the fields:

```

PS  > cat .\eventid1.json | jq -s '.[0]'
{
  "PayloadData1": "ProcessID: 5584, ProcessGUID: 817bddf3-3679-65cc-2902-000000001900",
  "PayloadData2": "RuleName: technique_id=T1027,technique_name=Obfuscated Files or Information",
  "PayloadData3": "SHA1=282F855BEB4FACF0726E13ECCADB7D3411B30B85,MD5=A1F5FF25E3D0F160BC7CE7CA57349D83,SHA256=B412C45DE423534D85F121ABC348FB38020FDA804EA0A972708B7447B0E7325D,IMPHASH=F84029681F81FED23E3E067364DA1699",
  "PayloadData4": "ParentProcess: C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "PayloadData5": "ParentProcessID: 4292, ParentProcessGUID: 817bddf3-3514-65cc-0802-000000001900",
  "PayloadData6": "ParentCommandLine: \"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "ExecutableInfo": "\"C:\\Program Files\\Mozilla Firefox\\pingsender.exe\" https://incoming.telemetry.mozilla.org/submit/telemetry/cb88145b-129d-471c-b605-4fdf09fec680/event/Firefox/122.0.1/release/20240205133611?v=4 C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\saved-telemetry-pings\\cb88145b-129d-471c-b605-4fdf09fec680 https://incoming.telemetry.mozilla.org/submit/telemetry/6fcd92a2-cc60-4df6-b6fb-66356dd011c1/main/Firefox/122.0.1/release/20240205133611?v=4 C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\saved-telemetry-pings\\6fcd92a2-cc60-4df6-b6fb-66356dd011c1",
  "MapDescription": "Process creation",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"technique_id=T1027,technique_name=Obfuscated Files or Information\"},{\"@Name\":\"UtcTime\",\"#text\":\"2024-02-14 03:41:45.304\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"817bddf3-3679-65cc-2902-000000001900\"},{\"@Name\":\"ProcessId\",\"#text\":\"5584\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Program Files\\\\Mozilla Firefox\\\\pingsender.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"122.0.1\"},{\"@Name\":\"Description\",\"#text\":\"-\"},{\"@Name\":\"Product\",\"#text\":\"Firefox\"},{\"@Name\":\"Company\",\"#text\":\"Mozilla Foundation\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"pingsender.exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"\\\"C:\\\\Program Files\\\\Mozilla Firefox\\\\pingsender.exe\\\" https://incoming.telemetry.mozilla.org/submit/telemetry/cb88145b-129d-471c-b605-4fdf09fec680/event/Firefox/122.0.1/release/20240205133611?v=4 C:\\\\Users\\\\CyberJunkie\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles\\\\avsa4d81.default-release\\\\saved-telemetry-pings\\\\cb88145b-129d-471c-b605-4fdf09fec680 https://incoming.telemetry.mozilla.org/submit/telemetry/6fcd92a2-cc60-4df6-b6fb-66356dd011c1/main/Firefox/122.0.1/release/20240205133611?v=4 C:\\\\Users\\\\CyberJunkie\\\\AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles\\\\avsa4d81.default-release\\\\saved-telemetry-pings\\\\6fcd92a2-cc60-4df6-b6fb-66356dd011c1\"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Program Files\\\\Mozilla Firefox\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"},{\"@Name\":\"LogonGuid\",\"#text\":\"817bddf3-311e-65cc-a7ae-1b0000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x1BAEA7\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"1\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"Medium\"},{\"@Name\":\"Hashes\",\"#text\":\"SHA1=282F855BEB4FACF0726E13ECCADB7D3411B30B85,MD5=A1F5FF25E3D0F160BC7CE7CA57349D83,SHA256=B412C45DE423534D85F121ABC348FB38020FDA804EA0A972708B7447B0E7325D,IMPHASH=F84029681F81FED23E3E067364DA1699\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"817bddf3-3514-65cc-0802-000000001900\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"4292\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Program Files\\\\Mozilla Firefox\\\\firefox.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"\\\"C:\\\\Program Files\\\\Mozilla Firefox\\\\firefox.exe\\\"\"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "118772",
  "ProcessId": 3028,
  "ThreadId": 4412,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": "Z:\\hackthebox-sherlocks\\unit42\\Microsoft-Windows-Sysmon-Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2024-02-14T03:41:45.3058822+00:00",
  "RecordNumber": 26
}

```

### Overview

I’ll start with the parent process (`PayloadData4`), the process (`ExecutableInfo`), both process IDs (`PayloadData1` and `PayloadData5`), and the timestamp:

```

PS > cat .\eventid1.json | jq -s '.[] | [.TimeCreated, .PayloadData4, .ExecutableInfo, .PayloadData1, .PayloadData5]'
[
  "2024-02-14T03:41:45.3058822+00:00",
  "ParentProcess: C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "\"C:\\Program Files\\Mozilla Firefox\\pingsender.exe\" https://incoming.telemetry.mozilla.org/submit/telemetry/cb88145b-129d-471c-b605-4fdf09fec680/event/Firefox/122.0.1/release/20240205133611?v=4 C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\saved-telemetry-pings\\cb88145b-129d-471c-b605-4fdf09fec680 https://incoming.telemetry.mozilla.org/submit/telemetry/6fcd92a2-cc60-4df6-b6fb-66356dd011c1/main/Firefox/122.0.1/release/20240205133611?v=4 C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\saved-telemetry-pings\\6fcd92a2-cc60-4df6-b6fb-66356dd011c1",
  "ProcessID: 5584, ProcessGUID: 817bddf3-3679-65cc-2902-000000001900",
  "ParentProcessID: 4292, ParentProcessGUID: 817bddf3-3514-65cc-0802-000000001900"
]
[
  "2024-02-14T03:41:56.5596188+00:00",
  "ParentProcess: C:\\Windows\\explorer.exe",
  "\"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe\" ",
  "ProcessID: 10672, ProcessGUID: 817bddf3-3684-65cc-2d02-000000001900",
  "ParentProcessID: 1116, ParentProcessGUID: 817bddf3-311f-65cc-0a01-000000001900"
]
[
  "2024-02-14T03:41:57.6052379+00:00",
  "ParentProcess: C:\\Windows\\System32\\services.exe",
  "C:\\Windows\\system32\\msiexec.exe /V",
  "ProcessID: 10220, ProcessGUID: 817bddf3-3685-65cc-2e02-000000001900",
  "ParentProcessID: 740, ParentProcessGUID: 817bddf3-307b-65cc-0b00-000000001900"
]
[
  "2024-02-14T03:41:57.7881524+00:00",
  "ParentProcess: C:\\Windows\\System32\\msiexec.exe",
  "C:\\Windows\\syswow64\\MsiExec.exe -Embedding 5364C761FA9A55D636271A1CE8A6742D C",
  "ProcessID: 6996, ProcessGUID: 817bddf3-3685-65cc-2f02-000000001900",
  "ParentProcessID: 10220, ParentProcessGUID: 817bddf3-3685-65cc-2e02-000000001900"
]
[
  "2024-02-14T03:41:57.9059712+00:00",
  "ParentProcess: C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "\"C:\\Windows\\system32\\msiexec.exe\" /i \"C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\main1.msi\" AI_SETUPEXEPATH=C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe SETUPEXEDIR=C:\\Users\\CyberJunkie\\Downloads\\ EXE_CMD_LINE=\"/exenoupdates  /forcecleanup  /wintime 1707880560  \" AI_EUIMSI=\"\"",
  "ProcessID: 10324, ProcessGUID: 817bddf3-3685-65cc-3002-000000001900",
  "ParentProcessID: 10672, ParentProcessGUID: 817bddf3-3684-65cc-2d02-000000001900"
]
[
  "2024-02-14T03:41:58.1794583+00:00",
  "ParentProcess: C:\\Windows\\System32\\msiexec.exe",
  "C:\\Windows\\syswow64\\MsiExec.exe -Embedding 5250A3DB12224F77D2A18B4EB99AC5EB",
  "ProcessID: 10280, ProcessGUID: 817bddf3-3686-65cc-3102-000000001900",
  "ParentProcessID: 10220, ParentProcessGUID: 817bddf3-3685-65cc-2e02-000000001900"
]

```

There’s a ton here in just 6 logs!
1. I don’t believe there’s anything malicious about this event. `pingsender.exe` is a common [Firefox feature](https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/internals/pingsender.html). Still, this does show that Firefox is running.
2. An executable from the Downloads folder is being run with parent process of `explorer.exe`, which suggests that the user double-clicked it to launch it.
3. `services.exe` is launching `msiexec.exe`. I don’t have enough information at this point to say if this is related to the previous event or not, but it is installation activity and close in proximity in time with the previous event.
4. `msiexec.exe` calling the 32-bit version of itself (from `syswow64`). The calling `msiexec.exe` is the one created in the previous event.
5. The downloaded binary from the second log calling `msiexec` to install.
6. `msiexec` from the third log is calling the 32-bit version of itself again, just like in the forth log.

It’s clear to say that 2 and 5 are related, and 3, 4, and 6 are related.

### Preventivo24.02.14.exe.exe

In searching around for terms like “Preventivo24.02.14.exe.exe”, “Preventivo24.02.14”, and “Preventivo.exe”, I’ll find a bunch of hits that look very suspicious:

![image-20240408111923143](/img/image-20240408111923143.png)

The logs have the hashes of the binary:

```

PS  > cat .\eventid1.json | jq -s '.[1]'
{
  "PayloadData1": "ProcessID: 10672, ProcessGUID: 817bddf3-3684-65cc-2d02-000000001900",
  "PayloadData2": "RuleName: technique_id=T1204,technique_name=User Execution",
  "PayloadData3": "SHA1=18A24AA0AC052D31FC5B56F5C0187041174FFC61,MD5=32F35B78A3DC5949CE3C99F2981DEF6B,SHA256=0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3,IMPHASH=36ACA8EDDDB161C588FCF5AFDC1AD9FA",
  "PayloadData4": "ParentProcess: C:\\Windows\\explorer.exe",
  "PayloadData5": "ParentProcessID: 1116, ParentProcessGUID: 817bddf3-311f-65cc-0a01-000000001900",
  "PayloadData6": "ParentCommandLine: C:\\Windows\\Explorer.EXE",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "ExecutableInfo": "\"C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe\" ",
  "MapDescription": "Process creation",
  "ChunkNumber": 0,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"technique_id=T1204,technique_name=User Execution\"},{\"@Name\":\"UtcTime\",\"#text\":\"2024-02-14 03:41:56.538\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"817bddf3-3684-65cc-2d02-000000001900\"},{\"@Name\":\"ProcessId\",\"#text\":\"10672\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\CyberJunkie\\\\Downloads\\\\Preventivo24.02.14.exe.exe\"},{\"@Name\":\"FileVersion\",\"#text\":\"1.1.2\"},{\"@Name\":\"Description\",\"#text\":\"Photo and vn Installer\"},{\"@Name\":\"Product\",\"#text\":\"Photo and vn\"},{\"@Name\":\"Company\",\"#text\":\"Photo and Fax Vn\"},{\"@Name\":\"OriginalFileName\",\"#text\":\"Fattura 2 2024.exe\"},{\"@Name\":\"CommandLine\",\"#text\":\"\\\"C:\\\\Users\\\\CyberJunkie\\\\Downloads\\\\Preventivo24.02.14.exe.exe\\\" \"},{\"@Name\":\"CurrentDirectory\",\"#text\":\"C:\\\\Users\\\\CyberJunkie\\\\Downloads\\\\\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"},{\"@Name\":\"LogonGuid\",\"#text\":\"817bddf3-311e-65cc-a7ae-1b0000000000\"},{\"@Name\":\"LogonId\",\"#text\":\"0x1BAEA7\"},{\"@Name\":\"TerminalSessionId\",\"#text\":\"1\"},{\"@Name\":\"IntegrityLevel\",\"#text\":\"Medium\"},{\"@Name\":\"Hashes\",\"#text\":\"SHA1=18A24AA0AC052D31FC5B56F5C0187041174FFC61,MD5=32F35B78A3DC5949CE3C99F2981DEF6B,SHA256=0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3,IMPHASH=36ACA8EDDDB161C588FCF5AFDC1AD9FA\"},{\"@Name\":\"ParentProcessGuid\",\"#text\":\"817bddf3-311f-65cc-0a01-000000001900\"},{\"@Name\":\"ParentProcessId\",\"#text\":\"1116\"},{\"@Name\":\"ParentImage\",\"#text\":\"C:\\\\Windows\\\\explorer.exe\"},{\"@Name\":\"ParentCommandLine\",\"#text\":\"C:\\\\Windows\\\\Explorer.EXE\"},{\"@Name\":\"ParentUser\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 1,
  "EventRecordId": "118793",
  "ProcessId": 3028,
  "ThreadId": 4412,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": "Z:\\hackthebox-sherlocks\\unit42\\Microsoft-Windows-Sysmon-Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2024-02-14T03:41:56.5596188+00:00",
  "RecordNumber": 47
}

```

Searching on these hashes, I’ll find the binary has been uploaded to many malware sandboxes like [Malware Bazaar](https://bazaar.abuse.ch/sample/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3/), [AnyRun](https://any.run/report/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3/3e25d1f5-ca2a-4502-9a3a-22a607f125c0), [JoeSandbox](https://www.joesandbox.com/analysis/1379424), and [VirusTotal](https://www.virustotal.com/gui/file/0cb44c4f8273750fa40497fca81e850f73927e70b13c8f80cdcfee9d1478e6f3). Each of these has markers saying this binary is malicious:

![](/img/unit42-sandboxes.png)

The name UltraVNC is common. This seems like enough to say that the full path of the malicious binary is `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` (Task 2). I’ll note the PID of that process is 10672.

## Malware Source

### Strategy

There are a couple directions to go from here, seeing what the known malicious process did, or looking back to see where it came from. I’ll start by looking back to see where the malware came from. For that, I’ll look for file events, network events, and DNS events.

### File Creation

If Sysmon was running when the malware was downloaded, then it would generate Events with ID 11. I’ll use `jq -c` to select these events and output them one per line. Then I can use `findstr` (like `grep` in Linux) to get only lines with 4292 (the process id of Firefox from the process analysis above). Then I’ll read the resulting lines in and print the timestamp as well as the file that’s written (which I see is `PayloadData4` by looking at an example log). It is also possible to filter based on data within `jq`, but sometimes I find this technique faster.

```

PS > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 11)' | findstr 4292 | jq -s '.[] | [.TimeCreated, .PayloadData4]'
[
  "2024-02-14T03:41:26.4630328+00:00",
  "TargetFilename: C:\\Users\\CYBERJ~1\\AppData\\Local\\Temp\\skZdsnwf.exe"
]
[
  "2024-02-14T03:41:26.4635006+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\Downloads\\skZdsnwf.exe.part"
]
[
  "2024-02-14T03:41:26.4639993+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\Downloads\\skZdsnwf.exe.part"
]
[
  "2024-02-14T03:41:26.4644853+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"
]
[
  "2024-02-14T03:41:30.4745302+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe:Zone.Identifier"
]
[
  "2024-02-14T03:41:45.2125243+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\prefs-1.js"
]
[
  "2024-02-14T03:41:45.2136161+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\avsa4d81.default-release\\prefs-1.js"
]

```

At 03:41:26, it starts downloading a temp file, which is eventually renamed to `Preventivo24.02.14.exe.exe` in the same second. Four seconds later the alternative data stream is set to mark the file as downloaded from the internet. At this point, the other processes don’t seem important. But it’s fair to say that this was downloaded from Firefox.

### DNS

So where did Firefox download it from? I’ll start with the DNS records, which are in EventId 22, using the same command line structure as the previous:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 22)' | findstr 4292 | jq -s '.[] | [.TimeCreated, .PayloadData4, .PayloadData3]'
[
  "2024-02-14T03:41:26.4441194+00:00",
  "QueryName: uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com",
  "Image: C:\\Program Files\\Mozilla Firefox\\firefox.exe"
]
[
  "2024-02-14T03:41:45.7793186+00:00",
  "QueryName: d.dropbox.com",
  "Image: C:\\Program Files\\Mozilla Firefox\\firefox.exe"
]

```

The first query is less than 0.1 second before the download begins. It’s safe to say the malware came from Dropbox (Task 3).

The second query is about 19 seconds later, 11 seconds before the malware is launches. It’s not clear yet what is happening here, but I’ll add it to the timeline as well.

### Network

There are no network connection logs (EventId 3) with the Firefox pid in them. I’ll come back to these later, but for now nothing more to learn.

## Malware Activity

### File Creation

I’ll work from the PID of the malicious process, noted above as 10672. It seems that the malware created six files on target:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 11)' | findstr 10672 | jq -s '.[] | [.TimeCreated, .PayloadData4]'
[
  "2024-02-14T03:41:58.4048771+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\c.cmd"
]
[
  "2024-02-14T03:41:58.4056902+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\cmmc.cmd"
]
[
  "2024-02-14T03:41:58.4065154+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\on.cmd"
]
[
  "2024-02-14T03:41:58.4075055+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\once.cmd"
]
[
  "2024-02-14T03:41:58.4104279+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\taskhost.exe"
]
[
  "2024-02-14T03:41:58.4225212+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\viewer.exe"
]

```

All of these are created within the same tenth of a second. The full path of the `once.cmd` file is `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd` (Task 5).

### DNS

This process made one DNS request:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 22)' | findstr 10672 | jq -s '.[] | [.TimeCreated, .PayloadData4, .PayloadData3]'
[
  "2024-02-14T03:41:58.7648370+00:00",
  "QueryName: www.example.com",
  "Image: C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe"
]

```

It’s to `www.example.com` (Task 6). This is almost certainly not actually controlled by the actor. It is either a connectivity check (making sure the internet is working to detect if it’s being run in a sandbox), or just an artifact to mislead defenders.

### Network

There is only a single network event (EventId 3), and it is from PID 10672:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 3)' | findstr 10672 | jq .
{
  "PayloadData1": "ProcessID: 10672, ProcessGUID: 817bddf3-3684-65cc-2d02-000000001900",
  "PayloadData2": "RuleName: technique_id=T1036,technique_name=Masquerading",
  "PayloadData3": "SourceHostname: -",
  "PayloadData4": "SourceIp: 172.17.79.132",
  "PayloadData5": "DestinationHostname: -",
  "PayloadData6": "DestinationIp: 93.184.216.34",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "MapDescription": "Network connection",
  "ChunkNumber": 2,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"technique_id=T1036,technique_name=Masquerading\"},{\"@Name\":\"UtcTime\",\"#text\":\"2024-02-14 03:41:57.159\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"817bddf3-3684-65cc-2d02-000000001900\"},{\"@Name\":\"ProcessId\",\"#text\":\"10672\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\CyberJunkie\\\\Downloads\\\\Preventivo24.02.14.exe.exe\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"},{\"@Name\":\"Protocol\",\"#text\":\"tcp\"},{\"@Name\":\"Initiated\",\"#text\":\"True\"},{\"@Name\":\"SourceIsIpv6\",\"#text\":\"False\"},{\"@Name\":\"SourceIp\",\"#text\":\"172.17.79.132\"},{\"@Name\":\"SourceHostname\",\"#text\":\"-\"},{\"@Name\":\"SourcePort\",\"#text\":\"61177\"},{\"@Name\":\"SourcePortName\",\"#text\":\"-\"},{\"@Name\":\"DestinationIsIpv6\",\"#text\":\"False\"},{\"@Name\":\"DestinationIp\",\"#text\":\"93.184.216.34\"},{\"@Name\":\"DestinationHostname\",\"#text\":\"-\"},{\"@Name\":\"DestinationPort\",\"#text\":\"80\"},{\"@Name\":\"DestinationPortName\",\"#text\":\"-\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 3,
  "EventRecordId": "118910",
  "ProcessId": 3028,
  "ThreadId": 4424,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": "Z:\\hackthebox-sherlocks\\unit42\\Microsoft-Windows-Sysmon-Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2024-02-14T03:41:58.9054838+00:00",
  "RecordNumber": 164
}

```

The IP connected to is 93.184.216.34 (Task 7).

### Time Stomping

One of the question successes that the malware is messing with the timestamps of files on the victim system. These are logged in Event Id 2, and there are 16 associated with the malware process:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 2)' | findstr 10672 | jq -s '.[] | [.TimeCreated, .PayloadData4, .PayloadData5, .PayloadData6]'
[
  "2024-02-14T03:41:57.5590448+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\main1.msi",
  "CreationTimeUTC: 2024-01-14 08:14:23.713",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:57.545"
]
[
  "2024-02-14T03:41:58.4045440+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\powercfg.msi",
  "CreationTimeUTC: 2024-01-10 18:12:27.357",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.389"
]
[
  "2024-02-14T03:41:58.4053804+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\c.cmd",
  "CreationTimeUTC: 2024-01-10 18:12:26.295",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.389"
]
[
  "2024-02-14T03:41:58.4061207+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\cmmc.cmd",
  "CreationTimeUTC: 2024-01-10 18:12:26.373",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4069465+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\on.cmd",
  "CreationTimeUTC: 2024-01-10 18:12:26.436",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4078369+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\once.cmd",
  "CreationTimeUTC: 2024-01-10 18:12:26.458",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4086077+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\cmd.txt",
  "CreationTimeUTC: 2024-01-10 18:12:26.326",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4093822+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\UltraVNC.ini",
  "CreationTimeUTC: 2024-01-10 18:12:26.530",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4101450+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\TempFolder\\~.pdf",
  "CreationTimeUTC: 2024-01-14 08:10:06.029",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4128728+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\taskhost.exe",
  "CreationTimeUTC: 2024-01-10 18:12:26.513",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]
[
  "2024-02-14T03:41:58.4231673+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\viewer.exe",
  "CreationTimeUTC: 2024-01-10 18:12:26.670",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]
[
  "2024-02-14T03:41:58.4258718+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\ddengine.dll",
  "CreationTimeUTC: 2024-01-10 18:12:26.406",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]
[
  "2024-02-14T03:41:58.4277653+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\UVncVirtualDisplay\\UVncVirtualDisplay.dll",
  "CreationTimeUTC: 2024-01-10 18:12:26.905",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]
[
  "2024-02-14T03:41:58.4288308+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\vnchooks.dll",
  "CreationTimeUTC: 2024-01-10 18:12:26.686",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]
[
  "2024-02-14T03:41:58.4299750+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\UVncVirtualDisplay\\uvncvirtualdisplay.cat",
  "CreationTimeUTC: 2024-01-10 18:12:26.889",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]
[
  "2024-02-14T03:41:58.4308868+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\WindowsVolume\\Games\\UVncVirtualDisplay\\UVncVirtualDisplay.inf",
  "CreationTimeUTC: 2024-01-10 18:12:27.013",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.420"
]

```

Many of the files associated with this event are in here, which makes sense.

There’s only one associated with a PDF:

```

PS  > cat .\20240408132435_EvtxECmd_Output.json | jq -c 'select(.EventId == 2)' | findstr 10672 | findstr pdf | jq -s '.[] | [.TimeCreated, .PayloadData4, .PayloadData5, .PayloadData6]'
[
  "2024-02-14T03:41:58.4101450+00:00",
  "TargetFilename: C:\\Users\\CyberJunkie\\AppData\\Roaming\\Photo and Fax Vn\\Photo and vn 1.1.2\\install\\F97891C\\TempFolder\\~.pdf",
  "CreationTimeUTC: 2024-01-14 08:10:06.029",
  "PreviousCreationTimeUTC: 2024-02-14 03:41:58.404"
]

```

The PDF timestamp was changed to 2024-01-14 08:10:06 (Task 4).

### Termination

There’s only one process termination event (Event Id 5), and it belongs to the malware:

```

PS > cat .\20240408132435_EvtxECmd_Output.json | jq 'select(.EventId == 5)'
{
  "PayloadData1": "ProcessID: 10672, ProcessGUID: 817bddf3-3684-65cc-2d02-000000001900",
  "UserName": "DESKTOP-887GK2L\\CyberJunkie",
  "ExecutableInfo": "C:\\Users\\CyberJunkie\\Downloads\\Preventivo24.02.14.exe.exe",
  "MapDescription": "Process terminated",
  "ChunkNumber": 2,
  "Computer": "DESKTOP-887GK2L",
  "Payload": "{\"EventData\":{\"Data\":[{\"@Name\":\"RuleName\",\"#text\":\"-\"},{\"@Name\":\"UtcTime\",\"#text\":\"2024-02-14 03:41:58.795\"},{\"@Name\":\"ProcessGuid\",\"#text\":\"817bddf3-3684-65cc-2d02-000000001900\"},{\"@Name\":\"ProcessId\",\"#text\":\"10672\"},{\"@Name\":\"Image\",\"#text\":\"C:\\\\Users\\\\CyberJunkie\\\\Downloads\\\\Preventivo24.02.14.exe.exe\"},{\"@Name\":\"User\",\"#text\":\"DESKTOP-887GK2L\\\\CyberJunkie\"}]}}",
  "UserId": "S-1-5-18",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventId": 5,
  "EventRecordId": "118907",
  "ProcessId": 3028,
  "ThreadId": 4412,
  "Level": "Info",
  "Keywords": "Classic",
  "SourceFile": "Z:\\hackthebox-sherlocks\\unit42\\Microsoft-Windows-Sysmon-Operational.evtx",
  "ExtraDataOffset": 0,
  "HiddenRecord": false,
  "TimeCreated": "2024-02-14T03:41:58.7996518+00:00",
  "RecordNumber": 161
}

```

It happens at 2024-02-14 03:41:58 (Task 8).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2024-02-14T03:41:26.4 | Firefox DNS query for Dropbox | DNS (22) |
| 2024-02-14T03:41:26.5 | Firefox malware download | File Creation (11) |
| 2024-02-14T03:41:30.4 | Windows tags malware as downloaded | File Creation (11) |
| 2024-02-14T03:41:45.8 | Firefox DNS query for Dropbox | DNS (22) |
| 2024-02-14T03:41:56.6 | `Preventivo24.02.14.exe.exe` launched | Process Creation (1) |
| 2024-02-14T03:41:57.9 | Malware starts `msiexec` | Process Creation (1) |
| 2024-02-14T03:41:58.4 | Malware writes files to disk | File Creation (11) |
| 2024-02-14T03:41:58.4 | Malware timestomps 15 files. | Time Modification (2) |
| 2024-02-14T03:41:58.6 | Malware connects to 93.184.216.34 | Network (3) |
| 2024-02-14T03:41:58.8 | Malware DNS query for `www.example.com` | DNS (22) |
| 2024-02-14 03:41:58.8 | Malware terminates itself | Process Termination (5) |

### Question Answers
1. How many Event logs are there with Event ID 11?

   56
2. Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim’s system?

   `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`
3. Which Cloud drive was used to distribute the malware?

   Dropbox
4. The initial malicious file time-stamped (a defense evasion technique, where the file creation date is changed to make it appear old) many files it created on disk. What was the timestamp changed to for a PDF file?

   2024-01-14 08:10:06
5. The malicious file dropped a few files on disk. Where was “once.cmd” created on disk? Please answer with the full path along with the filename.

   `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`
6. The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?

   `www.example.com`
7. Which IP address did the malicious process try to reach out to?
   93.184.216.34
8. The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?

   2024-02-14 03:41:58