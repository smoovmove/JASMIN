---
title: HTB Sherlock: Constellation
url: https://0xdf.gitlab.io/2024/06/05/htb-sherlock-constellation.html
date: 2024-06-05T09:00:00+00:00
difficulty: Medium
tags: htb-sherlock, forensics, sherlock-constellation, hackthebox, dfir, ctf, sherlock-cat-threat-intelligence, unfurl, url-forensics, exiftool, osint, linkedin, url-discord, url-google
---

![Constellation](/icons/sherlock-constellation.png)

Constellation is a fun Sherlock challenge largely focuced on forensics against URLs. Two URLs, from Discord and Google are shared, and I’ll use Unfurl to pull timestamps and other information from them to make a timeline of an insider threat interaction.

## Challenge Info

| Name | [Constellation](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fconstellation)  [Constellation](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fconstellation) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fconstellation) |
| --- | --- |
| Release Date | 14 December 2023 |
| Retire Date | 2024-05-30 |
| Difficulty | Medium |
| Category | Threat Intelligence Threat Intelligence |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

The Sherlock offers the following scenario:

> The SOC team has recently been alerted to the potential existence of an insider threat. The suspect employee’s workstation has been secured and examined. During the memory analysis, the Senior DFIR Analyst succeeded in extracting several intriguing URLs from the memory. These are now provided to you for further analysis to uncover any evidence, such as indications of data exfiltration or contact with malicious entities. Should you discover any information regarding the attacking group or individuals involved, you will collaborate closely with the threat intelligence team. Additionally, you will assist the Forensics team in creating a timeline.
>
> Warning : This Sherlock will require an element of OSINT and some answers can be found outside of the provided artifacts to complete fully.

Notes from the scenario:
- Dealing with insider threat.
- Forensics will be based on URLs.
- OSINT is required to complete this Sherlock.

### Questions

To solve this challenge, I’ll need to answer the following 11 questions:
1. When did the suspect first start Direct Message (DM) conversations with the external entity (A possible threat actor group which targets organizations by paying employees to leak sensitive data)? (UTC)
2. What was the name of the file sent to the suspected insider threat?
3. When was the file sent to the suspected insider threat? (UTC)
4. The suspect utilised Google to search something after receiving the file. What was the search query?
5. The suspect originally typed something else in search tab, but found a Google search result suggestion which they clicked on. Can you confirm which words were written in search bar by the suspect originally?
6. When was this Google search made? (UTC)
7. What is the name of the Hacker group responsible for bribing the insider threat?
8. What is the name of the person suspected of being an Insider Threat?
9. What is the anomalous stated creation date of the file sent to the insider threat? (UTC)
10. The Forela threat intel team are working on uncovering this incident. Any OpSec mistakes made by the attackers are crucial for Forela’s security team. Try to help the TI team and confirm the real name of the agent/handler from Anticorp.
11. Which City does the threat actor belong to?

### Data

The downloadable data consists of two files, a PDF and a text file:

```

oxdf@hacky$ unzip -l constellation.zip 
Archive:  constellation.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-03-05 05:02   Artifacts/
      959  2023-12-04 07:57   Artifacts/IOCs.txt
    25995  2024-03-05 05:02   Artifacts/NDA_Instructions.pdf
---------                     -------
    26954                     3 files

```

`IOCs.txt` has two URLs in it, one for Discord and the other for Google:

```

URL 1 : https://cdn.discordapp.com/attachments/1152635915429232640/1156461980652154931/NDA_Instructions.pdf?ex=65150ea6&is=6513bd26&hm=64de12da031e6e91cc4f35c64b2b0190fb040b69648a64365f8a8260760656e3&

URL 2 : https://www.google.com/search?q=how+to+zip+a+folder+using+tar+in+linux&sca_esv=568736477&hl=en&sxsrf=AM9HkKkFWLlX_hC63KqDpJwdH9M3JL7LZA%3A1695792705892&source=hp&ei=Qb4TZeL2M9XPxc8PwLa52Ag&iflsig=AO6bgOgAAAAAZRPMUXuGExueXDMxHxU9iRXOL-GQIJZ-&oq=How+to+archive+a+folder+using+tar+i&gs_lp=Egdnd3Mtd2l6IiNIb3cgdG8gYXJjaGl2ZSBhIGZvbGRlciB1c2luZyB0YXIgaSoCCAAyBhAAGBYYHjIIEAAYigUYhgMyCBAAGIoFGIYDMggQABiKBRiGA0jI3QJQ8WlYxIUCcAx4AJABAJgBqQKgAeRWqgEEMi00NrgBAcgBAPgBAagCCsICBxAjGOoCGCfCAgcQIxiKBRgnwgIIEAAYigUYkQLCAgsQABiABBixAxiDAcICCBAAGIAEGLEDwgILEAAYigUYsQMYgwHCAggQABiKBRixA8ICBBAjGCfCAgcQABiKBRhDwgIOEC4YigUYxwEY0QMYkQLCAgUQABiABMICDhAAGIoFGLEDGIMBGJECwgIFEC4YgATCAgoQABiABBgUGIcCwgIFECEYoAHCAgUQABiiBMICBxAhGKABGArCAggQABgWGB4YCg&sclient=gws-wiz

```

`NDA_Instructions.pdf` has instructions to the insider threat about how to get data for the threat actor and their payment. I’ll cover the contents and metadata in detail later.

### Tools

Both of these artifacts can be viewed in their raw form in native viewers, like any notepad application for `IOCs.txt` and any PDF viewer for `NDA_Instructions.pdf`.

Beyond that, the PDF file will have metadata associated with it that I’ll access with `exiftool`.

In searching for details on how to get forensic data from URLs with terms like “URL forensics”, I came across [this blog post on dfir.blog](https://dfir.blog/introducing-unfurl/) about a tool named Unfurl. It is [open source](https://github.com/obsidianforensics/unfurl?ref=dfir.blog) for local installation, but there’s also a [hosted version](https://dfir.blog/unfurl).

It takes a URL and breaks down all the known components to amazing detail:

![image-20240602181320957](/img/image-20240602181320957.png)

## PDF

### Contents

The PDF is instructions from the threat actor to the insider threat on what do do:

![image-20240602180333373](/img/image-20240602180333373.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The group responsible for this threat is AntiCorp Gr04p (Task 7), and the employee they are working with is Karen Riley (Task 8).

The instructions are to SSH into a server, use `tar` to create an archive of the target data, and upload it to an Amazon S3 bucket named “hahaha-you-lose-forela” using the AWS CLI. The actors are offering $20,000 to complete this task.

### Metadata

`exiftool` shows information about the metadata on the PDF. Some of it is mangled, like the Create Date of 2054-01-17 22:45:22 (Task 9), but some seems intact. It’s important to note that the metadata is malformed, which suggests that the actor may have attempted to modify it, and thus that the remaining data may not be trustworthy as well.

```

oxdf@hacky$ exiftool NDA_Instructions.pdf
ExifTool Version Number         : 12.40
File Name                       : NDA_Instructions.pdf
Directory                       : .
File Size                       : 25 KiB
File Modification Date/Time     : 2024:06:01 18:38:45-04:00
File Access Date/Time           : 2024:06:01 18:39:08-04:00
File Inode Change Date/Time     : 2024:06:01 18:44:41-04:00
File Permissions                : -rwxrwxrwx
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Producer                        : AntiCorp PDF FW
Create Date                     : 2054:01:17 22:45:22+01:00
Title                           : KarenForela_Instructions
Author                          : CyberJunkie@AntiCorp.Gr04p
Creator                         : AntiCorp
Modify Date                     : 2054:01:17 22:45:22+01:00
Subject                         : Forela_Mining stats and data campaign (Stop destroying env)

```

The File Modification, Access, and Inode Change date/times are the dates that the PDF is created on my system, and thus not forensically relevant. Still, the Producer of “AntiCorp PDF FW”, the Title of “KarenForela\_Instructions”, Creator of “AntiCorp”, and the Subject are all interesting. Most interesting is the Author email address, “CyberJunkie@AntiCorp.Gr04p”.

### OSINT

With that email address and the note that I may need to do OSINT, I’ll look for this email address:

![image-20240602175751424](/img/image-20240602175751424.png)

Two links to LinkedIn. The [profile](https://www.linkedin.com/in/abdullah-al-sajjad-434545293/) is clearly related:

![image-20240601212423711](/img/image-20240601212423711.png)

Their name is Abdullah Al Sajjad (Task 10), and their location is Bahawalpur, Punjab, Pakistan (Task 11).

## URLs

### Discord

#### Overview

When I enter the Discord URL into Unfurl, it makes a chart that looks like:

![image-20240602204633027](/img/image-20240602204633027.png)

The cluster at the far left is high level info about the host part of the URL:

[![image-20240602204745309](/img/image-20240602204745309.png)*Click for full size image*](/img/image-20240602204745309.png)

Nothing too interesting here. It comes from the legit Discord content delivery network (CDN).

#### Path

The next block is about the path of the URL, `/attachments/1152635915429232640/1156461980652154931/NDA_Instructions.pdf`, and it has four parts. The first is `attachments`, which doesn’t have any additional information. The second is about the number `1152635915429232640`:

[![image-20240602205109343](/img/image-20240602205109343.png)*Click for full size image*](/img/image-20240602205109343.png)

This is the “Channel ID”, and given that it is likely a DM between the threat actor and the employee, that channel is the direct message. The timestamp is for 2023-09-16 16:03:37, which must be the first time these two participants spoke over DM (Task 1).

The third block is the file ID, which also contains a timestamp:

[![image-20240602205405573](/img/image-20240602205405573.png)*Click for full size image*](/img/image-20240602205405573.png)

That shows that the file was uploaded to discord into this channel at 2023-09-27 05:27:02 (Task 3).

The final block in the path section is the filename itself, `NDA_Instructions.pdf` (Task 2).

[![image-20240602205528309](/img/image-20240602205528309.png)*Click for full size image*](/img/image-20240602205528309.png)

#### Query Parameters

The last section is the query data, which has three parameters:

[![image-20240602213914456](/img/image-20240602213914456.png)*Click for full size image*](/img/image-20240602213914456.png)

There’s two more timestamps. My best guess here is that `is` is the issued time (matching up with the creation time), and `ex` is the expiration time, 24 hours later. If I try to visit this URL, it does return that it’s no longer available:

![image-20240602214146681](/img/image-20240602214146681.png)

### Google

#### Overview

The Google URL is large, and makes a big chart on Unfurl:

![image-20240603112104805](/img/image-20240603112104805.png)

The query is formatted such that the host/path are very simple, and it’s really just a bunch of query parameters. I’ve added a newline to look at each parameter here:

```

https://www.google.com/search?
q=how+to+zip+a+folder+using+tar+in+linux&
sca_esv=568736477&
hl=en&
sxsrf=AM9HkKkFWLlX_hC63KqDpJwdH9M3JL7LZA%3A1695792705892&
source=hp&
ei=Qb4TZeL2M9XPxc8PwLa52Ag&
iflsig=AO6bgOgAAAAAZRPMUXuGExueXDMxHxU9iRXOL-GQIJZ-&
oq=How+to+archive+a+folder+using+tar+i&
gs_lp=Egdnd3Mtd2l6IiNIb3cgdG8gYXJjaGl2ZSBhIGZvbGRlciB1c2luZyB0YXIgaSoCCAAyBhAAGBYYHjIIEAAYigUYhgMyCBAAGIoFGIYDMggQABiKBRiGA0jI3QJQ8WlYxIUCcAx4AJABAJgBqQKgAeRWqgEEMi00NrgBAcgBAPgBAagCCsICBxAjGOoCGCfCAgcQIxiKBRgnwgIIEAAYigUYkQLCAgsQABiABBixAxiDAcICCBAAGIAEGLEDwgILEAAYigUYsQMYgwHCAggQABiKBRixA8ICBBAjGCfCAgcQABiKBRhDwgIOEC4YigUYxwEY0QMYkQLCAgUQABiABMICDhAAGIoFGLEDGIMBGJECwgIFEC4YgATCAgoQABiABBgUGIcCwgIFECEYoAHCAgUQABiiBMICBxAhGKABGArCAggQABgWGB4YCg&
sclient=gws-wiz

```

#### Query

The search query, `q`, URL-decodes to “how to zip a folder using tar in linux” (Task 4). `oq` is the original query, which is what the user started typing in the search box, before selecting the query from the auto-complete options. So in this case, the user typed “How to archive a folder using tar i” (Task 5), and then selected the query from the options, which I am able to recreate:

![image-20240603114254466](/img/image-20240603114254466.png)

#### Timestamps

There is timestamp data in the `ei` parameter, which is a base64-encoded representation of four values, a 32-byte int and three “varints” (variable size, map to unsigned ints). The first two of these values [have been determined](https://deedpolloffice.com/blog/articles/decoding-ei-parameter), where the other two haven’t. In this case,

[![image-20240603115144558](/img/image-20240603115144558.png)*Click for full size image*](/img/image-20240603115144558.png)

This gives the session timestamp of 2023-09-27 05:31:45 (Task 6).

The `sxsrf` value also contains a timestamp. After URL-decoding, it is “AM9HkKkFWLlX\_hC63KqDpJwdH9M3JL7LZA:1695792705892”. After the “:” is a Unix timestamp, which according to [this post](https://www.magnetforensics.com/resources/analyzing-timestamps-in-google-search-urls/), represents the timestamp of visiting the previous page:

> So if I visit [www.google.com](http://www.google.com/) and then search for “Magnet Forensics” this timestamp will reflect the date/time when I visited [www.google.com](http://www.google.com/) not when I conducted my search.

That doesn’t make a ton of sense here, as the timestamp actually comes 0.04 seconds after the page load timestamp:

[![image-20240603115716391](/img/image-20240603115716391.png)*Click for full size image*](/img/image-20240603115716391.png)

There’s another potential timestamp comes in the `sca_esv` parameter:

[![image-20240603120038197](/img/image-20240603120038197.png)*Click for full size image*](/img/image-20240603120038197.png)

What exactly this value represents is a [question still being worked](https://webapps.stackexchange.com/questions/172215/google-videos-search-sca-esv-query-parameter-possible-tracking). It seems well outside the interesting timeframe here.

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023-09-16 16:03:37 | First communication between threat actor and insider | Discord URL |
| 2023-09-27 05:27:02 | Instructions PDF shared via Discord | Discord URL |
| 2023-09-27 05:31:45 | Insider searched for tar instructions | Google URL |

### Question Answers
1. When did the suspect first start Direct Message (DM) conversations with the external entity (A possible threat actor group which targets organizations by paying employees to leak sensitive data)? (UTC)

   2023-09-16 16:03:37
2. What was the name of the file sent to the suspected insider threat?

   NDA\_Instructions.pdf
3. When was the file sent to the suspected insider threat? (UTC)

   2023-09-27 05:27:02
4. The suspect utilised Google to search something after receiving the file. What was the search query?

   how to zip a folder using tar in linux
5. The suspect originally typed something else in search tab, but found a Google search result suggestion which they clicked on. Can you confirm which words were written in search bar by the suspect originally?

   How to archive a folder using tar i
6. When was this Google search made? (UTC)

   2023-09-27 05:31:45
7. What is the name of the Hacker group responsible for bribing the insider threat?

   AntiCorp Gr04p
8. What is the name of the person suspected of being an Insider Threat?

   Karen Riley
9. What is the anomalous stated creation date of the file sent to the insider threat? (UTC)

   2054-01-17 22:45:22
10. The Forela threat intel team are working on uncovering this incident. Any OpSec mistakes made by the attackers are crucial for Forela’s security team. Try to help the TI team and confirm the real name of the agent/handler from Anticorp.

    Abdullah Al Sajjad
11. Which City does the threat actor belong to?

    Bahawalpur