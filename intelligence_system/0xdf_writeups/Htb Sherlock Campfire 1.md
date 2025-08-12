---
title: HTB Sherlock: Campfire-1
url: https://0xdf.gitlab.io/2024/06/24/htb-sherlock-campfire-1.html
date: 2024-06-24T10:06:47+00:00
difficulty: Very Easy
tags: htb-sherlock, ctf, dfir, hackthebox, forensics, sherlock-campfire-1, eventlogs, prefetch, evtx-dump, pecmd, win-event-4769, kerberoasting, jq, win-event-4104, powerview
---

![Campfire-1](/icons/sherlock-campfire-1.png)

Campfire-1 is the first in a series of Sherlocks looking at identifying critical active directory vulnerabilities. This challenge requires looking at event log and prefetch data to see an attack run PowerView and the Rubeus to perform a Kerberoasting attack.

## Challenge Info

| Name | [Campfire-1](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fcampfire-1)  [Campfire-1](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fcampfire-1) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fcampfire-1) |
| --- | --- |
| Release Date | 20 June 2024 |
| Retire Date | 20 June 2024 |
| Difficulty | Very Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> Alonzo Spotted Weird files on his computer and informed the newly assembled SOC Team. Assessing the situation it is believed a Kerberoasting attack may have occurred in the network. It is your job to confirm the findings by analyzing the provided evidence.
>
> You are provided with:
>
> 1- Security Logs from the Domain Controller
>
> 2- PowerShell-Operational Logs from the affected workstation
>
> 3- Prefetch Files from the affected workstation

Notes from the scenario:
- Kerberoasting attack.
- Security logs from the DC.
- PowerShell logs and prefetch files from the workstation.

### Questions

To solve this challenge, I’ll need to answer the following 7 questions:
1. Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred?
2. What is the Service Name that was targeted?
3. It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation?
4. Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network?
5. When was this script executed?
6. What is the full path of the tool used to perform the actual kerberoasting attack?
7. When was the tool executed to dump credentials?

### Data

The download has a folder, `Triage`. It has two folders, implying collection from two computers:

```

oxdf@hacky$ ls Triage/
'Domain Controller'   Workstation

```

`Domain Controller` has a single file representing the security event logs:

```

oxdf@hacky$ ls Triage/Domain\ Controller/
SECURITY-DC.evtx

```

`Workstation` has a folder labeled as triage, and PowerShell event logs:

```

oxdf@hacky$ ls Triage/Workstation/
2024-05-21T033012_triage_asset  Powershell-Operational.evtx

```

The triage folder has collection starting at `C:\`, but the only folder is the prefetch data:

```

oxdf@hacky$ ls -1 Triage/Workstation/2024-05-21T033012_triage_asset/C/Windows/prefetch/ | wc -l
214
oxdf@hacky$ ls Triage/Workstation/2024-05-21T033012_triage_asset/C/Windows/prefetch/
 ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf    MSMPENG.EXE-78AA5B62.pf                     SVCHOST.EXE-262B838E.pf
 APPLICATIONFRAMEHOST.EXE-8CE9A1EE.pf         MSPAINT.EXE-6406C4A1.pf                     SVCHOST.EXE-2F9E5F3D.pf
 AUDIODG.EXE-AB22E9A6.pf                      NGEN.EXE-4A8DA13E.pf                        SVCHOST.EXE-3D60499C.pf
 BACKGROUNDTASKHOST.EXE-F8B2DD01.pf           NGEN.EXE-734C6620.pf                        SVCHOST.EXE-44C0CDF7.pf
 CMD.EXE-0BD30981.pf                          NGENTASK.EXE-0E6CEC17.pf                    SVCHOST.EXE-4B98D760.pf
 COMPATTELRUNNER.EXE-B7A68ECC.pf              NGENTASK.EXE-849BFD75.pf                    SVCHOST.EXE-4BD0A607.pf
 CONHOST.EXE-0C6456FB.pf                      NOTEPAD++.EXE-3F73AA45.pf                   SVCHOST.EXE-59780EBF.pf
 CONSENT.EXE-40419367.pf                      NOTEPAD.EXE-C5670914.pf                     SVCHOST.EXE-59D511F9.pf
 CTFMON.EXE-795F8130.pf                       OBS-STUDIO-28.1.2-FULL-INSTAL-26510194.pf   SVCHOST.EXE-6493017E.pf
 DEFRAG.EXE-3D9E8D72.pf                       OBS-STUDIO-28.1.2-FULL-INSTAL-B2FCD437.pf   SVCHOST.EXE-6867B1E5.pf
 DLLHOST.EXE-077D6084.pf                      OBS64.EXE-FC4D8EA8.pf                       SVCHOST.EXE-6A4A44E7.pf
 DLLHOST.EXE-1BAE06BB.pf                      OFFICEC2RCLIENT.EXE-6DB2EFE8.pf             SVCHOST.EXE-73D024B2.pf
 DLLHOST.EXE-47BE07DC.pf                      OFFICECLICKTORUN.EXE-F5CCE208.pf            SVCHOST.EXE-764FA25C.pf
 DLLHOST.EXE-6F625E57.pf                      ONEDRIVE.EXE-05361D4F.pf                    SVCHOST.EXE-77C41F85.pf
 DLLHOST.EXE-7617EDA2.pf                      ONEDRIVE.EXE-191F0739.pf                    SVCHOST.EXE-7AAD9645.pf
 DLLHOST.EXE-7D5CE0CA.pf                      ONEDRIVE.EXE-267427AE.pf                    SVCHOST.EXE-852EC587.pf
 DLLHOST.EXE-810B6BBE.pf                      ONEDRIVE.EXE-B657FF91.pf                    SVCHOST.EXE-8F09AACB.pf
 DLLHOST.EXE-8EE3ADE8.pf                      ONEDRIVESETUP.EXE-11497479.pf               SVCHOST.EXE-952637C2.pf
 DLLHOST.EXE-F144D205.pf                      OPENWITH.EXE-8B50D58B.pf                    SVCHOST.EXE-9A28EB78.pf
 DLLHOST.EXE-F7FC6593.pf                      Op-EXPLORER.EXE-D5E97654-000000F5.pf        SVCHOST.EXE-9D041ABC.pf
 DWM.EXE-314E93C5.pf                          Op-MSEDGE.EXE-37D25F9A-00000001.pf          SVCHOST.EXE-A79A44A2.pf
 ELEVATION_SERVICE.EXE-479FE2CB.pf            PHPSTORM-2023.1.1.EXE-21B32079.pf           SVCHOST.EXE-B18C213B.pf
 EXCEL.EXE-FE860005.pf                        POWERPNT.EXE-7A8D1F9B.pf                    SVCHOST.EXE-B6F285B2.pf
 FILECOAUTH.EXE-7425F22E.pf                   POWERSHELL.EXE-CA1AE517.pf                  SVCHOST.EXE-C25BD44A.pf
 FILECOAUTH.EXE-771244B7.pf                   POWERSHELL_ISE.EXE-C4180667.pf              SVCHOST.EXE-C2DA4F6F.pf
 FILECOAUTH.EXE-88F71F64.pf                   PSEXEC64.EXE-BE2659AF.pf                    SVCHOST.EXE-C35F28CB.pf
 FILESYNCCONFIG.EXE-1C1104B5.pf               REGEDIT.EXE-DAB4D60B.pf                     SVCHOST.EXE-C38EF8DD.pf
 FILESYNCCONFIG.EXE-C1CD6527.pf               RUBEUS.EXE-5873E24B.pf                      SVCHOST.EXE-C4B64CAF.pf
'FIREFOX INSTALLER.EXE-13A26B52.pf'           RUNDLL32.EXE-1C52D230.pf                    SVCHOST.EXE-C625B657.pf
 GITHUBDESKTOP.EXE-CD0DF2E0.pf                RUNDLL32.EXE-27E52A2D.pf                    SVCHOST.EXE-D4A56B1A.pf
 GPUPDATE.EXE-7EBA4B6F.pf                     RUNDLL32.EXE-41CF339D.pf                    SVCHOST.EXE-D8C907E1.pf
 GUP.EXE-226DCAE9.pf                          RUNDLL32.EXE-75313621.pf                    SVCHOST.EXE-D9CC15E0.pf
 IDENTITY_HELPER.EXE-12341E99.pf              RUNDLL32.EXE-C0159C27.pf                    SVCHOST.EXE-DDF1360E.pf
 IDENTITY_HELPER.EXE-4E2A63C3.pf              RUNONCE.EXE-FB4EF753.pf                     SVCHOST.EXE-EBBF67E6.pf
 KMS_VL_ALL_AIO.EXE-DEC1136B.pf               RUNTIMEBROKER.EXE-0489BEEA.pf               SVCHOST.EXE-F5E1DCD3.pf
 LOCKAPP.EXE-ACD69F07.pf                      RUNTIMEBROKER.EXE-4551A062.pf               SVCHOST.EXE-F952D9A9.pf
 LOGONUI.EXE-F639BD7E.pf                      RUNTIMEBROKER.EXE-5A3B22F7.pf               SYSTEMPROPERTIESADVANCED.EXE-27792BE5.pf
'MICROSOFT OFFICE 2021 PRO PLU-A4822CF7.pf'   RUNTIMEBROKER.EXE-68C55521.pf               SYSTEMPROPERTIESCOMPUTERNAME.-449B662F.pf
 MICROSOFT.SHAREPOINT.EXE-EC13D0C5.pf         RUNTIMEBROKER.EXE-6B016F92.pf               SYSTEMSETTINGS.EXE-BE0858C5.pf
 MICROSOFT.SHAREPOINT.EXE-EECBA9B3.pf         RUNTIMEBROKER.EXE-AC4D2D35.pf               SYSTEMSETTINGSADMINFLOWS.EXE-F74198E7.pf
 MICROSOFTEDGEUPDATE.EXE-71600A40.pf          SCHTASKS.EXE-DC1676CD.pf                    TASKHOSTW.EXE-2E5D4B75.pf
 MICROSOFTEDGEUPDATE.EXE-7A595326.pf          SEARCHAPP.EXE-0848CA88.pf                   TASKKILL.EXE-BE180FC8.pf
 MICROSOFTEDGEUPDATESETUP_X86_-D9400B82.pf    SEARCHAPP.EXE-52924D3F.pf                   TASKMGR.EXE-4C8500BA.pf
 MICROSOFTEDGE_X64_124.0.2478.-8B2A5085.pf    SEARCHAPP.EXE-86067E5D.pf                   TEAMS.EXE-738C39C6.pf
 MICROSOFTEDGE_X64_124.0.2478.-D08ACD7F.pf    SEARCHAPP.EXE-D91D826A.pf                   TEXTINPUTHOST.EXE-B983F932.pf
 MICROSOFTEDGE_X64_125.0.2535.-136BADA2.pf    SEARCHAPP.EXE-F2D79AF9.pf                   TEXTINPUTHOST.EXE-BA8181DE.pf
 MMC.EXE-1EE19326.pf                          SEARCHFILTERHOST.EXE-44162447.pf            TEXTINPUTHOST.EXE-CAB6150D.pf
 MMC.EXE-3CD6519F.pf                          SEARCHPROTOCOLHOST.EXE-69C456C3.pf          TEXTINPUTHOST.EXE-D143C5BE.pf
 MMC.EXE-8F0FB2DD.pf                          SECHEALTHUI.EXE-FAB65C18.pf                 TIWORKER.EXE-FBD79BD6.pf
 MMC.EXE-9132A9C0.pf                          SECURITYHEALTHHOST.EXE-06344EE9.pf          TRUSTEDINSTALLER.EXE-766EFF52.pf
 MMC.EXE-F964DB0C.pf                          SECURITYHEALTHSERVICE.EXE-91B5FB98.pf       UNINSTALL.EXE-73AE4314.pf
 MOBSYNC.EXE-B307E1CC.pf                      SECURITYHEALTHSYSTRAY.EXE-E527A4AE.pf       USEROOBEBROKER.EXE-65584ADF.pf
 MOFCOMP.EXE-5225C32D.pf                      SETUP-STUB.EXE-BC55E5D8.pf                  VCREDIST_X64.EXE-D5DBE3C6.pf
 MOUSOCOREWORKER.EXE-4429AC2B.pf              SETUP.EXE-2E3AFC99.pf                       VCREDIST_X86.EXE-A6BFCA90.pf
 MPCMDRUN.EXE-0D65F9B9.pf                     SETUP.EXE-43CF0111.pf                       VC_REDIST.X64.EXE-2F3BF276.pf
 MPCMDRUN.EXE-8EF8E35F.pf                     SETUP.EXE-76C18A3B.pf                       VC_REDIST.X86.EXE-5177144C.pf
 MPRECOVERY.EXE-4022B70F.pf                   SETUP.EXE-77DD8DC0.pf                       VMTOOLSD.EXE-90328040.pf
 MPSIGSTUB.EXE-910CFE09.pf                    SETUP64.EXE-6C6157AB.pf                     VSSVC.EXE-6C8F0C66.pf
 MSCORSVW.EXE-16B291C4.pf                     SGRMBROKER.EXE-32481FEB.pf                  WERFAULT.EXE-155C56CF.pf
 MSCORSVW.EXE-8CE1A322.pf                     SHELLEXPERIENCEHOST.EXE-655318BF.pf         WERMGR.EXE-F439C551.pf
 MSDT.EXE-D579957D.pf                         SHELLEXPERIENCEHOST.EXE-B3EF1F80.pf         WEVTUTIL.EXE-1E154F39.pf
 MSEDGE.EXE-37D25F9A.pf                       SIHCLIENT.EXE-98C47F6C.pf                   WINRAR-X64-621.EXE-C833BA3D.pf
 MSEDGE.EXE-37D25F9B.pf                       SIHOST.EXE-115B507F.pf                      WINRAR.EXE-BA8CDB31.pf
 MSEDGE.EXE-37D25F9C.pf                       SMARTSCREEN.EXE-EACC1250.pf                 WINSAT.EXE-C345C80B.pf
 MSEDGE.EXE-37D25F9D.pf                       SPPEXTCOMOBJ.EXE-7D45A1AB.pf                WINWORD.EXE-AB6EC2FA.pf
 MSEDGE.EXE-37D25F9E.pf                       SPPSVC.EXE-96070FE0.pf                      WLRMDR.EXE-A7C36FDD.pf
 MSEDGE.EXE-37D25FA2.pf                       STARTMENUEXPERIENCEHOST.EXE-DC9B8E9D.pf     WMIADAP.EXE-BB21CD77.pf
 MSIEXEC.EXE-8FFB1633.pf                      STARTMENUEXPERIENCEHOST.EXE-DF593AF9.pf     WMIPRVSE.EXE-E8B8DD29.pf
 MSIEXEC.EXE-CDBFC0F7.pf                      SVCHOST.EXE-09F4AEA4.pf                     WUAUCLT.EXE-5D573F0E.pf
 MSINFO32.EXE-C3C668DA.pf                     SVCHOST.EXE-117C4441.pf                     WWAHOST.EXE-2CFA09D4.pf
 MSMPENG.EXE-68B3170C.pf                      SVCHOST.EXE-19B557B1.pf

```

### Artifact Background

#### Event Logs

Event logs are becoming relatively routine with Sherlocks investigating Windows systems. The `SECURITY` logs from the DC will have authentication events, which is what will show Kerberoasting attempts.

The workstation has PowerShell logs, which will contain the content of PowerShell scripts and commands run on the workstation host.

#### Prefetch

Windows has a system feature called prefetch that is designed to improve the speed / efficiency of loading and executing programs. When a program runs for the first time, it stores information about all the files that are accessed in loading that file. This data is stored in `.pf` files so that on subsequent runs of that same binary, these files can be preloaded into memory.

The `.pf` file also stores metadata such as the file name, the run count, and access times.

### Tools

#### Event Logs

In [several previous Sherlocks](/tags#event-logs) I’ve shown processing Windows event logs using [EvtxECmd](https://github.com/EricZimmerman/evtx), which is a really solid tool that runs on Windows. For variety, I’ll use `evtx_dump` (from [omerbenamram’s evtx repo](https://github.com/omerbenamram/evtx)) to convert the event log files to JSON. This is nice because it’s a Python script so it runs on Linux.

To get it into a format that works with `jq`, I’ll need to make sure the output format is `jsonl`:

```

oxdf@hacky$ evtx_dump -o jsonl -t 1 -f SECURITY-DC.json SECURITY-DC.evtx
oxdf@hacky$ wc -l SECURITY-DC.json
293 SECURITY-DC.json

```

I’ll do the same for the PowerShell logs from the workstation:

```

oxdf@hacky$ evtx_dump -o jsonl -t 1 -f Powershell-Operational.json Powershell-Operational.evtx
oxdf@hacky$ wc -l Powershell-Operational.json
42 Powershell-Operational.json

```

#### Prefetch

The prefetch files are a binary format as well, and processing them since Windows 10 requires specific Windows APIs that seem to prevent processing on Linux. I’ll use [PECmd](https://github.com/EricZimmerman/PECmd) (also from Eric Zimmerman) to process these files. It has options to process folders of files, but I find for most cases it’s easier to figure out which file I want details on and run it on that file. The output looks like:

```

PS > PECmd.exe -f .\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf
PECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/PECmd

Command line: -f .\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf

Warning: Administrator privileges not found!

Keywords: temp, tmp

Processing .\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf

Created on: 2024-06-21 01:16:48
Modified on: 2023-03-09 09:22:23
Last accessed on: 2024-06-23 11:41:12

Executable name: ACE2016-KB5002138-FULLFILE-X6
Hash: F6B4ABCD
File size (bytes): 32,882
Version: Windows 10 or Windows 11

Run count: 1
Last run: 2023-03-09 09:22:16

Volume information:

#0: Name: \VOLUME{01d951602330db46-52233816} Serial: 52233816 Created: 2023-03-08 01:48:53 Directories: 17 File references: 102

Directories referenced: 17

00: \VOLUME{01d951602330db46-52233816}\USERS
01: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD
02: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA
03: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA\LOCAL
04: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA\LOCAL\TEMP (Keyword True)
05: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA\LOCAL\TEMP\OWP3055.TMP (Keyword True)
06: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\DOWNLOADS
07: \VOLUME{01d951602330db46-52233816}\WINDOWS
08: \VOLUME{01d951602330db46-52233816}\WINDOWS\APPPATCH
09: \VOLUME{01d951602330db46-52233816}\WINDOWS\FONTS
10: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION
11: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION\SORTING
12: \VOLUME{01d951602330db46-52233816}\WINDOWS\REGISTRATION
13: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32
14: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US
15: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64
16: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\X86_MICROSOFT.WINDOWS.COMMON-CONTROLS_6595B64144CCF1DF_6.0.19041.1110_NONE_A8625C1886757984

Files referenced: 59

00: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NTDLL.DLL
01: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WOW64.DLL
02: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WOW64WIN.DLL
03: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\KERNEL32.DLL
04: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\KERNEL32.DLL
05: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\USER32.DLL
06: \VOLUME{01d951602330db46-52233816}\$MFT
07: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WOW64CPU.DLL
08: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\NTDLL.DLL
09: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\DOWNLOADS\ACE2016-KB5002138-FULLFILE-X64-GLB.EXE
10: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\KERNELBASE.DLL
11: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\LOCALE.NLS
12: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\APPHELP.DLL
13: \VOLUME{01d951602330db46-52233816}\WINDOWS\APPPATCH\SYSMAIN.SDB
14: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\OLEAUT32.DLL
15: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSVCP_WIN.DLL
16: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\UCRTBASE.DLL
17: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\COMBASE.DLL
18: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\RPCRT4.DLL
19: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\ADVAPI32.DLL
20: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSVCRT.DLL
21: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\SECHOST.DLL
22: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\OLE32.DLL
23: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\GDI32.DLL
24: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\WIN32U.DLL
25: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\GDI32FULL.DLL
26: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\USER32.DLL
27: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\IMM32.DLL
28: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\UXTHEME.DLL
29: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\KERNEL.APPCORE.DLL
30: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\BCRYPTPRIMITIVES.DLL
31: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WIN32KFULL.SYS
32: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\X86_MICROSOFT.WINDOWS.COMMON-CONTROLS_6595B64144CCF1DF_6.0.19041.1110_NONE_A8625C1886757984\COMCTL32.DLL
33: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINDOWSSHELL.MANIFEST
34: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\CABINET.DLL
35: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\VERSION.DLL
36: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSI.DLL
37: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\SHELL32.DLL
38: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\SHELL32.DLL.MUI
39: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\CLBCATQ.DLL
40: \VOLUME{01d951602330db46-52233816}\WINDOWS\REGISTRATION\R000000000006.CLB
41: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSXML3.DLL
42: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\BCRYPT.DLL
43: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\KERNELBASE.DLL.MUI
44: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSXML3R.DLL
45: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION\SORTING\SORTDEFAULT.NLS
46: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA\LOCAL\TEMP\OPATCHINSTALL(1).LOG (Keyword: True)
47: \VOLUME{01d951602330db46-52233816}\USERS\HAPPY.GRUNWALD\APPDATA\LOCAL\TEMP\OWP3055.TMP\EULA.TXT (Keyword: True)
48: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\MSCTF.DLL
49: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\USER32.DLL.MUI
50: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\SHCORE.DLL
51: \VOLUME{01d951602330db46-52233816}\WINDOWS\FONTS\STATICCACHE.DAT
52: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\TEXTSHAPING.DLL
53: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\TEXTINPUTFRAMEWORK.DLL
54: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\COREUICOMPONENTS.DLL
55: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\COREMESSAGING.DLL
56: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\WS2_32.DLL
57: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\NTMARTA.DLL
58: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSWOW64\WINTYPES.DLL
---------- Processed .\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch\ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf in 0.10303340 seconds ----------

```

## Domain Controller

### Kerberoasting Background

In a Kerberos environment, when a user wants to authenticate to a service, after the authenticate to the DC, they request a TGS from the DC for the service. The DC responds with a TGS that is encrypted with the NTLM hash of the password of the service account, so that when the user passes it to the service, it can decrypt and validate it.

Kerberoasting is requesting this TGS, but never passing it to the service, but rather taking that encrypted TGS offline to attempt brute force cracking, which can succeed if the password is weak.

ADSecurity has a nice [writeup](https://adsecurity.org/?p=3458) about it.

### Get 4769 Events

I’ll start with the event logs from the domain controller, and look at one log to get an understanding of the JSON format:

```

oxdf@hacky$ cat SECURITY-DC.json | head -1 | jq .
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "CommandLine": "",
      "MandatoryLabel": "S-1-16-16384",
      "NewProcessId": "0xac",
      "NewProcessName": "Registry",
      "ParentProcessName": "",
      "ProcessId": "0x4",
      "SubjectDomainName": "-",
      "SubjectLogonId": "0x3e7",
      "SubjectUserName": "-",
      "SubjectUserSid": "S-1-5-18",
      "TargetDomainName": "-",
      "TargetLogonId": "0x0",
      "TargetUserName": "-",
      "TargetUserSid": "S-1-0-0",
      "TokenElevationType": "%%1936"
    },
    "System": {
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Correlation": null,
      "EventID": 4688,
      "EventRecordID": 6417,
      "Execution": {
        "#attributes": {
          "ProcessID": 4,
          "ThreadID": 176
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 13312,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-05-21T03:05:08.700914Z"
        }
      },
      "Version": 2
    }
  }
}

```

The event Id is `.Event.System.EventID`. I’ll filter to just get ID 4769:

```

oxdf@hacky$ cat SECURITY-DC.json | jq 'select(.Event.System.EventID==4769)' -c | wc -l
16

```

By adding the `-c` to `jq`, it will output one log per line, so `wc -l` reports the number of logs remaining.

### Identify Kerberoasting

In a real environment, this would be a huge number, as every time a user authenticates to another system using Kerberos, which the article reports would typically be 10-20 requests per user per day. One way to look for Kerberoasting is to look for a high number of logs for a single user, but given the total of 16 here, that seems unlikely.

To filter further, based on the article above, I’ll look for the RC4 encryption type. Most systems will be using a stronger AES type, but an attacker (especially one who is going to try to crack a password using bruteforce) is going to ask the system to use the older and weaker RC4, which is type 0x17.

I’ll grab the first log and look at its structure:

```

oxdf@hacky$ cat SECURITY-DC.json | jq 'select(.Event.System.EventID==4769)' -c | head -1 | jq .
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "IpAddress": "::1",
      "IpPort": "0",
      "LogonGuid": "8ADC4D32-B1DC-937F-EFEC-0BDA6B606C42",
      "ServiceName": "DC01$",
      "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-1000",
      "Status": "0x0",
      "TargetDomainName": "FORELA.LOCAL",
      "TargetUserName": "DC01$@FORELA.LOCAL",
      "TicketEncryptionType": "0x12",
      "TicketOptions": "0x40810000",
      "TransmittedServices": "-"
    },
    "System": {
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Correlation": null,
      "EventID": 4769,
      "EventRecordID": 6461,
      "Execution": {
        "#attributes": {
          "ProcessID": 748,
          "ThreadID": 5268
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 14337,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-05-21T03:05:54.153123Z"
        }
      },
      "Version": 0
    }
  }
}

```

The encryption type is `.Event.EventData.TicketEncryptionType`, which I can filter on, leaving one log:

```

oxdf@hacky$ cat SECURITY-DC.json | jq '. | select(.Event.System.EventID==4769 and .Event.EventData.TicketEncryptionType=="0x17")' -c | wc -l
1
oxdf@hacky$ cat SECURITY-DC.json | jq '. | select(.Event.System.EventID==4769 and .Event.EventData.TicketEncryptionType=="0x17")'
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "IpAddress": "::ffff:172.17.79.129",
      "IpPort": "58107",
      "LogonGuid": "59F3B9B1-65ED-A449-5AC0-8EA1F68478EE",
      "ServiceName": "MSSQLService",
      "ServiceSid": "S-1-5-21-3239415629-1862073780-2394361899-1105",
      "Status": "0x0",
      "TargetDomainName": "FORELA.LOCAL",
      "TargetUserName": "alonzo.spire@FORELA.LOCAL",
      "TicketEncryptionType": "0x17",
      "TicketOptions": "0x40800000",
      "TransmittedServices": "-"
    },
    "System": {
      "Channel": "Security",
      "Computer": "DC01.forela.local",
      "Correlation": null,
      "EventID": 4769,
      "EventRecordID": 6672,
      "Execution": {
        "#attributes": {
          "ProcessID": 748,
          "ThreadID": 5376
        }
      },
      "Keywords": "0x8020000000000000",
      "Level": 0,
      "Opcode": 0,
      "Provider": {
        "#attributes": {
          "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
          "Name": "Microsoft-Windows-Security-Auditing"
        }
      },
      "Security": null,
      "Task": 14337,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-05-21T03:18:09.459682Z"
        }
      },
      "Version": 0
    }
  }
}

```

The timestamp on that log is the time that the Kerberoasting attack occurred, 2024-05-21 03:18:09 (Task 1). The targeted service is MSSQLService (Task 2), and the workstation the attack came from is 172.17.79.129 (Task 3).

## Workstation

### PowerShell Logs

#### Events Overview

I’ll take a quick look at the event IDs in this log file:

```

oxdf@hacky$ cat Powershell-Operational.json | jq '.Event.System.EventID' | sort | uniq -c | sort -nr
     29 4104
      4 53504
      4 40962
      4 40961
      1 4100

```

[This Crowdstrike article](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/) about PowerShell event logging says that 4104 events:

> records the script block contents, but only the first time it is executed in an attempt to reduce log volume.

#### Launch PowerShell

The interesting data in this log is under `.Event.EventData`:

```

oxdf@hacky$ cat Powershell-Operational.json | jq 'select(.Event.System.EventID==4104)' -c | head -1 | jq .
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "EventData": {
      "MessageNumber": 1,
      "MessageTotal": 1,
      "Path": "",
      "ScriptBlockId": "168b7dc8-7258-417e-98cc-5f6329cc58ad",
      "ScriptBlockText": "powershell -ep bypass"
    },
    "System": {
      "Channel": "Microsoft-Windows-PowerShell/Operational",
      "Computer": "Forela-Wkstn001.forela.local",
      "Correlation": {
        "#attributes": {
          "ActivityID": "B6DF577B-AB2B-0004-136C-DFB62BABDA01"
        }
      },
      "EventID": 4104,                                                                                                                                                                                                "EventRecordID": 135,
      "Execution": {
        "#attributes": {
          "ProcessID": 7268,
          "ThreadID": 9220
        }
      },
      "Keywords": "0x0",
      "Level": 3,
      "Opcode": 15,
      "Provider": {
        "#attributes": {
          "Guid": "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
          "Name": "Microsoft-Windows-PowerShell"
        }
      },
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-21-3239415629-1862073780-2394361899-1104"
        }
      },
      "Task": 2,
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2024-05-21T03:16:29.811516Z"
        }
      },
      "Version": 1
    }
  }
}

```

The first log is the actor calling `powershell -ep bypass`.

#### Powerview

The second 4104 log is alonzo.spire loading PowerView.ps1 (Task 4), a script [from PowerSploit](https://github.com/PowerShellMafia/PowerSploit):

```

oxdf@hacky$ cat Powershell-Operational.json | jq 'select(.Event.System.EventID==4104)' -c | head -2 | tail -1 | jq '.Event.EventData'
{
  "MessageNumber": 1,
  "MessageTotal": 20,
  "Path": "C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1",
  "ScriptBlockId": "e90ab1bc-fef9-43b2-bf1c-9e9a265c7f24",
  "ScriptBlockText": "#requires -version 2\n\n<#\n\n    PowerSploit File: PowerView.ps1\n    Author: Will Schroeder (@harmj0y)\n    License: BSD 3-Clause\n    Required Dependencies: None\n    Optional Dependencies: None\n\n#>\n\n########################################################\n#\n# PSReflect code for Windows API access\n# Author: @mattifestation\n#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1\n#\n########################################################\n\nfunction New-InMemoryModule\n{\n<#\n    .SYNOPSIS\n\n        Creates an in-memory assembly and module\n\n        Author: Matthew Graeber (@mattifestation)\n        License: BSD 3-Clause\n        Required Dependencies: None\n        Optional Dependencies: None\n\n    .DESCRIPTION\n\n        When defining custom enums, structs, and unmanaged functions, it is\n        necessary to associate to an assembly module. This helper function\n        creates an in-memory module that can be passed to the 'enum',\n        'struct', and Add-Win32Type functions.\n\n    .PARAMETER ModuleName\n\n        Specifies the desired name for the in-memory assembly and module. If\n        ModuleName is not provided, it will default to a GUID.\n\n    .EXAMPLE\n\n        $Module = New-InMemoryModule -ModuleName Win32\n#>\n\n    Param\n    (\n        [Parameter(Position = 0)]\n        [ValidateNotNullOrEmpty()]\n        [String]\n        $ModuleName = [Guid]::NewGuid().ToString()\n    )\n\n    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()\n\n    ForEach ($Assembly in $LoadedAssemblies) {\n        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {\n            return $Assembly\n        }\n    }\n\n    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)\n    $Domain = [AppDomain]::CurrentDomain\n    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')\n    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)\n\n    return $ModuleBuilder\n}\n\n\n# A helper function used to reduce typing while defining function\n# prototypes for Add-Win32Type.\nfunction func\n{\n    Param\n    (\n        [Parameter(Position = 0, Mandatory = $True)]\n        [String]\n        $DllName,\n\n        [Parameter(Position = 1, Mandatory = $True)]\n        [String]\n        $FunctionName,\n\n        [Parameter(Position = 2, Mandatory = $True)]\n        [Type]\n        $ReturnType,\n\n        [Parameter(Position = 3)]\n        [Type[]]\n        $ParameterTypes,\n\n        [Parameter(Position = 4)]\n        [Runtime.InteropServices.CallingConvention]\n        $NativeCallingConvention,\n\n        [Parameter(Position = 5)]\n        [Runtime.InteropServices.CharSet]\n        $Charset,\n\n        [Switch]\n        $SetLastError\n    )\n\n    $Properties = @{\n        DllName = $DllName\n        FunctionName = $FunctionName\n        ReturnType = $ReturnType\n    }\n\n    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }\n    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }\n    if ($Charset) { $Properties['Charset'] = $Charset }\n    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }\n\n    New-Object PSObject -Property $Properties\n}\n\n\nfunction Add-Win32Type\n{\n<#\n    .SYNOPSIS\n\n        Creates a .NET type for an unmanaged Win32 function.\n\n        Author: Matthew Graeber (@mattifestation)\n        License: BSD 3-Clause\n        Required Dependencies: None\n        Optional Dependencies: func\n\n    .DESCRIPTION\n\n        Add-Win32Type enables you to easily interact with unmanaged (i.e.\n        Win32 unmanaged) functions in PowerShell. After providing\n        Add-Win32Type with a function signature, a .NET type is created\n        using reflection (i.e. csc.exe is never called like with Add-Type).\n\n        The 'func' helper function can be used to reduce typing when defining\n        multiple function definitions.\n\n    .PARAMETER DllName\n\n        The name of the DLL.\n\n    .PARAMETER FunctionName\n\n        The name of the target function.\n\n    .PARAMETER ReturnType\n\n        The return type of the function.\n\n    .PARAMETER ParameterTypes\n\n        The function parameters.\n\n    .PARAMETER NativeCallingConvention\n\n        Specifies the native calling convention of the function. Defaults to\n        stdcall.\n\n    .PARAMETER Charset\n\n        If you need to explicitly call an 'A' or 'W' Win32 function, you can\n        specify the character set.\n\n    .PARAMETER SetLastError\n\n        Indicates whether the callee calls the SetLastError Win32 API\n        function before returning from the attributed method.\n\n    .PARAMETER Module\n\n        The in-memory module that will host the functions. Use\n        New-InMemoryModule to define an in-memory module.\n\n    .PARAMETER Namespace\n\n        An optional namespace to prepend to the type. Add-Win32Type defaults\n        to a namespace consisting only of the name of the DLL.\n\n    .EXAMPLE\n\n        $Mod = New-InMemoryModule -ModuleName Win32\n\n        $FunctionDefinitions = @(\n          (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),\n          (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),\n          (func ntdll RtlGetCurrentPeb ([IntPtr]) @())\n        )\n\n        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'\n        $Kernel32 = $Types['kernel32']\n        $Ntdll = $Types['ntdll']\n        $Ntdll::RtlGetCurrentPeb()\n        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')\n        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')\n\n    .NOTES\n\n        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189\n\n        When defining multiple function prototypes, it is ideal to provide\n        Add-Win32Type with an array of function signatures. That way, they\n        are all incorporated into the same in-memory module.\n#>\n\n    [OutputType([Hashtable])]\n    Param(\n        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]\n        [String]\n        $DllName,\n\n        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]\n        [String]\n        $FunctionName,\n\n        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]\n        [Type]\n        $ReturnType,\n\n        [Parameter(ValueFromPipelineByPropertyName = $True)]\n        [Type[]]\n        $ParameterTypes,\n\n        [Parameter(ValueFromPipelineByPropertyName = $True)]\n        [Runtime.InteropServices.CallingConvention]\n        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,\n\n        [Parameter(ValueFromPipelineByPropertyName = $True)]\n        [Runtime.InteropServices.CharSet]\n        $Charset = [Runtime.InteropServices.CharSet]::Auto,\n\n        [Parameter(ValueFromPipelineByPropertyName = $True)]\n        [Switch]\n        $SetLastError,\n\n        [Parameter(Mandatory = $True)]\n        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]\n        $Module,\n\n        [ValidateNotNull()]\n        [String]\n        $Namespace = ''\n    )\n\n    BEGIN\n    {\n        $TypeHash = @{}\n    }\n\n    PROCESS\n    {\n        if ($Module -is [Reflection.Assembly])\n        {\n            if ($Namespace)\n            {\n                $TypeHash[$DllName] = $Module.GetType(\"$Namespace.$DllName\")\n            }\n            else\n            {\n                $TypeHash[$DllName] = $Module.GetType($DllName)\n            }\n        }\n        else\n        {\n            # Define one type for each DLL\n            if (!$TypeHash.ContainsKey($DllName))\n            {\n                if ($Namespace)\n                {\n                    $TypeHash[$DllName] = $Module.DefineType(\"$Namespace.$DllName\", 'Public,BeforeFieldInit')\n                }\n                else\n                {\n                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')\n                }\n            }\n\n            $Method = $TypeHash[$DllName].DefineMethod(\n                $FunctionName,\n                'Public,Static,PinvokeImpl',\n                $ReturnType,\n                $ParameterTypes)\n\n            # Make each ByRef parameter an Out parameter\n            $i = 1\n            ForEach($Parameter in $ParameterTypes)\n            {\n                if ($Parameter.IsByRef)\n                {\n                    [void] $Method.DefineParameter($i, 'Out', $Null)\n                }\n\n                $i++\n            }\n\n            $DllImport = [Runtime.InteropServices.DllImportAttribute]\n            $SetLastErrorField = $DllImport.GetField('SetLastError')\n            $CallingConventionField = $DllImport.GetField('CallingConvention')\n            $CharsetField = $DllImport.GetField('CharSet')\n            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }\n\n            # Equivalent to C# version of [DllImport(DllName)]\n            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])\n            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,\n                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),\n                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),\n                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))\n\n            $Method.SetCustomAttribute($DllImportAttribute)\n        }\n    }\n\n    END\n    {\n        if ($Module -is [Reflection.Assembly])\n        {\n            return $TypeHash\n        }\n\n        $ReturnTypes = @{}\n\n        ForEach ($Key in $TypeHash.Keys)\n        {\n            $Type = $TypeHash[$Key].CreateType()\n\n            $ReturnTypes[$Key] = $Type\n        }\n\n        return $ReturnTypes\n    }\n}\n\n\nfunction psenum\n{\n<#\n    .SYNOPSIS\n\n        Creates an in-memory enumeration for use in your PowerShell session.\n\n        Author: Matthew Graeber (@mattifestation)\n        License: BSD 3-Clause\n        Required Dependencies: None\n        Optional Dependencies: None\n     \n    .DESCRIPTION\n\n        The 'psenum' function facilitates the creation of enums entirely in\n        memory using as close to a \"C style\" as PowerShell will allow.\n\n    .PARAMETER Module\n\n        The in-memory module that will host the enum. Use\n        New-InMemoryModule to define an in-memory module.\n\n    .PARAMETER FullName\n\n        The fully-qualified name of the enum.\n\n    .PARAMETER Type\n\n        The type of each enum element.\n\n    .PARAMETER EnumElements\n\n        A hashtable of enum elements.\n\n    .PARAMETER Bitfield\n\n        Specifies that the enum should be treated as a bitfield.\n\n    .EXAMPLE\n\n        $Mod = New-InMemoryModule -ModuleName Win32\n\n        $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{\n            UNKNOWN =                  0\n            NATIVE =                   1 # Image doesn't require a subsystem.\n            WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.\n            WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.\n            OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.\n            POSIX_CUI =                7 # Image runs in the Posix character subsystem.\n            NATIVE_WINDOWS =           8 # Image is a native Win9x driver.\n            WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.\n            EFI_APPLICATION =          10\n            EFI_BOOT_SERVICE_DRIVER =  11\n            EFI_RUNTIME_DRIVER =       12\n            EFI_ROM =                  13\n            XBOX =                     14\n            WINDOWS_BOOT_APPLICATION = 16\n        }\n\n    .NOTES\n\n        PowerShell purists may disagree with the naming of this function but\n        again, this was developed in such a way so as to emulate a \"C style\"\n        definition as closely as possible. Sorry, I'm not going to name it\n        New-Enum. :P\n#>\n\n    [OutputType([Type])]\n    Param\n    (\n        [Parameter(Position = 0, Mandatory = $True)]\n        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]\n        $Module,\n\n        [Parameter(Position = 1, Mandatory = $True)]\n        [ValidateNotNullOrEmpty()]\n        [String]\n        $FullName,\n\n        [Parameter(Position = 2, Mandatory = $True)]\n        [Type]\n        $Type,\n\n        [Parameter(Position = 3, Mandatory = $True)]\n        [ValidateNotNullOrEmpty()]\n        [Hashtable]\n        $EnumElements,\n\n        [Switch]\n        $Bitfield\n    )\n\n    if ($Module -is [Reflection.Assembly])\n    {\n        return ($Module.GetType($FullName))\n    }\n\n    $EnumType = $Type -as [Type]\n\n    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)\n\n    if ($Bitfield)\n    {\n        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())\n        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())\n        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)\n    }\n\n    ForEach ($Key in $EnumElements.Keys)\n    {\n        # Apply the specified enum type to each element\n        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)\n    }\n\n    $EnumBuilder.CreateType()\n}\n\n\n# A helper function used to reduce typing while defining struct\n# fields.\nfunction field\n{\n    Param\n    (\n        [Parameter(Position = 0, Mandatory = $True)]\n        [UInt16]\n        $Position,\n\n        [Parameter(Position = 1, Mandatory = $True)]\n        [Type]\n        $Type,\n\n        [Parameter(Position = 2)]\n        [UInt16]\n        $Offset,\n\n        [Object[]]\n        $MarshalAs\n    )\n\n    @{\n        Position = $Position\n        Type = $Type -as [Type]\n        Offset = $Offset\n        MarshalAs = $MarshalAs\n    }\n}\n\n\nfunction struct\n{\n<#\n    .SYNOPSIS\n\n        Creates an in-memory struct for use in your PowerShell session.\n\n        Author: Matthew Graeber (@mattifestation)\n        License: BSD 3-Clause\n        Required Dependencies: None\n        Optional Dependencies: field\n\n    .DESCRIPTION\n\n        The 'struct' function facilitates the creation of structs entirely in\n        memory using as close to a \"C style\" as PowerShell will allow. Struct\n        fields are specified using a hashtable where each field of the struct\n        is comprosed of the order in which it should be defined, its .NET\n        type, and optionally, its offset and special marshaling attributes.\n\n        One of the features of 'struct' is that after your struct is defined,\n        it will come with a built-in GetSize method as well as an explicit\n        converter so that you can easily cast an IntPtr to the struct without\n        relying upon calling SizeOf and/or PtrToStructure in the Marshal\n        class.\n\n    .PARAMETER Module\n\n        The in-memory module that will host the struct. Use\n        New-InMemoryModule to define an in-memory module.\n\n    .PARAMETER FullName\n\n        The fully-qualified name of the struct.\n\n    .PARAMETER StructFields\n\n        A hashtable of fields. Use the 'field' helper function to ease\n        defining each field.\n\n    .PARAMETER PackingSize\n\n        Specifies the memory alignment of fields.\n\n    .PARAMETER ExplicitLayout\n\n        Indicates that an explicit offset for each field will be specified.\n\n    .EXAMPLE\n\n        $Mod = New-InMemoryModule -ModuleName Win32\n\n        $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{\n            DOS_SIGNATURE =    0x5A4D\n            OS2_SIGNATURE =    0x454E\n            OS2_SIGNATURE_LE = 0x454C\n            VXD_SIGNATURE =    0x454C\n        }\n\n        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{\n            e_magic =    field 0 $ImageDosSignature\n            e_cblp =     field 1 UInt16\n            e_cp =       field 2 UInt16\n            e_crlc =     field 3 UInt16\n            e_cparhdr =  field 4 UInt16\n            e_minalloc = field 5 UInt16\n            e_maxalloc = field 6 UInt16\n            e_ss =       field 7 UInt16\n            e_sp =       field 8 UInt16\n            e_csum =     field 9 UInt16\n            e_ip =       field 10 UInt16\n            e_cs =       field 11 UInt16\n            e_lfarlc =   field 12 UInt16\n            e_ovno =     field 13 UInt16\n            e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)\n            e_oemid =    field 15 UInt16\n            e_oeminfo =  field 16 UInt16\n            e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)\n            e_lfanew =   field 18 Int32\n        }\n\n        # Example of using an explicit layout in order to create a union.\n        $TestUnion = struct $Mod TestUnion @{\n            field1 = field 0 UInt32 0\n            field2 = field 1 IntPtr 0\n        } -ExplicitLayout\n\n    .NOTES\n\n        PowerShell purists may disagree with the naming of this function but\n        again, this was developed in such a way so as to emulate a \"C style\"\n        definition as closely as possible. Sorry, I'm not going to name it\n        New-Struct. :P\n#>\n\n    [OutputType([Type])]\n    Param\n    (\n        [Parameter(Position = 1, Mandatory = $True)]\n        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]\n        $Module,\n\n        [Parameter(Position = 2, Mandatory = $True)]\n        [ValidateNotNullOrEmpty()]\n        [String]\n        $FullName,\n\n        [Parameter(Position = 3, Mandatory = $True)]\n        [ValidateNotNullOrEmpty()]\n        [Hashtable]\n        $StructFields,\n\n        [Reflection.Emit.PackingSize]\n        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,\n\n        [Switch]\n        $ExplicitLayout\n    )\n\n    if ($Module -is [Reflection.Assembly])\n    {\n        return ($Module.GetType($FullName))\n    }\n\n    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,\n        Class,\n        Public,\n        Sealed,\n        BeforeFieldInit'\n\n    if ($ExplicitLayout)\n    {\n        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout\n    }\n    else\n    {\n        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout\n    }\n\n    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)\n    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]\n    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))\n\n    $Fields = New-Object Hashtable[]($StructFields.Count)\n\n    # Sort each field according to the orders specified\n    # Unfortunately, PSv2 doesn't have the luxury of the\n    # hashtable [Ordered] accelerator.\n    ForEach ($Field in $StructFields.Keys)\n    {\n        $Index = $StructFields[$Field]['Position']\n        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}\n    }\n\n    ForEach ($Field in $Fields)\n    {\n        $FieldName"
}

```

It turns out all the rest of the logs are logging that, as it’s a long script:

```

oxdf@hacky$ cat Powershell-Operational.json | jq 'select(.Event.System.EventID==4104) | .Event.EventData.Path'
""
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"
"C:\\Users\\alonzo.spire\\Downloads\\powerview.ps1"

```

I’ll grab the system time for these events, and the time PowerView was first executed was 2024-05-21T03:16:32 (Task 5):

```

oxdf@hacky$ cat Powershell-Operational.json | jq 'select(.Event.System.EventID==4104) | .Event.System.TimeCreated["#attributes"].SystemTime'
"2024-05-21T03:16:29.811516Z"
"2024-05-21T03:16:32.588340Z"
"2024-05-21T03:16:32.588383Z"
"2024-05-21T03:16:32.588419Z"
"2024-05-21T03:16:32.588444Z"
"2024-05-21T03:16:32.588454Z"
"2024-05-21T03:16:32.588465Z"
"2024-05-21T03:16:32.588477Z"
"2024-05-21T03:16:32.588488Z"
"2024-05-21T03:16:32.588504Z"
"2024-05-21T03:16:32.588530Z"
"2024-05-21T03:16:32.588540Z"
"2024-05-21T03:16:32.588551Z"
"2024-05-21T03:16:32.588563Z"
"2024-05-21T03:16:32.588574Z"
"2024-05-21T03:16:32.588584Z"
"2024-05-21T03:16:32.588595Z"
"2024-05-21T03:16:32.588607Z"
"2024-05-21T03:16:32.588618Z"
"2024-05-21T03:16:32.588630Z"
"2024-05-21T03:16:32.588635Z"
"2024-05-21T03:16:32.717034Z"
"2024-05-21T03:16:32.753612Z"
"2024-05-21T03:16:32.814810Z"
"2024-05-21T03:17:23.244295Z"
"2024-05-21T03:17:23.247474Z"
"2024-05-21T03:17:23.249475Z"
"2024-05-21T03:17:25.365161Z"
"2024-05-21T03:17:25.370783Z"

```

### Prefetch

There are 214 files in the prefetch directory. The file names for a prefetch file start with the name of the executable file that’s run, so it’s not too much to quickly scan through these looking for any of interest. Some that jump out as interesting:
- There’s some potentially legit activity like Excel and Office, Notepad and Notepad++, and the OBS video creation software.
- There’s interactive shell activity, both `cmd.exe` and `powershell.exe` (both the terminal and the ISE), which indicates either administrator or attacker activity. The same can be said for `regedit.exe` and `schtasks.exe`.
- `PSExec.exe` is a legit tool created by Windows, but it’s almost certainly an indicator of malicious activity.
- `Rubeus.exe` is a [Kerberos attack tool](https://github.com/GhostPack/Rubeus), with no legitimate purpose.

One of Rubeus’ features is Kerberoasting. I’ll look at that file in more detail with `PECmd.exe`:

```

PS C:\Users\David\OneDrive\CTFs\hackthebox-sherlocks\campfire-1\Triage\Workstation\2024-05-21T033012_triage_asset\C\Windows\prefetch> .\PECmd.exe -f .\RUBEUS.EXE-5873E24B.pf
PECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/PECmd

Command line: -f .\RUBEUS.EXE-5873E24B.pf

Keywords: temp, tmp

Processing .\RUBEUS.EXE-5873E24B.pf

Created on: 2024-06-21 01:14:59
Modified on: 2024-05-21 03:18:09
Last accessed on: 2024-06-21 11:34:41

Executable name: RUBEUS.EXE
Hash: 5873E24B
File size (bytes): 86,612
Version: Windows 10 or Windows 11

Run count: 1
Last run: 2024-05-21 03:18:08

Volume information:

#0: Name: \VOLUME{01d951602330db46-52233816} Serial: 52233816 Created: 2023-03-08 01:48:53 Directories: 56 File references: 178

Directories referenced: 56

00: \VOLUME{01d951602330db46-52233816}\USERS
01: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE
02: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA
03: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA\LOCAL
04: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA\LOCAL\MICROSOFT
05: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA\LOCAL\MICROSOFT\WINDOWS
06: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA\LOCAL\MICROSOFT\WINDOWS\SCHCACHE
07: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\DOWNLOADS
08: \VOLUME{01d951602330db46-52233816}\WINDOWS
09: \VOLUME{01d951602330db46-52233816}\WINDOWS\APPPATCH
10: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY
11: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64
12: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB
13: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\316B66BA76E2CD70541B5FE8161637C9
14: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\3C1AA73B881E6BA477ED577740A7F174
15: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\5983164F9D7F1CA6CC256F34D228E951
16: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM
17: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CONFIGURATION
18: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CONFIGURATION\B8B5C9FB1A2911BC4E5D61227582D346
19: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE
20: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\37015A99A98319366B5CEDF511CDD1A0
21: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\6ADC713F8E9E8F186B01F8874E15F2AE
22: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\74AC779A016E30BC0F93BA3CCA2AD203
23: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.DIRED13B18A9#
24: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.DIRED13B18A9#\86B1CBA18F7A9F9A325AF6F6E3E3076E
25: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.XML
26: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.XML\2BD389016ACA8E778638103F4F5087CC
27: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\7445C290449652FAF35238F59F3455CC
28: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\973E1112D6F1680B1DD72D4DB09184BF
29: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\D01F0DD1232223C5448941B6176C54AA
30: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION
31: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION\SORTING
32: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET
33: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY
34: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL
35: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.CONFIGURATION
36: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.CONFIGURATION\V4.0_4.0.0.0__B03F5F7F11D50A3A
37: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES
38: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES.PROTOCOLS
39: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES.PROTOCOLS\V4.0_4.0.0.0__B03F5F7F11D50A3A
40: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES\V4.0_4.0.0.0__B03F5F7F11D50A3A
41: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.XML
42: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.XML\V4.0_4.0.0.0__B77A5C561934E089
43: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\FRAMEWORK64
44: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\FRAMEWORK64\V4.0.30319
45: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\FRAMEWORK64\V4.0.30319\CONFIG
46: \VOLUME{01d951602330db46-52233816}\WINDOWS\REGISTRATION
47: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32
48: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US
49: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_NETFX4-CLRJIT_DLL_B03F5F7F11D50A3A_4.0.15840.287_NONE_1A35A15FB302C60C
50: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_NETFX4-CLR_DLL_B03F5F7F11D50A3A_4.0.15840.287_NONE_362561601DFBBAEB
51: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SMDIAGNOSTICS_B77A5C561934E089_4.0.15840.287_NONE_EE2D2E5ED9D8957B
52: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.CORE_B77A5C561934E089_4.0.15840.287_NONE_E397616FDE7AAC5F
53: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.IDENTITYMODEL_B77A5C561934E089_4.0.15840.287_NONE_6CF5491A6DE4EB2D
54: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.SERVICEMODEL.INTERNALS_31BF3856AD364E35_4.0.15840.287_NONE_7509A363347F8BAE
55: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM_B77A5C561934E089_4.0.15840.281_NONE_2A24A49B85D3F7C0

Files referenced: 109

00: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NTDLL.DLL
01: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE (Executable: True)
02: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\MSCOREE.DLL
03: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\KERNEL32.DLL
04: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\KERNELBASE.DLL
05: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\LOCALE.NLS
06: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\APPHELP.DLL
07: \VOLUME{01d951602330db46-52233816}\WINDOWS\APPPATCH\SYSMAIN.SDB
08: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\ADVAPI32.DLL
09: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\MSVCRT.DLL
10: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SECHOST.DLL
11: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\RPCRT4.DLL
12: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\BCRYPT.DLL
13: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\FRAMEWORK64\V4.0.30319\MSCOREEI.DLL
14: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SHLWAPI.DLL
15: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\KERNEL.APPCORE.DLL
16: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\VERSION.DLL
17: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_NETFX4-CLR_DLL_B03F5F7F11D50A3A_4.0.15840.287_NONE_362561601DFBBAEB\CLR.DLL
18: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\USER32.DLL
19: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WIN32U.DLL
20: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\VCRUNTIME140_1_CLR0400.DLL
21: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\GDI32.DLL
22: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\VCRUNTIME140_CLR0400.DLL
23: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\UCRTBASE_CLR0400.DLL
24: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\GDI32FULL.DLL
25: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\MSVCP_WIN.DLL
26: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\UCRTBASE.DLL
27: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\IMM32.DLL
28: \VOLUME{01d951602330db46-52233816}\$MFT
29: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\FRAMEWORK64\V4.0.30319\CONFIG\MACHINE.CONFIG
30: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\COMBASE.DLL
31: \VOLUME{01d951602330db46-52233816}\WINDOWS\GLOBALIZATION\SORTING\SORTDEFAULT.NLS
32: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\316B66BA76E2CD70541B5FE8161637C9\MSCORLIB.NI.DLL.AUX
33: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\3C1AA73B881E6BA477ED577740A7F174\MSCORLIB.NI.DLL.AUX
34: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\5983164F9D7F1CA6CC256F34D228E951\MSCORLIB.NI.DLL.AUX
35: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\MSCORLIB\5983164F9D7F1CA6CC256F34D228E951\MSCORLIB.NI.DLL
36: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\OLE32.DLL
37: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\OLEAUT32.DLL
38: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\RPCSS.DLL
39: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\BCRYPTPRIMITIVES.DLL
40: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_NETFX4-CLRJIT_DLL_B03F5F7F11D50A3A_4.0.15840.287_NONE_1A35A15FB302C60C\CLRJIT.DLL
41: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\7445C290449652FAF35238F59F3455CC\SYSTEM.NI.DLL.AUX
42: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\973E1112D6F1680B1DD72D4DB09184BF\SYSTEM.NI.DLL.AUX
43: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM\D01F0DD1232223C5448941B6176C54AA\SYSTEM.NI.DLL.AUX
44: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM_B77A5C561934E089_4.0.15840.281_NONE_2A24A49B85D3F7C0\SYSTEM.DLL
45: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.DIRED13B18A9#\86B1CBA18F7A9F9A325AF6F6E3E3076E\SYSTEM.DIRECTORYSERVICES.NI.DLL.AUX
46: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES\V4.0_4.0.0.0__B03F5F7F11D50A3A\SYSTEM.DIRECTORYSERVICES.DLL
47: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NTDSAPI.DLL
48: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WS2_32.DLL
49: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\CRYPTBASE.DLL
50: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SECUR32.DLL
51: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SSPICLI.DLL
52: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NETAPI32.DLL
53: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\LOGONCLI.DLL
54: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NETUTILS.DLL
55: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\CLBCATQ.DLL
56: \VOLUME{01d951602330db46-52233816}\WINDOWS\REGISTRATION\R000000000006.CLB
57: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\ACTIVEDS.DLL
58: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\ADSLDPC.DLL
59: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WLDAP32.DLL
60: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SXS.DLL
61: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\ACTIVEDS.TLB
62: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\ADSLDP.DLL
63: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\MSWSOCK.DLL
64: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WSHQOS.DLL
65: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WSHTCPIP.DLL
66: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WSHIP6.DLL
67: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\DNSAPI.DLL
68: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\IPHLPAPI.DLL
69: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\NSI.DLL
70: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\RASADHLP.DLL
71: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\FWPUCLNT.DLL
72: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\WLDAP32.DLL.MUI
73: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\DSPARSE.DLL
74: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\KERBEROS.DLL
75: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\MSASN1.DLL
76: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\CRYPTDLL.DLL
77: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.DIRECTORYSERVICES.PROTOCOLS\V4.0_4.0.0.0__B03F5F7F11D50A3A\SYSTEM.DIRECTORYSERVICES.PROTOCOLS.DLL
78: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CONFIGURATION\B8B5C9FB1A2911BC4E5D61227582D346\SYSTEM.CONFIGURATION.NI.DLL.AUX
79: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.CONFIGURATION\V4.0_4.0.0.0__B03F5F7F11D50A3A\SYSTEM.CONFIGURATION.DLL
80: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\CRYPTSP.DLL
81: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\RSAENH.DLL
82: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.XML\2BD389016ACA8E778638103F4F5087CC\SYSTEM.XML.NI.DLL.AUX
83: \VOLUME{01d951602330db46-52233816}\WINDOWS\MICROSOFT.NET\ASSEMBLY\GAC_MSIL\SYSTEM.XML\V4.0_4.0.0.0__B77A5C561934E089\SYSTEM.XML.DLL
84: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SHELL32.DLL
85: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WINDOWS.STORAGE.DLL
86: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WLDP.DLL
87: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SHCORE.DLL
88: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\PROFAPI.DLL
89: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\37015A99A98319366B5CEDF511CDD1A0\SYSTEM.CORE.NI.DLL.AUX
90: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\6ADC713F8E9E8F186B01F8874E15F2AE\SYSTEM.CORE.NI.DLL.AUX
91: \VOLUME{01d951602330db46-52233816}\WINDOWS\ASSEMBLY\NATIVEIMAGES_V4.0.30319_64\SYSTEM.CORE\74AC779A016E30BC0F93BA3CCA2AD203\SYSTEM.CORE.NI.DLL.AUX
92: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.CORE_B77A5C561934E089_4.0.15840.287_NONE_E397616FDE7AAC5F\SYSTEM.CORE.DLL
93: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\WINNLSRES.DLL
94: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\WINNLSRES.DLL.MUI
95: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\URLMON.DLL
96: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\IERTUTIL.DLL
97: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SRVCLI.DLL
98: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\PROPSYS.DLL
99: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE:ZONE.IDENTIFIER
100: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\VIRTDISK.DLL
101: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\FLTLIB.DLL
102: \VOLUME{01d951602330db46-52233816}\USERS\ALONZO.SPIRE\APPDATA\LOCAL\MICROSOFT\WINDOWS\SCHCACHE\FORELA.LOCAL.SCH
103: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\TZRES.DLL
104: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\EN-US\TZRES.DLL.MUI
105: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.IDENTITYMODEL_B77A5C561934E089_4.0.15840.287_NONE_6CF5491A6DE4EB2D\SYSTEM.IDENTITYMODEL.DLL
106: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SMDIAGNOSTICS_B77A5C561934E089_4.0.15840.287_NONE_EE2D2E5ED9D8957B\SMDIAGNOSTICS.DLL
107: \VOLUME{01d951602330db46-52233816}\WINDOWS\WINSXS\AMD64_SYSTEM.SERVICEMODEL.INTERNALS_31BF3856AD364E35_4.0.15840.287_NONE_7509A363347F8BAE\SYSTEM.SERVICEMODEL.INTERNALS.DLL
108: \VOLUME{01d951602330db46-52233816}\WINDOWS\SYSTEM32\SECURITY.DLL
---------- Processed .\RUBEUS.EXE-5873E24B.pf in 0.07824480 seconds ----------

```

It was last run at 2024-05-21 03:18:08 (Task 7). Looking at the files referenced, item 1 shows the full path to `rubeus.exe` is `C:\\USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE` (Task 6).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2024-05-21 03:16:32 | PowerView.ps1 Loaded | Workstation PowerShell Logs |
| 2024-05-21 03:18:08 | Rubeus.exe run | Prefetch |
| 2024-05-21 03:18:09 | Kerberoasting auth attempt | DC Security Logs |

### Question Answers
1. Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred?

   2024-05-21 03:18:09
2. What is the Service Name that was targeted?

   MSSQLService
3. It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation?
   172.17.79.129
4. Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network?

   powerview.ps1
5. When was this script executed?

   2024-05-21 03:16:32
6. What is the full path of the tool used to perform the actual kerberoasting attack?

   C:\Users\Alonzo.spire\Downloads\Rubeus.exe
7. When was the tool executed to dump credentials?

   2024-05-21 03:18:08