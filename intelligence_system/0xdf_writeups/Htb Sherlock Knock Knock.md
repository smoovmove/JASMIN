---
title: HTB Sherlock: Knock Knock
url: https://0xdf.gitlab.io/2023/12/04/htb-sherlock-knock-knock.html
date: 2023-12-04T16:00:00+00:00
difficulty: Medium
tags: ctf, dfir, forensics, sherlock-knock-knock, sherlock-cat-dfir, hackthebox, pcap, zeek, pcap-nmap, pcap-password-spray, port-knocking, knockd, pcap-port-knocking, ansible, gonnacry, htb-sherlock, ransomware
---

![i-like-to](/icons/sherlock-knock-knock.png)

Knock Knock is a Sherlock from HackTheBox that provides a PCAP for a ransomware incident. I’ll find where the attacker uses a password spray to compromise a publicly facing FTP server. In there, the attacker finds a configuration file for a port-knocking setup, and uses that to get access to an internal FTP server. On that server, they find lots of documents, including a reference to secrets on the company GitHub page. In that repo, the attacker found SSH creds, and used an SSH session to download GonnaCry ransomware using wget.

## Challenge Info

| Name | [Knock Knock](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fknock+knock)  [Knock Knock](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fknock+knock) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fknock+knock) |
| --- | --- |
| Release Date | 2023-11-13 |
| Retire Date | 2023-11-30 |
| Difficulty | Medium |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> A critical Forela Dev server was targeted by a threat group. The Dev server was accidentally left open to the internet which it was not supposed to be. The senior dev Abdullah told the IT team that the server was fully hardened and it’s still difficult to comprehend how the attack took place and how the attacker got access in the first place. Forela recently started its business expansion in Pakistan and Abdullah was the one IN charge of all infrastructure deployment and management. The Security Team need to contain and remediate the threat as soon as possible as any more damage can be devastating for the company, especially at the crucial stage of expanding in other region. Thankfully a packet capture tool was running in the subnet which was set up a few months ago. A packet capture is provided to you around the time of the incident (1-2) days margin because we don’t know exactly when the attacker gained access. As our forensics analyst, you have been provided the packet capture to assess how the attacker gained access.

From this scenario, I’ve made a few notes:
- The company’s name is Forela Dev.
- Internal service left internet accessible.
- Have PCAP from around the incident.

### Questions

To solve this challenge, I’ll need to answer the following 21 questions:
- Which ports did the attacker find open during their enumeration phase?
- What’s the UTC time when attacker started their attack against the server?
- What’s the MITRE Technique ID of the technique attacker used to get initial access?
- What are valid set of credentials used to get initial foothold?
- What is the Malicious IP address utilized by the attacker for initial access?
- What is name of the file which contained some config data and credentials?
- Which port was the critical service running?
- What’s the name of technique used to get to that critical service?
- Which ports were required to interact with to reach the critical service?
- What’s the UTC time when interaction with previous question ports ended?
- What are set of valid credentials for the critical service?
- At what UTC Time attacker got access to the critical server?
- What’s the AWS AccountID and Password for the developer “Abdullah”?
- What’s the deadline for hiring developers for forela?
- When did CEO of forela was scheduled to arrive in pakistan?
- The attacker was able to perform directory traversel and escape the chroot jail. This caused [the] attacker to roam around the filesystem just like a normal user would. What’s the username of an account other than root having /bin/bash set as default shell?
- What’s the full path of the file which lead to ssh access of the server by attacker?
- What’s the SSH password which attacker used to access the server and get full access?
- What’s the full url from where attacker downloaded ransomware?
- What’s the tool/util name and version which attacker used to download ransomware?
- What’s the ransomware name?

### Data

#### Download

The challenge gives a zip archive that unpacks to provide a single file named `Capture.pcap`. This is the packet capture mentioned in the description. It’s 265 MB in size, which is not small.

#### Zeek

Zeek (formerly Bro) is a network traffic monitoring and summarization tool. It can parse a PCAP into a series of log files that then become text parsable, allowing me to apply bash tools to them.

[This SANS ICS diary](https://isc.sans.edu/diary/PCAP+Data+Analysis+with+Zeek/29530) has solid installation instructions for Ubuntu 22.04. After installing, I’ll run it on the PCAP:

```

oxdf@hacky$ zeek -r Capture.pcap 
1679323066.027416 warning in /opt/zeek/share/zeek/base/misc/find-checksum-offloading.zeek, line 54: Your trace file likely has invalid TCP and UDP checksums, most likely from NIC checksum offloading.  By default, packets with invalid checksums are discarded by Zeek unless using the -C command-line option or toggling the 'ignore_checksums' variable.  Alternatively, disable checksum offloading by the network adapter to ensure Zeek analyzes the actual checksums that are transmitted.
oxdf@hacky$ ls
analyzer.log  dpd.log       knockknock.zip     smtp.log    weird.log
Capture.pcap  files.log     ntp.log            snmp.log
conn.log      ftp.log       packet_filter.log  ssh.log
dhcp.log      http.log      reporter.log       ssl.log
dns.log       kerberos.log  sip.log            tunnel.log

```

That warning is a problem. It means a bunch of the data didn’t process. I’ll re-run with the `-C` flag as it suggests. I’ll also add `local` and `extract-all-files.zeek`. `local` tells it to use the profile defined in `/opt/zeek/share/zeek/site/local.zeek` (may be in a different location based on how you installed). I can also add `extract-all-files.zeek` to that to always run it, or pass it in directly as I do here:

```

oxdf@hacky$ zeek -C -r Capture.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek local
1679335945.618089 error in /opt/zeek/share/zeek/policy/protocols/ssh/geo-data.zeek, line 30: Failed to open GeoIP location database (lookup_location(SSH::lookup_ip))
oxdf@hacky$ ls
analyzer.log      conn.log  dpd.log        ftp.log       known_hosts.log     notice.log         reporter.log  snmp.log      ssl.log        tunnel.log
capture_loss.log  dhcp.log  extract_files  http.log      known_services.log  ntp.log            sip.log       software.log  stats.log      weird.log
Capture.pcap      dns.log   files.log      kerberos.log  loaded_scripts.log  packet_filter.log  smtp.log      ssh.log       telemetry.log  x509.log

```

There’s an `extracted_files` directory with a bunch of files, and more logs, which will be useful for my analysis.

### Strategy

From here, I will work through the PCAP and the Zeek logs to understand what happened. I’ll keep a timeline of events as well as the answers to the questions, both of which will be [at the end of this post](#results).

## PCAP Analysis

### Statistics

I’ll start by looking at the statistics on the capture (Wireshark under Statistics > Endpoints). There are 3,316 endpoints involved, though only a handful have more than 1000 packets, which is a good place to start:

![image-20231201150230295](/img/image-20231201150231772.png)

The Zeek logs show similar results:

```

oxdf@hacky$ cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -nr | head
  65694 3.109.209.43
   8023 172.31.39.46
   1062 193.86.95.34
    932 120.78.199.189
    659 89.248.163.73
    300 89.248.163.130
    250 3.9.12.146
    212 80.66.77.235
    209 36.103.235.133
    208 3.8.115.174
oxdf@hacky$ cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -nr | head
  83034 172.31.39.46
   5937 169.254.169.123
    170 172.31.0.2
    123 157.245.102.2
    123 103.146.168.7
    119 129.250.35.250
    114 91.189.94.4
    114 91.189.91.157
    114 185.125.190.58
    114 185.125.190.56

```

I’m using `zeek-cut` to pull certain columns from the data (in this case the client IP and server IP).

### Port Scan

I’ll filter to just look at this IP that’s at the top of the client list, `ip.addr==3.109.209.43`. The result shows a clear port scan starting at port 1 and working up sequentially:

![image-20231201150717127](/img/image-20231201150717127.png)

This is malicious activity, and thus the answer to Task 5 is 3.109.209.43.

The first packet to port 1 comes is the answer to Task 2: 21/03/2023 10:42:23.

I’ll set the filter to only show SYN/ACK packets, which means that the server replied trying to complete the TCP handshake (so the port is open). The filter `ip.addr==3.109.209.43 && tcp.flags.syn==1 && tcp.flags.ack==1` works nicely:

![image-20231201152223104](/img/image-20231201152223104.png)

After the scan, the attack enumerates the open ports a bit more. But the ones found open and answer to Task 1: 21,22,3306,6379,8086.

### Nmap Scan

Immediately after the port scan ends, there’s a very familiar pattern:

![image-20231201152745883](/img/image-20231201152745883.png)

The attacker pings and tries to contact the server on 80 and 443. This is how Nmap does a connection test. 80 and 443 aren’t open, but the ping reply is successful, so then `nmap` scans 22, 3306, 21, 8086, and 6379, getting SYN/ACKs from the server, to which `nmap` sends a reset (RST).

## FTP

### Brute Force

A few minutes after the `nmap` scan, there are a ton of connections from the attacker to FTP (TCP 21):

![image-20231201153520500](/img/image-20231201153520500.png)

Scrolling down a bit, I’ll start to see the username being sent, alonzo.spire:

![image-20231201153558623](/img/image-20231201153558623.png)

Then there’s a password brute force:

![image-20231201153626928](/img/image-20231201153626928.png)

Later, other users are attempted:

![image-20231201153848660](/img/image-20231201153848660.png)

Eventually there’s a successful login as tony.shephard with Summer2023! as the password (task 4):

![image-20231201153932984](/img/image-20231201153932984.png)

This attack of trying a few common passwords for each user is a “Password Spray”, which is [Mitre Attack ID T1110.003](https://attack.mitre.org/techniques/T1110/003/), the answer to task 3.

### Session

The FTP stream where the login is success can be viewed in Wireshark:

![image-20231201154643688](/img/image-20231201154643688.png)

Filtering on `ftp-data` in Wireshark shows the four packets sent:

![image-20231201155051476](/img/image-20231201155051476.png)

The `list -la` looks like the current working directory is a home directory:

![image-20231201155408448](/img/image-20231201155408448.png)

### Zeek

I can see the same stuff in Zeek. Zeek’s `ftp.log` shows information about the files collected:

```

oxdf@hacky$ cat ftp.log
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   ftp
#open   2023-12-07-18-06-27
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       user    password        command arg     mime_type       file_size       reply_code      reply_msg       data_channel.passive       data_channel.orig_h     data_channel.resp_h     data_channel.resp_p     fuid
#types  time    string  addr    port    addr    port    string  string  string  string  string  count   count   string  bool    addr    addr    port    string
1679395871.903261       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||53637|)T3.109.209.43    172.31.39.46    53637   -
1679395921.652407       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||7831|) T3.109.209.43    172.31.39.46    7831    Fa0KWK2iHXRixpf2J9
1679395923.445501       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||11365|)T3.109.209.43    172.31.39.46    11365   FiqIx63kGqtG7R5KB9
1679395923.447182       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        RETR    ftp://172.31.39.46/./.backup    -       265     226     Transfer complete.--       -       -       FgMmRQ11qkbBo3KqNd
1679396113.286100       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||63669|)T3.109.209.43    172.31.39.46    63669   FgMmRQ11qkbBo3KqNd
1679396113.287739       CXOOQb1Hdo6U5QMZAj      3.109.209.43    44880   172.31.39.46    21      tony.shephard   <hidden>        RETR    ftp://172.31.39.46/./fetch.sh   -       356     226     Transfer complete.--       -       -       FFyvQZ69UFh3EsEbj
1679396406.851084       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||23640|)T3.109.209.43    172.31.39.46    23640   -
1679396527.285844       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||25381|)T3.109.209.43    172.31.39.46    25381   FWtDjnuy0GOUASEAg
1679396527.287519       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/./.archived.sql      text/plain      2091    226     Transfer complete. -       -       -       -       Fjikrz1twh8YRR8H34
1679396532.852260       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||35153|)T3.109.209.43    172.31.39.46    35153   Fjikrz1twh8YRR8H34
1679396536.064070       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||27862|)T3.109.209.43    172.31.39.46    27862   FAJx1l2H7YpPZsF1Ug
1679396536.065694       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/./Tasks to get Done.docx     application/vnd.openxmlformats-officedocument.wordprocessingml.document    28935   226     Transfer complete.      -       -       -       -       FYD8L514rIoyQiOZZ3
1679396543.073447       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||5488|) T3.109.209.43    172.31.39.46    5488    FYD8L514rIoyQiOZZ3
1679396543.075172       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/./reminder.txt       -       519     226     Transfer complete. -       -       -       -       FMuQD02uu7Nf3AdPpi
1679396560.664053       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||22200|)T3.109.209.43    172.31.39.46    22200   FMuQD02uu7Nf3AdPpi
1679396584.379999       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||54007|)T3.109.209.43    172.31.39.46    54007   Fi7asO1wzVS2y5ee3b
1679396598.521119       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||19174|)T3.109.209.43    172.31.39.46    19174   F6d0jy2IIr1I4qmzF6
1679396598.522802       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/etc/passwd   text/plain      2343    226     Transfer complete. -       -       -       -       Fb8qEb4LFMJ4PP6yOh
1679396610.475189       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||19414|)T3.109.209.43    172.31.39.46    19414   Fb8qEb4LFMJ4PP6yOh
1679396610.476812       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/etc/shadow   -       -       550     Failed to open file.       -       -       -       -       Fb8qEb4LFMJ4PP6yOh
1679396630.630833       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||65040|)T3.109.209.43    172.31.39.46    65040   Fb8qEb4LFMJ4PP6yOh
1679396640.242750       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||22648|)T3.109.209.43    172.31.39.46    22648   FpFSiq4Sl1xbR5ZVMe
1679396654.267022       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||54459|)T
3.109.209.43    172.31.39.46    54459   FYnEBz4EyMt8wML0J7
1679396667.137713       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||52097|)T3.109.209.43    172.31.39.46    52097   FSA97m44xq2llGJojb
1679396670.519514       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||54852|)T3.109.209.43    172.31.39.46    54852   FY0HSL1fRdkoFIMRl9
1679396670.521169       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/bin/whoami   application/x-sharedlib 31232   226     Transfer complete. -       -       -       -       Fv6EAh1PEsQFRoO2Xh
1679396680.259857       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||43521|)T3.109.209.43    172.31.39.46    43521   Fv6EAh1PEsQFRoO2Xh
1679396735.419532       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||24338|)T3.109.209.43    172.31.39.46    24338   Fh8sPB1zdy28bMtus9
1679396741.791571       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||26282|)T3.109.209.43    172.31.39.46    26282   FHEwgr40TbwFlZtzzf
1679396745.431320       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||45303|)T3.109.209.43    172.31.39.46    45303   FDgVfD14DpPrUJYkDb
1679396749.505440       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||8945|) T3.109.209.43    172.31.39.46    8945    FtH3Ew3QUWSSstOOC
1679396753.965890       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||43118|)T3.109.209.43    172.31.39.46    43118   FaOCR6JX7DrW2A5li
1679396758.428068       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||44249|)T3.109.209.43    172.31.39.46    44249   FaOCR6JX7DrW2A5li
1679396758.429599       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/../opt/reminders/.reminder   -       94      226     Transfer complete. -       -       -       -       FisvA2LfAacDxZ9E9
1679396764.769623       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||60306|)T3.109.209.43    172.31.39.46    60306   FisvA2LfAacDxZ9E9
1679396781.186361       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||63146|)T3.109.209.43    172.31.39.46    63146   FYvEiptXSVoefIHw1
1679396792.948245       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||21567|)T3.109.209.43    172.31.39.46    21567   FMd8Bz2RxiORSdHapa
1679396792.949884       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        RETR    ftp://172.31.39.46/../proc/cpuinfo      -       0       226     Transfer complete. -       -       -       -       FMd8Bz2RxiORSdHapa
1679396799.680395       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||61640|)T3.109.209.43    172.31.39.46    61640   FMd8Bz2RxiORSdHapa
1679396808.129324       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||5128|) T3.109.209.43    172.31.39.46    5128    F5WOui02Zc0ryFEGl
1679396845.677879       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||9861|) T3.109.209.43    172.31.39.46    9861    FKsf3LM5qkutXwtO6
1679396856.552867       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||52221|)T3.109.209.43    172.31.39.46    52221   F9qnGL19fXHUGzqn9a
1679396861.471794       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||42557|)T3.109.209.43    172.31.39.46    42557   FRiZID3nk40JCd3Bei
1679396869.665866       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||12509|)T3.109.209.43    172.31.39.46    12509   FIvODr45ZQpsCalxGf
1679396948.767685       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||34912|)T3.109.209.43    172.31.39.46    34912   FoAaIJPs6QdoqWILa
1679396963.821229       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||34156|)T3.109.209.43    172.31.39.46    34156   FsoTLZ2inNSP8OmOYa
1679396994.030393       CZJ10A2gmHD2NP52ok      3.109.209.43    38032   172.31.39.46    24456   abdullah.yasin  <hidden>        EPSV    -       -       -       229     Entering Extended Passive Mode (|||42434|)T3.109.209.43    172.31.39.46    42434   FsDmGu4itH7ndLTUth
#close  2023-12-07-18-06-31

```

There’s a ton there, so I’ll use `zeek-cut` to get fewer columns. I’ll also use `grep` to remove the `EPSV` “Entering Extended Passive Mode” commands:

```

oxdf@hacky$ cat ftp.log | grep -v EPSV | zeek-cut id.orig_h id.resp_h id.resp_p user command arg file_size fuid
3.109.209.43    172.31.39.46    21      tony.shephard   RETR    ftp://172.31.39.46/./.backup    265     FgMmRQ11qkbBo3KqNd
3.109.209.43    172.31.39.46    21      tony.shephard   RETR    ftp://172.31.39.46/./fetch.sh   356     FFyvQZ69UFh3EsEbj
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/./.archived.sql      2091    Fjikrz1twh8YRR8H34
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/./Tasks to get Done.docx     28935   FYD8L514rIoyQiOZZ3
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/./reminder.txt       519     FMuQD02uu7Nf3AdPpi
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/etc/passwd   2343    Fb8qEb4LFMJ4PP6yOh
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/etc/shadow   -       Fb8qEb4LFMJ4PP6yOh
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/bin/whoami   31232   Fv6EAh1PEsQFRoO2Xh
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/../opt/reminders/.reminder   94      FisvA2LfAacDxZ9E9
3.109.209.43    172.31.39.46    24456   abdullah.yasin  RETR    ftp://172.31.39.46/../proc/cpuinfo      0       FMd8Bz2RxiORSdHapa

```

I see two different sessions, tony.shephard logging into port 21, and abdullah.yasin logging into port 24456. I’ll come back to the seconds session in a bit. Focusing on the first:

```

oxdf@hacky$ cat ftp.log | grep -v -e EPSV -e abdullah.yasin | zeek-cut command arg file_size fuid
RETR    ftp://172.31.39.46/./.backup    265     FgMmRQ11qkbBo3KqNd
RETR    ftp://172.31.39.46/./fetch.sh   356     FFyvQZ69UFh3EsEbj

```

Each file is in `extracted_files`:

```

oxdf@hacky$ ls extract_files/ | grep -e FgMmRQ11qkbBo3KqNd -e FFyvQZ69UFh3EsEbj
extract-1679395923.447464-FTP_DATA-FgMmRQ11qkbBo3KqNd
extract-1679396113.288-FTP_DATA-FFyvQZ69UFh3EsEbj

```

### Files

I can view the streams in Wireshark or get the files from Zeek to get the full contents. `fetch.sh` gives some more credentials:

```

#!/bin/bash

# Define variables
DB_HOST="3.13.65.234"
DB_PORT="3306"
DB_USER="tony.shephard"
DB_PASSWORD="GameOfthronesRocks7865!"
DB_NAME="Internal_Tasks"
QUERY="SELECT * FROM Tasks;"

# Execute query and store result in a variable
RESULT=$(mysql -h $DB_HOST -P $DB_PORT -u $DB_USER -p$DB_PASSWORD $DB_NAME -e "$QUERY")

# Print the result
echo "$RESULT"

```

`.backup` looks like a port knocking config with more credentials at the bottom:

```

[options]
	UseSyslog

[FTP-INTERNAL]
	sequence    = 29999,50234,45087
	seq_timeout = 5
	command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 24456 -j ACCEPT
	tcpflags    = syn

# Creds for the other backup server abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad

```

This looks like a configuration file for [knockd](https://linux.die.net/man/1/knockd).

`.backup` is the answer to task 6.

This also provides information about what the questions keep referring to as the “critical service”. It is the service hidden behind the port-knocking “protection”.

Task 7 is the port that is opened, 24456.

Task 8 is the term “port knocking”.

Task 9 is the ports, though for some reason I have to arrange them in ascending order: 29999,45087,50234

I can probably get task 11 here as well, but I’ll wait until I see the creds work.

## Critical FTP

### Access

At 10:58:50, the attacker sends three packets to 29999, 50234, and then 45087. Then there’s a connection sent to 24456, and it responds with a SYN/ACK. The port is now open!

![image-20231201160842470](/img/image-20231201160842470.png)

For task 10, the port knocking ends at 21/03/2023 10:58:50.

Immediately after, there’s another `nmap` scan on 24456:

![image-20231201161154280](/img/image-20231201161154280.png)

### Login

This port hosts another FTP server. The attacker first accidentally logs in as tony.shephard:

![image-20231201161319120](/img/image-20231201161319120.png)

Followed by a long session where the actor successfully logs in with the creds from the port knocking config:

![image-20231201161523237](/img/image-20231201161523237.png)

This answers task 11, `abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad`.

![image-20231201161810291](/img/image-20231201161810291.png)

And task 12, as the time there is 21/03/2023 11:00:01.

This all matches with what I observed in the Zeek data previously.

### Session

To get a better look at the packets as FTP, I need to tell Wireshark that this is FTP data. I’ll find the first packet in the session (number 210788), and right click > Decode As…. I’ll set the “Current” value to FTP:

![image-20231201163243313](/img/image-20231201163243313.png)

Looking at the FTP stream the actor grabs a couple files:
- `.archived.sql`
- `Done.docx`
- `reminder.txt`

Then the attacker moves out of the home directory to the system root:

![image-20231201162523694](/img/image-20231201162523694.png)

Next they read `/etc/passwd`, and try to read `/etc/shadow`, but fail:

![image-20231201162602603](/img/image-20231201162602603.png)

Later they go into `/opt/reminders` and find a `.reminder` file:

![image-20231201162703666](/img/image-20231201162703666.png)

### Files

#### WireShark

Scrolling through the packets, I’ll find where files are requested.

![image-20231201163529183](/img/image-20231201163529183.png)

Here the attacker asks for `.archived.sql`. Then the server responds in the TCP stream between two high ports. Once that’s done, the FTP stream reports that the transfer is complete.

For `.archived.sql`, I can get the full file by following the TCP stream:

```
-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
--
-- Host: localhost    Database: AWS_SECRETS
-- ------------------------------------------------------
-- Server version	8.0.32-0ubuntu0.22.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
--
-- Table structure for table `AWS_EC2_DEV`
--

DROP TABLE IF EXISTS `AWS_EC2_DEV`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `AWS_EC2_DEV` (
  `NAME` varchar(40) DEFAULT NULL,
  `AccountID` varchar(40) DEFAULT NULL,
  `Password` varchar(60) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
--
-- Dumping data for table `AWS_EC2_DEV`
--

LOCK TABLES `AWS_EC2_DEV` WRITE;
/*!40000 ALTER TABLE `AWS_EC2_DEV` DISABLE KEYS */;
INSERT INTO `AWS_EC2_DEV` VALUES ('Alonzo','341624703104',''),(NULL,NULL,'d;089gjbj]jhTVLXEROP.madsfg'),('Abdullah','391629733297','yiobkod0986Y[adij@IKBDS');
/*!40000 ALTER TABLE `AWS_EC2_DEV` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
-- Dump completed on 2023-03-17 12:05:16

```

It’s a database dupmp, and it has the AWS EC2 keys for Abdullad.

Task 13 asks for the AWS ID and password: `391629733297:yiobkod0986Y[adij@IKBDS`.

The same pattern happens requesting `Done.docx` at 11:02:16. Viewing the file isn’t as useful in the stream follow, but I’ll switch “Show data as” to “raw”, and then click “Save as…”. It saves:

```

oxdf@hacky$ file Done.docx 
Done.docx: Microsoft Word 2007+

```

I’ll open it in Libre Office and it has an image with deadlines:

![image-20231201164236383](/img/image-20231201164236383.png)

The answer to task 14 is 30/08/2023.

Continuing through the files, there’s a `reminder.txt`:

![image-20231202135912963](/img/image-20231202135912963.png)

Task 15, the CEO arrives in Pakistan on 8 March 2023 - that’s 08/03/2023.

Continuing through the packets from the attacker, they change directories and download `/etc/passwd`:

![image-20231202140132024](/img/image-20231202140132024.png)

Viewing the stream, there’s one other user with a shell:

![image-20231202140210097](/img/image-20231202140210097.png)

Task 16 is cyberjunkie.

Immediately after, they try to download `/etc/shadow`, but fail:

![image-20231202140407155](/img/image-20231202140407155.png)

The attacker then moves around the file system trying to run commands like `whoami`, listing files, etc. Eventually they end up in `/opt/reminders` where they get this directory listing:

![image-20231202140553098](/img/image-20231202140553098.png)

Then they get that file:

![image-20231202140622546](/img/image-20231202140622546.png)

The file contents are:

> A reminder to clean up the github repo. Some sensitive data could have been leaked from there

The attacker then moves into `/proc` and reads the `cpuinfo`, looks around some other directories, and exits at 11:10:21 with the `QUIT` command.

#### Zeek

These files are also in the Zeek data:

```

oxdf@hacky$ cat ftp.log | grep -v -e EPSV -e tony.shephard | zeek-cut command arg file_size fuid
RETR    ftp://172.31.39.46/./.archived.sql      2091    Fjikrz1twh8YRR8H34
RETR    ftp://172.31.39.46/./Tasks to get Done.docx     28935   FYD8L514rIoyQiOZZ3
RETR    ftp://172.31.39.46/./reminder.txt       519     FMuQD02uu7Nf3AdPpi
RETR    ftp://172.31.39.46/etc/passwd   2343    Fb8qEb4LFMJ4PP6yOh
RETR    ftp://172.31.39.46/etc/shadow   -       Fb8qEb4LFMJ4PP6yOh
RETR    ftp://172.31.39.46/bin/whoami   31232   Fv6EAh1PEsQFRoO2Xh
RETR    ftp://172.31.39.46/../opt/reminders/.reminder   94      FisvA2LfAacDxZ9E9
RETR    ftp://172.31.39.46/../proc/cpuinfo      0       FMd8Bz2RxiORSdHapa

```

Just like above, I can find them in `extracted_files` by their `fuid`.

## GitHub

### Identify

`.reminder` had a reference to sensitive data in a GitHub repo. While HackTheBox machines and challenges are limited to their own space, Sherlocks allow for open source reconnaissance.

Searching GitHub for the name of the company, Forela Dev returns a couple repos:

![image-20231202150612806](/img/image-20231202150612806.png)

The one from Forela-finance was last committed to by CyberJunkie, the username that is the answer to task 16:

![image-20231202150717139](/img/image-20231202150717139.png)

### internal-dev.yaml

The file in this repo is an Ansible playbook:

![image-20231202234555538](/img/image-20231202234555538.png)

There are some SSH actions, but no passwords.

### Commits

There are 9 commits to this repo:

![image-20231202234647268](/img/image-20231202234647268.png)

Clicking on that shows the commits:

![image-20231202234703764](/img/image-20231202234703764.png)

Clicking on each shows the changes for that commit. The [first commit on 21 March](https://github.com/forela-finance/forela-dev/commit/ab04702b3269f016def0521a734380fb12596994) shows passwords being removed:

![image-20231202234822061](/img/image-20231202234822061.png)

That confirms that `/opt/reminders/.reminder` is the file that lead to the compromise (task 17).

The password used to access the server is YHUIhnollouhdnoamjndlyvbl398782bapd (task 18).

### SSH

At 11:25:42, there’s an SSH connection from the attacker to the exploited server:

![image-20231202235351630](/img/image-20231202235351630.png)

The last SSH packet from the attacker’s IP is at 11:49:17. I can’t see the encrypted session data. The fact that the session goes on for a bit indicates that the password worked. It seems likely that was using the password above.

## Ransomware

### Download

After the SSH session, there’s not any additional activity from the attacker’s IP. I’ll look at the traffic in the PCAP during the session to see what else might have happened with the attacker’s control. During that time, there’s only one HTTP request:

![image-20231204103219231](/img/image-20231204103219231.png)

`Ransomeware2_server.zip` is a suspect file name for sure, and the full URL is the answer to task 19, which is assembled using the stream:

![image-20231204103519555](/img/image-20231204103519555.png)

It’s also clear from the User Agent string that the download tool is `Wget/1.21.2`, which answers task 20.

There’s a log for this download in `http.log` as well:

```

oxdf@hacky$ cat http.log | grep -e "^#" -e Wget | zeek-cut method host uri resp_fuids 
GET     13.233.179.35   /PKCampaign/Targets/Forela/Ransomware2_server.zip       FM4a5p1MGD3XkvhPU7

```

When I use `zeek-cut`, it needs to have the Zeek headers in the file, which is why I `grep` for either lines starting with `#` or “Wget”. I’ve created an alias on my host for `zeek-grep`:

```

oxdf@hacky$ alias zeek-grep
alias zeek-grep='grep -e "^#" -e'
oxdf@hacky$ cat http.log | zeek-grep Wget | zeek-cut method host uri resp_fuids 
GET     13.233.179.35   /PKCampaign/Targets/Forela/Ransomware2_server.zip       FM4a5p1MGD3XkvhPU7

```

### File Analysis

#### Carve File

I can easily get the file from Zeek using the `fuid` from the previous command:

```

oxdf@hacky$ ls extract_files/*FM4a5p1MGD3XkvhPU7
extract_files/extract-1679398954.413587-HTTP-FM4a5p1MGD3XkvhPU7
oxdf@hacky$ file extract_files/extract-1679398954.413587-HTTP-FM4a5p1MGD3XkvhPU7
extract_files/extract-1679398954.413587-HTTP-FM4a5p1MGD3XkvhPU7: Zip archive data, at least v1.0 to extract, compression method=store

```

Before I figured out how to extract files with Zeek, I went through the pain of extracting this from the PCAP. For some reason, the file does not show up in the HTTP objects list. I had a few issues trying to export the file using the trick I used above. I’ll open the stream, and make sure to wait for all the packets to load. I might need to scroll down to trigger this. Even then the first time I did this the bottom showed “Content truncated”. I had to save the stream to its own PCAP and open it, and then it worked:

![image-20231204111843556](/img/image-20231204111843556.png)

I’ll click “Save as…” and save this as `ransomware.data`.

This isn’t actually the zip file:

```

oxdf@hacky$ file ransomware.data
ransomware.data: data

```

That’s because the HTTP response headers are at the start of the file:

![image-20231204112209972](/img/image-20231204112209972.png)

I’ll just open it in vim and delete the header lines down so the file starts with `PK`, save it as `ransomware.zip`, and it works:

```

oxdf@hacky$ file ransomware.zip 
ransomware.zip: Zip archive data, at least v1.0 to extract, compression method=store

```

I’ll unzip it with `unzip ransomware`, and the resulting directory is `Ransomware2_server`:

```

oxdf@hacky$ ls Ransomware2_server/
LICENSE  README.md  src  talks

```

#### Analysis

The `README.md` file starts with the name of the ransomware:

```

# GonnaCry Rasomware

Original Repository of the GonnaCry Ransomware.

GonnaCry is a linux ransomware that encrypts all the user files with a strong encryption scheme.

This project is OpenSource, feel free to use, study and/or send pull request.

[![Travis branch](https://img.shields.io/travis/rust-lang/rust/master.svg)](https://github.com/tarcisio-marinho/GonnaCry)
[![Travis branch](https://img.shields.io/cran/l/devtools.svg)](https://github.com/tarcisio-marinho/GonnaCry/blob/master/LICENSE)
[![Travis branch](https://img.shields.io/badge/made%20with-%3C3-red.svg)](https://github.com/tarcisio-marinho/GonnaCry)
[![Travis branch](https://img.shields.io/github/stars/tarcisio-marinho/GonnaCry.svg)](https://github.com/tarcisio-marinho/GonnaCry/stargazers)
-------------
**Ransomware Impact on industry**

https://medium.com/@tarcisioma/how-can-a-malware-encrypt-a-company-existence-c7ed584f66b3
**How this ransomware encryption scheme works:**

https://medium.com/@tarcisioma/ransomware-encryption-techniques-696531d07bb9
**How this ransomware works:**

https://0x00sec.org/t/how-ransomware-works-and-gonnacry-linux-ransomware/4594

https://medium.com/@tarcisioma/how-ransomware-works-and-gonnacry-linux-ransomware-17f77a549114
**Mentions:**

https://www.sentinelone.com/blog/sentinelone-detects-prevents-wsl-abuse/

https://hackingvision.com/2017/07/18/gonnacry-linux-ransomware/

https://www.youtube.com/watch?v=gSfa2L158Uw
-------------

# Disclaimer

This Ransomware mustn't be used to harm/threat/hurt other person's computer.

Its purpose is only to share knowledge and awareness about Malware/Cryptography/Operating Systems/Programming.

GonnaCry is an academic ransomware made for learning and awareness about security/cryptography.
**Be aware running C/bin/GonnaCry or Python/GonnaCry/main.py Python/GonnaCry/bin/gonnacry in your computer, it may harm.**
-------------

# What's a Ransomware?

A ransomware is a type of malware that prevents legitimate users from accessing
their device or data and asks for a payment in exchange for the stolen functionality.
They have been used for mass extortion in various forms, but the
most successful one seems to be encrypting ransomware: most of the user data are
encrypted and the key can be obtained paying the attacker.
To be widely successful a ransomware must fulfill three properties:
**Property 1**: The hostile binary code must not contain any secret (e.g. deciphering
keys). At least not in an easily retrievable form, indeed white box cryptography
can be applied to ransomware.
**Property 2**: Only the author of the attack should be able to decrypt the
infected device.
**Property 3**: Decrypting one device can not provide any useful information
for other infected devices, in particular the key must not be shared among them.
-------------

# Objectives:
- [x] encrypts all user files with AES-256-CBC.
- [x] Random AES key and IV for each file.
- [x] Works even without internet connection.
- [x] Communication with the server to decrypt Client-private-key.
- [x] encrypts AES key with client-public-key RSA-2048.
- [x] encrypts client-private-key with RSA-2048 server-public-key.
- [x] Changes computer wallpaper -> Gnome, LXDE, KDE, XFCE.
- [x] Decryptor that communicate to server to send keys.
- [x] python webserver
- [x] Daemon
- [ ] Dropper
- [x] Kills databases

```

This seems to be a copy of [this opensource academic project](https://github.com/tarcisio-marinho/GonnaCry).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 10:42:23 | Start of port scan | PCAP Analysis - Port Scan |
| 10:42:26 | End of port scan | PCAP Analysis - Port Scan |
| 10:42:26 | `nmap` host up check | PCAP Analysis - Port Scan |
| 10:49:43 | Start FTP brute force | FTP - Brute Force |
| 10:51:04 | Successful login: tony.shephard / Summer2023! | FTP - Brute Force |
| 10:51:11 | FTP List | FTP - Session |
| 10:52:03 | FTP get `.backup` | FTP - Session |
| 10:55:13 | FTP get `fetch.sh` | FTP - Session |
| 10:58:50 | Port Knocking | Critical FTP - Access |
| 10:59:28 | Start of failed FTP session | Critical FTP - Login |
| 11:00:01 | Successful login to Critical FTP | Critical FTP - Login |
| 11:02:07 | Downloads `.archived.sql` | Critical FTP - Files |
| 11:02:16 | Downloads `Done.docx` | Critical FTP - Files |
| 11:02:23 | Downloads `reminder.txt` | Critical FTP - Files |
| 11:03:18 | Downloads `/etc/passwd` | Critical FTP - Files |
| 11:03:30 | Fails to download `/etc/shadow` | Critical FTP - Files |
| 11:05:58 | Downloads `/opt/reminders/.reminder` | Critical FTP - Files |
| 11:10:21 | Exits Internal FTP session | Critical FTP - Files |
| 11:25:42 | SSH session from attacker starts | GitHub - SSH |
| 11:42:34 | HTTP download `Ransomeware2_server.zip` | Ransomware - Download |
| 11:49:17 | SSH session from attacker ends | GitHub - SSH |

### Question Answers
1. Which ports did the attacker find open during their enumeration phase?

   21,22,3306,6379,8086 (PCAP Analysis - Port Scan)
2. What’s the UTC time when attacker started their attack against the server?

   21/03/2023 10:42:23 (PCAP Analysis - Port Scan)
3. What’s the MITRE Technique ID of the technique attacker used to get initial access?

   T1110.003 (FTP - Brute Force)
4. What are valid set of credentials used to get initial foothold?

   tony.shephard:Summer2023! (FTP - Brute Force)
5. What is the Malicious IP address utilized by the attacker for initial access?
   3.109.209.43 (PCAP Analysis - Port Scan)
6. What is name of the file which contained some config data and credentials?

   `.backup` (FTP - Session)
7. Which port was the critical service running?

   24456 (FTP - Session)
8. What’s the name of technique used to get to that critical service?

   Port Knocking (FTP - Session)
9. Which ports were required to interact with to reach the critical service?

   29999,45087,50234 (FTP - Session)
10. What’s the UTC time when interaction with previous question ports ended?

    21/03/2023 10:58:50 (Critical FTP - Access)
11. What are set of valid credentials for the critical service?

    `abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad` (Critical FTP - Login)
12. At what UTC Time attacker got access to the critical server?

    21/03/2023 11:00:01` (Critical FTP - Login)
13. What’s the AWS AccountID and Password for the developer “Abdullah”?

    `391629733297:yiobkod0986Y[adij@IKBDS` (Critical FTP - Files)
14. What’s the deadline for hiring developers for forela?

    30/08/2023 (Critical FTP - Files)
15. When did CEO of forela was scheduled to arrive in pakistan?

    08/03/2023 (Critical FTP - Files)
16. The attacker was able to perform directory traversel and escape the chroot jail. This caused [the] attacker to roam around the filesystem just like a normal user would. What’s the username of an account other than root having /bin/bash set as default shell?

    cyberjunkie (Critical FTP - Files)
17. What’s the full path of the file which lead to ssh access of the server by attacker?

    /opt/reminders/.reminder (Critical FTP - Files / GitHub - Commits)
18. What’s the SSH password which attacker used to access the server and get full access?

    YHUIhnollouhdnoamjndlyvbl398782bapd (GitHub - Commits)
19. What’s the full url from where attacker downloaded ransomware?

    `http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_server.zip` (Ransomware - Download)
20. What’s the tool/util name and version which attacker used to download ransomware?

    `Wget/1.21.2` (Ransomware - Download)
21. What’s the ransomware name?

    GonnaCry (Ransomware - File Analysis)