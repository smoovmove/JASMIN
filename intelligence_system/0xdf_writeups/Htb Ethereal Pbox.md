---
title: HTB: Ethereal Attacking Password Box
url: https://0xdf.gitlab.io/2019/03/09/htb-ethereal-pbox.html
date: 2019-03-09T13:46:30+00:00
tags: ctf, hackthebox, htb-ethereal, windows, pbox, freebasic, bruteforce, credentials, basic, source-code
---

![](https://0xdfimages.gitlab.io/img/ethereal-pbox-cover.png)For Ethereal, I found a DOS application, `pbox.exe`, and a `pbox.dat` file. These were associated with a program called PasswordBox, which was an early password manager program. To solve this box, most people likely just guessed the password, “password”. But what if I had needed to brute force it? The program was not friendly to taking input from stdin, or from running inside python. So I downloaded the source code, installed the FreeBasic compiler, and started hacking at the source until it ran in a way that I could brute force test 1000 passwords in 5 seconds. I’ll walk through my steps and thought process in this post.

## Prep

In order to create a modified pbox binary, I needed to figure out how to compile Basic. I’ll be working from my Kali box.

### Get Source

I got the source code from [here](https://sourceforge.net/projects/passwbox/files/pbox%20v0.11/), and unzip it:

```

root@kali# unzip pbox011-src.zip 
Archive:  pbox011-src.zip
  inflating: changes.txt
  inflating: license.txt
  inflating: pbox.bas
  inflating: pbox.ico
 extracting: pbox.png
  inflating: pbox.rc
  inflating: pbox.svg
  inflating: pbox.txt
  inflating: reprint.bi
  inflating: rijndael.bi
  inflating: throwmsg.bi
  inflating: wordwrap.bi

```

### Install FreeBasic

First, I’ll make sure I have all the prerequisites for the compiler:

```

apt install binutils gcc make lib{ncurses5,gpm,x11,xext,xpm,xrandr,xrender,gl1-mesa,ffi}-dev

```

Next, I’ll get the software from the [SourceForge page](https://sourceforge.net/projects/fbc/files/Binaries%20-%20Linux/). Decompress, and run the installer:

```

root@kali# tar xzf FreeBASIC-1.06.0-linux-x86_64.tar.gz

root@kali# ./install.sh
usage:
./install.sh -i [prefix]    install FB into prefix directory
./install.sh -u [prefix]    uninstall FB from prefix directory
(default prefix: /usr/local)

root@kali# ./install.sh -i
FreeBASIC compiler successfully installed in /usr/local

```

### Verify Compile

I’ll try to compile the software as is, before I start messing with it. Unfortunately, I get some errors:

```

root@kali# fbc pbox.bas 
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(209) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'T(x,y) = Asc(Mid$(text,(((y-1) Shl 2) + x),1))'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(215) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'T(y,x) = Asc(Mid$(text,(((y-1) Shl 2) + x),1))'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(235) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 's += Chr$(T(x,y))'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(247) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'ftext += Hex$(Asc(Mid$(convstr,i,1)),2)'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(259) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'f += Chr$(Val("&H"+Mid$(convstr,i,2)))'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(320) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'ptext += Chr$(0)'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(331) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'mtext = Mid$(ptext, ((i-1) Shl 4) + 1, 16)'
/media/sf_CTFs/hackthebox/ethereal-10.10.10.106/temp/rijndael.bi(339) error 148: Suffixes are only valid in -lang fb or deprecated or fblite in 'mtext = Mid$(ptext, ((i-1) Shl 4) + 1, 16)'

```

Looking at the man page for `fbc`, I see:

> ```

>   -lang name
>                 Select FB dialect: fb (default), deprecated, qb
>
> ```

I’ll try with `-lang deprecated`, and it works:

```

root@kali# fbc pbox.bas -lang deprecated
root@kali# ./pbox
Enter your master password: 

```

## pbox Overview

The `pbox` binary (in my case, elf) is pretty simple. I covered a bit of the overview in the [Ethereal walkthrough](/2019/03/09/htb-ethereal.html#password-box). After putting the `pbox.dat` file into `/root/.pbox.dat`, I can start the program, and it will prompt for the password:

```

root@kali# ./pbox
Enter your master password:

```

I can also run it with the `--dump` option, which will change some behavior once I know the password.

## Source Code Analysis

### Main Program

Other than analysis of VBA in Word document macros, I have no experience with Basic. I’m going to look through the source and see what I can figure out. I know there’s a prompt “Enter your master password:”, so I’ll search for that, and look around it. A bit up from that prompt, I see a comment (which apparently is `REM` and also `'` in Basic) that says `REM * * * Here begins the main program * * *`. That section looks like:

```

REM  * * *  Here begins the main program  * * *

DIM AS INTEGER x, SelectedEntry = 1, FirstDisplayedEntry = 1
DIM AS STRING LastKey

IF LEN(COMMAND(2)) > 0 THEN About()
IF LEN(COMMAND(1)) > 0 AND LCASE(COMMAND(1)) <> "--dump" THEN About()

ConfigFile = GetConfFile()
DebugOut("ConfigFile = " + ConfigFile)

SELECT CASE CheckDataFile()
  CASE 0
    PRINT "Invalid datafile. Program aborted."
    END(2)
  CASE -1
    PRINT "No database have been found. Your encrypted database will be initialised now."
    PRINT "The database will be stored at the following location:"
    PRINT GetConfFile()
    PRINT
    PRINT "Choose a master password: ";
    PassPhrase = GetText("", 30, 0)
    IF LEN(PassPhrase) = 0 THEN PRINT "Invalid master password! (can't be empty)." : END(1)
    PassPhrase = LEFT((PassPhrase & CHR(3,141,59,26,53,58,97,93,238,46,26,43,38,32,79,50,28,8)), 16)
    ModFlag = 1
  CASE 1
    PRINT "Enter your master password: ";
    PassPhrase = GetText("*", 30, 0)  ' Hash with "*", max 30 chars, EscapeChar not allowed
    PRINT ' Carriage return
    IF LEN(PassPhrase) = 0 THEN SLEEP 2000, 1 : PRINT "Password rejected." : END(1)
    PassPhrase = LEFT((PassPhrase & CHR(3,141,59,26,53,58,97,93,238,46,26,43,38,32,79,50,28,8)), 16)
    IF CheckPassPhrase() <> 1 THEN SLEEP 2000, 1 : PRINT "Password rejected." : END(1)
    LoadBox()
END SELECT

```

Here’s what I see that code doing:
1. Verifies the command line arguments, and if there are 2, or if there is 1 and it isn’t `--dump` then call `About()`. `COMMAND(#)` seems to refer to command line arguments.
2. Calls `CheckDataFile()` which presumably returns 0 for a bad file, -1 if it doesn’t exist, and 1 if it does.
3. Switches on the result of `CheckDataFile()`. In the case I’m interesting in, where the file exists, the return is one, and I’ll continue on that path.
4. Prints “Enter your master password: “.
5. Calls `GetText("*", 30, 0)` and store the result in `PassPhrase`. There’s a comment about hashing with “\*”, max 30 characters, and no escape chars. I’ll need to check what “hash” means here.
6. If the length of `PassPhrase` is 0, sleep for two seconds, print rejection message, and exit.
7. Append bytes to the end of the string, and then take the first 16 characters.
8. Call `CheckPassPhrase()`, and if it isn’t 1, then sleep for two seconds, print rejection message, and exit.
9. Call the `LoadBox()` function.

### CheckPassPhrase

The `CheckPassPhrase` function is a good place to start looking. Here it is:

```

FUNCTION CheckPassPhrase() AS BYTE
  REM Returns 1 if the Passphrase decrypted the file's header properly, 0 otherwise.
  DIM AS BYTE Result = 0
  DIM AS STRING LineBuff = SPACE(16), DecryptedHeader
  OPEN ConfigFile FOR BINARY AS #1
  GET #1, 13, LineBuff
  CLOSE #1
  DebugOut("Checking given password...")
  DecryptedHeader =  RIJNDAEL_Encrypt(LineBuff, PassPhrase, 2)
  DebugOut("DecryptedHeader = " + DecryptedHeader)
  IF LEFT(DecryptedHeader, 10) = "Monika <3 " THEN Result = 1
  RETURN Result
END FUNCTION

```

I think this function:
1. Creates a 16 byte buffer of spaces.
2. Reads the first 13 bytes of the config file into that buffer.
3. Calls `RIJNDAEL_Encrypt`, giving it the buffer, the password, and the argument 2 (which I’ll guess means decrypt).
4. If the first ten characters of the decrypted header are “Monika <3 “, then it sets the return value to 1.

Were I better at crypto, I suspect it’d be really easy to write a brute forcer or even some kind of `pbox2john` like function. That’s not my best area, so I’ll leave that for now.

## Modifying the Code

### Password As Command Line Arg

I need some way to pass in the password automatically. In the original state, I can’t pass in command lines from a loop. I’m going to edit the code so that it takes the password as the argument.

#### GetText

Since I’m going to replace `GetText`, I want to make sure I know what it is returning. Since there’s a reference to hashing with “\*”, I could see that being some kind of mangling of the string, or just hiding the input from the screen with \*s. I’ll add a simple line immediately after it’s called to print it back to me:

```

    PassPhrase = GetText("*", 30, 0)  ' Hash with "*", max 30 chars, EscapeChar not allowed
    PRINT ' Carriage return -- 0xdf added
    PRINT PassPhrase ' -- 0xdf added
    PRINT ' Carriage return

```

Now when I run it, I’ll see that my input, `0xdf0xdf`, comes back:

```

root@kali# fbc -lang deprecated pbox.bas 
root@kali# ./pbox
Enter your master password: ********
0xdf0xdf

Password rejected.

```

Now that I understand the call, I’ll remove those two added lines.

#### Remove Check on Args

I’ll comment out the check that requires the first arg be nothing or `--dump` so that I can make that my password:

```

IF LEN(COMMAND(2)) > 0 THEN About()
REM IF LEN(COMMAND(1)) > 0 AND LCASE(COMMAND(1)) <> "--dump" THEN About()

```

#### Replace GetText with Arg

Next, I’m going to comment out the call to `GetText()`, and set `PassPhrase` to be `COMMAND(1)`, which seems to be the first arg passed in:

```

    REM PRINT "Enter your master password: ";
    REM PassPhrase = GetText("*", 30, 0)  ' Hash with "*", max 30 chars, EscapeChar not allowed
    PassPhrase = COMMAND(1)
    REM PRINT ' Carriage return

```

Now I can test:

```

root@kali# fbc -lang deprecated pbox.bas 
root@kali# time ./pbox 0xdf
Password rejected.

real    0m2.019s
user    0m0.000s
sys     0m0.007s

```

Success. I didn’t enter anything. It tested my input, failed, slept for two seconds, and exited.

### Remove the Sleeps

If I’m going to brute force on this code, I need to take out these sleeps. That’s easy enough. I’ll comment out the original lines with sleep and message, and add a line that just ends on bad password:

```

    REM IF LEN(PassPhrase) = 0 THEN SLEEP 2000, 1 : PRINT "Password rejected." : END(1)
    IF LEN(PassPhrase) = 0 THEN END(1)
    PassPhrase = LEFT((PassPhrase & CHR(3,141,59,26,53,58,97,93,238,46,26,43,38,32,79,50,28,8)), 16)
    REM IF CheckPassPhrase() <> 1 THEN SLEEP 2000, 1 : PRINT "Password rejected." : END(1)
    IF CheckPassPhrase() <> 1 THEN END(1)

```

Here’s my running the program, giving a blank password before and after that change:

```

root@kali# time ./pbox 0xdf

real    0m0.006s
user    0m0.003s
sys     0m0.000s

```

Perfect, it worked.

### Message On Success

Currently, I have a program that takes a password as a command line argument, and immediately and silently exits on failure. I just want to update what happens on success. Instead of loading the box, I just want it to print the password it found and exit.

```

    IF CheckPassPhrase() <> 1 THEN END(1)
    PRINT "Password Found: ", COMMAND(1)
    END(0)
    LoadBox()

```

I’ll print the password as the argument passed in instead of `PassPhrase` because the one gets things appended to it. I’ll also have it exit with a 0 for success, as opposed to the `END(1)` exits for the failures above.

## Brute Force It

### Success

Now I’ll write a bash loop to check. Since failure prints nothing, and success prints the password, I can do this:

```

root@kali# time for pass in $(cat /usr/share/seclists/Passwords/darkweb2017-top1000.txt); do ./pbox $pass; done
Password Found:             password

real    0m5.808s
user    0m1.593s
sys     0m1.096s

```

In under 6 seconds, it checks 1000 passwords.

### Better Success

But I can do better. Since the program returns 0 on success and 1 on failure, I can use that. I can use and (`&&`) and/or or (`||`) to chain commands together based on the return values.

Bash is weird in that a return value of 0 is success. So if I have `./a && ./b`, it will only run `./b` if `./a` returns success, which is 0.

I’ll add an `&& break` to my loop. If the program is successful (returns 0), the it will also run break and exit the loop. That way I don’t have to keep checking passwords after I find the right one.

Now I can run in less than 0.03 seconds:

```

root@kali# time for pass in $(cat /usr/share/seclists/Passwords/darkweb2017-top1000.txt); do ./pbox $pass && break; done
Password Found:             password

real    0m0.029s
user    0m0.011s
sys     0m0.004s

```

[« Ethereal Walkthrough](/2019/03/09/htb-ethereal.html)[Shell Development »](/2019/03/09/htb-ethereal-shell.html)