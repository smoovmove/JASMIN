---
title: HTB Sherlock: Noted
url: https://0xdf.gitlab.io/2024/06/13/htb-sherlock-noted.html
date: 2024-06-13T09:00:00+00:00
difficulty: Easy
tags: htb-sherlock, forensics, sherlock-noted, dfir, ctf, hackthebox, notepad++, sherlock-cat-dfir
---

![Noted](/icons/sherlock-noted.png)

Noted is a quick Sherlock analysing the AppData directory associated with Notepad++. I’ll use the artifacts to recover the contents of two files, including a Java script used to collect files from the host for exfil. I’ll get the password for the pastes site containing the attacker information and some idea of the timeline over which the activity occurred.

## Challenge Info

| Name | [Noted](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnoted)  [Noted](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnoted) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnoted) |
| --- | --- |
| Release Date | 25 January 2024 |
| Retire Date | 13 June 2024 |
| Difficulty | Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> Simon, a developer working at Forela, notified the CERT team about a note that appeared on his desktop. The note claimed that his system had been compromised and that sensitive data from Simon’s workstation had been collected. The perpetrators performed data extortion on his workstation and are now threatening to release the data on the dark web unless their demands are met. Simon’s workstation contained multiple sensitive files, including planned software projects, internal development plans, and application codebases. The threat intelligence team believes that the threat actor made some mistakes, but they have not found any way to contact the threat actors. The company’s stakeholders are insisting that this incident be resolved and all sensitive data be recovered. They demand that under no circumstances should the data be leaked. As our junior security analyst, you have been assigned a specific type of DFIR (Digital Forensics and Incident Response) investigation in this case. The CERT lead, after triaging the workstation, has provided you with only the Notepad++ artifacts, suspecting that the attacker created the extortion note and conducted other activities with hands-on keyboard access. Your duty is to determine how the attack occurred and find a way to contact the threat actors, as they accidentally locked out their own contact information.

Notes from the scenario:
- Extortion note left on desktop of PC.
- Believed to be done in-person, not remotely.
- NotePad++ artifacts.
- Need to figure out how to contact attackers.

### Questions

To solve this challenge, I’ll need to answer the following 6 questions:
1. What is the full path of the script used by Simon for AWS operations?
2. The attacker duplicated some program code and compiled it on the system, knowing that the victim was a software engineer and had all the necessary utilities. They did this to blend into the environment and didn’t bring any of their tools. This code gathered sensitive data and prepared it for exfiltration. What is the full path of the program’s source file?
3. What’s the name of the final archive file containing all the data to be exfiltrated?
4. What’s the timestamp in UTC when attacker last modified the program source file?
5. The attacker wrote a data extortion note after exfiltrating data. What is the crypto wallet address to which attackers demanded payment?
6. What’s the email address of the person to contact for support?

### Artifact Background

#### Data

The download has a folder structure showing Simon.stark’s `AppData` folder for Notepad++ with four files in it:

```

oxdf@hacky$ unzip -l Noted.zip 
Archive:  Noted.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-01-31 16:54   Noted/
        0  2023-07-24 15:12   Noted/C/
        0  2023-07-24 15:12   Noted/C/Users/
        0  2023-07-24 15:12   Noted/C/Users/Simon.stark/
        0  2023-07-24 15:12   Noted/C/Users/Simon.stark/AppData/
        0  2023-07-24 15:12   Noted/C/Users/Simon.stark/AppData/Roaming/
        0  2023-12-02 01:25   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/
        0  2023-12-02 01:25   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/backup/
     3060  2023-07-24 15:05   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/backup/LootAndPurge.java@2023-07-24_145332
      713  2024-01-31 16:54   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/backup/YOU HAVE BEEN HACKED.txt@2023-07-24_150548
     8465  2023-07-24 15:10   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/config.xml
     1567  2023-07-24 15:10   Noted/C/Users/Simon.stark/AppData/Roaming/Notepad++/session.xml
---------                     -------
    13805                     12 files

```

#### Tools

Given all four files are text files, I’ll just be using a text editor.

## Analysis

### config.xml

The `config.xml` file has a combination of user settings as well as a updated history of files opened in NotePad++. At the top of the file is that history:

```

<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <FindHistory nbMaxFindHistoryPath="10" nbMaxFindHistoryFilter="10" nbMaxFindHistoryFind="10" nbMaxFindHistoryReplace="10" matchWord="no" matchCase="no" wrap="yes" directionDown="yes" fifRecuisive="yes" fifIn
HiddenFolder="no" fifProjectPanel1="no" fifProjectPanel2="no" fifProjectPanel3="no" fifFilterFollowsDoc="no" fifFolderFollowsDoc="no" searchMode="0" transparencyMode="1" transparency="150" dotMatchesNewline="no"
 isSearch2ButtonsMode="no" regexBackward4PowerUser="no" bookmarkLine="no" purge="no" />
    <History nbMaxFile="10" inSubMenu="no" customLength="-1">
        <File filename="C:\Program Files\Notepad++\change.log" />
        <File filename="C:\Users\Simon.stark\Documents\Internal-DesktopApp\Prototype-Internal_Login.cs" />
        <File filename="C:\Users\Simon.stark\Documents\Dev-WebServer-BetaProd\dev2prod_fileupload.php" />
        <File filename="C:\Users\Simon.stark\Documents\Internal-DesktopApp\App_init_validation.yml" />
        <File filename="C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl" />
    </History>  
...[snip]...

```

The files here seem to be legit files worked on by Simon.Stark. The one having to do with AWS operations is `migration.pl` (Task 1).

The rest of the file has the user’s config values, but nothing really interesting from a forensics point of view.

### session.xml

The `session.xml` file is much shorter. It defines the current state of NotePad++, including not only what files are open, but where their backups are saved and where in the file the view is scrolled to:

```

<?xml version="1.0" encoding="UTF-8" ?>
<NotepadPlus>
    <Session activeView="0">
        <mainView activeIndex="1">
            <File firstVisibleLine="21" xOffset="0" scrollWidth="848" startPos="1697" endPos="1697" selMode="0" offset="0" wrapCount="1" lang="Java" encoding="-1" userReadOnly="no" filename="C:\Users\Simon.stark\Desktop\LootAndPurge.java" backupFilePath="C:\Users\Simon.stark\AppData\Roaming\Notepad++\backup\LootAndPurge.java@2023-07-24_145332" originalFileLastModifTimestamp="-1354503710" originalFileLastModifTimestampHigh="31047188" tabColourId="-1" mapFirstVisibleDisplayLine="-1" mapFirstVisibleDocLine="-1" mapLastVisibleDocLine="-1" mapNbLine="-1" mapHigherPos="-1" mapWidth="-1" mapHeight="-1" mapKByteInDoc="512" mapWrapIndentMode="-1" mapIsWrap="no" />
            <File firstVisibleLine="0" xOffset="0" scrollWidth="1072" startPos="672" endPos="672" selMode="0" offset="0" wrapCount="1" lang="None (Normal Text)" encoding="-1" userReadOnly="no" filename="C:\Users\Simon.stark\Desktop\YOU HAVE BEEN HACKED.txt" backupFilePath="C:\Users\Simon.stark\AppData\Roaming\Notepad++\backup\YOU HAVE BEEN HACKED.txt@2023-07-24_150548" originalFileLastModifTimestamp="1536217129" originalFileLastModifTimestampHigh="31047190" tabColourId="-1" mapFirstVisibleDisplayLine="-1" mapFirstVisibleDocLine="-1" mapLastVisibleDocLine="-1" mapNbLine="-1" mapHigherPos="-1" mapWidth="-1" mapHeight="-1" mapKByteInDoc="512" mapWrapIndentMode="-1" mapIsWrap="no" />
        </mainView>
        <subView activeIndex="0" />
    </Session>
</NotepadPlus>

```

Both of the files from `backup` are present here, with more data about them. The source code used to collect and extract files is located at `C:\Users\Simon.stark\Desktop\LootAndPurge.java` (Task 2).

There are two values here that claim to be modification timestamps:

```

originalFileLastModifTimestamp="-1354503710" originalFileLastModifTimestampHigh="31047188"

```

[This forum post](https://community.notepad-plus-plus.org/topic/22662/need-explanation-of-a-few-session-xml-parameters-values) talks about how to convert these to a human readable timestamp. They are two 32-bit integers. `High` means to multiple that one by 232. The other shows as negative because it for some reason is handled as a signed int. I can convert it back to unsigned by adding 232.

```

>>> (31047188 * pow(2,32)) + (pow(2,32) - 1354503710)
133346660033227234

```

The [online converter](https://www.epochconverter.com/ldap) linked to in the forum post translates this to Monday, July 24, 2023 9:53:23 AM (Task 4):

![image-20240608173354170](/img/image-20240608173354170.png)

The other file is also on the Desktop, at `C:\Users\Simon.stark\Desktop\YOU HAVE BEEN HACKED.txt`. It’s lower word is positive, so I can simply multiple the high word and add:

```

>>> (31047190 * pow(2,32)) + (1536217129)
133346667218915369

```

![image-20240608175118026](/img/image-20240608175118026.png)

The note came about twelve minutes after the code was last modified.

### LootAndPurge.java@2023-07-24\_145332

#### Metadata

I’ll notice that the date / time after the filename is later than the last time this file was edited (as calculated above). I believe this is the last time that NotePad++ checked for changes and saved any. So for `LootAndPurge.java`, that would be at 14:53:32 (five hours after the last modification).

#### Contents

The contents are a Java file with a single class and four function:

```

java
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Sensitive_data_extort {
    public static void main(String[] args) {
       ...[snip]...
    }

    private static void collectFiles(File directory, List<String> extensions, List<File> collectedFiles) {
        ...[snip]...
    }

    private static String getFileExtension(String fileName) {
        ...[snip]...
    }

    private static void createZipArchive(List<File> files, String zipFilePath, String password) {
        ...[snip]...
    }
}

```

The `main` function gives a nice overview of what the file does:

```

    public static void main(String[] args) {                                                             
        String username = System.getProperty("user.name");      
        String desktopDirectory = "C:\\Users\\" + username + "\\Desktop\\";
        List<String> extensions = Arrays.asList("zip", "docx", "ppt", "xls", "md", "txt", "pdf");
        List<File> collectedFiles = new ArrayList<>();                      
                                                                                                         
        collectFiles(new File(desktopDirectory), extensions, collectedFiles);
                           
        String zipFilePath = desktopDirectory + "Forela-Dev-Data.zip";
        String password = "sdklY57BLghvyh5FJ#fion_7";        
                 
        createZipArchive(collectedFiles, zipFilePath, password);
                                             
        System.out.println("Zip archive created successfully at: " + zipFilePath);
    }        

```

It creates a list of all the files with certain file extensions in the user’s Desktop folder (or any subfolders) and puts them into a Zip archive named `Forela-Dev-Data.zip` (Task 3) on the user’s desktop with the password “sdklY57BLghvyh5FJ#fion\_7”.

I can verify that the functions `collectFiles` recursively gathers a list of files that match the list of extensions and that `createZipArchive` creates the archive with those files included.

### YOU HAVE BEEN HACKED.txt

#### Metadata

The date / time after the filename is the last time this file was edited. So in this case, `YOU HAVE BEEN HACKED.txt` was edited at 15:05:48 on 2023-07-24.

#### Contents

The file has the extortion note:

> HEllo
>
> This note is placed in your desktop and copied to other locations too. You have been hacked and your data has been deleted from your
> system. We made copies of your sensitive data and uploaded to our servers. The rule is simple
>
> ​ YOU PAY US
> ​ AND
> ​ WE DO NOT RELEASE YOUR COMPANY SECRETS TO PUBLIC AND RETURN YOUR DATA SAFELY TO YOU
>
> Failiure to oblige will result in immediate data leak to the public.
>
> For detailed information and process , Visit below link
>
> https://pastebin.com/CwhBVzPq
>
> OR
>
> https://pastes.io/mvc6sue6cf

#### Links

The first link has been taken down by Pastebin:

![image-20240608174640696](/img/image-20240608174640696.png)

I suspect when Noted released this was the only URL in the note, but when PasteBin took action, the download was updated.

The second link asks for a password:

![image-20240608174717279](/img/image-20240608174717279.png)

I’ll try the same password used for the Zip archive, and it works:

![image-20240608174755023](/img/image-20240608174755023.png)
- They want 50000 ETH or they will release the data.
- The wallet id is: 0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca (Task 5)
- The point of contact email is: CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion (Task 6)

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023-07-24 09:53:23 | Data collection program last edited | `session.xml` |
| 2023-07-24 10:05:21 | Extortion note last edited | `session.xml` |

### Question Answers
1. What is the full path of the script used by Simon for AWS operations?

   `C:\Users\Simon.stark\Documents\Dev_Ops\AWS_objects migration.pl`
2. The attacker duplicated some program code and compiled it on the system, knowing that the victim was a software engineer and had all the necessary utilities. They did this to blend into the environment and didn’t bring any of their tools. This code gathered sensitive data and prepared it for exfiltration. What is the full path of the program’s source file?

   `C:\Users\Simon.stark\Desktop\LootAndPurge.java`
3. What’s the name of the final archive file containing all the data to be exfiltrated?

   `Forela-Dev-Data.zip`
4. What’s the timestamp in UTC when attacker last modified the program source file?

   2023-07-24 09:53:23
5. The attacker wrote a data extortion note after exfiltrating data. What is the crypto wallet address to which attackers demanded payment?

   0xca8fa8f0b631ecdb18cda619c4fc9d197c8affca
6. What’s the email address of the person to contact for support?

   CyberJunkie@mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion