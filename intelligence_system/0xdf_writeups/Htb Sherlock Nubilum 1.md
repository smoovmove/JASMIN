---
title: HTB Sherlock: Nubilum-1
url: https://0xdf.gitlab.io/2024/05/30/htb-sherlock-nubilum-1.html
date: 2024-05-30T09:00:00+00:00
difficulty: Medium
tags: htb-sherlock, dfir, ctf, hackthebox, sherlock-nubilum-1, sherlock-cat-cloud, forensics, cloud, aws, cloudtrail, catscale, youtube, container, docker, python, s3, ec2, splunk, poshc2
---

![Nubilum-1](/icons/sherlock-nubilum-1.png)

Nublium-1 is all about cloud forensics, specifically a compromised AWS account that leads to multiple EC2 VM instances, including one acting as a PoshC2 server. I’ll work through the CloudTrail logs in a Splunk instance (run via Docker with video on setup), as well as CatScale logs and other forensic collection to show where the threat actor got credentials for the account, what they did in the cloud, and even identify a victim machine.

## Challenge Info

| Name | [Nubilum-1](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnubilum-1)  [Nubilum-1](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnubilum-1) [Play on HackTheBox](https://hacktheboxltd.sjv.io/g1jVD9?u=https%3A%2F%2Fapp.hackthebox.com%2Fsherlocks%2fnubilum-1) |
| --- | --- |
| Release Date | 30 November 2023 |
| Retire Date | 21 March 2024 |
| Difficulty | Medium |
| Category | Cloud Cloud |
| Creator | [sebh24 sebh24](https://app.hackthebox.com/users/118669) |

## Background

### Scenario

> Our cloud administration team recently received a warning from Amazon that an EC2 instance deployed in our cloud environment is being utilised for malicious purposes. Our sysadmin team have no recollection of deploying this EC2, however do recall logging onto the AWS console and finding in excess of 6 EC2s running, which he did not recall deploying.
>
> You have been provided with the interview with our Cloud sysadmin within the triage.

Notes from the scenario:
- EC2 (virtual machine in the cloud) is being abused.
- Our team didn’t deploy machine, or any of the 6 VMs running.
- I’m given an interview with the admin.

### Interview

One of the files in the data is `interview.txt`, and is important to understanding the remaining data.

The interview is as follows:

> **Incident Responder**: Can you tell me about the security measures you took after discovering the EC2 instances being launched randomly?
>
> **Cloud System Administrator**: Well, I deleted most of the running instances, with exception of the one potentially used for malicious purposes. I didn’t implement any other security measures.
>
> **Incident Responder**: Did you consider implementing any security measures such as multi-factor authentication or IP whitelisting to prevent similar incidents from happening in the future?
>
> **Cloud System Administrator**: No, I didn’t think about implementing any additional security measures at that time. I was focused on stopping the instances from launching and deleting the auto-scaling group.
>
> **Incident Responder**: I see. Can you also tell me about the S3 bucket you mentioned earlier? What kind of files do you store in it?
>
> **Cloud System Administrator**: Yes, we use the S3 bucket to store a variety of files including backups, static websites, and scripts. It’s an important part of our infrastructure and we access it frequently.
>
> **Incident Responder**: Where do you usually access either the AWS managemet console or AWS APIs from?
>
> **Cloud System Administrator**: We work from home and aren’t allowed to have any corporate VPNs on our corporate machines. We usually utilise any 86.5.206.X address.
>
> **Incident Responder**: Have you implemented any security measures for the S3 bucket?
>
> **Cloud System Administrator**: No, we haven’t. We want to ensure we can all access this bucket globally without auth.
>
> **Incident Responder**: I’d like you to work with our team to collect CloudTrail data and also a Phase 1 UNIX collection on the EC2 that may have been used for malicious purposes. Thank you.
>
> **Cloud System Administrator**: We have provided you the S3 bucket directories in /forela-storage/ & the P1 & CloudTrail collections.

Notes:
- Deleted all EC2 instances but the one that was being maliciously used immediately on discovery.
- Have not put any extra measures in place (2FA / IP allow-listing).
- S3 bucket has backups, websites, scripts and can be accessed globally without auth.
- Collecting CloudTrail logs as well as “Phase 1 UNIX” collection on the malicious EC2 instance.

### Data

There’s a ton of data:

```

oxdf@hacky$ unzip -l nubilum_1_int.zip
Archive:  nubilum_1_int.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
...[snip]...
---------                     -------
648774035                     13623 files

```

Decompressing it gives the interview and four types of artifacts:

```

oxdf@hacky$ ls nubilum_1_int
catscale_ip-172-31-24-20-20230130-1628.tar.gz  CloudTrail  forela-storage  interview.txt  unusual-directory.zip

```
- Cat-Scale logs - Information about what processes were run on a Linux system. This is part of the “Phase 1 UNIX collection” from the interview.
- CloudTrail Logs - Amazon cloud asset logs.
- The contents of the exposed S3 bucket (`forela-storage`).
- A directory found on the malicious VM. Also a part of the “Phase 1 UNIX collection”.

### Artifact Background

#### Cat-Scale

[Cat-Scale](https://labs.withsecure.com/tools/cat-scale-linux-incident-response-collection) is an incident response collection tool that pulls forensic data from a running Linux host via a Bash script that runs completely with native binaries.

To get to the output, I’ll decompress the archive and look at the structure it created:

```

oxdf@hacky$ tar -xzf catscale_ip-172-31-24-20-20230130-1628.tar.gz 
oxdf@hacky$ ls catscale_out/
Docker  ip-172-31-24-20-20230130-1628-console-error-log.txt  Logs  Misc  Persistence  Podman  Process_and_Network  System_Info  User_Files  Virsh

```

The post linked above does a nice job breaking down the different types of data:
- `Logs` - Full copy of `/var/log` as well as the output of `last`, `utmpdump`, `w`, and `who`.
- `Persistence` - Attempts to capture main persistence mechanisms used by threat actors.
- `Process_and_Network` - Running processes, SHA1 hashes of all binaries, links to open descriptors, memory maps, and `netstat` / `ss` data.
- `System_Info` - System information as well as key and recently changed `/etc` files.
- `User_Files` - All hidden files in `/home`.
- `Misc` - Potential webshells, timeline data, and other interesting collection.
- `Docker` / `Podman` / `Virsh` - virtualization-related data.

#### CloudTrail

[CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) is:

> an AWS service that helps you enable operational and risk auditing, governance, and compliance of your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. Events include actions taken in the AWS Management Console, AWS Command Line Interface, and AWS SDKs and APIs.

This is how AWS does logging. There are a bunch of different CloutTrail [Event Types](https://www.gorillastack.com/blog/real-time-events/cloudtrail-event-names/).

There are two types of log files in this collection:

```

oxdf@hacky$ ls CloudTrail/949622803460/
CloudTrail  CloudTrail-Digest

```

The Digest file are not useful to use at this time, so I’ll focus on the `CloudTrail` folder. There’s over eight thousand log files in this directory, all `.json` files:

```

oxdf@hacky$ find CloudTrail/949622803460/CloudTrail -type f | wc -l
8681
oxdf@hacky$ find CloudTrail/949622803460/CloudTrail -name '*.json' | wc -l
8681

```

### Tools

Most of this data I can handle from the Linux command line using Bash, text editing, `grep`, and other tools. To process the CloudTrail logs, I’m going to spin up an instance of Splunk. I’ll show how to make a Splunk Docker container and populate it with this data in [this video](https://www.youtube.com/watch?v=TG6zBnSgf5M):

## AWS Account Compromise

### S3 Bucket Triage

To see what was exposed, I’ll start in the files that were publicly available on the Forela S3 bucket. `forela-storage` has one folder, `backup`, which has:

```

oxdf@hacky$ ls
ec2.py  forela-cytopia-ansible.tar  forela-static-site-version1.tar  forela-static-site-version2.tar  forela-static-site-version3.tar  jenkins-forela-automation.tar  test.txt

```

`test.txt` is empty.

All of the `.tar` files are Docker images. For example:

```

oxdf@hacky$ tar tf forela-static-site-version1.tar 
31cd39dc731a382a1c525db3508ee53a52f29059ad02c1819363d9e4ea4723a5/
31cd39dc731a382a1c525db3508ee53a52f29059ad02c1819363d9e4ea4723a5/VERSION
31cd39dc731a382a1c525db3508ee53a52f29059ad02c1819363d9e4ea4723a5/json
31cd39dc731a382a1c525db3508ee53a52f29059ad02c1819363d9e4ea4723a5/layer.tar
3897cc63ef89526dccef521a40485962a1b9ad618f7f996f5c7746dcdeca326f/
3897cc63ef89526dccef521a40485962a1b9ad618f7f996f5c7746dcdeca326f/VERSION
3897cc63ef89526dccef521a40485962a1b9ad618f7f996f5c7746dcdeca326f/json
3897cc63ef89526dccef521a40485962a1b9ad618f7f996f5c7746dcdeca326f/layer.tar
551c5675a936ced73e6a206122451e18026db83f2fd04f48dc06a75caadb1323.json
7c46fd33f248d30476f03bb5e6a97155cdfff9e931d349377d3f3f6bbc0b23c7/
7c46fd33f248d30476f03bb5e6a97155cdfff9e931d349377d3f3f6bbc0b23c7/VERSION
7c46fd33f248d30476f03bb5e6a97155cdfff9e931d349377d3f3f6bbc0b23c7/json
7c46fd33f248d30476f03bb5e6a97155cdfff9e931d349377d3f3f6bbc0b23c7/layer.tar
aac21bbe1239c6da7f2bddf4daa80b2fa11fc7eee4c9f9d974560e3b7da22f13/
aac21bbe1239c6da7f2bddf4daa80b2fa11fc7eee4c9f9d974560e3b7da22f13/VERSION
aac21bbe1239c6da7f2bddf4daa80b2fa11fc7eee4c9f9d974560e3b7da22f13/json
aac21bbe1239c6da7f2bddf4daa80b2fa11fc7eee4c9f9d974560e3b7da22f13/layer.tar
beb4c267210679bd6d4bd1e56fdca329f54fcbc9a709764dbfbf3452ba68a1ab/
beb4c267210679bd6d4bd1e56fdca329f54fcbc9a709764dbfbf3452ba68a1ab/VERSION
beb4c267210679bd6d4bd1e56fdca329f54fcbc9a709764dbfbf3452ba68a1ab/json
beb4c267210679bd6d4bd1e56fdca329f54fcbc9a709764dbfbf3452ba68a1ab/layer.tar
d388b754d3eca0d520ee34aa44b5e84d8a892b963df16fbdcd7ddb73d1288c27/
d388b754d3eca0d520ee34aa44b5e84d8a892b963df16fbdcd7ddb73d1288c27/VERSION
d388b754d3eca0d520ee34aa44b5e84d8a892b963df16fbdcd7ddb73d1288c27/json
d388b754d3eca0d520ee34aa44b5e84d8a892b963df16fbdcd7ddb73d1288c27/layer.tar
e3e05b8bbe6a9a3bc5d25fd3f47668152afd75ba05ea77fecb6ea730f67cd622/
e3e05b8bbe6a9a3bc5d25fd3f47668152afd75ba05ea77fecb6ea730f67cd622/VERSION
e3e05b8bbe6a9a3bc5d25fd3f47668152afd75ba05ea77fecb6ea730f67cd622/json
e3e05b8bbe6a9a3bc5d25fd3f47668152afd75ba05ea77fecb6ea730f67cd622/layer.tar
f2210dd9ce0c863a057efdf73b359923001a1f957d167f8b55aa768a36b1dda7/
f2210dd9ce0c863a057efdf73b359923001a1f957d167f8b55aa768a36b1dda7/VERSION
f2210dd9ce0c863a057efdf73b359923001a1f957d167f8b55aa768a36b1dda7/json
f2210dd9ce0c863a057efdf73b359923001a1f957d167f8b55aa768a36b1dda7/layer.tar
manifest.json
repositories

```

This structure represents the different layers in an image.

`ec2.py` is a (broken) Python script.

### ec2.py

#### Script

This script is a (broken) Python script that intends to list the running EC2 instances under a given account and their region:

```

import boto3

# Replace with your own access key and secret
access_key = AKIA52GPOBQCO4SRMOWK
secret_key = txaF/m7lZnGQpppqCV4rCcsCvBHtlgtyE1BKBopb

# Create session
session = boto3.Session(
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_key
)

# Get all regions
client = session.client('ec2')
regions = [region['RegionName'] for region in client.describe_regions()['Regions']]

# Iterate over each region
for region in regions:
    # Connect to EC2 in this region
    ec2 = session.client('ec2', region_name=region)
    # Get all running instances
    instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    # Print the instances
    for reservation in instances[Reservations]:
        for instance in reservation[Instances]:
            print(f'Instance {instance[InstanceId]} is running in {region}')

```

It also leaks the `access_key` and `secret_key` for the administration of the AWS account (Task 2).

#### Bucket Access

I’ll add “ec2.py” as a filter in my search and it returns 32 events:

![image-20240528213811383](/img/image-20240528213811383.png)

Looking at the `eventName` for these events shows what’s happening:

[![image-20240524145642175](/img/image-20240524145642175.png)*Click for full size image*](/img/image-20240524145642175.png)

This query will show the S3 activity:

```

ec2.py | table eventName, eventTime, requestParameters.key, sourceIPAddress

```

The results show one IP address, 86.5.206.121, putting the object in place and another, 212.102.35.148, getting the object twice:

[![image-20240524150403405](/img/image-20240524150403405.png)*Click for full size image*](/img/image-20240524150403405.png)

The [whois](https://www.whois.com/whois/86.5.206.121) data for 86.5.206.121 is Virgin Media, a residential and mobile provider. I’ll confirm in the next section that this is likely the admin user.
212.102.35.148 is [owned by](https://www.whois.com/whois/212.102.35.148) [Datacamp](https://www.datacamp.co.uk/), a UK CDN. Given the interview, this IP is suspect. This IP only exists in three logs, once listing objects and then twice downloading `ec2.py`:

```

sourceIPAddress="212.102.35.148"
| stats count by eventName
| sort -count

```

![image-20240524151219628](/img/image-20240524151219628.png)

### Initial Access

I’ll click on “All Fields” and filter for any that contain the string “user”:

[![image-20240524141711962](/img/image-20240524141711962.png)*Click for full size image*](/img/image-20240524141711962.png)

I’ll “Select All Within Filter” to bring these to the main page. The `useridentity.arn` field is the one that gives a username:

[![image-20240524141840437](/img/image-20240524141840437.png)*Click for full size image*](/img/image-20240524141840437.png)

One of the fields loaded from the CloudTrail logs is `sourceIPAddress`:

[![image-20240524141354762](/img/image-20240524141354762.png)*Click for full size image*](/img/image-20240524141354762.png)

Given the description in the interview about how no one logs in over VPNs, I’ll look at the IPs for each account using this pipeline:

```
* | stats values(sourceIPAddress) as sourceIPAddresses by userIdentity.arn

```

Right away, there’s a bunch of private IPs:

[![image-20240528214108870](/img/image-20240528214108870.png)*Click for full size image*](/img/image-20240528214108870.png)

I can just ignore them manually, but it’s nice to be able to filter them out:

```

NOT (sourceIPAddress="10.0.0.0/8" OR sourceIPAddress="172.16.0.0/12" OR sourceIPAddress="192.168.0.0/16")
| stats values(sourceIPAddress) as sourceIPAddresses by userIdentity.arn

```

That gives:

[![image-20240524143239077](/img/image-20240524143239077.png)*Click for full size image*](/img/image-20240524143239077.png)
86.5.206.121 is the admin IP mentioned above.
95.181.232.0/24 is [owned by](https://www.whois.com/whois/95.181.232.4) M247 Europe, a commercial ISP that also handles a lot of VPN services. That definitely looks suspect, and it’s safe to say that the forela-ec2-automation account is the compromised one (Task 1). The threat actor IPs are identified as 95.181.232.4,95.181.232.8,95.181.232.9,95.181.232.28 (Task 9).

I’ll update my filter to show only the logs from these IPs:

```

sourceIPAddress="95.181.232.0/24"

```

Now 49 events remain:

[![image-20240528214211610](/img/image-20240528214211610.png)*Click for full size image*](/img/image-20240528214211610.png)

I can use `stats` with `min` and `max` to get the time window for this activity:

[![image-20240528214317630](/img/image-20240528214317630.png)*Click for full size image*](/img/image-20240528214317630.png)

## AWS Activity

### EventName Overview

I’ll continue with the filter on the attacker IPs and look at the different `eventName` values associated with it:

```

source="/data/*" host="053ec19ba969" sourceIPAddress="95.181.232.0/24"
| stats count by eventName
| sort -count

```

[![image-20240524151407232](/img/image-20240524151407232.png)*Click for full size image*](/img/image-20240524151407232.png)

These are the events undertaken by the threat actions from the IP range 95.181.232.0/24.

### Security Groups

There are two `eventNames` having to do with security groups, for six total events:

[![image-20240528215346207](/img/image-20240528215346207.png)*Click for full size image*](/img/image-20240528215346207.png)

The interesting one is the `CreateSecurityGroup` event:

[![image-20240528215531275](/img/image-20240528215531275.png)*Click for full size image*](/img/image-20240528215531275.png)

The actor successfully created a group named “1337” with a description of “still here” (Task 7).

### Security Group Rules / Ingress

There are three `eventName` types related to security group rules / ingress for 26 events. To get a quick timeline of events, I’ll look at them as a timeline:

```

sourceIPAddress=95.181.232.0/24 eventName=ModifySecurityGroupRules OR eventName=DescribeSecurityGroupRules OR eventName=AuthorizeSecurityGroupIngress
| table eventName, eventTime 
| sort eventTime

```

[![image-20240528220642969](/img/image-20240528220642969.png)*Click for full size image*](/img/image-20240528220642969.png)

I won’t go into these in detail here, but I will add them to the timeline for content.

### KeyPair Creation

There are two logs with the `CreateKeyPair` event name:

![image-20240528221539014](/img/image-20240528221539014.png)

The first event show a request for a key named `1337.key`:

[![image-20240528221655000](/img/image-20240528221655000.png)*Click for full size image*](/img/image-20240528221655000.png)

The second requests a key named `13337`:

[![image-20240528221746914](/img/image-20240528221746914.png)*Click for full size image*](/img/image-20240528221746914.png)

Data about the key pair generation solves three tasks, the names (Task 4), timestamps (Task 5), and ids (Task 6).

### Instance Creation

The Sherlock prompt specifically mentioned that this challenge is focused on malware discovered running on rogue EC2 instances. There are 8 `CreateInstances` events, responsible for the creation of 13 EC2 instances (Task 3):

```

sourceIPAddress=95.181.232.0/24 eventName=RunInstances
| table eventTime, requestParameters.instanceType, requestParameters.instancesSet.items{}.keyName, responseElements.instancesSet.items{}.instanceId
| sort eventTime

```

[![image-20240528223059110](/img/image-20240528223059110.png)*Click for full size image*](/img/image-20240528223059110.png)

The actor is using the two newly created keys for access.

### Instance Termination

With the threat actor’s IP as a filter, there are no `TerminateInstance` events. However, from the admin IP there are four events:

[![image-20240528224035492](/img/image-20240528224035492.png)*Click for full size image*](/img/image-20240528224035492.png)

The first two are before the attack began. The last two shutdown 12 of the 13 running instances, six at a time. The first time the admin shuts down attacker-generated EC2 instances is at 23:25 on 24 Jan (Task 8).

## VM Activity

### CatScale

As expected, the CatScale output has a bunch of different data:

```

oxdf@hacky$ ls
Docker  ip-172-31-24-20-20230130-1628-console-error-log.txt  Logs  Misc  Persistence  Podman  Process_and_Network  System_Info  User_Files  Virsh

```

There’s nothing in the virtualization folders. I don’t see much of interest in the `Misc` and `User_Files` folders. `Logs` has information about last logins. For example, this system was last booted on 2023-01-25 at 14:03:

```

oxdf@hacky$ cat Logs/ip-172-31-24-20-20230130-1628-who.txt
           system boot  2023-01-25 14:03
LOGIN      ttyS0        2023-01-25 14:03               683 id=tyS0
LOGIN      tty1         2023-01-25 14:03               685 id=tty1
           run-level 5  2023-01-25 14:03
ubuntu   + pts/0        2023-01-30 16:27   .         29650 (3.120.181.43)

```

I suspect the ubuntu login on 2023-01-30 is the IR team.

The `Persistence` directory has logs that show a service running `posh-server` (Task 10):

```

oxdf@hacky$ grep -B 3 -A 7 posh ip-172-31-24-20-20230130-1628-persistence-systemdlist.txt 
[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/posh-server

[Install]
WantedBy=default.target[Unit]
Description=Remove Stale Online ext4 Metadata Check Snapshots
ConditionCapability=CAP_SYS_ADMIN
ConditionCapability=CAP_SYS_RAWIO
Documentation=man:e2scrub_all(8)
oxdf@hacky$ grep posh ip-172-31-24-20-20230130-1628-systemctl_all.txt
poshc2.service                                 enabled         enabled 

```

In the processes and network folder, a file shows the command lines of running processes, which includes several PoshC2-related processes:

```

oxdf@hacky$ cat Process_and_Network/ip-172-31-24-20-20230130-1628-process-cmdline.txt | tr '\000' ' '
...[snip]...
==> /proc/11757/cmdline <==
/bin/bash /usr/local/bin/posh-server 
==> /proc/11766/cmdline <==
sudo python3 -m pipenv run python3 -u start.py --server 
==> /proc/11767/cmdline <==
sudo tee -a /var/poshc2/money/poshc2_server.log 
==> /proc/11768/cmdline <==
tee -a /var/poshc2/money/poshc2_server.log 
==> /proc/11769/cmdline <==
/root/.local/share/virtualenvs/PoshC2-KGSTtxLR/bin/python3 -u start.py --server 
...[snip]...

```

Just like the `cmdline` files in `/proc`, the arguments are null separated, which I’m replace with spaces using `tr`. Another file has the `environ` file for each process, where I can see PoshC2 is running as root:

```

oxdf@hacky$ cat Process_and_Network/ip-172-31-24-20-20230130-1628-process-environment.txt | tr '\000' ' '
...[snip]...
==> /proc/11757/environ <==
LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin HOME=/root LOGNAME=root USER=root SHELL=/bin/sh INVOCATION_ID=7aab7c87907d47e8a36a47fa0add8767 JOURNAL_STREAM=8:42935 
==> /proc/11766/environ <==
SHELL=/bin/sh PWD=/opt/PoshC2 LOGNAME=root HOME=/root LANG=C.UTF-8 INVOCATION_ID=7aab7c87907d47e8a36a47fa0add8767 USER=root SHLVL=0 JOURNAL_STREAM=8:42935 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/
sbin:/bin:/snap/bin OLDPWD=/ _=/usr/bin/sudo 
==> /proc/11767/environ <==
SHELL=/bin/sh PWD=/opt/PoshC2 LOGNAME=root HOME=/root LANG=C.UTF-8 INVOCATION_ID=7aab7c87907d47e8a36a47fa0add8767 USER=root SHLVL=0 JOURNAL_STREAM=8:42935 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin OLDPWD=/ _=/usr/bin/sudo 
==> /proc/11768/environ <==
LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin MAIL=/var/mail/root LOGNAME=root USER=root HOME=/root SHELL=/bin/bash TERM=unknown SUDO_COMMAND=/usr/bin/tee -a /var/poshc
2/money/poshc2_server.log SUDO_USER=root SUDO_UID=0 SUDO_GID=0 
==> /proc/11769/environ <==
LANG=C.UTF-8 PATH=/root/.local/share/virtualenvs/PoshC2-KGSTtxLR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin MAIL=/var/mail/root LOGNAME=root USER=root HOME=/root SHELL=/bin/bash T
ERM=unknown SUDO_COMMAND=/usr/bin/python3 -m pipenv run python3 -u start.py --server SUDO_USER=root SUDO_UID=0 SUDO_GID=0 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_PYTHON_PATH=/usr/bin/python3 PYTHONDONTWRITEBYTECODE=
1 VIRTUAL_ENV=/root/.local/share/virtualenvs/PoshC2-KGSTtxLR PIPENV_ACTIVE=1 
...[snip]...

```

### File Analysis

#### Overview

`unusual-directory.zip` has a `postc2` directory (Task 10 again). It has more files about the C2 instance:

```

oxdf@hacky$ ls
config-template.yml  CURRENT_PROJECT  money
oxdf@hacky$ cat CURRENT_PROJECT 
money

```

The `CURRENT_PROJECT` file is used to tell PoshC2 what the current project name is. Inside the `money` directory, there’s the files for the project:

```

oxdf@hacky$ ls
config.yml  downloads  payloads  poshc2_server.log  posh.crt  posh.key  PowershellC2.SQLite  quickstart.txt  reports  rewrite-rules.txt  webserver.log

```

`config.yml` has the current configuration:

```

# These options are loaded into the database on first run, changing them after
# that must be done through commands (such as set-defaultbeacon), or by
# creating a new project

# Server Config
BindIP: '0.0.0.0'
BindPort: 443

# Database Config
DatabaseType: "SQLite" # or Postgres
PostgresConnectionString: "dbname='poshc2_project_x' port='5432' user='admin' host='192.168.111.111' password='XXXXXXX'" # Only used if Postgres in use

# Payload Comms
PayloadCommsHost: "https://3.65.198.167" # "https://www.domainfront.com:443,https://www.direct.com"
DomainFrontHeader: ""  # "axpejfaaec.cloudfront.net,www.direct.com"
Referrer: ""  # optional
ServerHeader: "Apache"
UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36"  # This should be updated to match the environment, this is Chrome on 2020-03-2

DefaultSleep: "5s"
Jitter: 0.20
KillDate: "2999-12-01"  # yyyy-MM-dd
UrlConfig: "urls" # Beacon URLs will be taken from resources/urls.txt if value is 'urls'. If value is 'wordlist' beacon URLs will be randomly generated on server creation from resources/wordlist.txt

# Payload Options
PayloadStageRetries: true
PayloadStageRetriesInitialWait: 60 # Stager will retry after this many seconds, doubling the wait each time if it fails
PayloadStageRetriesLimit: 30 # Stager retry attempts before failing
DefaultMigrationProcess: "C:\\Windows\\system32\\netsh.exe"  # Used in the PoshXX_migrate.exe payloads
PayloadDomainCheck: "" # If non-empty then the UserDomain on the target will be checked and if it 'contains' this value then the payload will execute, else it will not.

# Notifications Options
NotificationsProjectName: "PoshC2"
EnableNotifications: "No"

# Pushover - https://pushover.net/
Pushover_APIToken: ""
Pushover_APIUser: ""

# Slack - https://slack.com/
Slack_BotToken: "" # The token used by the application to authenticate. Get it from https://[YourSlackName].slack.com/apps/A0F7YS25R (swap out [YourSlackName]). Should start with xobo-.
Slack_UserID: "" # Found under a users profile (i.e UHEJYT2AA). Can also be "channel".
Slack_Channel: "" # i.e #bots

# SOCKS Proxying Options
SocksHost: "http://127.0.0.1:49031" # The host the C2 http requests communicate with - not the port the SOCKS client connects to. Most cases should be left like this and set in rewrite rules.

# PBind Options
PBindPipeName: "jaccdpqnvbrrxlaf"
PBindSecret: "mtkn4"

# FComm Options
FCommFileName: "C:\\Users\\Public\\Public.ost"

# XOR key
XOR_KEY: "random_alphanum_key_goes_here"

```

This configuration is very generic, with only the host IP changed from the template:

```

oxdf@hacky$ diff config.yml ../config-template.yml 
14c14
< PayloadCommsHost: "https://3.65.198.167" # "https://www.domainfront.com:443,https://www.direct.com"
---
> PayloadCommsHost: "https://127.0.0.1" # "https://www.domainfront.com:443,https://www.direct.com"

```

#### Database

The `PowershellC2.SQLite` has information about the clients connecting to it in the `Implants` table:

```

sqlite> .headers on
sqlite> .tables                
AutoRuns      Creds         NewTasks      Tasks
C2Server      Hosted_Files  OpSec_Entry   URLs
C2_Messages   Implants      PowerStatus  
sqlite> .schema Implants 
CREATE TABLE Implants (
        ImplantID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI VARCHAR(20),
        URLID INTEGER,
        User TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        ProcName TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT,
        Pivot TEXT,
        Label TEXT,
        FOREIGN KEY(URLID) REFERENCES URLs(URLID));

```

There are two victims here:

```

sqlite> select Hostname,User from Implants;
Hostname|User
DESKTOP-R4KM0GJ|Marcus Athony
DESKTOP-JGLLJLD|admin

```

#### Log

The `poshc2_server.log` file gives a log of everything happening with the C2. The most interesting part is where the implants connect:

```

oxdf@hacky$ cat poshc2_server.log | grep -A1 'implant connected'
[1] New PS implant connected: (uri=DipzfRGn3hD7RMd key=dkIJ88tRU61XoxMP4mZ+ZJRJK1N727nkG4kgYgDXyTw=)
37.19.205.153:40216 | Time:2023-01-25 15:00:39 | PID:368 | Process:powershell | Sleep:5s | Marcus Athony @ DESKTOP-R4KM0GJ (AMD64) | URL: default
--
[2] New PS implant connected: (uri=qryOUVE5JolwLJ2 key=dHbhqbsqZpLKT4FbbruTO5D94ADKG17poSt/sUqw/9w=)
185.192.69.84:43393 | Time:2023-01-28 12:30:44 | PID:5836 | Process:powershell | Sleep:5s | admin @ DESKTOP-JGLLJLD (AMD64) | URL: default

```

The first computer, DESKTOP-R4KM0GJ, shows a bunch of interaction run after connection:

```

oxdf@hacky$ cat poshc2_server.log | grep DESKTOP-R4KM0GJ
37.19.205.153:40216 | Time:2023-01-25 15:00:39 | PID:368 | Process:powershell | Sleep:5s | Marcus Athony @ DESKTOP-R4KM0GJ (AMD64) | URL: default
Task 00001 (autoruns) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:00:46)
Task 00001 (autoruns) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:00:49)
Task 00002 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:04)
Task 00003 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:04)
Task 00002 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:07)
Task 00003 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:10)
Task 00004 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:19)
Task 00005 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:19)
Task 00004 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:22)
Task 00005 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:02:25)
Task 00006 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:05:06)
Task 00006 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:05:07)
Task 00007 (darktracker) issued against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:09:49)
Task 00007 (darktracker) returned against implant 1 on host DESKTOP-R4KM0GJ\Marcus Athony @ DESKTOP-R4KM0GJ (2023-01-25 15:09:52)

```

The second doesn’t get any interaction from the actor:

```

oxdf@hacky$ cat poshc2_server.log | grep DESKTOP-JGLLJLD
185.192.69.84:43393 | Time:2023-01-28 12:30:44 | PID:5836 | Process:powershell | Sleep:5s | admin @ DESKTOP-JGLLJLD (AMD64) | URL: default
Task 00008 (autoruns) issued against implant 2 on host DESKTOP-JGLLJLD\admin @ DESKTOP-JGLLJLD (2023-01-28 12:30:49)
Task 00008 (autoruns) returned against implant 2 on host DESKTOP-JGLLJLD\admin @ DESKTOP-JGLLJLD (2023-01-28 12:30:50)

```

The only victim interacted with is DESKTOP-R4KM0GJ\Marcus Athony (Task 11).

## Results

### Timeline

Putting all that together makes the following timeline:

| Time (UTC) | Description | Reference |
| --- | --- | --- |
| 2023-01-24 22:36:58 | `ec2.py` downloaded by attacker IP | CloudTrail [`GetObject`] |
| 2023-01-24 22:37:59 | `ec2.py` downloaded again by attacker IP | CloudTrail [`GetObject`] |
| 2023-01-24 22:48:34 | Initial log from attacker IP range | CloudTrail |
| 2023-01-24 22:48:34 | Create key pair `1337.key` | CloudTrail [`CreateKeyPair`] |
| 2023-01-24 22:54:45 - 22:59:58 | Start 6 instances of t2.micro EC2 (3 commands) with `1337.key` | CloudTrail [`RunInstances`] |
| 2023-01-24 23:10:27 - 23:22:25 | Enumerating / modifying security group rules [17 events] | CloudTrail [`ModifySecurityGroupRules` / `DescribeSecurityGroupRules`] |
| 2023-01-24 23:25:55 | Admin terminates 6 EC2 instances | CloudTrail [`TerminateInstances`] |
| 2023-01-25 11:38:44 | Created 1337 security group | CloudTrail [`CreateSecurityGroup`] |
| 2023-01-25 11:51:02 | Create 5 instances of t2.micro EC2 (1 command) with `1337.key` | CloudTrail [`RunInstances`] |
| 2023-01-25 11:56:46 - 11:59:13 | Enumerating / modifying security group ingress [6 events] | CloudTrail [`DescribeSecurityGroupRules` / `AuthorizeSecurityGroupIngress`] |
| 2023-01-25 12:02:25 | Create 1 instance of t2.micro EC2 (1 command) with `13337` | CloudTrail [`RunInstances`] |
| 2023-01-25 13:41:44 - 13:57:34 | Enumerating / modifying security group ingress [2 events] | CloudTrail [`AuthorizeSecurityGroupIngress`] |
| 2023-01-25 13:59:00-14:03:02 | Two failed instances and a successful instance of t2.micro EC2 with `13337` | CloudTrail [`RunInstances`] |
| 2023-01-25 14:03 | Last boot of PoshC2 C2 EC2 instance | CatScale [`last-utmp.txt`] |
| 2023-01-25 14:35:02 | Enumerating / modifying security group ingress [1 event] | CloudTrail [`AuthorizeSecurityGroupIngress`] |
| 2023-01-25 14:35:02 | Last activity from attack IP range | CloudTrail |
| 2023-01-25 15:00:46 - 15:09:52 | DESKTOP-R4KM0GJ\Marcus Athony victim interacts with PoshC2 | PoshC2 logs |
| 2023-01-25 15:11:37 | ADmin terminates 6 EC2 instances | CloudTrail [`TerminateInstances`] |

### Question Answers
1. Which AWS IAM account was compromised by the TA?

   forela-ec2-automation
2. Where did the attacker locate the hard coded IAM credentials?

   `/backups/ec2.py`
3. In total how many EC2 hosts were deployed by the TA?

   13
4. What is the name of the key pair/s generated by the attacker?
   1337.key, 13337
5. What time were the key pair/s generated by the attacker?

   2023-01-24T22:48:34Z,2023-01-25T12:01:38Z
6. What are the key pair ID/s of the key/s generated by the attacker?

   key-0450dc836eaf2aa37
7. What is the description of the security group created by the attacker?

   still here
8. At what time did the Sys Admin terminate the first set of EC2s deployed?

   2023-01-24 23:25
9. Can we confirm the IP addresses used by the TA to abuse the leaked credentials? (Ascending Order)
   95.181.232.4,95.181.232.8,95.181.232.9,95.181.232.28
10. In addition to the CloudTrail data and S3 access we have provided artefacts from the endpoint reported by AWS. What is the name of the malicious application installed on the EC2 instance?

    PoshC2
11. Please can you provide the hostname and username details of any victims of the C2 server?

    DESKTOP-R4KM0GJ\Marcus Athony