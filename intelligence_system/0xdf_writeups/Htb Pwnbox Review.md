---
title: HTB Pwnbox Review
url: https://0xdf.gitlab.io/2020/08/04/htb-pwnbox-review.html
date: 2020-08-04T09:00:00+00:00
tags: ctf, hackthebox, pwnbox, parrot, vm, ssh, scp, tmux, api
---

![](https://0xdfimages.gitlab.io/img/pwnbox-cover.png)

I was recently talking with some of the folks over at HackTheBox, and they asked my thoughts about Pwnbox. My answer was that I’d never really used it, but that I would give it a look and provide feedback. The system is actually quite feature packed. It is only available to VIP members, but if you are VIP, it’s worth spending a few minutes setting up the customizations. That way, if you should find yourself in need of an attack VM, you have it, and you might even just switch there.

## Background

### What is Pwnbox

HackTheBox announced [Pwnbox was live](https://twitter.com/hackthebox_eu/status/1265680749832871940) on May 27, 2020:

> [#HackTheBox](https://twitter.com/hashtag/HackTheBox?src=hash&ref_src=twsrc%5Etfw) Presents Pwnbox 📢[#Hack](https://twitter.com/hashtag/Hack?src=hash&ref_src=twsrc%5Etfw) all [#HTB](https://twitter.com/hashtag/HTB?src=hash&ref_src=twsrc%5Etfw) labs directly from your browser ANYTIME, ANYWHERE! Start PwnBox NOW 🤩 <https://t.co/fArbAqDXo6>[#CyberSecurity](https://twitter.com/hashtag/CyberSecurity?src=hash&ref_src=twsrc%5Etfw) [#CyberSecurityTraining](https://twitter.com/hashtag/CyberSecurityTraining?src=hash&ref_src=twsrc%5Etfw) [#Pentesting](https://twitter.com/hashtag/Pentesting?src=hash&ref_src=twsrc%5Etfw) [#Infosec](https://twitter.com/hashtag/Infosec?src=hash&ref_src=twsrc%5Etfw) [pic.twitter.com/gnF6K7uDYr](https://t.co/gnF6K7uDYr)
>
> — Hack The Box (@hackthebox\_eu) [May 27, 2020](https://twitter.com/hackthebox_eu/status/1265680749832871940?ref_src=twsrc%5Etfw)

Last week they announced it was available on the new updated HTB platform (I’ll show the new interface in this post):

> [#HTB](https://twitter.com/hashtag/HTB?src=hash&ref_src=twsrc%5Etfw) [#Pwnbox](https://twitter.com/hashtag/Pwnbox?src=hash&ref_src=twsrc%5Etfw) now in <https://t.co/2V9BORRJDW> 🚨  
> Read the full story plus TRICKS + TIPS to utilize it to the MAX 💯 here: <https://t.co/XGv71f7acU>   
> Ready to [#Hack](https://twitter.com/hashtag/Hack?src=hash&ref_src=twsrc%5Etfw) from any place - any time?  
> SPAWN NOW Pwnbox and unleash your inner [#Hacker](https://twitter.com/hashtag/Hacker?src=hash&ref_src=twsrc%5Etfw) 😎[#HackTheBox](https://twitter.com/hashtag/HackTheBox?src=hash&ref_src=twsrc%5Etfw) [#InfoSec](https://twitter.com/hashtag/InfoSec?src=hash&ref_src=twsrc%5Etfw) [#CyberSecurity](https://twitter.com/hashtag/CyberSecurity?src=hash&ref_src=twsrc%5Etfw) [pic.twitter.com/eNEPB0aP4C](https://t.co/eNEPB0aP4C)
>
> — Hack The Box (@hackthebox\_eu) [July 31, 2020](https://twitter.com/hackthebox_eu/status/1289259532221177857?ref_src=twsrc%5Etfw)

The [Pwnbox help page](https://help.hackthebox.eu/machines-challenges/pwnbox-v2?utm_source=0xdf&utm_medium=blog&utm_campaign=pwnbox&utm_content=20200727) has the details:

> **Pwnbox** is a customized, online, [parrot security](https://www.parrotsec.org/) linux distribution with many hacking tools pre-installed. You can use it to play in our labs without the need to install a local VM serving the same purpose.
>
> VIP users have a limit of **24 hours** per month to use their **Pwnbox**. This limit gets renewed with each month that you renew your VIP subscription.
>
> **Pwnboxes** also have a lifetime of their own, once you spawn one, you can see its’ remaining time in the panel.
>
> If you’re wondering about having the right tool, don’t worry! Our custom-made parrot security distro comes equipped with a plethora of tools of the trade. Take a look below at the list:
>
> BurpSuite, FoxyProxy, Wappalyzer, gobuster, dirb, dirbuster, SecLists, PayloadAllTheThings, LinuxPrivChecker, LinPeas, Sublime, PowerShell, Terminal, BloodHound, and the list goes on.

### My Preconceptions

Frankly, from the time PwnBox was announced, I was uninterested by the idea of a VM in the browser, and hadn’t given it much thought. I like having my VM I hack from. But now I’m thinking about a recent experience where I was traveling a few weeks ago, and my laptop had a really old Kali VM on it. I had an hour and a half free, and went to do some HTB, but a bunch of the tools in the VM were broken to the point that I was struggling to do the box. I ended up doing something else, because rebuilding the VM would have taken all my time.

I also am running into VMs in the browser more and more. SANs Netwars Mini and Holiday Hack have been putting terminals in the browser for some time. But I also recently ran into a system at work where Apache Guacamole was used to RDP through a browser, and I was shocked by how well it worked. All of that is to say, I came in somewhat skeptical, but with an open mind.

## General Use

### Boot

To get started in the [new HTB GUI](https://app.hackthebox.eu/getting-started?utm_source=0xdf&utm_medium=blog&utm_campaign=pwnbox&utm_content=20200727) there’s a connections icon at the very top right of the page:

![image-20200803144518411](https://0xdfimages.gitlab.io/img/image-20200803144518411.png)

Clicking that opens a sidebar with connection options:

![image-20200803144546208](https://0xdfimages.gitlab.io/img/image-20200803144546208.png)

Clicking Pwnbox will open the options:

![image-20200803144649997](https://0xdfimages.gitlab.io/img/image-20200803144649997.png)

Select a location, the VPN to connect to, which server, and click Start Pwnbox:

![image-20200803144754301](https://0xdfimages.gitlab.io/img/image-20200803144754301.png)

A little computer monitor will appear and progress as the machine starts, ending with a (live) image of the new desktop:

![image-20200803145417576](https://0xdfimages.gitlab.io/img/image-20200803145417576.png)

There are three buttons under the desktop image for Desktop, Terminate, and SSH. Terminate kills the VM. I’ll go into the other two a minute. There’s also a Spectator Link just above and to the right of the desktop. I’ll cover that below as well.

### Connect

#### SSH

If I don’t want a full desktop, I can SSH to the host. The SSH button from above pops up asking to open it in `xdg-open` (at least for me on Ubuntu in Chromium):

![image-20200717155518859](https://0xdfimages.gitlab.io/img/image-20200717155518859.png)

Originally, clicking Open xdg-open did nothing for me, until I found [this post](https://lithostech.com/2014/04/get-ssh-protocol-links-working-in-ubuntuchromeunity/), and ran the two commands in it. Now clicking the button just pops a `bash` window with SSH connecting to the host.

I can also just SSH in from a terminal by typing in the command `ssh htb-0xdf@htb-[random].htb-cloud.com`. The password is random and changes each time an instance is started. In the old platform, the password was displayed once the box started. Not sure if they will add that to the new platform or not. I could also fetch it via the API.

![image-20200717155424251](https://0xdfimages.gitlab.io/img/image-20200717155424251.png)

Even better, I can add an SSH key (and persist it between sessions, see below).

SSH access means I can also SCP files to/from the host. This is critical for me, as I keep a lot of notes, and don’t want to lose them.

#### Desktop in Browser

Most of the time I’ll want to work through a full desktop environment. Clicking the button here will open a new browser tab with the desktop in it:

![image-20200804075908405](https://0xdfimages.gitlab.io/img/image-20200804075908405.png)

Anyone with the url can connect in at the same time, if you wanted to do some co-hacking, passing the mouse back and forth.

#### Spectator Link

There’s also a spectator link. This will open the desktop to the same view, but it will allow a view only experience. This seems like a really cool thing to try with a team when you want to demonstrate something, or for making stream.

### Hacking A Box

I’ve completed two boxes using Pwnbox, and I can say it’s exceeded my expectations in every aspect. It runs by default as a non-root user, but I’m given passwordless `sudo`. As someone who is very used to running as root all the time while CTF-ing, this took a bit of getting used to, but it wasn’t too bad.

The VM was super easy to use, and most of the time I couldn’t tell I was in a browser as opposed to a local VM. Copy and paste work well both in and out.

All of the tools I need to start pretty much every box were installed by default, including but not limited to: Burp, Firefox, FoxyProxy (to enable/disable flow through Burp), `nmap`, `gobuster`, `wfuzz`, `hashcat`, `john`, the [PEAS tools](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), Seclists, Impacket (to include `smbserver.py` and other AD tools).

When I did run into tools that weren’t there, I could download them and install as needed (and for important things include install in my `user_init` script).

`tmux` is installed, though in the default terminal prompt it looks a little busted. I fixed this by adding `screen*` to the following `case` statement in the default `.bashrc`:

```

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*|screen*)
    PS1="\[\033[1;32m\]\342\224\200\$([[ \$(/opt/vpnbash.sh) == *\"10.\"* ]] && echo \"[\[\033[1;34m\]\$(/opt/vpnserver.sh)\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\$(/opt/vpnbash.sh)\[\033[1;32m\]]\342\224\200\")[\[\033[1;37m\]\u\[\033[01;32m\]@\[\033[01;34m\]\h\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\w\[\033[1;32m\]]\\$\[\e[0m\] "
    ;;
*)
    ;;
esac

```

Now that will trigger in `tmux` as well and looks better. I also did make some other customizations to the prompt - I don’t love multi-line prompts as a general case, but that was easy to fix.

One thing that didn’t work well for me is using the Firefox screenshot mechanism to capture full pages to the clipboard. It will still save a copy locally, but I regularly use that feature to copy directly into Typora, and it didn’t work here. That is a small bug that probably only impacts me.

## Advanced Features

### Persistent Feature

On my first few tests, I was blown away by how good the performance was, but frustrated with having to update my `.tmux.conf` and `.vimrc` files to make the system behave like I wanted. Then someone pointed out to me the `my_data` folder and the `user_init` script. In my home directory, there’s a folder named `my_data`. Anything I write there will be packed up and stored between sessions. When I initiate a new session, it will be put back.

Even cooler, in `my_data` is a script `user_init`. This will run on startup. I made the following customizations:
- Created a `confs` directory in `my_data` with my desired `.bashrc`, `.tmux.conf`, and `.vimrc` files. My `user_init` script copies each of the conf files to the appropriate place on boot.
- Create `~/.ssh` and `echo` a public SSH key into `authorized_keys` so I don’t have to use a password when connecting with SSH or SCP.
- Install things with `sudo apt install`, `sudo gem install`, `git clone`, `pip install`, etc.

### API

This entire thing is run by API, which I’m told will be publicly documented soon. With a preview of some of the API paths, I was able to script a utility to start, stop, or get status on my instance. For example, a `pwnbox start` command that will initiate a session, check the status until it is done booting, change my local SSH profile to include the new hostname, and then open Chrome to the VM window.

### Tips

Some random things that I’ve encountered while playing with Pwnbox that are worth noting:
- The terminal shows up as PyCharm in the applications bar. The first time I minimized a terminal, I couldn’t find it! I suspect Pwnbox runs the terminal through PyCharm. Not a big deal, but good to know.

![image-20200717163656949](https://0xdfimages.gitlab.io/img/image-20200717163656949.png)
- If you look at the netstat, Python is listening on 80. It’s coming from the process `python -m websockify 80 localhost:5901 -D`, which I suspect is what forwards the browser access to the VM. Don’t kill this process. I’d recommend that they move this to another port, since people like to use port 80 while hacking.
- Don’t mess with the root or user passwords. It can mess up how things are backed up.
- Don’t shutdown the host. Use the terminate button (or API). Running `shutdown` will cause the host to terminate before it stores any persistent data.
- Be careful if you are used to using `crtl-w` to delete back one word in a terminal. It will close the browser tab in this case. Luckily it’s not hard to bring right back to where you were (the VM isn’t killed), but it’s still annoying.
- Things are sprinkled around in kind of weird places. For example, SecLists, PayloadsAllTheThings, Privilege Escalation Awesome Scripts, and linuxprivchecker are in `/opt/useful`, which is also shortcut to on the Desktop. The Dirbuster wordlists are in `/usr/share/dirbuster/wordlists/`, which is just different enough from Kali (`/usr/share/wordlists/dirbuster/`) to make you feel crazy.

## Feature Requests
- Give me the same hostname on each spawn. Allow me to request it to change in case it leaks and somehow it is getting attacked. Treat the hostname like an API key - it’s the same until I request it die and spawn a new one. This would allow more easily for SSH config files.
- Automatically connect Pwnbox to whichever VPN I was connected to in the previous instance. Or, allow me to pick as the system is booting (since I’m waiting anyway)
- Move the `websockify` listener if possible to a high port, not something like 80 that I might want to use.
- Allow me to map a local folder into the VM. That would be a step better than relying on `my_data` to backup notes, etc. I could just save stuff in that shared folder.

## Summary

I probably won’t use Pwnbox as my daily hacking machine, but the fact that I have to even consider it is super surprising to me. I was really impressed with how slick this environment was, and for anyone who doesn’t want to go through the hassle of making a VM, it’s a really nice solution. I might think HTB would consider offering free accounts some limited time, as it’s a good gateway for people who don’t know if they want to do this hacking thing, and thus don’t really want to build a VM.

The things that will keep me from using it as my primary VM are:
- Needing to shutdown regularly. I often hack a box in small increments, 30 minutes here, and hour there. And when I finish, I like to spend time exploring and taking notes. With my VM, I can often walk away and come back hours later and have my session still intact. Here, that would blow through my monthly limit very quickly.
- Limited hours - I spend too much time on HTB apparently, but 24 hours a month just isn’t enough for me.
- Small configuration things - There are things I just haven’t figure out how to automate yet. For example, I have FoxyProxy set to use patterns to push anything in 10.10.10.\* through Burp, but not general traffic. I haven’t figured out how to fix that yet. It could probably be done, but with the other limiting factors, it’s not worth my time at the moment.

But even if it’s not my daily VM, it’s a tool I will find use for, especially while traveling, and I suspect others will too.

Also, big thanks to the HTB team. I my initial draft of this post had several other things that didn’t work quite right, but they were very prompt to fix them. There’s a channel for Pwnbox in their Discord where you can submit feedback.