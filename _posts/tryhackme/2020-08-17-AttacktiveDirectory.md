---
title: Tryhackme - AttacktiveDirectory
boxinfo: /images/thm/Attacktive-directory/logobox.png
author: Rhovelionz
date: 2020-08-17 07:21:00 +0700
categories: [Tryhackme]
tags: [Smbclient, Winrm, Kerbrute, Hashcat, Cracking, Secretsdump, Base64, Decode]
image: /assets/img/Post/AD.png

---

>   **Any actions and or activities related to the material contained within this Website is solely your responsibility. This site contains materials that can be potentially damaging or dangerous. If you do not fully understand something on this site, then GO OUT OF HERE! Refer to the laws in your province/country before accessing, using,or in any other way utilizing these materials.These materials are for educational and research purposes only.**


## **<span style='color:#ff5555'>Summary</span>**
***
- Download **username.txt** and **password.txt** from the room page.
- Enumerate the kerberos with **kerbrute**.
- Getting hash and crack with **hashcat**.
- Get in with **smbclient** to get `backup_credentials.txt`.
- Crack the bash with **base64**.
- Use `secretsdump.py` to dump credentials from **backup@spookysec.local**.
- Get in as **Administrator** with NTLM hash.


## **<span style='color:#ff5555'>Port scan</span>**
***

Run nmap is helpful to gather information about the target.

![]({{ "/images/thm/attacktive-directory/nmap.png" | relative_url }})

Found DNS of the target is `spookysec.local`, add it to **/etc/hosts**, it's a good practice to add the target machine into our **/etc/hosts**.

## **<span style='color:#ff5555'>Check the website</span>**
***

![]({{ "/images/thm/attacktive-directory/website.png" | relative_url }})

I'm not going to look around because I hate **windows**'s interface.

By seeing nmap's result, there are port that used for `Active Directory` which is **389**.

## **<span style='color:#ff5555'>Enumeration</span>**
***

I ran **enum4linux** with **-a** flag for simple enumeration against the target to get list of users, machines, group & member list, sharelist, etc. 

![]({{ "/images/thm/attacktive-directory/enum4linux.png" | relative_url }})

The username and password were given by the author of the room, no idea why.

I only need the potential username and I need to bruteforce the kerberos with **kerbrute** to get usernames.

## **<span style='color:#ff5555'>Bruteforce Kerberos</span>**
***

> Get the kerberos [here](https://github.com/ropnop/kerbrute)

So I ran **kerbrute** to get potential real users in order to proceed to the next steps.

![]({{ "/images/thm/attacktive-directory/kerbrute2.png" | relative_url }})

Next step is to get the password or bash for the user and with `GetPNUsers.py` from **Impacket**.

![]({{ "/images/thm/attacktive-directory/gethash.png" | relative_url }})

## **<span style='color:#ff5555'>Cracking</span>**
***

Decided to decrypt it with **hashcat**, and got the cracked password to login with **smb**. `John` also can be used but I prefer **hashcat** because it quicker than john IMO.

![]({{ "/images/thm/attacktive-directory/hashcat.png" | relative_url }})

After getting the credentials of svc-admin, I decided to check shared file as `svc-admin` 

## **<span style='color:#ff5555'>Smbclient</span>**
***

There are multiple **sharename** and I selected one of those which **backup**.

![]({{ "/images/thm/attacktive-directory/smbclient1.png" | relative_url }})

It turns out someone put `backup_credentials.txt` inside, and I can download it to my machine and read it.

![]({{ "/images/thm/attacktive-directory/getbackupcreds.png" | relative_url }})

The file was encoded with base64, so I decrypt it immediately on  in order to get the password of the user.

![]({{ "/images/thm/attacktive-directory/base64crack.png" | relative_url }})

## **<span style='color:#ff5555'>Escalating to Administrator</span>**
***

Now I have username and password, I decided to get **Administrator**'s hash with `secretsdump.py`, also from **impacket**

![]({{ "/images/thm/attacktive-directory/secretsdump.png" | relative_url }})

As of now I have the NTLM hash of the **Administrator**, I can just login with `evil-winrm`. and read the flag.

![]({{ "/images/thm/attacktive-directory/roottxt.png" | relative_url }})

***

![]({{ "/images/mandatory/pwned.png" | relative_url }})