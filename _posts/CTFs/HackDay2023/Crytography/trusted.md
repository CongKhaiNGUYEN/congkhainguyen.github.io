---
title: CTFs | HackDay2023 | Trusted
author: Kaiba_404
date: 2023-03-30
categories: [CTFs, HackDay2023, Trusted]
tags: [CTF, HackDay2023, Cryptography]
permalink: /CTFs/HackDay2023/Cryptography/Trusted
---

# Trusted


> The situation is bad. The magistrate database from the Sagittarius sector has been leaked!
> The incident response team continues to see unknown connections in the logs from outside the sector, even though the passwords have all been changed.
> We suspect the problem is with the authentication portal… Do something about it!

In this chall, we are given a [trusted.py](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/_posts/CTF_events/Hackday2023/Crytography) and a remote instance running at `sie2op7ohko.hackday.fr:1338`.

Here is the content of the given file:

```python
#!/usr/bin/env python3

import hashlib
from random import randbytes

def MAC(msg, key):
    print(key + msg)
    return hashlib.sha256(key + msg).hexdigest()

secret = randbytes(32)

example = "my_login"
print(len(example.encode() + secret))
mac_example = MAC(example.encode(), secret)

banner = f"""
 _____              _           _ 
|_   _|            | |         | |
  | |_ __ _   _ ___| |_ ___  __| |
  | | '__| | | / __| __/ _ \/ _` |
  | | |  | |_| \__ \ ||  __/ (_| |
  \_/_|   \__,_|___/\__\___|\__,_|

Welcome to the magistrates' systems authentication portal.
These systems contain confidential information. By authenticating, you accept our terms of usage and confidentiality policy.
On a first line, please send your login. On a second line, send the MAC of the login.

Here's an example:

> {example}
> {mac_example}

"""

print(banner)

login = input("> ").encode("utf-8", "surrogateescape")
mac = input("> ")


mac_pre = MAC(login, secret)
print(mac_pre)

if b"admin" not in login:
    print("User not recognized.")
    exit(1)

if mac != mac_pre:
    print("Login error, the MAC is invalid.")
    exit(1)

with open("flag.txt") as flag:
    print("Welcome, dear magistrate.", flag.read())
```

After reading the code, I observed that the message authentication code (MAC) implemented uses a simplistic method of protecting its secret by simply concatenating the secret and the message and then hashing the result using SHA256. However, after conducting some research online, I discovered that this type of protection can be vulnerable to an attack known as the ["Length Extension Attack"](https://en.wikipedia.org/wiki/Length_extension_attack).

Since this type of attack has been widely discussed on various websites, I was confident that I could find a helpful document or blog that explains the attack in detail. Fortunately, I came across an excellent document by following this [link](https://seedsecuritylabs.org/Labs_16.04/PDF/Crypto_Hash_Length_Ext.pdf).

In the document I found a suitable C code to exploit the vulnerability in this challenge

```c
/* length_ext.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
int main(int argc, const char *argv[])
{
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;
    SHA256_Init(&c);
    for(i=0; i<64; i++)
    SHA256_Update(&c, "*", 1);
    // MAC of the original message M (padded)
    c.h[0] = htole32(0x6f343800);
    c.h[1] = htole32(0x1129a90c);
    c.h[2] = htole32(0x5b163792);
    c.h[3] = htole32(0x8bf38bf2);
    c.h[4] = htole32(0x6e39e57c);
    c.h[5] = htole32(0x6e951100);
    c.h[6] = htole32(0x5682048b);
    c.h[7] = htole32(0xedbef906);
    // Append additional message
    SHA256_Update(&c, "Extra message", 13);
    SHA256_Final(buffer, &c);
    for(i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
    return 0;
}
```

All that is left for me to do is to calculate the necessary parameters and then run the program to obtain the flag.

When I start the connection to the server I have to create a login of the form: 

```python
padding = b"my_login" b"\x80" + b"\x00"*15 + b"\x00\x00\x00\x00\x00\x00\x01\x40"
new_string = b"admin"
payload = padding + new_string
```

Then I use the following script to send the payload to the server

```python
from pwn import *

# p = process("./trusted.py")
p = remote("sie2op7ohko.hackday.fr", 1338)

p.recvuntil("Here's an example:")
print(p.recv().decode())

padding = b"my_login" + b"\x80" + b"\x00"*15 + b"\x00\x00\x00\x00\x00\x00\x01\x40"
new_string = b"admin"
payload = padding + new_string

p.sendline(payload)
p.interactive()
```

Since there is no timeout set on the server, I plan to use the hash value provided as an example, input it into the C code mentioned earlier, obtain the resulting value, and then send it back to the server.

Below is the C code after some editing

```c
/* length_ext.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
int main(int argc, const char *argv[])
    {
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;
    SHA256_Init(&c);
    for(i=0; i<64; i++)
    SHA256_Update(&c, "*", 1);
    // MAC of the original message M (padded)
    c.h[0] = htole32(0xd11f0adb);
    c.h[1] = htole32(0x38bccbc3);
    c.h[2] = htole32(0xea65abed);
    c.h[3] = htole32(0x8f1b0d73);
    c.h[4] = htole32(0xcc877119);
    c.h[5] = htole32(0x04672777);
    c.h[6] = htole32(0x3986a5db);
    c.h[7] = htole32(0xcdf244e8);
    // Append additional message
    SHA256_Update(&c, "admin", 5);
    SHA256_Final(buffer, &c);
    for(i = 0; i < 32; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
    return 0;
}
```

```bash
$ gcc crack.c -o crack -lcrypto
$ ./crack
47727d2158ebd5d82b6531ba2af218b8e15e99165b03aba8ef21eabc7cdec2f1
```

After sending the obtained string to the server, I was able to successfully retrieve the flag.

```bash
Welcome, dear magistrate. HACKDAY{l3ngth_3xt3n510n_4tt4ck5}
```

Flag: `HACKDAY{l3ngth_3xt3n510n_4tt4ck5}`