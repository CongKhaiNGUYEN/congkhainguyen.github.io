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