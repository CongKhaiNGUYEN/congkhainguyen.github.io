---
title: CTFs | 404CTF2023 | Reverse | LeDivinCrackme
author: Kaiba_404
date: 2023-06-04
categories: [CTFs, 404CTF2023, Reverse]
tags: [CTF, 404CTF2023, reverse]
permalink: /CTFs/404CTF2023/reverse/ledivincrackme
---

# Le Divin Crackme

In this challenge we have access to the ELF file [divin-crackme](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/reverse/files/divin-crackme). We can see that Le Divin Crackme is an introduction challenge, so it is relatively easy. We just have to open it in Ghidra to get the answer.

![divin](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/2b8f9f8e-f28d-45f3-b44a-979890f41f05)

`Password = local_48 + acStack_3e + acStack_34 = "L4_pH1l0so" + "Ph13_d4N5_" + "l3_Cr4cKm3"`

`Password = L4_pH1l0soPh13_d4N5_l3_Cr4cKm3`


```shell
objdump -s -j .comment divin-crackme 

divin-crackme:     file format elf64-x86-64

Contents of section .comment:
 0000 4743433a 20284465 6269616e 2031322e  GCC: (Debian 12.
 0010 322e302d 31342920 31322e32 2e3000    2.0-14) 12.2.0.
```

Le compilateur: `gcc`

Fonction: `strncmp`

**Flag:** `404CTF{gcc:strncmp:L4_pH1l0soPh13_d4N5_l3_Cr4cKm3}`