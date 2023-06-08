---
title: CTFs | 404CTF2023 | LeDivinCrackme
author: Kaiba_404
date: 2023-06-04
categories: [CTFs, 404CTF2023, LeDivinCrackme]
tags: [CTF, 404CTF2023, reverse]
permalink: /CTFs/404CTF2023/reverse/ledivinvrackme
---

# Le Divin Crackme

In this challenge we have access to the ELF file [divin-crackme](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/reverse/files/divin-crackme). We can see that Le Divin Crackme is an introduction challenge, so it is relatively easy. We just have to open it in Ghidra to get the answer.

![divin](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/2b8f9f8e-f28d-45f3-b44a-979890f41f05)

`Password = local_48 + acStack_3e + acStack_34 = "L4\_pH1l0so" + "Ph13\_d4N5\_" + "l3\_Cr4cKm3"`

`Password = L4_pH1l0soPh13_d4N5_l3_Cr4cKm3`

Le compilateur: `gcc`

Fonction: `strncmp`

**Flag:** `404CTF{gcc:strncmp:L4_pH1l0soPh13_d4N5_l3_Cr4cKm3}`