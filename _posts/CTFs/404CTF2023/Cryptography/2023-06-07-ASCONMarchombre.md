---
title: CTFs | 404CTF2023 | Cryptography | ASCON Marchombre
author: Kaiba_404
date: 2023-06-07
categories: [CTFs, 404CTF2023, Cryptography]
tags: [CTF, 404CTF2023, Cryptography]
permalink: /CTFs/404CTF2023/Cryptography/ASCONMarchombre
---

![ASCON](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/3d9812c0-812d-49c6-a955-38e493c6fb03)

Important information:

**nonce:** `0`

**message chiffré:** 
`ac6679386ffcc3f82d6fec9556202a1be26b8af8eecab98783d08235bfca263793b61997244e785f5cf96e419a23f9b29137d820aab766ce986092180f1f5a690dc7767ef1df76e13315a5c8b04fb782`

**Données associées:** `80400c0600000000`

I found a very cool github [repo](https://github.com/meichlseder/pyascon) for ASCON. After modifying the code a little bit I got the decoded msg.

**Code after modifying** [code](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/Cryptography/files/ascon_modified.py)

```bash
$ python3 ascon_modified.py 
=== demo encryption using Ascon-128 ===
key:           0x00456c6c616e61206427416c2d466172 (16 bytes)
nonce:         0x00000000000000000000000000000000 (16 bytes)
ass.data:      0x80400c0600000000 (8 bytes)
decrypted_msg: 0x4c6120766f6965206465206c276f6d6272650a45742064752073696c656e63650a3430344354467b563372355f6c345f6c756d31e872332e7d0a456c6c616e61 (64 bytes)
```

Using cyberchef to get the flag:

![cyber_chef_ASCON](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/83df2349-b616-4855-9ff4-9298dbdab5e1)

**Flag:**  `404CTF{V3r5_l4_lum1èr3.}`