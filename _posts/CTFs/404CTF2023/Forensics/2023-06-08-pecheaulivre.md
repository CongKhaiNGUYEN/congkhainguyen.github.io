---
title: CTFs | 404CTF2023 | Forensics | Peche au livre
author: Kaiba_404
date: 2023-06-08
categories: [CTFs, 404CTF2023, Forensics]
tags: [CTF, 404CTF2023]
permalink: /CTFs/404CTF2023/pecheaulivre
---


![pecheaulivre](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/33487952-0177-4858-8a52-d0a247a0705e)

In this challenge, we are given a file [pcapng](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/Forensics/files/Capture.pcapng)

Open it by wireshark,

![frensics](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/eb61a0ce-01aa-4739-b68d-ff68c0380738)

Then we do the following steps: `File->Export Objects->HTTP...`

![expport_object](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/55f1b715-c833-4724-81d0-18071fbaa5a8)

Choose `save all`, then go to the saved folder and get the flag.

![flag_for_intro](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/c800ddfd-c126-4fa4-9b8d-a47845c4b2ed)

**Flag:**   `404CTF{345Y_W1r35h4rK}`