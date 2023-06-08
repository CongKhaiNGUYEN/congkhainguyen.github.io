---
title: CTFs | 404CTF2023 | Forensics | Le Mystère du roman d'amour
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, Forensics]
tags: [CTF, 404CTF2023, Forensics]
permalink: /CTFs/404CTF2023/Forensics/roman_damour
---

# Le Mystère du roman d'amour

![roman_damour](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/6ff6ad5e-ef53-491a-b50e-7fc3ed783d1a)

We are given a [swp](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/Forensics/files/fichier-etrange.swp) file in this challenge.

A .swpfile is a Vim Swap file. It is created by the Vim text editor whenever somebody opens a file to edit. This temporary file stores modifications made to the original document and safeguards it in case of unexpected crashes or system malfunctions.

By using the `file` command we can retrieve some useful information

```shell
$ file fichier-etrange.swp 
fichier-etrange.swp: Vim swap file, version 7.4, pid 168, user jaqueline, host aime_ecrire, file ~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeur d'artichaut/brouillon.txt
```

The `PID` is `168`, the Rouletabille’s friend's name is `jaqueline`, the hostname is `aime_ecrire` and the full path to the file is `~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeur d'artichaut/brouillon.txt`.

Vim has the ability to recover data from swp files and we can try it

```shell
vim -r fichier-etrange.swp

Using swap file "fichier-etrange.swp"
Original file "~jaqueline/Documents/Livres/404 Histoires d'Amour pour les biblio
"~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeu
r d'artichaut/brouillon.txt" [New DIRECTORY]
Recovery completed. You should check if everything is OK.
(You might want to write out this file under another name
and run diff with the original file to check for changes)
You may want to delete the .swp file now.

Press ENTER or type command to continue
[Press enter]
```

In vim we can use `:w img.png` to save the recovery file into `img.png`

![img_book](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/e5f28a6a-b2e3-47b4-bd83-bd3c938ec836)

Try searching for hidden information in images using the website <https://www.aperisolve.com/>. We find the qr code as follows

![qr_code_for](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/852573ac-e4d3-4008-8b21-40deb0037b9e)

Scan this QR, we get 

```
Il était une fois, dans un village rempli d'amour, deux amoureux qui s'aimaient...

Bien joué ! Notre écrivaine va pouvoir reprendre son chef-d'oeuvre grâce à vous !
Voici ce que vous devez rentrer dans la partie "contenu du fichier" du flag : 3n_V01L4_Un_Dr0l3_D3_R0m4N
```

**Flag:** `404CTF{168-~jaqueline/Documents/Livres/404 Histoires d'Amour pour les bibliophiles au coeur d'artichaut/brouillon.txt-jaqueline-aime_ecrire-3n_V01L4_Un_Dr0l3_D3_R0m4N}`