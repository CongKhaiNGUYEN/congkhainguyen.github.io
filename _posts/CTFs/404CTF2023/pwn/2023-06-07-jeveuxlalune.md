---
title: CTFs | 404CTF2023 | JeVeuxLaLune
author: Kaiba_404
date: 2023-06-07
categories: [CTFs, 404CTF2023, JeVeuxLaLune]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/jeveuxlalune
---


# Je veux la lune

![je_veux_la_lune](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/6582e6b5-5f91-446a-b5cd-9618ad1186b3)

In this challenge, we have access to the file [donne_moi_la_lune.sh](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/pwn/files/donne_moi_la_lune.sh). After reading the contents of the file, I see that we can find the flag in `lune.txt`. Now let's analyze a bit of the code to find the way to get it.

I noticed that the command `eval "grep -wie ^$personne informations.txt"` is probably exploitable.

This command is using the grep command to search for a pattern in the file `informations.txt`. The pattern being searched for is the value of the variable `$personne`, which is assumed to be previously defined in the script. The `^` character in the pattern means that the search term should match at the beginning of a line in the file.

The `w` option is used to ensure that the search term matches only whole words, while the `i` option is used to make the search case-insensitive.

Since this command uses regex, we can dump the entire content using the pattern `.* lune.txt &` to get the flag.

```bash
En attendant j'ai aussi obtenu des informations sur Cherea, Caesonia, Scipion, Senectus, et Lepidus, de qui veux-tu que je te parle ?
.* lune.txt &
/app/donne_moi_la_lune.sh: fork: retry: Resource temporarily unavailable
/app/donne_moi_la_lune.sh: line 11: cannot redirect standard input from /dev/null: No such file or directory
404CTF{70n_C0EuR_v4_7e_1Ach3R_C41uS}
/app/donne_moi_la_lune.sh: line 11: informations.txt: command not found
```

`Flag: 404CTF{70n_C0EuR_v4_7e_1Ach3R_C41uS}`