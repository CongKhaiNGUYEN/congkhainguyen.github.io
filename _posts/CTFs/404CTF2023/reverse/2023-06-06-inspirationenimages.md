---
title: CTFs | 404CTF2023 | Inspiration en images
author: Kaiba_404
date: 2023-06-06
categories: [CTFs, 404CTF2023, Inspiration en images]
tags: [CTF, 404CTF2023, reverse]
permalink: /CTFs/404CTF2023/reverse/inspirationenimages
---

# L'inspiration en images

![Challenge](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/f7e51a54-9246-4608-8cfb-14e7f79d21de)

In this challenge, we have access to two file [vue_sur_un_etrange_tableau](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/reverse/files/vue_sur_un_etrange_tableau)  (binary executable file) and [verso.txt](https://github.com/CongKhaiNGUYEN/congkhainguyen.github.io/tree/main/_posts/CTFs/404CTF2023/reverse/files/verso.txt) (text file).  Like in the challenge said, we do not need to worry about the file verso.txt because it will not help to find the flag. So I decided to use Ghidra to look at the binary and find something interesting.


It looks like this file is very complicated and main function contains a lot of variables as shown below.

![image_main](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/c50209bc-bfb7-4a47-a2e5-dfeb70ec0a0a)

As the challenge mentioned, we just need to find the parameters corresponding to the background color of this challenge so I'm not trying to read the code but just learn a few things who allows me to find the flag. 

After conducting some research on Google, I discovered that this binary file utilizes the GLFW engine for its images and animations. As a result, I can explore the GLFW documentation to identify the function responsible for modifying the background color. I can then search for this function within Ghidra to locate the corresponding parameter for the color of the background.

After some further searching in the GLFW documentation, I found that the function glClearColor() can be used to change the background color. Therefore, I have decided to search for this function within Ghidra to locate its implementation and relevant parameters.

![glClearColor_search](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/f2d770da-3705-4459-9432-f1fc9963fbeb)

After clicking on the line XREF[1] (green text on the right as shown above), I found a string used to call this function as shown below

![glad_glClearColor](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/e4a51237-3242-48b9-9e3a-c687e13a279a)

Now let's try to search for the string "glad_glClearColor" in the functions. Fortunately, we have it in the main function.

![main_clearcolor](https://github.com/CongKhaiNGUYEN/CTF/assets/61443497/4c66c7d4-2639-4ac1-b34f-b1d40fbc7794)

It is evident that the four hexadecimal numbers `0x3e4ccccd, 0x3e99999a, 0x3e99999a, and 0x3f800000` correspond to the parameters for the background color. However, to adhere to the requirement of representing them as real numbers with one digit after the decimal point, I utilized the [gregstoll](https://gregstoll.com/~gregstoll/floattohex/) website to perform the conversion.

***Flag***: 404CTF{vec4(0.2,0.3,0.3,1.0)}

