---
layout: post
title: "MBE Lab4 Format Strings Write Up"
---

# 0x00 背景

此篇write up 对应于MBE的[Lab4](https://github.com/RPISEC/MBE/tree/master/src/lab04)，针对的是字符串格式化漏洞，环境不变仍需要关闭ASLR，按照注释编译，不过在利用过程中需要了解的sec机制有[RELRO](http://tacxingxing.com/2017/07/14/relro/)和[FORTIFY_SOURCE](http://tacxingxing.com/2017/07/17/fortifysource/)。

<!-- more -->

# 0x01 Lab4

## lab4C

这一题虽然是用`-z norelro`编译，但在[提示](http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/10/10_lab.pdf)中要求不能使用GOT/PLT Overwrites，所以这一题很明显就是通过字符串格式化漏洞得到real_pass的内容，进入代码的if逻辑就得到shell了，按例查看偏移为0x76：

![][1]

所以format向下28个%x后，即可读出real_pass数组的内容：

![][2]

## lab4A

该题使用`-z execstack -z relro -z now`编译，完全开启了RELRO，所以就只能通过printf读取地址信息，写入ret至栈地址执行shellcode。当今字符串格式化的漏洞比较少是因为在编译过程中编译器就会产生相应告警，即可直接定位漏洞点：

![][3]

首先向下`AAAA%80$08x` leak出filename的地址：

![][4]

相对偏移是不变的所以在非调试状态下可得到`arg[1]`的地址为0xbffff2be，不过现在我们还需要得到ret的地址，以便在其中写入我们可控buff `arg[1]`的地址处。可以通过以下脚本爆破出当前栈地址和`arg[1]`的偏移：

```bash
#!/bin/bash

for i in {1..2000}
do
  x=`./lab4A AAAA%$i\\$08x`
  result=`grep AAAA4141414 ./backups/.log | wc -c`
  if [ $result -gt 0 ];then
    echo $i
    break
  fi
done
```

所以在snprintf传参过程中，filename位于的栈地址为`0xbffff2be-276*4=0xbfffee6e`，而其与ret地址相对偏移为308，所以我们需要覆写的ret地址为`0xbfffee6e +308=0xbfffefa2`。然后将log_wrapper中ret的地址写为栈中shellcode的起始地址。但在实践过程中不同环境下会导致log_warpper中的栈地址和`arg[1]`地址的相对位移会变，但是计算的基本思想不变，利用字符串格式化的漏洞读取ret和shellcode的地址，然后写入即可。如下是在gdb-peda中的成功exploit：

![][5]

## lab4B

此题printf后exit，显而易见是为了覆盖在exit过程中会调用的`.dtor`上的函数指针，但在当前编译环境中为`.fini_array` section，而且前后没有0xffffffff和0x00000000，直接覆盖即可：

![][6]

因为编译选项为`-z execstack -z norelro -fno-stack-protector`栈上可执行并完全[disable](http://blog.isis.poly.edu/exploitation%20mitigation%20techniques/exploitation%20techniques/2011/06/02/relro-relocation-read-only/)了relro，所以覆盖内容为栈上地址即可。在调试过程发现，`%5$08x`读取出的地址和buf的栈地址刚好相差0x20：

![][7]

这样就可以覆盖函数指针为shellcode的起始地址，但是题中会破坏`[0x41, 0x5a]`的shellcode，而原始的shellcode中`\x50`为`push eax`正好中招，我们只需将其换为`\x6a\x00`即`push 0`就[好了](http://shell-storm.org/online/Online-Assembler-and-Disassembler/?opcodes=%5Cx31%5Cxc0%5Cx6a%5Cx00%5Cx68%5Cx2f%5Cx2f%5Cx73%5Cx68%5Cx68%5Cx2f%5Cx62%5Cx69%5Cx6e%5Cx89%5Cxe3%5Cx89%5Cxc1%5Cx89%5Cxc2%5Cxb0%5Cx0b%5Cxcd%5Cx80%5Cx31%5Cxc0%5Cx40%5Cxcd%5Cx80&arch=x86-32&endianness=little#disassembly)：

![][8]

# 0x02 总结

字符串格式漏洞通过读写内容执行shellcode，但是漏洞本身并不常见，在利用过程中需要注意覆盖地址的大小端问题和字节的计算，当然pwntools中有可以直接使用的函数，无源码exp的[套路](https://www.anquanke.com/post/id/85817)在CTF中也比较常见。

[1]: https://wx2.sinaimg.cn/large/ee2fecafly1fp2afv10i9j20k407mdgq.jpg
[2]: https://wx4.sinaimg.cn/large/ee2fecafly1fp2afwawdgj20k40ajmyh.jpg
[3]: https://wx3.sinaimg.cn/large/ee2fecafly1fp2afx2ijuj20k10413yy.jpg
[4]: https://wx3.sinaimg.cn/large/ee2fecafly1fp2afymex8j20k40ak404.jpg
[5]: https://wx2.sinaimg.cn/large/ee2fecafly1fp2ag0nr5aj20k307j0tw.jpg
[6]: https://wx2.sinaimg.cn/large/ee2fecafly1fp2ag21x2bj20k00aldh7.jpg
[7]: https://wx4.sinaimg.cn/large/ee2fecafly1fp2ag3f2ubj20k20amwg1.jpg
[8]: https://wx1.sinaimg.cn/large/ee2fecafly1fp2ag4im4kj20k105ndgo.jpg
