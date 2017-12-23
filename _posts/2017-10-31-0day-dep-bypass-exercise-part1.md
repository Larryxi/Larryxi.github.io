---
layout: post
title: "0day安全DEP绕过实验（上）"
---

# 0x00 实验环境

* 操作系统：xp sp3
* 编译器：vs 2010
* 编译选项：Release版本；开启DEP，关闭GS，SafeSEH，ASLR

<!-- more -->

# 0x01 Ret2Libc实战之利用ZwSetInformationProcess

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.>
#include <Windows.h>

char shellcode[] = …;

void test()
{
	char dest[240];
	strcpy(dest, shellcode);
}

int _tmain(int argc, _TCHAR* argv[])
{
	HINSTANCE hIns = LoadLibrary(_T("shell32.dll"));
	//char s[240];
	test();
	return 0;
}
{% endhighlight %}

由于payload大于200字节，这里还是让缓冲区为240个字节，main函数的字符数组的声明还是为了抬升esp，如果在shellcode中有抬升esp的操作，那么这一句就可以注释掉了。此实验中是调用ZwSetInformationProcess函数来关闭DEP的保护，可跳转的地址和书中一样为7C93CD1F：

![][1]

其中跳转的地址7C95F70E为把ESI赋值给[EBP-4]，然后再返回：

![][2]

如果溢出的缓冲区布局如下：

![][3]

那么在离开test函数时的pop ebp指令会使ebp的值变为90909090，那么在关闭DEP的代码中访问[EBP-4]的值时就会发生非法的内存访问：

![][4]

按照书中所说就需要通过PUSH ESP POP EBP RETN把EBP定位到一个可写的位置，如果函数中未加载shell32.dll就搜索不到这样的指令，shell32.dll的意义就在于此。

再选取恢复EBP的地址追加值缓冲区，布局如下：

![][5]

在恢复EBP时，PUSH ESP POP EBP之后ESP和EBP指向同一位置，在RETN 4之后ESP指向EBP+8，然后在调用ZwSetInformationProcess函数时，由于cdecl的参数传递方式，&ExecuteFlags正好为&ProcessExecuteFlags，其值的低位为0x2，所以正好可以用来传参：

![][6]

跟进调用ZwSetInformationProcess函数，在调用结束即将返回时，我们需要注意一下返回的情况，继续布置栈来获取程序的控制权：

![][7]

在RETN 4后EIP即将会转向00000004，而其正是我们传递的size参数，说明在当前的栈中传递参数就会影响到shellcode的布局，可以将ESP增大：

![][8]

由于在恢复EBP时的RETN 4导致在即将增大ESP时，ESP指向的是关闭DEP代码的起始地址：

![][9]

进入关闭DEP的代码，在调用Zw函数即将返回时，可以看到RETN 4返回的会是我们占位的90909090，而且ESP会指向当前shellcode的末尾：

![][10]

因为关闭了DEP的保护，我们可以在90909090的位置填充为JUMP ESP的地址，然后在末尾加上一个回跳的指令转而去执行我们栈上的payload，布局如下：

![][11]

这里就和书中的布局相同了，但在编译执行后还是有内部的异常，因为这里ESP又指向了我们的shellcode附近，所以在回跳之前尝试再次增大ESP，如果使用 ADD ESP, 0x100等指令会引入\x00字节，但是我们也可以SUB ESP, -512做一个负数的减法，而且负数用补码表示就不会有\x00字节了。一开始减去-512还是有异常，最后干脆减去-1024就ok了，最终shellcode如下：

![][12]

Exploit效果如图：

![][13]

# 0x02 Ret2Libc实战之利用VirtualProtect

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <Windows.h>

char shellcode[] = …;

void test()
{
	char dest[240];
	memcpy(dest, shellcode, 600);
}


int _tmain(int argc, _TCHAR* argv[])
{
	HINSTANCE hInst = LoadLibrary(_T("shell32.dll"));
	char str[400];
	test();
	return 0;
}
{% endhighlight %}

实验代码中加载shell32.dll依旧是为了提供可使用的跳转字节码，未使用的字符数组也是为了抬升栈底，由于在利用VirtualProtect函数中不可避免\x00，所以使用memcpy函数造成溢出，为了利用236字节的payload，这里的缓冲区大小都比书中的大一些。

书中的操作系统环境是windows 2003，所以我这里还需要知道VirtualProtect函数的地址，使用vs自带的工具查看kernel32.dll的导出函数：`C:\Program Files\Microsoft Visual Studio 10.0\VC>dumpbin /exports "C:\Windows\System32\kernel32.dll"`：

![][14]

在相关偏移处看到VirtualProtect的内部逻辑和书中的例子一致：

![][15]

在test函数返回时会pop ebp，所以一开始还是需要push esp pop ebp retn 4修复ebp，然后esp指向ebp+8，而且在此之后ebp的值都不会被改变，我们就可以更改ebp+8~ebp+14的值，然后转入VirtualProtect的逻辑即可：

![][16]

因为ebp+8传入的是lpAddress的参数，所以使用retn和push esp去压入当前esp的值到ebp+8，以便更改后续payload的执行属性：

![][17]

push esp后加上jmp eax 即pop pop pop rent指令来越过硬编码的ebp+c和ebp+10参数，然后再利用相同的方法push esp jmp eax来把当前esp压入ebp+14处的参数，pop pop pop retn后转入VirtualProtect内部执行：

![][18]

由于末尾的pop ebp和retn 10在计算好偏移后，最后来个jump esp即可转入payload的位置去执行了，由于这里的ebp的位置始终不变而且通过ret2libc的方式跳转esp去执行payload，esp的变化在大脑中也很好复现，shellcode的布局就不细化了，最终exploit的效果如下：

![][19]

[1]: http://ojyzyrhpd.bkt.clouddn.com/20171031/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20171031/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20171031/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20171031/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20171031/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20171031/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20171031/7.png
[8]: http://ojyzyrhpd.bkt.clouddn.com/20171031/8.png
[9]: http://ojyzyrhpd.bkt.clouddn.com/20171031/9.png
[10]: http://ojyzyrhpd.bkt.clouddn.com/20171031/10.png
[11]: http://ojyzyrhpd.bkt.clouddn.com/20171031/11.png
[12]: http://ojyzyrhpd.bkt.clouddn.com/20171031/12.png
[13]: http://ojyzyrhpd.bkt.clouddn.com/20171031/13.png
[14]: http://ojyzyrhpd.bkt.clouddn.com/20171031/14.png
[15]: http://ojyzyrhpd.bkt.clouddn.com/20171031/15.png
[16]: http://ojyzyrhpd.bkt.clouddn.com/20171031/16.png
[17]: http://ojyzyrhpd.bkt.clouddn.com/20171031/17.png
[18]: http://ojyzyrhpd.bkt.clouddn.com/20171031/18.png
[19]: http://ojyzyrhpd.bkt.clouddn.com/20171031/19.png
