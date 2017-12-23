---
layout: post
title: "0day安全GS绕过实验"
---

# 0x00 实验环境

* 操作系统：xp sp3
* 编译器：vs 2010
* 编译选项：Release版本；开启GS；关闭函数优化，内部函数，ASLR，DEP，SafeSEH

<!-- more -->

    ![][1]

Exploit过程中我使用的是msfvenom生成的payload，大小一般都大于200字节，所以在实验时构建的exp和书中略有不同，也算是小小的实践。实验过程中会使用msfvenom，msfpescan等工具，如果kali上面没有，可以clone [rex-bin_tools](https://github.com/rapid7/rex-bin_tools)项目安装。

根据msfvenom的[文档](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)，一般会使用以下的命令：

* `msfvenom -l payloads` ：查看要使用哪种payload
* `msfvenom -p windows/exec --payload-options` ：查看生成payload需要设置的选项
* `msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/shikata_ga_nai -b '\x00' -f c -v payload -n 16` ：输出的变量名设置为payload，并且添加16个字节的nop
    ![][2]

在jump esp去执行使用msfvenom生成的payload时，其中的指令会[毁坏堆栈数据](http://www.programlife.net/win32-bind-port-shellcode.html)导致shellcode无法正常执行，所以在生成payload时就直接加上一部分的nop字节，或者在payload开始时就抬高栈顶。

根据msfpescan的文档，一般也会使用msfpescan去寻找pop pop ret指令的地址：

![][3]

# 0x01 GS保护环境

![][4]

需要注意的是：

1. 变量重排的情况
2. arg参数副本的保存可能会在构建exploit时用到

# 0x02 覆盖虚函数

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include "string.h"


class GSVirtual
{
public:
	void gsv(char *src)
	{
		char buf[280];
		strcpy(buf, src);
		vir();
	}

	virtual void vir(){}
};

int _tmain(int argc, _TCHAR* argv[])
{
	GSVirtual test;
	test.gsv(…);
	return 0;
}
{% endhighlight %}

既然我这里是280个字节的buff，那么我就先传入249个\x90试试水，F4 运行到strcpy结束，可以先看看前一个栈帧的情况，this指针也就是指向虚表的地址为0x0040221C，字符串参数的指针为0x00402100，在strcpy结束后如果需要向下溢出覆盖虚表地址则需要20个字节，和书中情况相同：

![][5]

而书中的原始参数位于0x00402100，虚表位于0x004021D0，所以书中shellcode尾部覆盖掉内存中虚表的第一个字节为0x00，虚表就位于0x00402100即可转而去执行原始参数中的payload了。而在我的环境中，使用类似方法虚表地址覆盖为0x00402200，而原始参数位于0x00402100，地址对不上。如果shellcode尾部为\x00\x22\x40，理想上是可以覆盖但实际上出现了0x00无法copy。干脆尾部就定为\x04\x22\x40，前面4个字节用\x90顶上也是可以曲线救国的。

Shellcode头部为\x90\x90\x90\x90\xA9\x1D\x80\x7C后，调用虚函数时即会去call 0x7C801DA9的pop pop ret指令。在调用后的堆栈环境如下：

![][6]

可以看到栈中保存的返回地址是0x0040108F，如果说执行的指令时一般的某个函数指令，那么eip还是会返回至0x0040108F执行，也就不会到0x12FE4C去执行我们的shellcode了。同时也要注意到栈中EBP-130保存的是0x0012FE4C正好指向字符串参数的地址，而此地址正是在gsv函数初始部分保存的arg副本：

![][7]

所以我们在pop pop ret后eip进而去转到0x0012FE4C执行，shellcode的最终布局如下：

![][8]

由于pop pop ret的地址也主要作为指令被执行后才会执行payload，所以这个地址作为指令时不能有任何异常，需要多选取试一下，在我的环境下就是\xA9\x1D\x80\x7C，最终的exploit效果如下：

![][9]

# 0x03 攻击异常处理

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include "string.h"


char payload[] = …;

int test(char *input)
{
	char buf[240];
	strcpy(buf, input);
	strcat(buf, input);

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	test(payload);
	return 0;
}
{% endhighlight %}

这里我直接使用的是220个字节的payload，所以就定义了240个字节的buff，依旧使用239个字节的\x90试水，F4 运行至strcpy结束，观察当前栈帧情况：

![][10]

既然我们这里是覆盖SE handler的地址转而执行我的shellcode，那就按照书中的方法将其覆盖为栈中shellcode的起始地址0x0012FE78，剩余部分使用\x90填充，但再次运行后不能弹出计算器。无奈之下只好和正常的SHE处理流程对比，一步步跟踪调试，发现在进行异常处理的过程中会检测handler的地址是否是处于栈空间当中，如果是的话就会跳转至另一个分支而不会执行handler：

![][11]

如果把SE handler的地址覆盖为shellcode在.data段的地址0x00403018，判断通过就可以执行我们的shellcode了：

![][12]

如果说想要shellcode更加通用一点，我们可以继续观察在即将调用我们覆盖的SE handler时：

![][13]

这里传入的四个参数，即为调用_except_handler时传入的参数，其中第二个参数的值0x0012FFB0即是SHE结构中的PEXCEPTION_REGISTRATION_RECORD指针，如果我们把Handler的地址覆盖为pop pop ret那么eip正好会转回我们shellcode的范围里，所以我们shellcode的布局大致可以设定为：

![][14]

在pop pop ret后转而再想把Next覆盖成一个jump short的机器码，但是在调试过程中发现在异常处理时又有其他的检测跳转分支导致不能执行覆盖掉的handler，加上之前handler地址是否在栈空间的检测，结合后面safeSEH的内容才发现这里编译出来的可执行文件还是打开了safeSEH。可恶，这里只能以后再解决了。

# 0x04 同时替换栈中和.data的Cookie

实验代码和书中相似：

{% highlight c %}
#include "stdafx.h"
#include <string.h>
#include <stdlib.h>

char shellcode[] = …;

void test(char *s, int i, char *src)
{
	char dest[240];
	if(i<0x9995)
	{
		char *buff = s+i;
		*buff = *src;
		*(buff+1) = *(src+1);
		*(buff+2) = *(src+2);
		*(buff+3) = *(src+3);
		strcpy(dest, src);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	char *str = (char *)malloc(0x10000);
	test(str, 0xFFFF2FB8, shellcode);
	return 0;
}
{% endhighlight %}

依旧240个字节的\x90试水之后，发现Security_Cookie已被我们覆盖为0x90909090，ebp的值为0x0012FF64，我们只需向下溢出16个字节就可以覆盖返回地址：

![][15]

由于在函数返回后esp会指向0x0012FF6C，而在主函数中调用test函数时cdecl调用传参，所以如果返回地址为pop pop ret，那么程序最终会转向shellcode地址去执行，shellcode布局构造如下：

![][16]

Exploit效果如下：

![][17]

# 0x05 总结参考

1. safeSEH和编译选项以及操作系统的关系还没理清楚，还需要后续学习safeSEH的绕过。
2. 栈中参数的副本和cdecl的传参方式，结合pop pop ret食用效果更佳。
3. 相关参考：
    * <http://blog.nsfocus.net/tutorial-overflow/>
    * <http://papap.info/2016/03/29/%E5%9C%A8%E6%A0%88%E4%B8%AD%E5%88%A9%E7%94%A8SEH/>

[1]:http://ojyzyrhpd.bkt.clouddn.com/20170919/1.png
[2]:http://ojyzyrhpd.bkt.clouddn.com/20170919/2.png
[3]:http://ojyzyrhpd.bkt.clouddn.com/20170919/3.png
[4]:http://ojyzyrhpd.bkt.clouddn.com/20170919/4.png
[5]:http://ojyzyrhpd.bkt.clouddn.com/20170919/5.png
[6]:http://ojyzyrhpd.bkt.clouddn.com/20170919/6.png
[7]:http://ojyzyrhpd.bkt.clouddn.com/20170919/7.png
[8]:http://ojyzyrhpd.bkt.clouddn.com/20170919/8.png
[9]:http://ojyzyrhpd.bkt.clouddn.com/20170919/9.png
[10]:http://ojyzyrhpd.bkt.clouddn.com/20170919/10.png
[11]:http://ojyzyrhpd.bkt.clouddn.com/20170919/11.png
[12]:http://ojyzyrhpd.bkt.clouddn.com/20170919/12.png
[13]:http://ojyzyrhpd.bkt.clouddn.com/20170919/13.png
[14]:http://ojyzyrhpd.bkt.clouddn.com/20170919/14.png
[15]:http://ojyzyrhpd.bkt.clouddn.com/20170919/15.png
[16]:http://ojyzyrhpd.bkt.clouddn.com/20170919/16.png
[17]:http://ojyzyrhpd.bkt.clouddn.com/20170919/17.png
