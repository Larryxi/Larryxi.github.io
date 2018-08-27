---
layout: post
title: "0day安全safeSEH绕过实验"
---

# 0x00 实验环境

* 操作系统：xp sp3
* 编译器：vs 2010
* 编译选项：Release版本；关闭优化，DEP，ASLR

<!-- more -->

# 0x01 从堆中绕过

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include <string.h>
#include <stdlib.h>

char shellcode[] = …;

void test(char *input)
{
	char str[240];
	strcpy(str, input);
	int zero=0;
	zero = 1/zero;
}

int _tmain(int argc, _TCHAR* argv[])
{
	char *buf=(char *)malloc(500);
	__asm int 3
	strcpy(buf, shellcode);
	test(shellcode);
	return 0;
}
{% endhighlight %}

240个字节试水后，malloc在堆上分配的地址为0x00393F48，strcpy之后还需要100字节才能覆盖到SE handler，而safeSEH不会校验指向堆中的指针，所以构造shellcode布局如下：

![][1]

轻松exploit：

![][2]

# 0x02 利用未启用SafeSEH模块绕过

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include <string.h>
#include <Windows.h>

char shellcode [] = …;

DWORD MyException(void)
{
	printf("This ia an exception");
	getchar();
	return 1;
}

void test(char * input)
{
	char str[240];
	strcpy(str, input);
	int zero=0;
	__try
	{
		zero =1/zero;
	}
	__except(MyException())
	{
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	HINSTANCE hInst = LoadLibrary(_T("SEH_NoSafeSEH_JUMP.dll"));
	//char str[240];
	__asm int 3
	test(shellcode);
	return 0;
}
{% endhighlight %}

起初在main函数中开辟的数组感觉没有就先注释掉了。240字节试水，strcpy后栈帧环境如下：

![][3]

向下溢出20个字节即可覆盖SE Handler，在这里使用的是和书中相同的没有开启safeSEH的dll文件中的pop pop ret地址0x11121068。在调试过程中发现dll编译链接不成功，原来是书中代码少包含了windows.h头文件。另一处是__asm int 3调用olldbg去调试时，发现总是无法加载插件，在Appearance中指定一下插件目录就可以了：

![][4]

所以利用方式和前文绕过GS中探究的类似，将SE handler覆盖为pop pop ret地址，eip会转到0x0012FF5C去执行，其后再接上我们的payload就可以了，shellcode布局如下：

![][5]

这样的布局在调试后会发现，就算payload的起始copy地址为0x0012FF60，一直到栈空间的末尾也才160个字节，无法完全复制236字节的payload，而且也会产生异常。所以在main函数中字符数组str[240]的定义实际上就是为了抬高栈顶，让后面有足够的空间strcopy我们的shellcode，最终exploit效果如下：

![][6]

# 0x03 利用加载模块之外的地址绕过

实验代码和书中类似：

{% highlight c %}
#include "stdafx.h"
#include <string.h>
#include <Windows.h>

char shellcode [] = …;

DWORD MyException(void)
{
	printf("This ia an exception");
	getchar();
	return 1;
}

void test(char * input)
{
	char str[240];
	strcpy(str, input);
	int zero=0;
	__try
	{
		zero =1/zero;
	}
	__except(MyException())
	{
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	//__asm int 3
	test(shellcode);
	return 0;
}
{% endhighlight %}

这个实验的内容和前一个实验的内容也相似，也是覆盖SE handler的地址，因为这里找的是模块之外的跳板地址，所以safeSEH就起不到作用了。通过ollyfindaddr找到的是位于0x00280b0b的指令call [ebp+0x30]，而这个[ebp+0x30]指向的刚好就是Pointer to next SHE record的地址：

![][7]

Next指针处就和书中的一样填充为一个短跳的指令\xeb\xf6\x90\x90（短跳的字节码为\xeb，\xf6为-10的补码），短跳之后在接一个近跳（\xe9）的指令，因为近跳指令地址和shellcode在栈中的起始地址相差253个字节，所以近跳后接的16位位移为\xff\xff\xff\x03：

![][8]

最终shellcode布局如下：

![][9]

这种短跳结合近跳的方法也适用于上一个实验的shellcode构建（就不用开始的抬高栈顶了），所以exploit效果如下：

![][10]

# 0x04 利用Adobe Flash Player ActiveX控件绕过

这里就是借助未开启SafeSEH的Flash Player ActiveX控件，在具有溢出漏洞中的AxtiveX控件中，覆盖SE handler地址，利用未启用SafeSEH来模块中的跳板地址来绕过。实验中也是因为程序会对栈中数据有些破坏，所以就用短跳指令去执行payload，思路大体都是类似的，详见他人的实践：<http://www.freebuf.com/articles/web/149886.html>，我就不赘述啦。

[1]:http://ojyzyrhpd.bkt.clouddn.com/20171022/1.png
[2]:http://ojyzyrhpd.bkt.clouddn.com/20171022/2.png
[3]:http://ojyzyrhpd.bkt.clouddn.com/20171022/3.png
[4]:http://ojyzyrhpd.bkt.clouddn.com/20171022/4.png
[5]:http://ojyzyrhpd.bkt.clouddn.com/20171022/5.png
[6]:http://ojyzyrhpd.bkt.clouddn.com/20171022/6.png
[7]:http://ojyzyrhpd.bkt.clouddn.com/20171022/7.png
[8]:http://ojyzyrhpd.bkt.clouddn.com/20171022/8.png
[9]:http://ojyzyrhpd.bkt.clouddn.com/20171022/9.png
[10]:http://ojyzyrhpd.bkt.clouddn.com/20171022/10.png
