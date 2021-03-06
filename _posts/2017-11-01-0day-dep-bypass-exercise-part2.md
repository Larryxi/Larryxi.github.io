---
layout: post
title: "0day安全DEP绕过实验（下）"
---

# 0x00 实验环境

* 操作系统：xp sp3
* 编译器：vs 2010
* 编译选项：Release版本；开启DEP，关闭GS，SafeSEH，ASLR

<!-- more -->

# 0x01 Ret2Libc实战之利用VirtualAlloc

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

这个实验主要是利用VirtualAlloc函数分配一段可执行的内存空间，然后使用memcpy函数把payload片段复制过去进而执行。依旧查看kernel32.dll的导出函数VirtualAlloc位于9AE1偏移处，内如逻辑如下：

![][1]

VirtualAlloc要求传入的参数都是硬编码即可，所以在test函数返回后push esp pop ebp retn 4后，即可安排ebp+8~ebp+14为对应的参数，然后跳转至VirtualAlloc内部执行，shellcode暂且布局为：

![][2]

跟进到要调用函数时，栈环境已经被我们安排好了：

![][3]

函数调用成功后就分配了一块可执行内存，接下来要做的就是使用memcpy函数，安排栈环境把payload复制过去。Memcpy中需要参数目的地址和复制大小都是我们已经确定的，源地址还要我们来动态确定，只要源地址在payload位置之前即可，因此可以使用push esp jmp eax来填充这个参数。由于在VirtualAlloc的末尾会pop ebp retn 10，所以还需要回复ebp以便后续利用memcpy，调整布局如下：

![][4]

在即将恢复好ebp后，我们可以看到esp会掉到ebp+8：

![][5]

而在memcpy函数的内部，ebp+8指向的是目的地址，ebp+c指向的是源地址，ebp+10指向的是复制长度。如果想在ebp+c中放入esp的值就需要在ebp+10中push esp，所以要让esp掉到ebp+10就可以使用pop retn，然后在ebp+10处放置的为push esp jmp eax，这样ebp+c处就为当前esp的值了，同时为了向下跨越8个字节调用memcpy，在eax中就可以设置为pop pop retn，最终布局如下：

![][6]

最后可见memcpy在即将返回时，正好会跳转至我们\x90填充的字节，如果更改为我们开辟的内存地址空间就可以转而去执行复制的payload了：

![][7]

由于我这里的payload是有16字节的nop填充，所以在memcpy之后碰巧没有出现异常情况，也就不用像书中那样微调一下payload了，最后exploit的效果如下：

![][8]

# 0x02 利用可执行内存跳转DEP

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
	VirtualAlloc((LPVOID)0x003d0000, 0x00001000, 0x00001000, 0x40);
	char str[400];
	test();
	return 0;
}
{% endhighlight %}

需要说明的是书中直接使用0x140000的可执行地址去memcpy，然而我也不知道这块RWE的地址是怎么来的，就在main函数中自己先VirtualAlloc了一块RWE地址，由于可执行地址我们有了，所以利用方法和上一个实验相似，只需要把payload memcpy过去就行了，最终exploit的效果如下：

![][9]

[1]: https://wx2.sinaimg.cn/large/ee2fecafgy1foqs9yla73j20em03rweg.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafgy1foqsa10jnaj20ct04gdfq.jpg
[3]: https://wx3.sinaimg.cn/large/ee2fecafgy1foqsa4av0qj20z808xaaw.jpg
[4]: https://wx3.sinaimg.cn/large/ee2fecafgy1foqsa5om51j20g906qaa2.jpg
[5]: https://wx2.sinaimg.cn/large/ee2fecafgy1foqsa7nrggj20vd07ajrx.jpg
[6]: https://wx4.sinaimg.cn/large/ee2fecafgy1foqsa91rcuj20ga09gaa6.jpg
[7]: https://wx4.sinaimg.cn/large/ee2fecafgy1foqsaav0gjj210309kq3x.jpg
[8]: https://wx3.sinaimg.cn/large/ee2fecafgy1foqsacpkb7j20l90ar3z8.jpg
[9]: https://wx3.sinaimg.cn/large/ee2fecafgy1foqsaele4vj20kh08x0tf.jpg
