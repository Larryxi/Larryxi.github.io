---

title: "Binexp 逆向分析初体验"

date: 2017-07-25

---

# 0x00 前言

怎么着都得去学习接触二进制，才能算是踏入安全的领域，所以就跟着[Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)加强一下学习，主要还是以探究做练习为主，争取不拖团队后腿。（本次练习的题目是课程前四周涉及的内容）

# 0x01 Crackme

在crackme0x00a中直接加载进入IDA，主要逻辑为输入密码并判断正误，牛刀小试。

![][1]

在crackme0x00b中，程序和0x00a类似，不过是使用_wcscmp来比较字符串，但在scanf中也有%ls修饰输入为宽字节，在Linux-x86下为utf-32编码，直接跟进看是哪些字符就好：

![][2]

不仔细的话就会先入为主被IDA的注释给坑了，也可以在hex-view查看相关数据：

![][3]

crackme0x01则是比较输入的数字，同样easy：

![][4]

Crackme0x02进行了一下加法和乘法的运算：

![][5]

Crackme0x04也是先输入一段字符串，然后调用check函数，check检测字符串的长度是否为15就ok了：

![][6]

Crackme0x03的前半段逻辑一样，进行加法和乘法的运算后，调用test(int(s),338724)函数，很明显输入相等即可成功：

![][7]

不过这里将输出“加密”了一下，跟进shift函数：

![][8]

所以将字符统一前移3位即可显形。

Crackeme0x05中输入字符串后调用check函数：

![][9]

Check函数检测输入的各个字符上的数字之和是否为16，再决定调用parell函数与否，在parell函数中：

![][10]

将输入的数字和1按位相与，数值不是奇数即可pass：

![][11]

Crackme0x06和逻辑和0x05类似，都有check和parell函数，并且传入了程序启动时的envp参数，并在parell函数中增加了dummy函数：

![][12]

只有dummy函数返回真值，并且输入的数字各个位数和为16且不是奇数才算成功。在dummy函数中：

![][13]

在函数调用伊始，栈中布局为EBP,RETURN ADDRESS, int(s),envp，所以说ebp+arg_4即ebp+0Ch指向的就是envp。那么函数的逻辑就显而易见了，循环环境变量数组，如果有”LOL”开头的环境变量就返回1，否则返回0。

我们允许程序前添加对应的环境变量，再按0x05的套路来就crack了：

![][14]

Crackme0x07的逻辑和0x06类似，不过要求各个位数和为24，而且传入的参数变为arg_8，应该和linux下程序的启动有关，可见[这里](http://www.jianshu.com/p/eb39eac9d82e)：

![][15]

其他的按部就班就好：

![][16]

Crackme0x08和0x07一样：

![][17]

Crackme0x09和0x08一样，就不赘述了。

# 0x02 Lab

Lab1程序开始初始化var_1，然后就是常规的让我们输入密码判断正确性：

![][18]

之后的流程如下图：

![][19]

loc_804853E和loc_8048539处的代码可以理解为一直循环到输入字符串的末尾，然后每个字符都进入loc_80484FF的比较逻辑，如果每个字符都满足`s[var_1] == var_1 ^ storedpass[var_1]`，那就是妥妥的成功了。所以就有：

![][20]

Lab2的验证流程和Lab1类似，也是将存储好的字符串进行一定的变换，再和我们输入的密码比较是否相符：

![][21]

从汇编代码来看其中可能是进行了一个除法的操作，在计算出MagicNumber后可以得到关键的比较逻辑`if(i+1)^storedpass[i] == s[i])`，对应还原即可：

![][22]

Lab3的主要逻辑是需要我们输入长度大于5的用户名，然后逆向出相应的序列号才算成功，汇编上的表现就是将内部生成的序列号和我们输入的进行对比：

![][23]

其中dword_804A034处保存的是我们输入的序列号：

![][24]

dword_804A038处保存的是内部算法生成的序列号：

![][25]

遇到的第一个坑就是这里不知道dword_804A038的初始值，在经历了patch程序去除ptrace的反调试又载入gdb没有相应的符号表和IDA远程调试无法attach程序后，最终还是知道了.bss段的存在，dword_804A038在程序中是全局变量的存在，所以其初始值为0：

![][26]

那么一切都很完美了，按照代码的逻辑即可计算出相应的序列码，可是'larry'对应的468总是不对，而偶然尝试的'00000'对应的序列码0又是成立的，很是奇怪：

![][27]

隐约感觉到问题还是可能出在` ([dword_804A038] + name[i]) ^ name[(i-1)%strlen(name)]`这一句代码中，于是在参考[这里](http://blog.csdn.net/wjcsharp/article/details/11075993)后，修改了sp的值，再F5看汇编的伪代码，结果和我分析的逻辑是一样的，还是很困惑：

![][28]

最后还是觉得应该从汇编的角度去看，觉得问题可能会存在于汇编的div中，探索一番发现汇编的取余数和C语言及Python的取模还是有区别的。实验一番发现，在Python里-1%5的结果为4，在C语言里-1%5的结果为-1，而从汇编的角度来看第一次异或的值就应该是`name[0xffffffff]%strlen(name)]`，所以'larry'对应的序列号就是297，实验如下：

![][29]

# 0x03 总结

逆向分析C语言相关的题目时，多看看《C++反汇编与逆向分析技术揭秘》这本书也是挺好的，接触得多了也就能肉眼翻译出汇编代码对应的高级语言代码，多看多验证自己的想法总是有益的，对于汇编指令的理解和gdb动态调试方面还需要加强，IDA用得熟练也是必须要做到的。


[1]: http://ojyzyrhpd.bkt.clouddn.com/20170725/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20170725/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20170725/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20170725/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20170725/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20170725/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20170725/7.png
[8]: http://ojyzyrhpd.bkt.clouddn.com/20170725/8.png
[9]: http://ojyzyrhpd.bkt.clouddn.com/20170725/9.png
[10]: http://ojyzyrhpd.bkt.clouddn.com/20170725/10.png
[11]: http://ojyzyrhpd.bkt.clouddn.com/20170725/11.png
[12]: http://ojyzyrhpd.bkt.clouddn.com/20170725/12.png
[13]: http://ojyzyrhpd.bkt.clouddn.com/20170725/13.png
[14]: http://ojyzyrhpd.bkt.clouddn.com/20170725/14.png
[15]: http://ojyzyrhpd.bkt.clouddn.com/20170725/15.png
[16]: http://ojyzyrhpd.bkt.clouddn.com/20170725/16.png
[17]: http://ojyzyrhpd.bkt.clouddn.com/20170725/17.png
[18]: http://ojyzyrhpd.bkt.clouddn.com/20170725/18.png
[19]: http://ojyzyrhpd.bkt.clouddn.com/20170725/19.png
[20]: http://ojyzyrhpd.bkt.clouddn.com/20170725/20.png
[21]: http://ojyzyrhpd.bkt.clouddn.com/20170725/21.png
[22]: http://ojyzyrhpd.bkt.clouddn.com/20170725/22.png
[23]: http://ojyzyrhpd.bkt.clouddn.com/20170725/23.png
[24]: http://ojyzyrhpd.bkt.clouddn.com/20170725/24.png
[25]: http://ojyzyrhpd.bkt.clouddn.com/20170725/25.png
[26]: http://ojyzyrhpd.bkt.clouddn.com/20170725/26.png
[27]: http://ojyzyrhpd.bkt.clouddn.com/20170725/27.png
[28]: http://ojyzyrhpd.bkt.clouddn.com/20170725/28.png
[29]: http://ojyzyrhpd.bkt.clouddn.com/20170725/29.png