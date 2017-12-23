---
layout: post
title: "EyeWitness工具小记"
---

# 0x00 前言

还是在看《黑客秘笈》的时候，比较认同一个观点就是在渗透测试的过程中时间是很重要的，当我们在扫描过一个C段或者是有上百个Web服务需要面对的时候，找到水桶的短板是很最重要的，如果我们人工去一个一个访问判断它是不是武大郎的话就很耗费时间和人力。

所以书里面就使用Peeping Tom（<https://bitbucket.org/LaNMaSteR53/peepingtom/>）这个工具来调用浏览器访问指定的IP和端口，对Web服务进行截图，最后统一汇总到一个页面中，我们就可以挑一些柿子开捏了（Tomcat，JBoss，CMS等一些公开漏洞比较多的框架或软件）。

<!-- more -->

实际上当我来准备下载工具试用了时候，看到了作者已停止更新该软件了，并且向大家推荐了另一个更好的孪生兄弟，EyeWitness（<https://github.com/ChrisTruncer/EyeWitness>）。
 
![][1]

# 0x01 安装

EyeWitness的安装比较简单，看github上的README就可以知道，要求系统是Kali2或者Debian 7+，切换到setup目录直接运行setup.sh脚本就行了。
 
![][2]

# 0x02 使用

帮助选线则是如下所示：

![][3]

虽然从选项中都能知道其具体的功能，但官方也专门写了篇文章（<https://www.christophertruncer.com/eyewitness-2-0-release-and-user-guide/>）进行介绍，就不赘述了。

但是当我在Kali2上安装好之后直接运行却出现如下的报错：

![][4]

一查原因（<http://ju.outofmemory.cn/entry/290716>）应该是firefox的版本太低了，Kali2自带的Iceweasel版本只有38，所以果断卸载装上最新的Firefox（<https://krasnek-andreas.blogspot.com/2014/02/kali-linux-tutorial-ii-remove-iceweasel.html>），最后就可以愉快地玩耍了。
 
![][5]

[1]: http://ojyzyrhpd.bkt.clouddn.com/20161228/1.jpg
[2]: http://ojyzyrhpd.bkt.clouddn.com/20161228/2.jpg
[3]: http://ojyzyrhpd.bkt.clouddn.com/20161228/3.jpg
[4]: http://ojyzyrhpd.bkt.clouddn.com/20161228/4.jpg
[5]: http://ojyzyrhpd.bkt.clouddn.com/20161228/5.jpg
