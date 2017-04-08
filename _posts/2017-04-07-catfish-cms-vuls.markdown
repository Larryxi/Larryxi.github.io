---
title: "Catfish CMS漏洞集合"
date: 2017-04-07
---

# 0x00 背景

* 版本：V 4.2.35
* 官网下载：<http://www.catfish-cms.com/page/4.html>

文章内容仅作学习参考，勿以恶小而为

# 0x01 任意文件删除

拿到一个cms进行安装后，首先比较喜欢看看其安装逻辑，查找有没有在安装流程中直接导致重装的可能性。由于系统是THINKPHP5开发的，所以可以定位到application/install/controller/Index.php为安装的控制器，其中的check函数根据install.lock来保证系统不会被二次安装，如下：

![][1]

不能直接重装的话，就只能借助unlink等函数看能不能删除任意文件进行重装，定位到application/user/controller/Index.php中的编辑头像的逻辑touxiang函数，如下：

![][2]

其中第119~127行调用了unlink函数，意思是上传头像后删除原来的头像图片，具体步骤为：用户在客户端上传完头像后，客户端还会向这个touxiang函数POST新头像的url，然后程序将新url和旧url进行对比，不同的话就把旧url对应的（头像）文件删除，把新url写入到数据库中。

其中POST的url是我们可控的，而且程序也没有对url做任何限制，这样我们就可以删除任意文件乃至重装漏洞了。

那么我们来实际验证一下，首先在网站上注册一个用户，在上传完图片后用burp截获到POST 新url的请求:

![][3]

我们把新url的路径改为install.lock对应的路径再重放过去 ，这样新图片的url就更改了，如下：

![][4]

所以当我们再POST一个新的url，旧的url文件就会被删除了：

![][5]

Install.lock文件被删除，所以导致了重装：

![][6]

当用户上传完图片后，内部逻辑直接更新数据库就好，何必要信任恶意的外来输入呢。

# 0x02 用户评论处xss

由于这个框架的注入不是太好找，那就来看看有没有xss漏洞，首先从application/config.php看到其默认是没有任何过滤的：

![][7]

那么根据用户的操作来定向追踪一下可能存在xss的点，开发者对于修改资料和提交留言处都对输入进行了htmlspecialchars处理，但在用户评论处application/index/controller/Index.php中：

![][8]

开发者直接将post的评论内容插入数据库，这里就有可能导致xss漏洞了。在评论后抓包看一下：

![][9]

开发者只是依据前端来进行过滤，这样的效果甚微，我们还是可以注入xss。在后台页面会直接从数据库拿出前5条评论输出显示，这样我们在提交评论后就可以影响到后台了，证明如下图：

![][10]

# 0x03 任意评论或收藏删除

基于逻辑来寻找漏洞的话，可以看看用户有哪些操作可能导致越权等常规的逻辑漏洞，因此在application/user/controller/Index.php中找到这么一段逻辑:

![][11]

这里未验证身份就可以删除对应id的评论和收藏，而且也没做任何的权限验证，那我们循环跑一遍请求就可删除所有的评论和收藏了。下图中不加sessionid即可删除对应评论：

![][12]

# 0x03 后记

在测试任意文件删除的时候，我本地环境有点问题就直接上官网去测了，一时手快就直接让官网重装了，扰乱了人家的运营有些尴尬，这种敏感文件的操作还是尽量本地或demo站测试比较好。

在审计出任意文件删除后看到一位大牛的博客<http://balis0ng.com/post/dai-ma-shen-ji/2017-03-27> ，审计的同一套系统，比我早三天，也可以拿来学习。

虽说这个CMS是用THINKPHP5框架写的，但是开发者还是没有考虑太多的安全问题，在掌握了框架的一些应用规则后，代码审计的思路都是相通的，多实践才能多知晓。

[1]: http://ojyzyrhpd.bkt.clouddn.com/20170407/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20170407/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20170407/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20170407/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20170407/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20170407/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20170407/7.png
[8]: http://ojyzyrhpd.bkt.clouddn.com/20170407/8.png
[9]: http://ojyzyrhpd.bkt.clouddn.com/20170407/9.png
[10]: http://ojyzyrhpd.bkt.clouddn.com/20170407/10.png
[11]: http://ojyzyrhpd.bkt.clouddn.com/20170407/11.png
[12]: http://ojyzyrhpd.bkt.clouddn.com/20170407/12.png