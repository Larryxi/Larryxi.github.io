---
title: "XerCMS文件名注入与垂直越权漏洞"
date: 2017-04-20
---

# 0x00 背景

* 版本：1.0.3
* 下载地址：<http://www.xercms.com/?p=analysis&e=down&file=2015%2fXerCMS-1.0.3[Release].rar>

# 0x01 前台用户上传文件名注入

这个CMS也是自己实现的一种MVC框架，在主文件index.php中可以看出，主要是由XerCMS/Kernel.php来负责将请求路由到对应的Model进行action的处理。

全局代码看下来在用户操作的文件中，即XerCMS/Modules/member/index.php中有一个upfiles函数，如下：

![][1]

该函数在页面中并没有展示出来，还是一个文件上传的操作，可以看到其在111行实例化upload class并调用files方法进行文件的上传。

跟进其中的逻辑在XerCMS/Library/XerCMS_upload.php中，如下：

![][2]

具体在file方法中，首先获取上传文件的后缀，进行黑名单`array('php','asp','aspx','vbs','bat','asa')`的检测，这里很明显的黑名单不完全，配合一些服务器的解析漏洞是可以直接拿shell的，也就不细说了。然后80行对文件进行记录后就进行上传的操作。

跟进record方法，如下：

![][3]

在第145行，把文件名未经过滤就插入到数据库当中，而在数据库中insert的逻辑如下（XerCMS/Library/XerCMS_db.php）：

![][4]

![][5]

可以看出其中的insert的值是未经过滤就插入，这里就可以使用报错注入来获取相关数据了。

简单写个本地post file的html，如下：

{% highlight html %}
<!DOCTYPE html>
<html>
<head>
    <title>test</title>
</head>
<body>
<form action="http://demo.xercms.com/index.php?m=member&a=upfiles&id=1" method="post" enctype="multipart/form-data">
    <input type="file" name="larry" />
    <input type="submit" name="submit" value="Submit" />
</form>
</body>
</html>
{% endhighlight %}

然后burp抓包修改文件名即可进行注入，demo演示如下：

![][6]

# 0x02 用户垂直越权更改group

这个问题是出现在用户操作中的profilePost函数，旨在是用户更新自己的profile，如下：

![][7]

在这里对传入参数的值有过滤，在数据库脚本中对键也有验证，sql注入的可能性就不大了，但是我们可以使用正常的字段来更改用户所属的group，演示如下：

![][8]

更改group字段后，用户所属组就会从“路人甲”变成“内部组”，个人感觉具体利用起来可能还是有些鸡肋的。

# 0x03 后记

一开始在补天看到是这个cms又出来一个SQL注入，想也去找一找有没有其他的注入漏洞，但是自己看了半天还是前人已经挖过的漏洞(<https://www.ihonker.org/thread-9279-1-1.html>)。道行不够还是得多补补==

[1]: http://ojyzyrhpd.bkt.clouddn.com/20170420/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20170420/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20170420/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20170420/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20170420/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20170420/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20170420/7.png
[8]: http://ojyzyrhpd.bkt.clouddn.com/20170420/8.png
