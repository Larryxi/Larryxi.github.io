---
layout: post
title: "CwCMS简单代码审计实践"
---

# 0x00 背景

代码简介：创文企业网站管理系统PHP版（简称CwCMS），采用PHP+MySQL版···在站长之家上的下载地址为：<http://down.chinaz.com/soft/38317.htm>。该CMS代码量比较少，写得也比较简单，下面就从安全的角度对其审计一番。

<!-- more -->

# 0x01 注入后台绕过

admin/index.php处，直接将POST数据带入sql语句，无任何过滤，导致可注入直接登录后台：

![][1]

对应的cw_admin表中有4列，所以直接union控制对应的密码MD5，轻松登录：

![][2]

# 0x02 无身份认证垂直越权

这个cms在登录了之后就直接信任当前用户，随便看一个admin/cw_user.php增加管理员的功能：

![][3]

在开头没有经过身份再次认证就直接开始代码逻辑，所以可导致垂直越权，直接访问对于url也能增加管理员：

![][4]

# 0x03 上传文件无验证getshell

在admin/info.php的功能中有上传图片的地方，上传处理的代码位于admin/upload.php：

![][5]

这里也没有身份认证就不提了，对于图片的上传没有限制扩展名，只是验证了MIME类型，很基本的就getshell了：

![][6]

验证一下执行命令：

![][7]

[1]: http://ojyzyrhpd.bkt.clouddn.com/20161101/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20161101/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20161101/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20161101/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20161101/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20161101/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20161101/7.png