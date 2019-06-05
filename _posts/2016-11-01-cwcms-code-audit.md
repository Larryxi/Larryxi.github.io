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


[1]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qptd89ycj20tv0i2413.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qptdxstxj211j08fjtg.jpg
[3]: https://wx1.sinaimg.cn/large/ee2fecafly1g3qptfcpcjj20qn0bejtx.jpg
[4]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qptfpc7pj210n08ajrp.jpg
[5]: https://wx2.sinaimg.cn/large/ee2fecafly1g3qptgjfijj20tu0f576v.jpg
[6]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qpth50asj20qw0ctgn1.jpg
[7]: https://wx4.sinaimg.cn/large/ee2fecafly1g3qpthkiq7j20hl05haag.jpg
