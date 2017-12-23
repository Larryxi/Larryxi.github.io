---
layout: post
title: "NmapRecordSearch && MSSQL-SQLi-Labs 初步开发小结"
---

# 0x00 前言

皮之不存毛将焉附，没有编程的积累也就谈不上是在搞安全了。出于学习和练习编程的目的，之前开发了两个小的项目，都是初步开发还有许多不足要去改善，现将其中的要点记录下来，这两个项目都可以在我的Github上找到：NmapRecordSearch && MSSQL-SQLi-Labs。

<!-- more -->

# 0x01 NmapRecordSearch

这个Nmap结果导入搜索系统是受启发于《黑客秘笈》这本书，我们在实际进行渗透测试时，面对大量的端口扫描结果，我们就需要从其中的短板入手，快速搜索和利用弱点服务就在渗透测试中起着很关键的作用。系统是用经典的bootstrap+php+mysql搭建的，其中的设计要点如下：

1. 在数据库设计方面，我分了三个数据库表：scan_list记录每一次扫描的原信息，包括制定的project name和id；host_list包含每个host的详细的端口扫描结果；port_list包含每个端口对应的服务名，服务产品，便于后面的搜索。
2. 在php代码层面写了一个install的脚本，还有about、record和search页面：record页面可以上传nmap扫描的XML结果并显示，search界面可以指定不同的搜索类型并查看某一ip详细的端口扫描结果：
    ![][1]
3. 在前端方面我则是使用bootstrap搭建了一下，凑合着还能看：
    ![][2]

后续需要改进的有一下三点：

1. 需要加上用户登录，打算搞成一个多用户协助的系统
2. 代码只是在功能上实现了自己使用的一些功能，安全方面需要加固
3. 还需要面对对象来编程

# 0x02 MSSQL-SQLi-Labs

这个系统相对于原版的php+mysql架构，用的则是asp+mssql 2000。数据库和代码逻辑层面也大多数是仿造的原版本，而且由于时间精力等原因也是只开发了前面的20关。

![][3]

asp和php在本质上还是有区别的，所以在开发过程中遇到了一下几个关键点：

1. 首先就是asp的整体代码编写逻辑，由于asp不支持动态包含文件我只能重复改写多套前端模板；而且对于数据库的报错特性，我只能先设置捕获陷阱，当有报错时再把错误信息写入到页面中：
    ![][4]
2. 由于使用到Recordset，不能简单地取出某一列来判断SQL语句是否有查询出结果，而是需要同时判断BOF和EOF才更加合理：
    ![][5]
3. 还有就是由于在SQL Server 2000中QUOTED_IDENTIFIER 为 ON 时，双引号只能用于分隔标识符，不能用于分隔字符串，所以我在某些关卡中进行了替换。

虽然这个系统是属于练习的弱点系统，但真正有价值的地方还是在于练习的过程，也要抽空好好学习一下。

[1]: http://ojyzyrhpd.bkt.clouddn.com/20170111/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20170111/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20170111/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20170111/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20170111/5.jpg
