---
layout: post
title: "大米CMS两处代码逻辑漏洞"
---

# 0x00 背景

* 版本：5.5.2 试用版
* 下载链接：<http://www.damicms.com/Down>

<!-- more -->

# 0x01 订单数量为负数可提现

大米CMS提供了会员在线购物的模块，在测试支付逻辑漏洞的时候，可以看看其支付的逻辑代码。大米CMS有三种支付方式：支付宝支付，货到付款和站内支付，在Web/Lib/Action/MemberAction.class.php中的585到641行为站内付款的代码逻辑，大致如下：

![][1]

在第594行中，接收到商品的数量`$_POST['qty']`后没有检查其是否大于0就intval然后乘以价格加到总费用当中，最后在629行进行数据库操作完成站内余额的扣款。

在这里我们就可以在生成订单时，传入负数的商品数量，不仅可以买到对应的产品，而且站内余额在减去负数后反而会增加，借助网站的提现功能即可提取增加的金额，官网demo演示如下：

![][2]

相应的站内余额增加，可以提现：

![][3]

修复意见自然就是在生成订单时校验商品数量是否大于0。

# 0x02 array_walk_recursive函数误用可导致XSS

在涉及用户的操作中，全系统跟踪下来一共有两处的安全防御，第一处就是在入口文件index.php中包含的php_safe.php文件，其主要是对sql注入的payload进行匹配退出；第二处就是位于Web/Lib/Action/BaseAction.class.php的初始化函数，如下：

![][4]

其中第20~24行的代码逻辑是想对POST数组使用array_walk_recursive函数进行过滤。而array_walk_recursive的文档如下：

![][5]

其中的回调函数的第一个参数必须为变量的引用才能达到过滤其数组的作用。

在这里，自定义的inject_check函数也是正则匹配到注入的payload就退出程序，影响也不大。而自定义的remove_xss函数传入的也不是对参数的引用，如下：

![][6]

htmlspecialchars函数就更不用说了，而且htmlspecialchars函数不支持传入两个参数。综上所述，只要程序依赖于内部的过滤规则，对用户POST提交数据存储就有可能造成存储型XSS攻击。

举个例子就还是在用户操作中，在修改资料时对一些敏感的POST变量unset后就直接插入数据库，这样是可以造成xss攻击的，如下：

![][7]

那么我们在用户资料处随便加入一个xss payload，后台查看时即可触发，演示如下：

![][8]

当然在0x01中订单提交后一些信息也是直接那POST数据插入到数据库当中，也是有可能造成存储型XSS的，就不一一测试了。

修复意见就是参考官方文档合理正确地使用array_walk_recursive函数，或者完善过滤逻辑。

[1]: https://wx4.sinaimg.cn/large/ee2fecafly1g3qpfbyu8pj20pq0i3ta1.jpg
[2]: https://wx1.sinaimg.cn/large/ee2fecafly1g3qpfdlqy9j20w70hjjub.jpg
[3]: https://wx2.sinaimg.cn/large/ee2fecafly1g3qpfel60lj20ug0ew0tt.jpg
[4]: https://wx2.sinaimg.cn/large/ee2fecafly1g3qpffaermj20n00byaah.jpg
[5]: https://wx4.sinaimg.cn/large/ee2fecafly1g3qpfftvp3j20o90gvwfk.jpg
[6]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qpfg9yjdj20oy09x0t8.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1g3qpfgpbc9j20ik0b2mxr.jpg
[8]: https://wx4.sinaimg.cn/large/ee2fecafly1g3qpfhh6uxj210t0fwgoe.jpg
