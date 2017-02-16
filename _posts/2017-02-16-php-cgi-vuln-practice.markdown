---
title: "php-cgi 默认配置解析漏洞实践"
date: 2017-02-16
---

# 0x00 背景

中午看到[P牛](https://www.leavesongs.com/)20分钟拿下WebShell很是崇拜，大家问其究竟得知是`xxx.jpg/.php`被解析成php脚本轻松拿下，抱着自愧不如的心理来学习一下。

* <http://www.80sec.com/nginx-securit.html>
* [Nginx(PHP/fastcgi)的PATH_INFO问题](http://www.laruence.com/2009/11/13/1138.html)
* [Nginx + PHP CGI的一个可能的安全漏洞](http://www.laruence.com/2010/05/20/1495.html)
* [Setting up PHP-FastCGI and nginx? Don’t trust the tutorials: check your configuration!](https://nealpoole.com/blog/2011/04/setting-up-php-fastcgi-and-nginx-dont-trust-the-tutorials-check-your-configuration/)

上面的链接主要阐述的是，在Nginx服务器上由于PHP的cgi.fix_pathinfo默认为开启状态，加上Web服务器上没有对应地安全处理最终导致解析漏洞的发生。

# 0x01 实践

这个漏洞从10年被发现，而如今我测试的php-5.6.25版本中cgi.fix_pathinfo仍为默认开启状态，由于Web安全是个贯穿性的整体，下面就从不同平台上的Web服务器进行测试实践。

## Windows 平台

在Windows平台上，运维者如果在搭建好环境后在实际环境中使用默认配置，将请求未做处理就传入php的fastcgi，解析问题就随之而来了。

### Nginx

参考[这里](http://blog.qiji.tech/archives/3092)搭建好环境，测试漏洞存在：

![][1]

### IIS

IIS服务器在[搭建](http://www.cnblogs.com/haocool/archive/2012/10/14/windows-8-iis-to-configure-php-runtime-environment.html)好后，使用fastcgi模块处理php脚本，同样存在问题：

![][2]

## Linux 平台

在Linux平台下我直接是Ubuntu apt-get 安装的nginx、php和php5-fpm，首先是随便请求一个php文件，浏览器中响应如下：

![][3]

像这种只是响应很简单的body而不是nginx的404页面，很有可能说明是直接将请求传递到了fastcgi中。（Widnwos平台上也是类似的道理）

可是在访问`http://192.168.1.124/larry.txt/.php`页面时出现了`Access denied.`信息拒绝访问，查看error日志和Google一番之后得知php在5.3.9版本中对php-fpm添加了[security.limit_extensions](https://bugs.php.net/bug.php?id=55181)选项，防止Web服务的错误配置而带来的php代码执行。所以我在`/etc/php5/fpm/pool.d/www.conf`中添加`security.limit_extensions = .php .txt`，再重启php5-fpm就能复现解析漏洞了：

![][4]

# 0x02 感悟

探究这个漏洞久了总感觉似曾相识，最后才恍然大悟是看过的[Upload_Attack_Framework](http://172.16.24.178/www.owasp.org.cn/OWASP_Training/Upload_Attack_Framework.pdf)中的内容，当初理解实践地不够深入现在只能再慢慢还了。对比之下我这个探究也“自愧不如”了。

在Google过程中发现orange大牛在hitcon大会演讲的ppt中也有提到过该问题的相关思考，其中针对某种防御形式的绕过也是蛮有意思的，有兴趣的同学可以[瞅瞅](https://hitcon.org/2015/CMT/download/day1-c-r0.pdf)。

比较有意思的是发现在国内某个比较火的php环境集成软件中，也有一键化部署nginx+php的环境，而其中的默认配置不可避免地会被拿下，结合浏览器的关键字
搜索和对应存在上传图片的网站，这样我也能够“20分钟”轻松拿下了：

![][5]

[1]: http://ojyzyrhpd.bkt.clouddn.com/2017/02/16/1.jpg
[2]: http://ojyzyrhpd.bkt.clouddn.com/2017/02/16/2.jpg
[3]: http://ojyzyrhpd.bkt.clouddn.com/2017/02/16/3.jpg
[4]: http://ojyzyrhpd.bkt.clouddn.com/2017/02/16/4.jpg
[5]: http://ojyzyrhpd.bkt.clouddn.com/2017/02/16/5.jpg