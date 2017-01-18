---
title:  "基础级Google Hacking"
date:   2015-03-28 00:38:00
---

# 0x00 引言 ##

---

“无用信息输入，无用信息输出”，本文适当总结脚本小子的Google Hacking方法未涉及脚本自动化处理数据，翻墙请自备，大神请轻喷。鄙人觉得也应当配合不同的搜索引擎使用相应的搜索语法组合出最佳的结果，当然可以由自动化工具实现或学习相关\*HDB进行手工搜索。(下文中“===”代表搜索结果相同)

<!--more-->

# 0x01 Google搜索基础知识  #

---

1. 手气不错，自定义搜索结果，语言设置，高级设置大家都懂哈 
![Example](http://ojyzyrhpd.bkt.clouddn.com/20150328/1.png)
2. 基本搜素：一个或一组单词(google hacker);双引号封装的词组("Google Hacking")
3. Google搜索的黄金法则： 
    * Google查询不区分大小写：hack === HAck 但单词or作为布尔操作符时必须为大写就，即OR 
    * Google通配符：星号(\*)仅代表搜索词组中的一个词。（注意与表示任意单一字母的词干提取技术相区别）
    * Google保留忽略查询关键字的权利(哪些关键字会被忽略呢 [Link](https://code.google.com/p/stop-words/)):(how 1 = WHERE 4) === (1 = WHERE 4) 两者搜索结果相同。如何突破？搜索"how" 1 = WHERE 4即可  
    * 32个单词的限制：突破方法：使用通配符(*)来代替某些单词。Google不认为通配符是一个查询项，这使得我们能够稍稍扩展查询. 
4. 使用布尔操作符和特殊字符： 
    * AND：用于在查询中包含多个关键字。例如：hacker AND cracker。但AND关键字对于Google来说是多余的。默认情况下，Google会自动搜索查询中的所有关键字。加号(+)强制Google搜索它后面的单词。在加号后面不得有空格，用于强制搜索被忽略的单词，例如：+and justice for +all。当然，也可以使用双引号构建查询，即"and justice for all" 
    * NOT：用于在查询中忽略一个单词。也可以使用减号(-)达到相应效果，在减号和搜索关键字之间不能有空格。例如：hacker -golf 
    * OR：用于查找搜索中的一个或者另外一个关键字。也可以使用管道符号(\|)达到相应效果。例如：admin \| user 
    * 注意：Google从左到右读取查询，操作符之间拥有相同优先级，且搜索不受括号影响。例如：intext:(password \| passcode) intext:(username \| userid \| user) filetype:csv 
5. 使用Google URL:
    当你提交完一个Google查询之后，可以看到相应的Google结果页面，而这个页面的URL可以用于修改一个查询的或者在以后重新使用这个查询   
    例如：www.google.com.hk/search?variable1=value&variable2=value  
    相关URL参数列表 [Link](http://ylbook.com/cms/web/gugecanshu.htm)

# 0x02 Google高级操作符 #

---

1.  操作符语法：
    * 基本语法：opearator:search_term
    * 在操作符、冒号、搜索关键字之间是没有空格的。
    * 布尔操作符和特殊字符（例如OR和+）仍可用于高级操作符查询，但是不能把它们放在冒号之前二把冒号和操作符分开。
    * 高级操作符能够和单独的查询混合使用，但是必须遵循基本Google查询语法和高级操作符语法。
    * 一般情况下，一个查询只能使用一次ALL操作符，而且不能和其他操作符混用。
    * 例如：intitle:"index of" private  这个查询将返回标题包含词组index of，而且网页的任何地方（URL、标题、文本等）包含单词private的页面。要注意的是，intitle只对词组index of起作用，而不会影响单词private，这是因为引号外的第一个空格位于词组index of之后。Google吧这个空格解释为高级操作符搜索关键字的结尾，然后接着处理查询中剩下的部分。 
2. Google高级操作符（列举常用的）：
  * intitle: 在页面标题中查找字符串
  * allintitle: 在页面标题中查找所有的关键字
  * inurl: 在页面的URL中查找字符串
  * allinurl: 在页面的URL中查找所有的关键字
  * filetype: 根据文件扩展名查找特定类型的 文件，等同于ext，也需要附加搜索关键字
  * site: 限定在某个特定的网站或者域搜索，也可以单独使用
  * cache: 现实页面的缓存版本，但不能很好地与其他操作符或者关键字混合使用   
    ![example](http://ojyzyrhpd.bkt.clouddn.com/20150328/2.png)

# 0x03 Google Hacking Wooyun案例： #

---

* 具体的Google Hacking一般性练手：
    * [WooYun: 关于Google Hacking一些Tips](http://www.wooyun.org/bugs/wooyun-2012-06968)
    * [WooYun: 万达集团某处未授权任意浏览MM、GG信息](http://www.wooyun.org/bugs/wooyun-2013-017368)
* 利用网页快照收集信息，当然也可以用于匿名浏览：
    * [WooYun: 某校服供应商sql注入漏洞导致数万学生信息泄漏极详细另带shell](http://www.wooyun.org/bugs/wooyun-2014-086085)
* 配置文件或日志文件敏感信息泄露：
    * [WooYun: 多家单位深信服设备敏感文件下载(补丁不及时),可成功控制设备  (3)  ---大结局](http://www.wooyun.org/bugs/wooyun-2013-020012)
* office文档包含用户名、口令等敏感信息泄露：
    * [WooYun: 瑞金市教育局视频会议账号及管理员名单泄露](http://www.wooyun.org/bugs/wooyun-2014-087891)
    * [WooYun: TCL集团技术信息服务平台用户信息泄露(弱口令登录)](http://www.wooyun.org/bugs/wooyun-2014-051023)
* 数据库挖掘配合不当配置：
    * [WooYun: 国内某大学网站phpmyadmin配置不当，导致可通过google hack以root权限管理后台](http://www.wooyun.org/bugs/wooyun-2014-055361)
    * [WooYun: 4399某游戏MONGOD泄露影响归纳（敏感数据库信息）](http://www.wooyun.org/bugs/wooyun-2014-085697)
* 利用已有漏洞进行Google挖掘：
    * [WooYun: 盛大网络旗下多个站点SQL注入打包](http://www.wooyun.org/bugs/wooyun-2014-067058)
    * [WooYun: 万户OA未修补漏洞致多个政府&amp;集团OA中招](http://www.wooyun.org/bugs/wooyun-2014-081513)
* 相关网络设备泄露登陆入口及信息：
    * [WooYun: 禹神国际酒店出现漏洞，可更改支付平台账号](http://www.wooyun.org/bugs/wooyun-2014-089042)
    * [WooYun: 阿里FTP密码泄漏](http://www.wooyun.org/bugs/wooyun-2012-07282)
* 搜索引擎爬行的那些事：
    * [WooYun: 搜搜 搜索引擎越权爬行](http://www.wooyun.org/bugs/wooyun-2012-08604)
    * [WooYun: 搜狗输入法泄露部分用户隐私信息](http://www.wooyun.org/bugs/wooyun-2013-024626) 

# 0x04 相关防卫措施  #

---

* 禁止目录列表、错误信息和不当的配置或者删除默认页面及配置
* 设置Robots.txt文件和特殊的META标记阻止Crawler
* 利用自动化工具和GHDB(Google Hacking Datebase)来检测自己的网站
* 使用Google的Webmaster删除页面的缓存版本 

# 0x05 扩展及参考资料  #

---

* owasp-testing-guide-v4 [Link][link0]
* wiki相关 [Link][link1]
* Google Hacking技术手册 [Link][link2]
* GHDB(Google Hacking Datebase) [Link][link3]
* 工具相关：[Diggity Project][tool0] [SiteDigger][tool1] [Google Hacker][tool2] [PunkSPIDER][tool3]

  [link0]:  http://kennel209.gitbooks.io/owasp-testing-guide-v4/content/zh/index.html
  [link1]:  http://en.wikipedia.org/wiki/Google_hacking
  [link2]:  http://baike.baidu.com/link?url=YBxKy0FR6zJnBiGTdk-z8gqw3IqvVcvx9Q0aDY3Ssta8X1wNGVQXhENenxQ1ffSokpoDrHLpGVZ9VQ_7GiMucK
  [link3]:  http://www.exploit-db.com/google-dorks/
  [tool0]:  http://www.bishopfox.com/resources/tools/google-hacking-diggity/
  [tool1]:  http://www.mcafee.com/uk/downloads/free-tools/sitedigger.aspx
  [tool2]:  http://yehg.net/lab/pr0js/files.php/googlehacker.zip
  [tool3]:  http://punkspider.hyperiongray.com/
