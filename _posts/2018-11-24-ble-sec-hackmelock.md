---
layout: post
title: "BLE安全初探之HACKMELOCK"
---

# 0x00 环境搭建

低功耗蓝牙技术（Bluetooth Low Energy）作为一种无线通信技术，其设计目标和实现与经典蓝牙技术有很大的不同，关于其的概述和技术细节可以参考文末的链接和著作。本文会结合书本知识对其中的协议数据包进行备注，以加深对主从设备交互流程的理解，进一步探索针对某BLE应用的攻击方式。

<!-- more -->

环境主从设备的选取是参考[BLUETOOTH SMART HACKMELOCK](https://smartlockpicking.com/hackmelock/)提供的仿真环境，其在树莓派中用nodejs搭建了一个虚拟的BLE门锁，专门写了一个Android app来对这个门锁进行操作，两端都遗留了一些安全问题供我们后续探索学习。

[UnicornTeam](https://weibo.com/unicornteam)曾经讲过无线通信的攻击手段可以分为监听、重放、欺骗和劫持攻击。个人感觉先要嗅探相关流量进行理解分析才能知己知彼有所突破，厚着脸皮向大佬团队借了一个[nRF51422](https://www.nordicsemi.com/eng/Products/ANT/nRF51422)来对BLE进行嗅探，其文档[nRF-Sniffer-UG-v2](https://www.nordicsemi.com/eng/nordic/download_resource/65244/3/23454585/136165)也写得很清楚，所以最终构建的环境如图所示：

![][1]

# 0x01 流程探索

上文搭建的虚拟环境中APP点击相关功能，服务端响应后在控制台也可以看到一定的log输出，方便我们理解协议的交互，接下来我会配合捕获的流量进行解释，数据包流量也已备份至[Github](https://github.com/Larryxi/My_tools/tree/master/ble_hackmelock)。低功耗蓝牙的体系结构如下：

![][2]

## 广播建立连接和发现服务特性

建立起虚拟门锁从设备后，其就在不停地广播。广播报文的类型有7种，用途比较广泛的类型是ADV_IND通用广播指示，广播报文的大致结构如下：

![][3]

在数据包中也可以看到很多树莓派的广播报文：

![][4]

打开手机App在被动扫描接收到所需的广播报文后，便会发起连接请求：

![][5]

主从设备在进入连接态后就会发送数据报文进行通信，数据报文格式和广播报文格式略有不同：

![][6]

数据报文中的逻辑链路标识符LLID把数据报文分成三种类型，其中链路层控制报文（11）用于管理连接，如下的数据包便是在管理连接中的版本交换：

![][7]

不仅是只有链路层的数据包，两个设备的上层服务还是会通过L2CAP信道（数据包序列），其结构如下：

![][8]

低功耗蓝牙一共使用3条信道，如下的L2CAP数据包则是低功耗信令信道的数据包，用于主机层的信令：

![][9]

属性层和通用属性规范层作为BLE的核心概念，一个是抽象协议一个是通用配置文件。属性通俗地来讲就是一条有标签的、可以被寻址的数据，其结构如下：

![][10]

在低功耗蓝牙中特性是由一种或多种属性组成，服务是由一种或多种特性组成，并且是由服务声明来对服务进行分组，用特性声明来对特性进行分组。服务和特性的发现由通用属性规范规定，具体则表现为不同类型的属性协议，如下的数据包便是按组类型读取请求来读取首要服务声明：

![][11]

响应则是所有首要服务声明的属性句柄、该首要服务中最后一个属性以及首要服务声明的数值：

![][12]

类似的，对于每一个服务也会有发现特性的请求和响应：

![][13]

![][14]

在数据包中分开看请求的服务和特性可能不是太方便，可以借助[bleah](https://github.com/evilsocket/bleah)直接枚举设备上的所以属性：

![][15]

## 门锁初始化配置

门锁的初始化配置在服务端控制台的输出如下：

![][16]

在数据包上的表现就是先对从设备的0x0013 handler进行读取请求，得到响应值后开始对0x000c handler进行一系列的写入请求，一共写入了24个序列完成初始化阶段：

![][17]

## 开关锁操作

开关锁的操作在服务端控制台的输出上看，貌似是有一个内部的认证过程：

![][18]

首先读取0x0013 handler读取一个random challenge，将响应写入0x000c handler，如果通过了认证则可以进行开关锁的操作，并且开关锁向handler中写入的值也是固定的：

![][19]


## 认证凭据重置

这个功能在服务端上被称为Data transfer，通过接收一条命令触发，并重新生成了24个序列通知客户端：

![][20]

在数据包上可以看到还有对0x0010 handler的写入请求，向0x000c写入的则是数据重传命令：

![][21]

# 0x02 攻击方式

## 流程探索

流程中比较感兴趣的就是内部实现的认证和数据重传部分，首先猜测不经过认证直接写入数据重传指令是否可以重置门锁，这里借助gatttool进行BLE的连接和请求：

![][22]

很遗憾是需要认证的，那我们就需要分析服务端或者客户端的程序，逆向出认证的具体流程。上jeb反编译apk，根据auth字符串定位至认证相关逻辑。可知在接收Challenge后，和v7一起传入`hackmelockDevice.calculateResponse`方法，正常的开锁流程会使v7为1，通过二维码分享的开锁流程会使v7为2：

![][23]

跟进去可知，根据不同的keyID对Challenge进行两次AES加密计算出响应：

![][24]

而其中的keys数组则是在最开始初始化门锁中传递的23个序列：

![][25]

对于keyID为0的序列tohex为12个字节，后面用空字符补齐16字节，进行两次AES加密用python代码还是很简单就实现了：

```python
import sys
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex

def calc(key, challenge):
    plaint_1 = a2b_hex(challenge)
    key_1 = a2b_hex(key)
    aes_1 = AES.new(key_1, AES.MODE_ECB)
    cipher_1 = aes_1.encrypt(plaint_1)
    print b2a_hex(cipher_1)

    plaint_2 = a2b_hex("DDAAFF03040506070809101112131415")
    key_2 = cipher_1
    aes_2 = AES.new(key_2, AES.MODE_ECB)
    cipher_2 = aes_2.encrypt(plaint_2)
    print b2a_hex(cipher_2)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        calc(sys.argv[1], sys.argv[2])

```

![][26]


## 服务端后门

[服务端代码](https://github.com/smartlockpicking/hackmelock-device)是用nodejs写的，看起来比安卓逆向轻松多了，在服务端留下了一个后门可以使用特定密码直接通过认证：

```javascript
  if ( (authResponse === fin_16.toString('hex')) || (authResponse === '4861636b6d654c6f636b4d6173746572')) {
    console.log('AUTHENTICATION OK!'.green);
    this.authenticated = true;
    this.status = statusAuthenticated;
  }
```

![][27]


## 认证代码缺陷

最开始按照正常的加密逻辑，向0x000c handler写入response总是认证不通过，对比在app上操作的控制台输出，发现其在计算出的response后多加了一个`00`，幡然醒悟最后一个写入的字符就是用来指示keyID的。而在服务端代码中，其不仅加载了初始化时传递的23个key，还以`00`扩展至128个：

```javascript
Hackmelock.prototype.loadConfig = function(configFile) {
  this.config = fs.readFileSync(configFile).toString().split("\n");
  //pop last empty line
  this.config.pop();

  for (i=this.config.length; i<128; i++) {
    this.config.push('000000000000000000000000')
  }
```

如果我们将keyID指示得过大，那么第一轮AES加密的key就已经确定了，相应的认证措施也就失效了：

![][28]

## 二维码信息泄露

App中还有个Share功能，旨在向他人提供临时开关锁的权限：

![][29]

从App逆向的结果来看，二维码中会保存keyID为1的序列，有了任意的key就不存在权限和时间的限制了。如上的二维扫出的结果就是`576C0603:4CE495E48D0BF00BF1BC85F3:1:1542885650:1542902400`，与之前数据传输的记录相符：

![][30]

## 其他

1. [服务端代码](https://github.com/smartlockpicking/hackmelock-device/blob/master/hackmelock.js#L173)中使用`Math.random()`来生成随机数，但这种方法并不是[cryptographically-secure](https://stackoverflow.com/questions/5651789/is-math-random-cryptographically-secure)，可能会被预测但我个人暂未想出来合适的攻击场景。
2. 作者还提示存在命令注入的问题，我对nodejs和安卓了解的不多，感兴趣的同学可以探索一下。

# 0x03 总结参考

## 总结

1. Android上也可以对蓝牙进行[抓包](https://blog.csdn.net/wangbf_java/article/details/81269149)，不过是主设备上HCI信道的数据包，看起来可能不是太直接。
2. 上面的虚拟门锁的使用的是默认安全级别，链路没有加密和认证配对的操作，深入探究的话可以使用工具进行中间人和重放攻击的尝试，smartlockpicking团队提供的[培训讲义](http://smartlockpicking.com/slides/BruCON0x09_2017_Hacking_Bluetooth_Smart_locks.pdf)还是很值得学习一下的。
3. 换一种角度看，喜欢做练习的同学可以尝试一下[BLE CTF](http://www.hackgnar.com/2018/06/learning-bluetooth-hackery-with-ble-ctf.html)，当然挖掘BLE相关的[漏洞](https://mp.weixin.qq.com/s/cu-DCXuqJ50YRTFDmBUrtA)也是有可能的。

## 参考

* [低功耗蓝牙开发权威指南](https://book.douban.com/subject/26297532/)
* [BLUETOOTH SMART HACKMELOCK](https://smartlockpicking.com/hackmelock/)
* [物联网安全拔“牙”实战——低功耗蓝牙（BLE）初探](http://drops.xmd5.com/static/drops/tips-10109.html)
* [BLE安全入门及实战（1）](https://sec.xiaomi.com/article/38)
* [Hardwear_2018_BLE_Security_Essentials](http://smartlockpicking.com/slides/Hardwear_2018_BLE_Security_Essentials.pdf)

[1]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g0scroj22c02c0npd.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g176ntj20f60axtcc.jpg
[3]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g1itj5j20fo0csn0q.jpg
[4]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g1ttogj20xd0c576r.jpg
[5]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g26krnj20yq0bi0v8.jpg
[6]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g2gke0j20ia0cz427.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g2tap5j20xs0cl0vw.jpg
[8]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g38626j20hj06ogmu.jpg
[9]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g3hs4rj20xo0bdwgw.jpg
[10]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g3saukj20j703x74z.jpg
[11]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g4jh1dj210o09mdhv.jpg
[12]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g48rdoj210p09z767.jpg
[13]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g4xjj8j210o0audhz.jpg
[14]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g578j7j210o0bc0vo.jpg
[15]: https://wx4.sinaimg.cn/large/ee2fecafly1fxj2g5n652j20xl0ekwx2.jpg
[16]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g65r0cj20ik0f0wrn.jpg
[17]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g6qccvj20z90dan1a.jpg
[18]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g71nurj20lf0bedq7.jpg
[19]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g7c0ckj20z90cb0wp.jpg
[20]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g7pzuwj20j90hxqiv.jpg
[21]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g849qej210l0atn1v.jpg
[22]: https://wx4.sinaimg.cn/large/ee2fecafly1fxj2g8gf91j2115085dkd.jpg
[23]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2g8tet6j20qa0c53z6.jpg
[24]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g94fv1j20ng0frjse.jpg
[25]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2g9hrsjj20ok0gt0ty.jpg
[26]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2g9wktmj211r0c2dmo.jpg
[27]: https://wx2.sinaimg.cn/large/ee2fecafly1fxj2ga85dtj211r07itdm.jpg
[28]: https://wx1.sinaimg.cn/large/ee2fecafly1fxj2gat1kqj211r0ck44p.jpg
[29]: https://wx3.sinaimg.cn/large/ee2fecafly1fxj2gb8p3yj20u01hcmzv.jpg
[30]: https://wx4.sinaimg.cn/large/ee2fecafly1fxj2gbv4shj20l209v3z0.jpg
