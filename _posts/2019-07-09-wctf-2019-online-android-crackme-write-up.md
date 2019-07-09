---
layout: post
title: "WCTF 2019 Online Android Crackme Write Up"
---

# 参赛初衷

懂的人会问你打过什么CTF或者挖过什么洞，仔细一想两者都会是对自己能力的突破，多参加点高质量的赛事终究是有益无害的，如果能学到新姿势或者入个门那更是赚到了。作为老油条只能被gd师傅带着打打线上赛，个人也就会做两个签到的安卓逆向题，新鲜接触青涩记录。

<!-- more -->

# Crackme1

JEB打开Crackme1.apk，搜索字符串`Welcome`定位至MainActivity，其调用native方法`doSomeThing`处理账号密码，这就[意味着](http://www.tasfa.cn/index.php/2018/12/19/android-sty-native/)我们要分析apk中的.so文件了：

![][1]

从简单的`/lib/x86/libtest-jni.so`入手，搜索`Opps`的base64编码定位至`z`函数，虽然可以F5看但不如结合动态调试来得直接。安装Android Studio理解[adb](https://developer.android.com/studio/command-line/adb#howadbworks)的用法，debug apk时创建Nexus 6 API 25的虚拟设备（可以`su`至root权限），上传IDA 7的android_x86_server后进行[远程调试](https://blog.csdn.net/wmh_100200/article/details/72847878)。

该函数对接收的`Name`值计算SHA1后再变换一番，和处理后的`Password`比较，相同则认为登录成功：

![][2]

由于题目中给的用户名是固定的，所以其比较的`s2`也是固定的。只需关注密码的处理操作，是进行了一次base64解码：

![][3]

将用户名的比较值进行base64编码即为正确密码：

![][4]

# Crackme2_Jessie

Android Emulator模拟打开Crackme2_Jessie.apk，输入账号密码报错为`Name or Password Error!`，对应在Main2Activity中根本没有任何的处理操作：

![][5]

真正的处理在MainActivity中，接收密码后进入native层的`stringFromJNI`逻辑：

![][6]

想动态调试就必须进入MainActivity，那意味着要重打包。根据CTF的常见[套路](https://blog.csdn.net/xiaoi123/article/details/79262538)，修改AndroidManifest.xml以启动`com.example.bear.helloworld.MainActivity`：

```xml
        <activity android:name="com.example.bear.helloworld.MainActivity" android:screenOrientation="portrait">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
```

[然后](https://resources.infosecinstitute.com/android-hacking-security-part-17-cracking-android-app-binaries/#gref)使用[apktool](https://ibotpeaches.github.io/Apktool/install/)重新编译Crackme2_Jessie.apk，对`dist`目录下的输出文件签名后重装apk即可：

```bash
keytool -genkey -alias key.keystore -keyalg RSA -validity 20000 -keystore key/key.keystore
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore key/key.keystore Crackme2_Jessie.apk key.keystore
```

如果立即`adb install`会因和原始apk签名不一样而拒绝安装，所以得先卸载后安装：

![][7]

按照出题者的尿性，定位至`x`函数，其首先调用`Tool::callFunc`并始终返回为0导致登录失败，即使修改eax为1进入后续逻辑，其会将`Tool::callFunc`生成的md5值` d41d8cd98f00b204e9800998ecf8427e`变换得到`2062203020323024010d0954085a5d01`，和输入的密码`abcdefg`比较：

![][8]

跟进存在猫腻的`Tool::callFunc`，其动态加载java class并调用对象方法，其会调用`com.bear.function.Tool `的`getString`方法读取`META-INF/MAN1FE5T.MF`文件：

![][9]

随后根据返回内容决定是比较`abcdefg`，还是对md5值进行计算操作：

![][10]

注意到开头的`Tool::copyFile`调用，有对`icon.png`的读取操作，到这里可能就是个杂项题目了，动态加载隐藏在图片中的类，遂在`open`函数处下断点得到文件路径：

![][11]

解压得到classes.dex，[dex2jar](https://aptx0.github.io/2017/06/01/CTF-android-apk/)转为classes-dex2jar.jar，[jd-gui](https://github.com/java-decompiler/jd-gui)即可查看`Tool`类的源码了，其中的`getString`方法为调用[readLine](https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html#readLine--)读取文件内容，`calcMD5`方法即为flag相关的计算操作：

![][12]

写个py脚本即可得到最终答案`21382420613021345152040153575b5c`，注意此答案直接在apk中输入仍旧是`Opps!`：

```python
import base64

#echo -n Jessie | md5sum -
j = '27b61398e94ca5c6cef7bdbd38d4e255'
j = j.decode('hex')
p = '0123456789ABCDEF'
m = ''
for i in xrange(16):
    index = ord(j[i]) >> 4 & 0xF
    m += p[index].lower()
    index = ord(j[i]) & 0xF
    m += p[index].lower()

print m
#m = '7ac66c0f148de9519b8bd264312c4d64'
#m = '0123456789abcdeffedcba9876543210'
#m = 'abcdefg\x00com/example/bear/helloworld/Control\x00'
xor2 = m[0:8]
and2 = m[8:16]
xor1 = m[16:24]
and1 = m[24:32]
print and1
r = ''
for i in xrange(8):
    r += chr(ord(and1[i])&ord(and2[i]))
for i in xrange(8):
    r += chr(ord(xor1[i])^ord(xor2[i]))

print r
print base64.b64encode(r)
print r.encode('hex')
```

# 赛后感想

1. 最简单的题目有点脑洞，但更希望能接触到代码混淆和反调试的更接地气的对抗题目。
2. 高大上的安全方向没有想象中的难，肯花时间有动力，越过门槛剩下就是轻车熟路了。
3. 入门后坚持下来，远离浅滩多见世面，起点低没关系但要有突破成长，导数得比自己强。

[1]: https://wx3.sinaimg.cn/large/ee2fecafly1g4trzcovztj20js0ert9m.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafly1g4trzd2gr1j21eg0ixwhl.jpg
[3]: https://wx4.sinaimg.cn/large/ee2fecafly1g4trzdewlpj21fs0jxtc5.jpg
[4]: https://wx4.sinaimg.cn/large/ee2fecafly1g4trzdq4xnj20qi0cqwfd.jpg
[5]: https://wx1.sinaimg.cn/large/ee2fecafly1g4trze534cj20po08smxu.jpg
[6]: https://wx2.sinaimg.cn/large/ee2fecafly1g4trzek3umj20si0eq75g.jpg
[7]: https://wx2.sinaimg.cn/large/ee2fecafly1g4trzeuu88j20eg0mv3zo.jpg
[8]: https://wx3.sinaimg.cn/large/ee2fecafly1g4trzf9eraj20jr0eywfg.jpg
[9]: https://wx3.sinaimg.cn/large/ee2fecafly1g4trzfjhefj20on0ep3zh.jpg
[10]: https://wx3.sinaimg.cn/large/ee2fecafly1g4trzfvruej213h0q6jtz.jpg
[11]: https://wx2.sinaimg.cn/large/ee2fecafly1g4trzg9ebbj20r80glmyb.jpg
[12]: https://wx2.sinaimg.cn/large/ee2fecafly1g4trzgl8obj20y708yaat.jpg
