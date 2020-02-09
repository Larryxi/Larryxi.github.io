---
layout: post
title: "常见嵌入式Web服务器CGI处理功能简要分析"
---

# 0x00 背景

在一些中小型的IoT设备中，当需要使用Web界面管理设备时，开发者可能会选取合适的开源嵌入式Web服务器进行二次开发，实现单纯的Web服务器中间件，或者将转发请求功能和后端处理功能融合在一个二进制文件当中。二次开发的特定功能如身份认证等和后端的CGI功能，在缺乏安全开发的意识之下很容易出现问题，因此了解熟悉嵌入式设备中常用的Web服务器和其CGI处理功能的实现方式，有助于快速发现设备Web端的审计或测试点。

<!-- more -->

# 0x01 boa

[Boa](http://www.boa.org/documentation/boa-1.html)作为一个单任务型的HTTP服务器，它对HTTP连接在内部多路复用，只会对CGI请求进行`fork`进程。个人认为其主要的[限制](http://www.boa.org/documentation/boa-3.html)是没有访问控制功能，需要二次开发身份认证等功能，会是IoT固件中常见的问题点。

## 源码分析

[boa](http://www.boa.org/boa-0.94.14rc21.tar.gz)程序在解析请求头的收尾函数`process_header_end`中，`translate_uri`函数会解析请求的虚拟路径，根据URI判断是否为CGI请求，进一步则调用`init_cgi`来`execve`执行相关CGI程序：

```c
int process_header_end(request * req)
{
    if (!req->logline) {
        log_error_doc(req);
        fputs("No logline in process_header_end\n", stderr);
        send_r_error(req);
        return 0;
    }

    /* Percent-decode request */
    if (unescape_uri(req->request_uri, &(req->query_string)) == 0) {
        log_error_doc(req);
        fputs("URI contains bogus characters\n", stderr);
        send_r_bad_request(req);
        return 0;
    }

    /* clean pathname */
    clean_pathname(req->request_uri);

    if (req->request_uri[0] != '/') {
        log_error("URI does not begin with '/'\n");
        send_r_bad_request(req);
        return 0;
    }

    if (vhost_root) {
        ...
    }

    if (translate_uri(req) == 0) { /* unescape, parse uri */
        /* errors already logged */
        SQUASH_KA(req);
        return 0;               /* failure, close down */
    }

    if (req->method == M_POST) {
        ...
    }

    if (req->cgi_type) {
        return init_cgi(req);
    }

    req->status = WRITE;

    return init_get(req);       /* get and head */
}
```

`translate_uri`函数中的`init_script_alias`函数，负责解析`ScriptAlias`请求，设置请求cgi类型，查看文件是否存在以及具有相关权限：

```c
static int init_script_alias(request * req, alias * current1, unsigned int uri_len)
{
    static char pathname[MAX_HEADER_LENGTH + 1];
    struct stat statbuf;

    int i = 0;
    char c;
    int err;

    /* copies the "real" path + the non-alias portion of the
       uri to pathname.
     */

    if (vhost_root) {
        ...
    } else {
        if (current1->real_len + uri_len -
            current1->fake_len + 1 > sizeof(pathname)) {
            log_error_doc(req);
            fputs("uri too long!\n", stderr);
            send_r_bad_request(req);
            return 0;
        }
        memcpy(pathname, current1->realname, current1->real_len);
        memcpy(pathname + current1->real_len,
               &req->request_uri[current1->fake_len],
               uri_len - current1->fake_len + 1); /* the +1 copies the NUL */
    }
#ifdef FASCIST_LOGGING
    log_error_time();
    fprintf(stderr,
            "%s:%d - pathname in init_script_alias is: \"%s\" (\"%s\")\n",
            __FILE__, __LINE__, pathname, pathname + current1->real_len);
#endif
    if (strncmp("nph-", pathname + current1->real_len, 4) == 0
        || (req->http_version == HTTP09))
        req->cgi_type = NPH;
    else
        req->cgi_type = CGI;

...


    req->pathname = strdup(pathname);
    if (!req->pathname) {
        boa_perror(req, "unable to strdup pathname for req->pathname");
        return 0;
    }

    return 1;
}
```

其中的关键就在于`ScriptAlias`设置的寻找，在`boa.conf`配置文件中，该指令设置CGI执行的真实目录：

```
Redirect, Alias, and ScriptAlias <path1> <path2>
Redirect, Alias, and ScriptAlias all have the same semantics -- they match the beginning of a request and take appropriate action. Use Redirect for other servers, Alias for the same server, and ScriptAlias to enable directories for script execution.
```

## 实际案例

2017年[vivetok摄像头](https://www.anquanke.com/post/id/185336)固件中就使用的是boa二次开发的Web服务器：

```
larry@u:~/opt/_CC8160-VVTK-0100d.flash.pkg.extracted/_31.extracted/_rootfs.img.extracted/squashfs-root$ strings -a ./usr/sbin/httpd | grep boa
boa_set_default_values_for_server_push_multiple_stream_uris
src/boa.c
[debug] in boa_it_is_server_push_multiple_stream_uri() match %s %s
boa: server version %s
/etc/conf.d/boa/boa.conf
Could not open boa.conf for reading.
Attempt to hash NULL or empty string! [boa_hash]!
boa: server version %s(%s)
boa: starting server pid=%d, port %d
%s/boa-temp.XXXXXX
/etc/conf.d/boa/modules
/etc/conf.d/boa/vadp-available
/etc/conf.d/boa/vadp-enabled
```

搜索`ScriptAlias`可知其真实的CGI文件路径为`/usr/share/www/cgi-bin/`，也可以用`find`命令验证其CGI功能都对应一个可执行的cgi程序：

```
larry@u:~/opt/_CC8160-VVTK-0100d.flash.pkg.extracted/_31.extracted$ find . -name "boa.conf"
./defconf/_CC8160.tar.bz2.extracted/_0.extracted/etc/conf.d/boa/boa.conf

larry@u:~/opt/_CC8160-VVTK-0100d.flash.pkg.extracted/_31.extracted$ grep ScriptAlias ./defconf/_CC8160.tar.bz2.extracted/_0.extracted/etc/conf.d/boa/boa.conf 
# Redirect, Alias, and ScriptAlias all have the same semantics -- they
# Redirect for other servers, Alias for the same server, and ScriptAlias
# ScriptAlias: Maps a virtual path to a directory for serving scripts
# Example: ScriptAlias /htbin/ /www/htbin/
#ScriptAlias /cgi-bin/ /home/httpd/cgi-bin/
ScriptAlias /cgi-bin/ /usr/share/www/cgi-bin/
#ScriptAlias /api/ /usr/share/www/cgi-bin/

larry@u:~/opt/_CC8160-VVTK-0100d.flash.pkg.extracted/_31.extracted$ find . -name "*.cgi" | head
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/anonymous/getparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/anonymous/setparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/viewer/getparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/viewer/setparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/viewer/senddata.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/viewer/getparam_cache.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/operator/getparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/operator/setparam.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/operator/senddata.cgi
./_rootfs.img.extracted/squashfs-root/usr/share/www/cgi-bin/operator/getparam_cache.cgi
```

该httpd程序是按照boa的特性，根据请求的`pathname`执行相关的`*.cgi`程序。但也有开发者会修改boa源码，增加一些特有的`alias`或者路由信息，比如360路由器固件中的boa，会根据URI来`execve`不同的cgi程序：

```
.data:00423048 off_423048:     .word aRouterWCgi        # DATA XREF: sub_403F24+24↑o
.data:00423048                                          # sub_403F24+50↑o
.data:00423048                                          # "^/router/\\w+\\.cgi$"
.data:0042304C off_42304C:     .word aWebCgiBinCgite    # DATA XREF: sub_403FF0+30↑o
.data:0042304C                                          # "/web/cgi-bin/cgitest.cgi"
.data:00423050                 .word 0
.data:00423054                 .word 0
.data:00423058                 .word aWeb360WCgi        # "^/web360/\\w+\\.cgi$"
.data:0042305C                 .word aWebWeb360N360C    # "/web/web360/n360.cgi"
.data:00423060                 .word 0
.data:00423064                 .word 0
.data:00423068                 .word aWebnoauthWCgi     # "^/webnoauth/\\w+\\.cgi$"
.data:0042306C                 .word aWebWebnoauthNa    # "/web/webnoauth/na.cgi"
.data:00423070                 .word 0
.data:00423074                 .word 0
.data:00423078                 .word aAppWWWCgi         # "^/app/(\\w+)/(\\w+/)*\\w+\\.cgi$"
.data:0042307C                 .word 0
.data:00423080                 .word 0x403898
.data:00423084                 .word 0x404298
.data:00423088                 .word 0
```

在执行cgi程序的`main`函数中，会调用`IGD_GetCgiHandler`函数得到请求`\\w+\\.cgi`对应的handler函数，最终跳转执行：

```c
int IGD_CgiCall(undefined4 param_1,undefined4 param_2)

{
  size_t __n;
  undefined auStack20 [4];
  int local_10;
  code *local_c;
  
  local_c = (code *)0x0;
  local_c = (code *)IGD_GetCgiHandler(param_1);
  if (local_c == (code *)0x0) {
    local_10 = -0xefff;
  }
  else {
    __n = strlen("HTTP/1.1 200 OK\r\n");
    write(0x1f,"HTTP/1.1 200 OK\r\n",__n);
    local_10 = (*(code *)0x6598)(auStack20);
    if (local_10 == 0) {
      (*(code *)0x67d4)(param_1);
      local_10 = (*local_c)(0,param_2,auStack20);
    }
  }
  return local_10;
}

undefined4 IGD_GetCgiHandler(char *param_1)

{
  int iVar1;
  int local_c;
  
  local_c = 0;
  cgi_perm_flag = 0;
  while( true ) {
    if ((&IGD_CGI_FUN_MAP)[local_c * 3] == 0) {
      return 0;
    }
    iVar1 = strcmp((char *)(&IGD_CGI_FUN_MAP)[local_c * 3],param_1);
    if (iVar1 == 0) break;
    local_c = local_c + 1;
  }
  cgi_perm_flag = *(undefined4 *)(&DAT_0002e024 + local_c * 0xc);
  return *(undefined4 *)(&DAT_0002e020 + local_c * 0xc);
}
```

# 0x02 uhttpd

[uHTTPd](https://openwrt.org/docs/guide-user/services/webserver/http.uhttpd)作为OpenWrt中默认的HTTP服务器，主要是用来配合[LuCI](https://openwrt.org/docs/guide-user/luci/luci.essentials) Web接口方便OpenWrt设备的管理，[支持](https://openwrt.org/docs/guide-user/services/webserver/uhttpd)CGI、Lua和UBUS完成对请求的处理。在IoT设备上使用OpenWrt比较常见的情况是，结合uhttpd使用LuCI框架编写lua处理脚本，安全审计偏向于Web安全中的代码审计，也会有lua的逆向内容需要解决。

## 源码分析

uhttp的[代码](https://git.openwrt.org/?p=project/uhttpd.git;a=summary)中，接收完请求头后调用`uh_handle_request`函数，使用`dispatch_find`函数根据请求的url找到合适的`dispatch_handler`：

```c
void uh_dispatch_add(struct dispatch_handler *d)
{
	list_add_tail(&d->list, &dispatch_handlers);
}

static struct dispatch_handler *
dispatch_find(const char *url, struct path_info *pi)
{
	struct dispatch_handler *d;

	list_for_each_entry(d, &dispatch_handlers, list) {
		if (pi) {
			if (d->check_url)
				continue;

			if (d->check_path(pi, url))
				return d;
		} else {
			if (d->check_path)
				continue;

			if (d->check_url(url))
				return d;
		}
	}

	return NULL;
}
```

而`cgi_prefix`在`/etc/config/uhttpd`[配置文件](https://openwrt.org/docs/guide-user/services/webserver/uhttpd)中的默认值为`/cgi-bin`，并且程序在`main`函数中默认添加了`cgi_dispatch`,当请求的url通过`check_cgi_path`函数校验，则会调用`cgi_handle_request`函数回调`cgi_main`函数`execl`执行对应的CGI程序：

```c
static void cgi_handle_request(struct client *cl, char *url, struct path_info *pi)
{
	unsigned int mode = S_IFREG | S_IXOTH;
	char *escaped_url;

	if (!pi->ip && !((pi->stat.st_mode & mode) == mode)) {
		escaped_url = uh_htmlescape(url);

		uh_client_error(cl, 403, "Forbidden",
				"You don't have permission to access %s on this server.",
				escaped_url ? escaped_url : "the url");

		if (escaped_url)
			free(escaped_url);

		return;
	}

	if (!uh_create_process(cl, pi, url, cgi_main)) {
		uh_client_error(cl, 500, "Internal Server Error",
				"Failed to create CGI process: %s", strerror(errno));
		return;
	}

	return;
}

struct dispatch_handler cgi_dispatch = {
	.script = true,
	.check_path = check_cgi_path,
	.handle_request = cgi_handle_request,
};
```

最终调用的`/www/cgi-bin/luci`即LuCI，是遵循MVC理念的后端Web处理[框架](https://github.com/openwrt/luci/wiki)，详细分析可参看[《Luci实现框架》](https://www.cnblogs.com/zmkeil/archive/2013/05/14/3078774.html)。LuCI在`/usr/lib/lua/luci/controller`目录下的lua脚本包含请求url的相关路由信息，这些脚本中的`index`函数，调用`entry (path, target, title, order)`函数创建dispatching node，需要重点关注`target`参数中可能传递`call`函数来调用函数处理请求：

```
entry (path, target, title, order)
    Create a new dispatching node and define common parameters.
    Parameters
        path: Virtual path
        target: Target function to call when dispatched.
        title: Destination node title
        order: Destination node order value (optional)
    Return value:
    Dispatching tree node
```

## 实际案例

某款[斐讯](http://www.phicomm.com/cn/support.php/Soho/software_support/t/sm.html)路由器的固件就是基于OpenWrt开发的，虽然使用的是[lighttpd](https://openwrt.org/docs/guide-user/luci/luci.on.lighttpd)作为HTTP服务器，但最终调用的还是LuCI。关注到其后台自动更新处的脚本`/usr/lib/lua/luci/controller/admin/autoupgrade.lua`中蕴涵的路由及handler信息：

```lua
function index()
    local page
    page = entry({"admin", "more_sysset", "autoupgrade"}, call("auto_up"), _("autoupgrade"), 81)
    entry({"admin", "more_sysset", "autoupgrade", "save"}, call("save"), nil, nil)
    entry({"admin", "more_sysset", "autoupgrade", "recheck"}, call("recheck"), nil, nil)
    entry({"admin", "more_sysset", "autoupgrade", "upgrade"}, call("upgrade"), nil, nil)
end
```

其在调用`save`函数过程中，接收form参数`autoUpTime`拼接命令执行，就有可能造成命令注入的问题：

```lua
function save()
    local time = luci.http.formvalue("autoUpTime")
    local mode = luci.http.formvalue("mode")
    local upgrading = "1"

    if mode == "1" then
        luci.sys.call("uci set system.autoupgrade.up_time=%s" % time)
        luci.sys.call("uci set system.autoupgrade.up_type=0")
        luci.sys.call("uci commit system")

        scheduletask.settaskatr("system", "autoupgrade", "/lib/auto_upgrade.sh", "yes", "10","up_time")
        scheduletask.cfgscdutskbylua("add","system","autoupgrade")
    elseif mode == "0" then
        luci.sys.call("uci set system.autoupgrade.up_type=1")
        luci.sys.call("uci commit system")
        scheduletask.cfgscdutskbylua("del","system","autoupgrade")
    end
    
    luci.http.redirect(luci.dispatcher.build_url("admin","more_sysset","autoupgrade"),{
        mode=mode,
        upgrading = upgrading
        })
end

--- Execute a given shell command and return the error code
-- @class		function
-- @name		call
-- @param 		...		Command to call
-- @return		Error code of the command
function call(...)
	return os.execute(...) / 256
end
```

有些基于LuCI的固件会将lua脚本预编译成为字节码加速执行，这就需要针对性地[反编译](http://webcache.googleusercontent.com/search?q=cache:DRSZOu-QEBUJ:storypku.com/2015/07/+&cd=5&hl=zh-CN&ct=clnk)OpenWRT Lua Bytecode。还有些更改lua虚拟机的[情况](https://e3pem.github.io/2019/07/03/IoT/%E5%B0%8F%E7%B1%B3%E8%B7%AF%E7%94%B1%E5%99%A8%E4%BB%8E%E5%BC%80%E5%A7%8B%E5%88%B0%E6%94%BE%E5%BC%83/)，需要深入逆向解析其自定义的opcode，并配合历史固件版本分析。当然，lua语言自身的[安全问题](https://conference.hitb.org/hitbsecconf2019ams/materials/D1T1%20-%20SeasCoASA%20-%20Exploiting%20a%20Small%20Leak%20in%20a%20Great%20Ship%20-%20Kaiyi%20Xu%20&%20Lily%20Tang.pdf)有时也可以考虑在攻击面范围内。

# 0x03 Goahead

[GoAhead](https://www.embedthis.com/goahead/doc/)也是一个比较常见的嵌入式Web服务器，目前主要的开发版本为[GoAhead 3/4](https://github.com/embedthis/goahead/)。其官方文档中详细阐述了在`route.txt`定义的[路由规则](https://www.embedthis.com/goahead/doc/users/routing.html)，根据匹配的URI来执行不同的[handler](https://www.embedthis.com/goahead/doc/users/handlers.html)：有[action](https://www.embedthis.com/goahead/doc/users/goactions.html) handler直接在GoAhead进程中执行C函数，[CGI](https://www.embedthis.com/goahead/doc/users/cgi.html) handler执行新的CGI程序，也有默认的file handler处理文件请求，还可以自定义新的[handler](https://www.embedthis.com/goahead/doc/developers/handlers.html)。开发者自定义的`GoActions`则是常见的审计点，goahead代码的[自身问题](https://www.anquanke.com/post/id/94195)也需考虑在内。

## 源码分析

执行CGI程序的流程与前述的Web服务器大同小异，这里重点关注可以在goahead中直接执行的`action`功能。IoT固件中常见的情况是使用2.1.8版本的[goahead](https://github.com/embedthis/goahead/tree/v2.1.8)，`Actions`功能[对应](https://www.embedthis.com/goahead/doc/developers/migrating.html)为`GoForms`功能。其会在`websReadEvent`函数中配合`websGetInput`函数更新处理请求的状态机器，读取完请求头后调用`websUrlHandlerRequest`函数找到匹配URL前缀的处理函数。而在Web服务器初始化过程中调用的`initWebs`函数，会定义几个默认的URL handler：

```c
static int initWebs()
{
	struct hostent	*hp;
	struct in_addr	intaddr;
	char			host[128], dir[128], webdir[128];
	char			*cp;
	char_t			wbuf[128];

    /* ... */

/*
 *	Configure the web server options before opening the web server
 */
	websSetDefaultDir(webdir);
	cp = inet_ntoa(intaddr);
	ascToUni(wbuf, cp, min(strlen(cp) + 1, sizeof(wbuf)));
	websSetIpaddr(wbuf);
	ascToUni(wbuf, host, min(strlen(host) + 1, sizeof(wbuf)));
	websSetHost(wbuf);

    /* ... */

/*
 * 	First create the URL handlers. Note: handlers are called in sorted order
 *	with the longest path handler examined first. Here we define the security 
 *	handler, forms handler and the default web page handler.
 */
	websUrlHandlerDefine(T(""), NULL, 0, websSecurityHandler, 
		WEBS_HANDLER_FIRST);
	websUrlHandlerDefine(T("/goform"), NULL, 0, websFormHandler, 0);
	websUrlHandlerDefine(T("/cgi-bin"), NULL, 0, websCgiHandler, 0);
	websUrlHandlerDefine(T(""), NULL, 0, websDefaultHandler, 
		WEBS_HANDLER_LAST); 

/*
 *	Now define two test procedures. Replace these with your application
 *	relevant ASP script procedures and form functions.
 */
	websAspDefine(T("aspTest"), aspTest);
	websFormDefine(T("formTest"), formTest);

/*
 *	Create the Form handlers for the User Management pages
 */
#ifdef USER_MANAGEMENT_SUPPORT
	formDefineUserMgmt();
#endif

/*
 *	Create a handler for the default home page
 */
	websUrlHandlerDefine(T("/"), NULL, 0, websHomePageHandler, 0); 
	return 0;
}
```

开发者可以借助`websFormDefine`函数定义与`formName`相关联的C处理函数。这样在处理`/goform`开头的请求时，会在`formSymtab`中找到对应的`formName`，最终调用之前`define`过的`fn`函数：

```c
/************************************* Code ***********************************/
/*
 *	Process a form request. Returns 1 always to indicate it handled the URL
 */

int websFormHandler(webs_t wp, char_t *urlPrefix, char_t *webDir, int arg, 
	char_t *url, char_t *path, char_t *query)
{
	sym_t		*sp;
	char_t		formBuf[FNAMESIZE];
	char_t		*cp, *formName;
	int			(*fn)(void *sock, char_t *path, char_t *args);

	a_assert(websValid(wp));
	a_assert(url && *url);
	a_assert(path && *path == '/');

	websStats.formHits++;

/*
 *	Extract the form name
 */
	gstrncpy(formBuf, path, TSZ(formBuf));
	if ((formName = gstrchr(&formBuf[1], '/')) == NULL) {
		websError(wp, 200, T("Missing form name"));
		return 1;
	}
	formName++;
	if ((cp = gstrchr(formName, '/')) != NULL) {
		*cp = '\0';
	}

/*
 *	Lookup the C form function first and then try tcl (no javascript support 
 *	yet).
 */
	sp = symLookup(formSymtab, formName);
	if (sp == NULL) {
		websError(wp, 200, T("Form %s is not defined"), formName);
	} else {
		fn = (int (*)(void *, char_t *, char_t *)) sp->content.value.integer;
		a_assert(fn);
		if (fn) {
/*
 *			For good practice, forms must call websDone()
 */
			(*fn)((void*) wp, formName, query);

/*
 *			Remove the test to force websDone, since this prevents
 *			the server "push" from a form>
 */
#if 0 /* push */
			if (websValid(wp)) {
				websError(wp, 200, T("Form didn't call websDone"));
			}
#endif /* push */
		}
	}
	return 1;
}

/******************************************************************************/
/*
 *	Define a form function in the "form" map space.
 */

int websFormDefine(char_t *name, void (*fn)(webs_t wp, char_t *path, 
	char_t *query))
{
	a_assert(name && *name);
	a_assert(fn);

	if (fn == NULL) {
		return -1;
	}

	symEnter(formSymtab, name, valueInteger((int) fn), (int) NULL);
	return 0;
}
```

## 实际案例

在某型号的Dlink固件当中使用goahead作为Web服务器，逆向可知其沿用的是2.1.8版本的代码，在`main`函数中可以找出开发者新增的、和功能处理相关的`formDefine*`函数：

```c
          websSetDefaultDir(acStack336);
          __s1 = inet_ntoa(__in);
          sVar5 = strlen(__s1);
          uVar6 = sVar5 + 1;
          if (0x7f < uVar6) {
            uVar6 = 0x80;
          }
          ascToUni(auStack208,__s1,uVar6);
          websSetIpaddr(auStack208);
          websSetHost(auStack208);
          websSetDefaultPage("default.asp");
          websSetPassword(PTR_DAT_004c19a4);
          websOpenServer(DAT_004c1994,DAT_004c1998);
          websUrlHandlerDefine(&DAT_00473984,0,0,websSecurityHandler,1);
          websUrlHandlerDefine("/goform",0,0,websFormHandler,0);
          websUrlHandlerDefine("/cgi-bin",0,0,websCgiHandler,0);
          websUrlHandlerDefine("/sharefile",0,0,websShareFileHandler,0);
          websUrlHandlerDefine(&DAT_00473984,0,0,websDefaultHandler,2);
          formDefineUtilities();
          formDefineInternet();
          form_define_ip_control();
          formDefineQoS();
          formDefineWireless();
          formDefineInic();
          formDefineFirewall();
          formDefineManagement();
          formDefineLogout();
          formDefineWizard();
          formDefineVPN();
          formDefineHttpSharefile();
          websUrlHandlerDefine(&DAT_00471298,0,0,&LAB_0045df0c,0);
```

这些`formDefine*`函数大多使用`websFormDefine`函数定义新增的处理函数，在审计时可重点关注：

```c
void formDefineQoS(void)

{
  websFormDefine("QoSPortSetup",&LAB_0046d75c);
  websFormDefine("qosClassifier",&LAB_0046c590);
  websFormDefine("QoSSetup",FUN_0046db08);
  websFormDefine("QoSDeleteULRules",&LAB_0046d5d4);
  websFormDefine("QoSDeleteDLRules",&LAB_0046d5f8);
  websFormDefine("QoSLoadDefaultProfile",&LAB_0046d61c);
                    /* WARNING: Could not recover jumptable at 0x0046e84c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  websAspDefine("QoSisPortBasedQoSSupport",&LAB_0046e73c);
  return;
}
```

# 0x04 总结

从对以上嵌入式Web服务器的分析可以看出，其会在读取完HTTP请求头后，根据URL前缀来选择执行的CGI程序或内部函数，并且根据`PATH_INFO`选择执行程序内最终的handler函数。Web服务器自身的历史问题、新增的二进制代码问题、脚本语言代码审计问题、功能控制点的逻辑问题以及相关的逆向工作都是需要重点关注的。希望通过这次的简要总结能对未知嵌入式Web服务器的安全审计工作提供些参考。

