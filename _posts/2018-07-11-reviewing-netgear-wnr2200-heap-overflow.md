---
layout: post
title: "Reviewing Netgear WNR2200 Heap Overflow"
---

# 0x00 Preface

Although the security protection on routers is relatively poor, it is also necessary to learn some attack surfaces and how to exploit them on different platforms. [Porting exploits to a Netgear WNR2200](https://www.contextis.com/blog/porting-exploits-netgear-wnr2200) is an example of using the exp in MSF to compromise easily the router with old version samba. While the cross platform exploitation has been completed, it can be known that the function pointer of the structure is covered due to a heap overflow, with the executable permissions and brute force on the heap, the shellcode in different architectures is carried out. There is a Netgear WNR2200 on in my hand, and the firmware version is the same as the one in the text. Therefore, it is a good chance to analyze the exploitation of [CVE-2007-2446](https://www.exploit-db.com/exploits/16859/) on the router.

<!-- more -->

# 0x01 Environment preparation

## Unpacking the firmware

There are some obstructions during the firmware unpacking in the original article, but the newer binwalk in Kali hasn't pressure at all:

![][1]

## Obtaining the shell

If you are too lazy like me to find out the serial port, let's explore whether the router will start the telnet related process or not:

![][2]

The method of opening telnet service is given: turning on the router debug mode and sending a specific package to telnetenable process. I am always curious about everything with my IDA, it can be seen that 23 port of UDP is binded, and the payload is filled. It is only after the correct compare that the utelnetd will be started:

![][3]

The original telenetenable script seems to be useless, but the excellent elder has made corresponding [modifications](https://github.com/insanid/netgear-telenetenable/commit/445c972ec7bf04433986d96b8f26dfd9c1af722a#commitcomment-9706551), which is worth learning:

![][4]

## Setting up Samba

The friends who understand [Samba](http://cn.linux.vbird.org/linux_server/0370samba.php) know that some configuration jobs have to be done before starting it. I happen to have a same router, so it's natural to plug in the U disk and set up a shared folder by Samba process:

![][5]

If you use QEMU to simulate samba, you have to run the `/etc/init.d/samba` script to boot service, which I won't talk about more in the article.

If you like x86 instead of mipsbe, [compiling and installing](http://rockycao2008.blogspot.com/2007/02/samba-3024_25.html) by yourself is helpful for subsequent analysis and exploitation.

# 0x02 Analysis

You can see that the version of the smbd is [3.0.24](https://ftp.samba.org/pub/samba/stable/samba-3.0.24.tar.gz) and the Linux kernel version is relatively low and old in the shell, and the author has ported the ['lsa_io_trans_names'Heap Overflow](https://www.exploit-db.com/exploits/16859/) vulnerability. Owing to the rare analysis of the vulnerability in the Internet, there should be a meal.

At the beginning of the analysis I went into the misunderstanding and always wanted to understand the content or specification of the samba, dcerpc, LSA protocol in exploitation. In fact, the complex process in exploitation could cover up the real vulnerabilities. Under the xd_xd shifu's [reveal](http://xdxd.love/2017/11/09/samba-cve-2007-2446-%E5%A0%86%E6%BA%A2%E5%87%BA%E5%88%86%E6%9E%90/), we can see the vulnerability more clearly through its [patch](https://github.com/samba-team/samba/commit/f65214be68c1a59d9598bfb9f3b19e71cc3fa07b?diff=unified#diff-6cfc9b6d911b446fa3dd0ade6e4a35f0), in which the num_entries and num_entries2 fields are compared and unified:

![][6]

Being combined with the vulnerability function lsa_io_trans_names, the source code will be more clear. Num_entries and num_entries2 are our controlled fields in the protocol, which assigns num_entries LSA_TRANS_NAME structure size memory, and then writes the structure from network stream to memory in a num_entries2 times loop. If num_entries2 is larger than num_entries, the metadata of second allocated heap `trn->uni_name` will be overwritten:

![][7]

As luck would have it, samba uses a custom heap allocator, talloc, which adds a number of meta information to make up a new metadata. It also contains a function pointer that will be called when the heap is being freed:

![][8]

The things after hijacking pc by overriding are routine.  If you are still crazy about the protocol, it is more efficient to read the source code and capture the [traffic](https://github.com/Larryxi/My_tools/tree/master/cve_2007_2446_pcapng) to analysis at the same time. The connection and login operation based on the [samba protocol](https://msdn.microsoft.com/en-us/library/cc246231.aspx) are no need to explain, [binding](https://msdn.microsoft.com/en-us/library/cc234432.aspx) handle to generate [dcerpc](https://en.wikipedia.org/wiki/DCE/RPC), then calling [LsarOpenPolicy](https://msdn.microsoft.com/en-us/library/cc234489.aspx) to open a context handle, finally, calling [LsarLookupSids](https://msdn.microsoft.com/en-us/library/cc234488.aspx) to convert Sids to name ports to the vulnerability function. In general, the [relationship](https://msdn.microsoft.com/en-us/library/cc234427.aspx) between several agreements is the following: 

![][9]

# 0x03 Exploit

Before we debug the vulnerability, let's take a look at the relevant security mechanism. Although ASLR in the system is 1, its memory distribution is unchanged even after rebooting the system, and the heap has executable permission:

![][10]

Samba forks sub process for each connection, the memory layout is the same and the crash does not affect the parent process. After the coverage of the function pointer, we can jump to the executable heap, the heap also has the shellcode that we carry in the package, but we don't know which address the shellcode is on. Nop sled and brute force are used to trigger the shellcode in the exploitation.

At first, I wanted to debug the overflow on the router remotely, but it was found that the router's system might not support [fork debugging](https://sourceware.org/gdb/onlinedocs/gdb/Forks.html) and could not be interrupted in the sub process. In fact, we don't have to stick at a platform using the same exploitation, so I will debug on the lovely Ubuntu.

After setting the breakpoint on `lsa_io_trans_names` and target on Ubuntu, the processing of  packets can be seen during the exploitation:

![][11]

After calling second `PRS_ALLOC_MEM`, let's look at the second talloc_chunk header (16 bytes alignment). We can use the `\x70\xec\x14\xe8` flags value in exploitation as the location reference, at this time the function pointer is 0:

![][12]

After writing the memory num_entries2 times, the function pointer in the metadata of header is covered with `0x08352000` in the exploitation. It is more interesting that the `next` and `prev` covered with `0x41414141` would cause an exception in the article, but MSF has no problem with the script that has been [modified](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/samba/lsa_transnames_heap.rb#L280) to `0x00000000`; The place that is `0x50505050` is changed to `0x00005050`, it is no harm because of some aligned operations:

![][13]

After calling `smb_io_unistr2`, it will return 0 to make `lsa_io_trans_names2` return False directly:

![][14]

After contine instruction, the function pointer will be called in the talloc free process:

![][15]

The heap address  is left to brute force beacuse of the mines on it:

![][16]

The router is the mips bigend environment, MSF is also very considerate for us to prepare the `mipsbe/better` NOP and rebound shell payload, it is more magical that the heap address scope on mips platform is added to brute force, which may be the author's masterpiece:

![][17]

Get road with code, get shell with dream:

![][18]

# 0x04 Conclusion

1. The exploit way in the article also gives us a new IoT security audit point: pay attention to the historical vulnerability of old version service; the use of the samba protocol in the IoT device is also noteworthy.
2. There is a `\xe9` jump in the exploitation, we need to think about the intention here.
3. Smbd can be interrupted by using QEMU according to the original method.

![][19]


[1]: https://wx3.sinaimg.cn/large/ee2fecafly1ft6aoq6psbj20k306jwiz.jpg
[2]: https://wx2.sinaimg.cn/large/ee2fecafly1ft6aotpvyxj20ju08kn2p.jpg
[3]: https://wx4.sinaimg.cn/large/ee2fecafly1ft6aov9bpoj20vp0lcmyp.jpg
[4]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6ap0bnsxj20jt0ezajk.jpg
[5]: https://wx4.sinaimg.cn/large/ee2fecafly1ft6ap1ullmj21ge0dlta0.jpg
[6]: https://wx4.sinaimg.cn/large/ee2fecafly1ft6ap37lrxj20r90d5757.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1ft6ap4fxs4j20pd0nejsw.jpg
[8]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6ap4ybbfj20hx04oaa5.jpg
[9]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6ap5v9w0j20eb09fgmi.jpg
[10]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6ap8jablj20jt070jw7.jpg
[11]: https://wx2.sinaimg.cn/large/ee2fecafly1ft6ap9u72uj20jt09lab6.jpg
[12]: https://wx2.sinaimg.cn/large/ee2fecafly1ft6apakt8zj20jt031t8w.jpg
[13]: https://wx3.sinaimg.cn/large/ee2fecafly1ft6apbdqrxj20js07mgm5.jpg
[14]: https://wx2.sinaimg.cn/large/ee2fecafly1ft6apclaecj20jt0a2t9z.jpg
[15]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6apdygshj20jt09iq3y.jpg
[16]: https://wx1.sinaimg.cn/large/ee2fecafly1ft6apes61hj20jr07i3za.jpg
[17]: https://wx4.sinaimg.cn/large/ee2fecafly1ft6aplahszj20k00dkjzs.jpg
[18]: https://wx3.sinaimg.cn/large/ee2fecafly1ft6apqqefej20k20d2qc9.jpg
[19]: https://wx3.sinaimg.cn/large/ee2fecafly1ft6apv5racj20k30engs6.jpg
