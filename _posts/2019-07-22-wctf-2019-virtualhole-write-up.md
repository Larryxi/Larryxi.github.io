---
layout: post
title: "WCTF 2019 VirtualHole Write Up"
---

# 0x00 环境搭建

VirtualHole是WCTF2019线下赛一道关于qemu虚拟机逃逸的题目，也是一个[qemu漏洞挖掘](httpss://www.tuicool.com/articles/MzqYbia)的入门机会。作者给出了修改后的megasas.c及安装好的虚拟机镜像文件，无疑是要搭建针对qemu的调试环境。

<!-- more -->

宿主机的环境选择为Ubuntu 16.04，其上的libc版本的堆分配机制还没用到[tcache](httpss://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)机制，方便我们利用前期堆块的布局构造。而我是在VMWare上搭建的Ubuntu，需要开启虚拟机的嵌套虚拟化选项：

![][1]

线下交流可知使用的qemu版本为qemu-3.1.0-rc5，按照[文档](httpss://wiki.qemu.org/Hosts/Linux)从源码编译，编译前建议安装文档里推荐的附加package，不然在程序断下时来会出现把鼠标卡死的状况。可开启debug和关闭pie方便我们的调试分析：

```shell
./configure  --enable-kvm --target-list=x86_64-softmmu --enable-debug --disable-pie
make
sudo make install
```

使用gdb直接attach qemu进程时可能会出现长时间的等待，直接从gdb中启动就比较省事，并[忽略](httpss://wiki.qemu.org/Documentation/Debugging)SIGUSR1，当然也可以写个[文件](httpss://blog.csdn.net/iamanda/article/details/54587104)启动：

```
sudo gdb -q --args qemu-system-x86_64 -m 2048 -hda ~/opt/virtualhole/Centos7-Guest.img --enable-kvm -device megasas
handle SIGUSR1 noprint nostop
```

qemu/kvm作为一个hypervisor会对外部设备进行模拟，客户机中的程序一般通过对应设备的驱动程序和这些虚拟设备交互，而这些虚拟设备暴露的攻击面，我们在测试时就需要编写对应操作系统的驱动程序来直接和虚拟设备交互了。驱动程序的编写可参考[《LINUX设备驱动编程一书》](httpss://lwn.net/Kernel/LDD3/)，linux内核模块的[Makefile](httpss://stackoverflow.com/questions/20301591/m-option-in-make-command-makefile)如下：

```
ifneq ($(KERNELRELEASE),)
	obj-m := virtualhole.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif
```

关于更多的攻击面和深入研究，可参看[《QEMU 与 KVM 虚拟化安全研究介绍》](httpss://bbs.pediy.com/thread-224371.htm)，VictorV师傅领进门了哇。

# 0x01 题目分析

根据提示信息`qemu-system-x86_64 -m 2048 -hda Centos7.img --enable-kvm -device megasas`或者megasas.c中的注释信息`QEMU MegaRAID SAS 8708EM2 Host Bus Adapter emulation`，都可知这是一个[RAID](httpss://baike.baidu.com/item/RAID%E7%A3%81%E7%9B%98%E9%98%B5%E5%88%97)存储设备。根据文件目录`hw/scsi/megasas.c`可知使用的是SCSI接口。

其实稍微了解的同学，可直接从`qemu-system-x86_64 -device ?`中知晓：

![][2]

或者在客户机中执行`lshw`，还能看到设备的I/O端口和I/O内存：

![][3]

因为是修改过后的megasas.c文件，有个取巧的套路是diff原文件快速定位可能出现的问题点，虽然实战环境没有那么直接，权当这次是在补丁分析吧。diff文件详见[gist](httpss://gist.github.com/Larryxi/98fa732415fdd9f80dbf877901e08815)，其主要是新增了`megasas_queue_write`的处理内容：

```
***************
*** 2189,2195 ****
  static void megasas_queue_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
  {
!     return;
  }
  
  static const MemoryRegionOps megasas_queue_ops = {
--- 2410,2422 ----
  static void megasas_queue_write(void *opaque, hwaddr addr,
                                 uint64_t val, unsigned size)
  {
!     MegasasState *s = opaque;
!     PCIDevice *pci_dev = PCI_DEVICE(s);
!  
!     if(!mega_main.pci_dev){
!         mega_main.pci_dev = pci_dev;
!     }
!    handle_plus_write(&mega_main, addr>>2, val);
  }
```

原始在`megasas_scsi_realize`函数中初始化了对megasas_queue的操作`megasas_queue_ops`内存区段长度为0x40000，对应的I/O内存就是上图中的`0xfeb80000-0xfebbffff`：

```c
    memory_region_init_io(&s->mmio_io, OBJECT(s), &megasas_mmio_ops, s,
                          "megasas-mmio", 0x4000);
    memory_region_init_io(&s->port_io, OBJECT(s), &megasas_port_ops, s,
                          "megasas-io", 256);
    memory_region_init_io(&s->queue_io, OBJECT(s), &megasas_queue_ops, s,
                          "megasas-queue", 0x40000);
```

我们在内核模块中使用`ioremap`映射后就可以对I/O内存操作啦，试验性地编写内核模块和调试就能理清文件中新增的switch-case内容了：

```c
#include <linux/init.h>
#include <linux/module.h>
#include <asm/io.h>

#define PHYS_ADDR 0xfeb80000
#define MAP_PHYS_LEN 0x1000

MODULE_LICENSE("Dual BSD/GPL");

void exploit(void *mapped_addr)
{
    writel(0x200, mapped_addr+1*4);
}

static int virtualhole_init(void)
{
    printk(KERN_ALERT "VirtualHole Init\n");
    void *mapped_addr = ioremap(PHYS_ADDR, MAP_PHYS_LEN);
    exploit(mapped_addr);
    iounmap(mapped_addr);
    return 0;
}

static void virtualhole_exit(void)
{
    printk(KERN_ALERT "VirtualHole Exit\n");
}

module_init(virtualhole_init);
module_exit(virtualhole_exit);
```

其实读源代码也容易弄懂逻辑，其主要定义了两个结构：Block和frame，两者均使用`calloc`动态申请，预测是需要找个溢出的漏洞，间接调用在frame_header中保存的get_flag函数指针即可：

```c
typedef struct _data_block{
    void *buffer;
    uint32_t size;
} data_block;

typedef struct _frame_header{
    uint32_t size;
    uint32_t offset;
    void *frame_buff;
    void (*get_flag)(void *dst);
    void (*write)(void *dst, void *src, uint32_t size);
    uint32_t reserved[56];
} frame_header;

typedef struct _mainState{
    uint32_t data_size;
    uint32_t block_size;
    PCIDevice *pci_dev;
    frame_header* frame_header;
} mainState;
```

frame结构作为一个中间者，在客户机端和block中进行数据的传递，并且frame_header中的size有时会有0x200字节的限制。而`megasas_quick_read`函数则可以直接和相应block交互，如图所示：

![][4]

在`megasas_quick_read`函数中也有对`pci_dma_read`的调用，这里涉及到了直接内存访问（DMA）的[内容](https://www.embeddedlinux.org.cn/emb-linux/kernel-driver/201702/12-6170.html)， 我的理解是其直接在物理内存上交换数据进行处理，使用`kmalloc`等函数分配一段物理地址连续的内存，填充上我们的数据之后，将这个位于低端内存的内核逻辑地址经`virt_to_phys`[函数](httpss://blog.csdn.net/macrossdzh/article/details/5958368)转为物理地址，传递给`pci_dma_read`读取：

![][5]

让我们来花十分钟看一下可疑的`megasas_quick_read`函数：

```c
void megasas_quick_read(mainState *mega_main, uint32_t addr)
{
    uint16_t offset;
    uint32_t buff_size, size;
    data_block *block;
    void *buff;

    struct{
        uint32_t offset;
        uint32_t size;
        uint32_t readback_addr;
        uint32_t block_id;
    } reader;

    pci_dma_read(mega_main->pci_dev, addr, &reader, sizeof(reader));

    offset = reader.offset;
    size = reader.size;
    block = &Blocks[reader.block_id];
    buff_size = (size + offset + 0x7)&0xfff8;

    if(!buff_size || buff_size < offset ||
        buff_size < size ){
        return;
    }

    if(!block->buffer){
        return;
    }

    buff = calloc(buff_size, 1);

    if(size + offset >= block->size){
        memcpy(buff + offset, block->buffer, block->size);
    }else{
        memcpy(buff + offset, block->buffer, size);
    }
    
    pci_dma_write(mega_main->pci_dev, reader.readback_addr, 
                    buff + offset, size);

    free(buff);
}
```

其中接收的reader结构体内容可控，block_id有范围检查，offset和size也做的有整数溢出的检查。关键点就在于`memcpy`附近，使用`if(size + offset >= block->size)`作为判断条件没错，可以理解为`if(buff_len >= block_size)`，但应该是`memcpy(buff, block->buffer, block->size)`才能保证在向buff中拷贝时不会溢出，如此一来最多可以溢出offset个字节。从另一个角度考虑，正确的写法也可以是`if(size >= block->size)`。

# 0x02 局部写入

如果溢出能覆盖frame_header中保存的write函数指针，那么在调用`megasas_framebuffer_store`或`megasas_framebuffer_readback`函数后即可劫持控制流。作为一道CTF题目，作者贴心地提供了get_flag函数简化了我们的利用流程。

首先想到的是不借助信息泄露漏洞，溢出write函数指针的最后一个字节（小端序），使其变为get_flag地址，两者的参数列表类似，调用`megasas_framebuffer_store`即可把flag信息写入block，最终通过`megasas_quick_read`正常读取就可以了。

要溢出frame_header结构，就得使`megasas_quick_read`中`calloc`分配的buff位于frame_header之上，如图所示：

![][6]

如果你对常规的[glibc堆分配](httpss://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)比较熟悉，不难发现上图中省略了chunk_header信息。要完成此布局，我这里使用的方法是先分配BASE_ID个大小的chunk，将Small Bin和Large Bin都耗尽，乃至是从Top Chunk上分配堆块。接着释放`Blocks[BASE_ID+1]`和`Blocks[BASE_ID+3]`堆块（防止合并相邻free chunk），分配frame_header和frame_buff结构后释放`Blocks[BASE_ID+0]`堆块，在` megasas_quick_read`中分配的buff就可以定位在frame_header之上了：

![][7]

总体的攻击思路如下：

1. 根据上述思路完成堆内存布局。
2. `kzalloc`分配溢出使用的payload，`virt_to_phys`转换后经case 8和case 10，存储至`Blocks[BASE_ID+4]`中。
3. 经case 12调用`megasas_quick_read`触发溢出覆盖write指针低位一字节。
4. 经case 10调用`megasas_framebuffer_store`，间接调用`get_flag`函数将flag字符串写入`Blocks[BASE_ID+4]`中。
5. 经case 12正常读取`Blocks[BASE_ID+4]`中的flag信息。

代码详见[gist](httpss://gist.github.com/Larryxi/89b8ab78e183d99e54b89adda8074ee3)，其中有几点需注意：

1. overwrite_payload结构体内部对齐会使溢出的位移有所偏差，所以在其中均使用`uint8_t`类型规避此问题。
2. 溢出过程中需要考虑freme_header堆块的chunk_header，保持该堆块的size为0x115，绕过`free(buff)`过程中double free的检查。
3. `megasas_quick_read`过程中传递的reader结构体，生成方法和步骤2一样。
4. 我搭建的环境中get_flag的偏移为0x55，这256个偏移的爆破成本我觉得是可以接受的。

![][8]

# 0x03 信息泄露

没有信息泄露终归是胜之不武，拿着能溢出的frame_header结构看看是否有信息泄露点。在`megasas_framebuffer_store`函数中，尾部拷贝的size长度是我们溢出可控的，源frame_buff的长度只有0x200，只要size不大于block的size，即可将frame_buff后面的内容拷贝至block中，信息泄露因此产生：

```c
int megasas_framebuffer_store(mainState *mega_main, uint32_t block_id)
{
    frame_header *header = mega_main->frame_header;
    void *src = header->frame_buff;
    uint32_t offset = header->offset;
    uint32_t size = header->size;
    data_block *block = NULL;

    if(block_id >= MAX_BLOCK_ID){
        return -1;
    }

    block = &Blocks[block_id];
    if(block->buffer == NULL || 
        size + offset > block->size ||
        size + offset < size ||
        size + offset < offset)
    {
        return -1;
    }

    header->write(block->buffer + offset, src, size);
    return 0;
}
```

当然是要泄露frame_header中保存的函数指针内容，内存布局就要求frame_header位于frame_buff之后，如图所示：

![][9]

总体的攻击思路如下：

1. 使用相同思路完成堆内存布局。
2. 将覆盖`frame_header->size`为0x500的payload，经case 8和case 10传递至`Blocks[BASE_ID+0]`中。
3. 经case 12调用`megasas_quick_read `仅溢出size字段。
4. 经case 10调用`megasas_framebuffer_store`函数，从frame_buff开始拷贝0x500字节至`Blocks[BASE_ID+4]`中。
5. 经case 12正常读取`Blocks[BASE_ID+4]`内容，获取到泄露的frame_header结构。
6. 经case 2申请分配`Blocks[BASE_ID+2]`，经case 5释放frame_header和frame_buff，经case 4重新分配frame结构，最后经case 3释放`Blocks[BASE_ID+2]`内容。
7. 将覆盖frame_header中的size为0x200和write函数指针为get_flag的payload，同步骤2传递至`Blocks[BASE_ID+0]`中。
8. 经case 12调用`megasas_quick_read `溢出frame_header的size和write字段。
9. 经case 11调用`megasas_framebuffer_readback`函数，将flag信息拷贝至frame_buff中。
10. 经case 9调用`pci_dma_write`函数，最终取回flag字符串。

以上在泄露出get_flag函数地址后，可以和之前“局部写入”走相同的简便思路。这里使用frame_buff来传递flag虽然麻烦但效果是一样的。需要注意的是在第二次存放payload时，`frame_header-size`需要等于0x200才能调用`pci_dma_read`函数，所以多了一个frame结构重分配的步骤6。利用代码详见[gist](httpss://gist.github.com/Larryxi/eca65a4d806e39fc4d619e70d7ede7ef)。

![][10]

# 0x04 总结反思

1. 堆上面的漏洞利用和堆分配机制密切相关，有机会可以多了解Windows上的堆分配和堆风水的有关内容。
2. 记忆天生没有别人好，练就是了。

[1]: https://wx4.sinaimg.cn/large/ee2fecafly1g5a5f8l8iej20kd08a3yy.jpg
[2]: https://wx3.sinaimg.cn/large/ee2fecafly1g5a5f92qorj20kc07qmyj.jpg
[3]: https://wx2.sinaimg.cn/large/ee2fecafly1g5a5f9gra7j20sf09e3yo.jpg
[4]: https://wx3.sinaimg.cn/large/ee2fecafly1g5a5f9w2xej20s607taaa.jpg
[5]: https://wx2.sinaimg.cn/large/ee2fecafly1g5a5famayoj20o70dit9w.jpg
[6]: https://wx4.sinaimg.cn/large/ee2fecafly1g5a5fb0cfhj20cb0b5q30.jpg
[7]: https://wx3.sinaimg.cn/large/ee2fecafly1g5a5fc320yj20xu0p0gpk.jpg
[8]: https://wx2.sinaimg.cn/large/ee2fecafly1g5a5fd7ha1j21a90j1gqi.jpg
[9]: https://wx4.sinaimg.cn/large/ee2fecafly1g5a5fdrcmcj20e10djaa8.jpg
[10]: https://wx2.sinaimg.cn/large/ee2fecafly1g5a5feq0zwj20wo0ijn15.jpg
