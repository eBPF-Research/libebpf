## 代码清理计划

1. 每种架构尽量只保留一个头文件
将和Linux Kernel相关的删掉。
#include <linux-header/bpf.h>
#include <uapi/linux/errno.h>
#include <linux-header/filter.h>

https://github.com/eBPF-Research/libebpf/blob/master/src/ebpf_jit_x86_64.h

2. 其他makefile和文档尽可能简洁

3. 单元测试
qemu-user
