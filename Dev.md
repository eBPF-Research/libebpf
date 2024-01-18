### Dev Plan

C开发一个Lua那样方便移植和嵌入的ebpf运行时，支持从256kb内存的嵌入式IoT到linux server等全部设备和多种架构。

#### 功能开发规划

目标1：打造一个lua那样可嵌入的ebpf语言库，和ubpf项目差异化，摆脱ubpf影响，以及移除掉linux header相关的JIT header
> 最终可以只保留 ubpf JIT， python工具链，和单元测试用例。可以从[这个项目](https://github.com/IoTAccessControl/libebpf)重新复制一遍   
> 除了python工具链，其他地方ubpf改成ebpf，叫ebpf_xxx，而不是ubpf_xxx   
> 甚至可以删光现有c代码（特别是那些多余的目录），开个新分支从头全部重写。确保接口像lua那样简单方便嵌入   
> 封装自己的ebpf_malloc接口，方便设置分配器
> Less is more, 保证清晰可读的前提下，文件和代码、目录尽可能少。代码即注释，采用下划线命名   
   

目标2:重写VM解释器。
> 参考linux kernel，复制其基于table jump的和基于switch的解释器   
> 这行居然copy struct，需要改成指针， https://github.com/eBPF-Research/libebpf/blob/master/src/ebpf_vm.c#L293   
   


目标3:复制linux 内核其他架构的eBPF JIT。
> 保留ubpf现有的x86_64和arm64 JIT，模仿其接口风格，复制移植linux kernel中现有JIT（arm32/mips/riscv，至少完成arm32）架构   
> 提供基于qemu-user or qemu-system的其他架构测试命令。确保JIT都通过ubpf自带的多种单元测试   
> [这里其实复制了](https://github.com/eBPF-Research/libebpf/blob/master/src/linux_bpf.h)但是仍然有linux的类型以及不必要的结构体（bpf_prog等），需要完全抹去kernel痕迹，风格和ubpf JIT一致   
   


目标4:Map功能
> 实现和kernel现有接口类似的map功能，实现arraymap, hashmap (unordered_map这样的即可，不必红黑树。可以像这样[复制一个](https://github.com/IoTAccessControl/tor/blob/master/src/lib/ebpf/ewfd-defense/src/hashmap.c)), ringbuffer三种map    
  

目标5:实现FFI
> 实现一个比上次hotpatch更好（性能、设计、功能）的ffi接口。 


目标6:加上CI和简单demo   
> demo参考：https://github.com/IoTAccessControl/libebpf/tree/master/example   
> 把现在JIT和解释器的单元测试加到CI任务

    

#### Git提交原则
- 建议每个commit尽量200行以上的修改（bug fix的除外）  
- 每个commit应该体现出关键milestone（想象一下公司里面有code review，可以像kernel那样一个pull request，全部commit rebase成一个）   
- 别提交没意义的小commit（改几行文档那种），可以先自己分支上再合并小commit（例如：每次开个分支，直接无脑commit --amend合并后面的提交）   



#### C代码风格
- 使用tab-4 
- “{ ”不换行 （节约屏幕高度，尽可能看到更多行代码）
- 行宽150 （大家的显示器应该都很长？）
- if 一行也需要花括号“{}”
- 变量和“=”间保持基本空格（例如: int i = 0而[不要写 i=0](https://github.com/cloudwu/skynet/blob/master/skynet-src/socket_server.c#L349)）
