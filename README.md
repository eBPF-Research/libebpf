## Embedded eBPF library for IoT Devices  


#### Design  
1. VM-centrate  
struct ebpf_env {
    void *helpers;
    int err_code;
    char err_msg[32];
    int ref_cnt;
};
struct ebpf_vm {
    u8 code;
    int code_len;
    int pc;
};
u64 ebpf_vm_exec(void *mem, int mem_size);
u64 ebpf_vm_jit_run();

struct ebpf_prog {
    ebpf_vm *vm;
}
env -> mutiple vm
vm -> env

one ebpf_prog <=> one vm instance

2. Prog-centrate
ebpf_vm_run(ebpf_env *env, u8 *code, int codelen, u8 *mem, int memlen);

