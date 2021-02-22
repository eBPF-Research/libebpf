#ifndef UBPF_VM_H_
#define UBPF_VM_H_

#include "ebpf_types.h"
#include "ebpf_inst.h"

#define MAX_INSTS 4096
#define STACK_SIZE 512
// #define STACK_SIZE 128
#define MAX_BPF_EXT_REG 16

#define MAX_EXT_FUNCS 12

typedef u64 (*ext_func)(u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 arg4);

typedef uint64_t (*ebpf_jit_fn)(void *args, uint16_t args_len);

typedef struct ebpf_helper_func {
	ext_func *ext_funcs;
	const char **ext_func_names;
	int refcnt;
} ebpf_helper_func;

struct jit_mem;
typedef struct ebpf_vm {
	struct ebpf_inst *insts;
	u16 num_insts;
	bool bounds_check_enabled;
	ebpf_helper_func *helper_func;
	ebpf_jit_fn jit_func;
	struct jit_mem *jmem;
	bool use_jit;
} ebpf_vm;

struct ebpf_vm *ebpf_create(void);
void ebpf_vm_destroy(struct ebpf_vm *vm);
/*
Load code
Execute code
*/

// use code reference 
void ebpf_vm_set_inst(struct ebpf_vm *vm, const uint8_t *code, uint32_t code_len);

// copy code to vm
int ebpf_vm_load(struct ebpf_vm *vm, const void *code, u32 code_len);

u64 ebpf_vm_exec(const struct ebpf_vm *vm, void *mem, u32 mem_len);

// register functions
int ebpf_register(struct ebpf_vm *vm, unsigned int idx, const char *name, void *fn);

#endif