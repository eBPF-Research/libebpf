#include "jit.h"
#include "ebpf_allocator.h"
#include "ebpf_vm.h"

#if defined(JIT_STATIC_MEM)
static uint8_t jit_buffer[2048];
static uint8_t offset_mem[1024];

jit_mem g_jit_mem;

jit_mem* jit_mem_allocate(int insts_num) {
	jit_mem *mem = &g_jit_mem;
	mem->code_size = sizeof(jit_buffer);
	mem->jit_code = jit_buffer;
	mem->jmp_offsets = offset_mem;
	memset(jit_buffer, 0, sizeof(jit_buffer));
	memset(offset_mem, 0, sizeof(offset_mem));
	return mem;
}

void jit_mem_free(jit_mem *mem) {
	mem->code_size = 0;
	mem->jit_code = NULL;
	mem->jmp_offsets = NULL;
}

#else

// 
jit_mem* jit_mem_allocate(int insts_num) {
	jit_mem *mem = ebpf_malloc(sizeof(jit_mem));
	mem->code_size = 10 * insts_num + 16;
	mem->jit_code = ebpf_malloc(mem->code_size);
	int offset_size = 4 * insts_num + 16;
	mem->jmp_offsets = ebpf_malloc(offset_size);
	memset(mem->jit_code, 0, mem->code_size);
	memset(mem->jmp_offsets, 0, offset_size);
}

void jit_mem_free(jit_mem *mem) {
	ebpf_free(mem->jit_code);
	ebpf_free(mem->jmp_offsets);
	ebpf_free(mem);
}

#endif

void jit_state_set_mem(jit_state *state, jit_mem *mem) {
	state->jmem = mem;
	state->jit_code = (uint8_t *) ((uint32_t) mem->jit_code & (~0x3));
	state->offsets = (uint32_t *) mem->jmp_offsets;
}

void gen_jit_code(struct ebpf_vm *vm) {
	if (vm->jmem != NULL) {
		jit_mem_free(vm->jmem);
	}
	vm->jmem = jit_mem_allocate(vm->num_insts);
	jit_state state;
	state.insts = vm->insts;
	state.inst_num = vm->num_insts;
	state.idx = 0;
	//state.jit_code = (uint8_t *) ((uint32_t) vm->jmem->jit_code & (~0x3));
	state.err_line = 0;
	state.__bpf_call_base = (uint32_t) vm->helper_func;
	jit_state_set_mem(&state, vm->jmem);
	jit_compile(&state);
	vm->jit_func = (ebpf_jit_fn) ((uint32_t) vm->jmem->jit_code | 0x1);
	jit_dump_inst(&state);
#ifdef LINUX_TEST
	// jit_dump_inst(&state);
#endif

#ifdef SYS_CORTEX_M4
    __asm__("DSB");
    __asm__("ISB");
#endif
}