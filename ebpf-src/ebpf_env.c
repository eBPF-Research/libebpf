#include "ebpf_env.h"
#include "ebpf_vm.h"
#include "ebpf_error.h"
#include "ebpf_allocator.h"
#include <stddef.h>

ebpf_env current_env;

void init_ubpf_env() {
    current_env.prog_list = NULL;
    current_env.tail = NULL;
    current_env.cur_size = 0;
}

ebpf_prog* ebpf_add_prog(const void *code, u32 code_len) {
	ebpf_prog *prog = (ebpf_prog*) ebpf_malloc(sizeof(ebpf_prog));
    prog->next = NULL;
    ebpf_vm *vm = ebpf_create();
    prog->vm = vm;
    int ret = ebpf_vm_load(vm, code, code_len);
    // prog

    if (current_env.prog_list == NULL) {
        current_env.prog_list = prog;
    }
    if (current_env.tail != NULL) {
        current_env.tail->next = prog;
    }
    current_env.tail = prog;
    current_env.cur_size++;
    prog->prog_id = current_env.cur_size;

    return prog;
}

int ebpf_remove_prog(ebpf_prog *prog) {
    ebpf_vm_destroy(prog->vm);
    ebpf_free(prog);
    return RET_OK;
}

void destory_ebpf_env() {
    
}