#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
#include <string.h>
#define _GNU_SOURCE
#include <libebpf.h>
#include <stdlib.h>
#include <libebpf_internal.h>

ebpf_malloc _libebpf_global_malloc = &malloc;
ebpf_free _libebpf_global_free = &free;

char _libebpf_global_error_string[1024] = "";

void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free) {
    _libebpf_global_malloc = malloc;
    _libebpf_global_free = free;
}

const char *ebpf_error_string() {
    return _libebpf_global_error_string;
}

ebpf_vm_t *ebpf_vm_create() {
    ebpf_vm_t *vm = _libebpf_global_malloc(sizeof(ebpf_vm_t));
    if (!vm) {
        ebpf_set_error_string("global_malloc returned NULL when allocating ebpf_vm");
        return NULL;
    }
    memset(vm, 0, sizeof(*vm));
    vm->helpers = _libebpf_global_malloc(sizeof(ebpf_external_helper_fn) * MAX_EXTERNAL_HELPER);
    if (!vm->helpers) {
        ebpf_set_error_string("global_malloc returned NULL when allocating helpers");
        _libebpf_global_free(vm);
        return NULL;
    }
    vm->bounds_check_enabled = true;
    return vm;
}
void ebpf_vm_destroy(ebpf_vm_t *vm) {
    _libebpf_global_free(vm);
}

int ebpf_vm_register_external_helper(ebpf_vm_t *vm, size_t index, const char *name, ebpf_external_helper_fn fn) {
    if (index >= MAX_EXTERNAL_HELPER) {
        ebpf_set_error_string("Index too large");
        return -E2BIG;
    }
    vm->helpers[index].fn = fn;
    strncpy(vm->helpers[index].name, name, MAX_EXTERNAL_HELPER_NAME_LENGTH);
    return 0;
}

int ebpf_vm_load_instructions(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len) {
    int err;
    if ((err = ebpf_vm_verify(vm, code, code_len)) < 0) {
        return err;
    }
    if (vm->insns) {
        ebpf_set_error_string("code has already been loaded into this VM. Use ebpf_unload_code() if you need to reuse this VM");
        return -EEXIST;
    }
    vm->insns = _libebpf_global_malloc(sizeof(struct libebpf_insn) * code_len);
    if (!vm->insns) {
        ebpf_set_error_string("Failed to call malloc");
        return -ENOMEM;
    }
    memcpy(vm->insns, code, sizeof(struct libebpf_insn) * code_len);
    return 0;
}
void ebpf_vm_unload_instructions(ebpf_vm_t *vm) {
    if (vm->insns) {
        _libebpf_global_free(vm->insns);
        vm->insns = NULL;
        vm->insn_cnt = 0;
    }
}

void ebpf_vm_set_ld64_helpers(ebpf_vm_t *vm, ebpf_map_by_fd_callback map_by_fd, ebpf_map_by_idx_callback map_by_idx, ebpf_map_val_callback map_val,
                              ebpf_code_addr_callback code_addr, ebpf_var_addr_callback var_addr) {
    vm->code_addr = code_addr;
    vm->var_addr = var_addr;
    vm->map_by_fd = map_by_fd;
    vm->map_by_idx = map_by_idx;
    vm->map_val = map_val;
}
