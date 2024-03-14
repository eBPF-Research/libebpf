#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
#include <string.h>
#define _GNU_SOURCE
#include <libebpf.h>
#include <stdlib.h>
#include <libebpf_internal.h>

static ebpf_malloc global_malloc = &malloc;
static ebpf_free global_free = &free;

static char global_error_string[1024] = "";

void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free) {
    global_malloc = malloc;
    global_free = free;
}

const char *ebpf_error_string() {
    return global_error_string;
}

ebpf_vm_t *ebpf_vm_create() {
    ebpf_vm_t *vm = global_malloc(sizeof(ebpf_vm_t));
    if (!vm) {
        ebpf_set_error_string("global_malloc returned NULL when allocating ebpf_vm");
        return NULL;
    }
    memset(vm, 0, sizeof(*vm));
    vm->helpers = global_malloc(sizeof(ebpf_external_helper_fn) * MAX_EXTERNAL_HELPER);
    if (!vm->helpers) {
        ebpf_set_error_string("global_malloc returned NULL when allocating helpers");
        global_free(vm);
        return NULL;
    }

    return vm;
}
void ebpf_vm_destroy(ebpf_vm_t *vm) {
    global_free(vm);
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
    if (vm->insns) {
        global_free(vm->insns);
    }
    vm->insns = global_malloc(sizeof(struct libebpf_insn) * code_len);
    if (!vm->insns) {
        ebpf_set_error_string("Failed to call malloc");
        return -ENOMEM;
    }
    memcpy(vm->insns, code, sizeof(struct libebpf_insn) * code_len);
    return 0;
}
void ebpf_vm_unload_instructions(ebpf_vm_t *vm) {
    if (vm->insns) {
        global_free(vm->insns);
        vm->insns = NULL;
        vm->insn_cnt = 0;
    }
}
