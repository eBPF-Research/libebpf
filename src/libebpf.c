#include "libebpf_insn.h"
#include "libebpf_vm.h"
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libebpf.h>
#include <stdlib.h>
#include <libebpf_internal.h>

#define IS_UNIX_LIKE defined(__unix__) || defined(__linux__)
#ifdef IS_UNIX_LIKE
#include <sys/mman.h>
#endif
ebpf_malloc _libebpf_global_malloc = &malloc;
ebpf_free _libebpf_global_free = &free;
ebpf_realloc _libebpf_global_realloc = &realloc;
#ifdef IS_UNIX_LIKE
static void *allocate_and_copy(void *buf, size_t bufsize) {
    void *mem = mmap(0, bufsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        ebpf_set_error_string("Unable to mmap");
        return NULL;
    }
    memcpy(mem, buf, bufsize);
    if (mprotect(mem, bufsize, PROT_READ | PROT_EXEC) < 0) {
        ebpf_set_error_string("Unable to set mprotect");
        munmap(mem, bufsize);
        return NULL;
    }
    return mem;
}

ebpf_allocate_execuable_memory_and_copy _libebpf_executable_allocator = &allocate_and_copy;
ebpf_release_executable_memory _libebpf_executor_release = &munmap;
#else

ebpf_allocate_execuable_memory_and_copy _libebpf_executable_allocator = NULL;
ebpf_release_executable_memory _libebpf_executor_release = NULL;
#endif

char _libebpf_global_error_string[1024] = "";

void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free, ebpf_realloc realloc) {
    _libebpf_global_malloc = malloc;
    _libebpf_global_free = free;
    _libebpf_global_realloc = realloc;
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
    _libebpf_global_free(vm->helpers);
    if (vm->insns)
        _libebpf_global_free(vm->insns);
    if (vm->begin_of_local_function)
        _libebpf_global_free(vm->begin_of_local_function);
    if (vm->translated_code)
        _libebpf_global_free(vm->translated_code);
    if (vm->jit_mapped_page) {
        _libebpf_executor_release(vm->jit_mapped_page, vm->jit_size);
    }
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

#define TEST_REQUIRE(v)                                                                                                                              \
    if (!vm->v) {                                                                                                                                    \
        ebpf_set_error_string("Required " #v " by LDDW at %p", i);                                                                                   \
        return -EINVAL;                                                                                                                              \
    }

int ebpf_vm_load_instructions(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len) {
    int err;
    if ((err = ebpf_vm_verify(vm, code, code_len)) < 0) {
        return err;
    }
    // Check for long lddws
    for (size_t i = 0; i < vm->insn_cnt; i++) {
        if (code[i].code == (BPF_CLASS_LD | BPF_LS_SIZE_DW | BPF_LS_MODE_IMM)) {
            if (i + 1 == vm->insn_cnt) {
                ebpf_set_error_string("LDDW found at pc %d, which is the last instruction", i);
                return -EINVAL;
            }
            if (code[i].src_reg == 1) {
                TEST_REQUIRE(map_by_fd);
            } else if (code[i].src_reg == 2) {
                TEST_REQUIRE(map_by_fd);
                TEST_REQUIRE(map_val);
            } else if (code[i].src_reg == 3) {
                TEST_REQUIRE(var_addr);
            } else if (code[i].src_reg == 4) {
                TEST_REQUIRE(code_addr);
            } else if (code[i].src_reg == 5) {
                TEST_REQUIRE(map_by_idx);
            } else if (code[i].src_reg == 6) {
                TEST_REQUIRE(map_val);
                TEST_REQUIRE(map_by_idx);
            } else if (code[i].src_reg != 0) {
                ebpf_set_error_string("Unexpected source register %d of lddw at %d", code[i].src_reg, i);
                return -EINVAL;
            }
        }
    }
    if (vm->insns) {
        ebpf_set_error_string("code has already been loaded into this VM. Use ebpf_unload_code() if you need to reuse this VM");
        return -EEXIST;
    }
    vm->insns = _libebpf_global_malloc(sizeof(struct libebpf_insn) * code_len);
    vm->begin_of_local_function = _libebpf_global_malloc(sizeof(bool) * code_len);
    if (!vm->insns) {
        ebpf_set_error_string("Failed to call malloc");
        return -ENOMEM;
    }
    if (!vm->begin_of_local_function) {
        ebpf_set_error_string("Failed to call malloc");
        _libebpf_global_free(vm->insns);
        return -ENOMEM;
    }
    vm->insn_cnt = code_len;
    memset(vm->begin_of_local_function, 0, sizeof(bool) * vm->insn_cnt);
    memcpy(vm->insns, code, sizeof(struct libebpf_insn) * code_len);

    for (size_t i = 0; i < vm->insn_cnt; i++) {
        if (code[i].code == (BPF_CLASS_JMP | BPF_SOURCE_K | BPF_JMP_CALL) || code[i].code == (BPF_CLASS_JMP | BPF_SOURCE_X | BPF_JMP_CALL) ||
            code[i].code == (BPF_CLASS_JMP32 | BPF_SOURCE_K | BPF_JMP_CALL) || code[i].code == (BPF_CLASS_JMP32 | BPF_SOURCE_X | BPF_JMP_CALL)) {
            if (code[i].src_reg == 1) {
                // Call to a local function
                uint32_t target = i + vm->insns[i].imm + 1;
                vm->begin_of_local_function[target] = true;
            }
        } else if (vm->insns[i].code == (BPF_CLASS_LD | BPF_LS_SIZE_DW | BPF_LS_MODE_IMM) && vm->insns[i].src_reg != 0) {
            uint32_t imm1 = vm->insns[i].imm;
            uint32_t imm2 = vm->insns[i + 1].imm;

            uint64_t result = 0;
            if (vm->insns[i].src_reg == 1) {
                result = vm->map_by_fd(imm1);
            } else if (vm->insns[i].src_reg == 2) {
                result = (uintptr_t)(vm->map_val(vm->map_by_fd(imm1)) + imm2);
            } else if (vm->insns[i].src_reg == 3) {
                result = (uintptr_t)vm->var_addr(imm1);
            } else if (vm->insns[i].src_reg == 4) {
                result = (uintptr_t)vm->code_addr(imm1);
            } else if (vm->insns[i].src_reg == 5) {
                result = (uintptr_t)vm->map_by_idx(imm1);
            } else if (vm->insns[i].src_reg == 6) {
                result = (uintptr_t)(vm->map_val(vm->map_by_idx(imm1)) + imm2);
            }
            vm->insns[i].src_reg = 0;
            vm->insns[i].imm = result & 0xffffffff;
            vm->insns[i + 1].imm = (result >> 32);
        }
    }
    return 0;
}
void ebpf_vm_unload_instructions(ebpf_vm_t *vm) {
    if (vm->insns) {
        _libebpf_global_free(vm->insns);
        vm->insns = NULL;
        _libebpf_global_free(vm->begin_of_local_function);
        vm->begin_of_local_function = NULL;
        vm->insn_cnt = 0;
    }
    if (vm->translated_code) {
        _libebpf_global_free(vm->translated_code);
        vm->translated_code = NULL;
        vm->translated_code_size = 0;
    }
    if (vm->jit_mapped_page) {
        _libebpf_executor_release(vm->jit_mapped_page, vm->jit_size);
        vm->jit_mapped_page = NULL;
        vm->jit_size = 0;
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

#ifdef LIBEBPF_ENABLE_JIT

static int prepare_translated_code(ebpf_vm_t *vm) {
    if (vm->translated_code)
        return 0;
    return ebpf_translate(vm, &vm->translated_code, &vm->translated_code_size);
}

static int prepare_executable_page(ebpf_vm_t *vm) {
    int err;
    err = prepare_translated_code(vm);
    if (err < 0) {
        goto out;
    }
    if (_libebpf_executable_allocator != NULL) {
        void *page = _libebpf_executable_allocator(vm->translated_code, vm->translated_code_size);
        if (!page) {
            err = -1;
            goto out;
        }
        vm->jit_mapped_page = page;
        vm->jit_size = vm->translated_code_size;
    } else {
        ebpf_set_error_string("Executable page allocator has not been set");
        err = -1;
        goto out;
    }

out:
    return err;
}

ebpf_jit_fn ebpf_vm_compile(ebpf_vm_t *vm) {
    if (prepare_translated_code(vm) < 0) {
        return NULL;
    }
    if (prepare_executable_page(vm) < 0) {
        return NULL;
    }
    return (ebpf_jit_fn)vm->jit_mapped_page;
}

#else

ebpf_jit_fn ebpf_vm_compile(ebpf_vm_t *vm) {
    ebpf_set_error_string("JIT is not supported on the current platform");
    return NULL;
}

#endif
