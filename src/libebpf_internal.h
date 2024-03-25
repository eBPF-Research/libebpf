#ifndef _LINEBPF_INTERNAL_H
#define _LINEBPF_INTERNAL_H

#include "libebpf.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
struct ebpf_external_helper_definition {
    char name[MAX_EXTERNAL_HELPER_NAME_LENGTH];
    ebpf_external_helper_fn fn;
};

struct ebpf_vm {
    struct ebpf_external_helper_definition *helpers;
    size_t insn_cnt;
    struct libebpf_insn *insns;
    ebpf_map_by_fd_callback map_by_fd;
    ebpf_map_by_idx_callback map_by_idx;
    ebpf_map_val_callback map_val;
    ebpf_code_addr_callback code_addr;
    ebpf_var_addr_callback var_addr;
    bool bounds_check_enabled;
};

extern char _libebpf_global_error_string[1024];

static int ebpf_set_error_string(const char *fmt, ...) {
    char output_buf[1024];
    const char *fmt_str = (const char *)fmt;
    va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wvarargs"
    va_start(args, fmt_str);
    long ret = vsnprintf(output_buf, sizeof(output_buf), fmt_str, args);
#pragma GCC diagnostic pop
    va_end(args);
    strncpy(_libebpf_global_error_string, output_buf, sizeof(_libebpf_global_error_string));
    return ret;
}

int ebpf_vm_verify(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len);
static inline int bit_test(uint64_t m, uint64_t pat) {
    return (m & pat) == pat;
}
static inline int bit_test_mask(uint64_t m, uint64_t msk, uint64_t pat) {
    return (m & msk) == pat;
}

/**
 * @brief Only for unit tests. Directly call a helper
 * 
 * @param vm 
 * @param idx 
 * @param a 
 * @param b 
 * @param c 
 * @param d 
 * @param e 
 * @return uint64_t 
 */
static inline uint64_t ebpf_vm_call_helper(ebpf_vm_t *vm, int idx, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    return vm->helpers[idx].fn(a, b, c, d, e);
}

extern ebpf_malloc _libebpf_global_malloc;
extern ebpf_free _libebpf_global_free;
extern ebpf_realloc _libebpf_global_realloc;
#endif
