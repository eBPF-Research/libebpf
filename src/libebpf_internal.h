#ifndef _LINEBPF_INTERNAL_H
#define _LINEBPF_INTERNAL_H

#include "libebpf.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
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
};

static int ebpf_set_error_string(const char *fmt, ...) {
    const char *fmt_str = (const char *)fmt;
    va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wvarargs"
    va_start(args, fmt_str);
    long ret = vprintf(fmt_str, args);
#pragma GCC diagnostic pop
    va_end(args);
    return ret;
}

int ebpf_vm_verify(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len);

#endif
