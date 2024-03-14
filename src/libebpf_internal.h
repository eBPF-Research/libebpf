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

#endif
