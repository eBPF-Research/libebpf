#ifndef _LINEBPF_INTERNAL_H
#define _LINEBPF_INTERNAL_H

#include "libebpf.h"
#include <stddef.h>
struct ebpf_external_helper_definition {
    char name[MAX_EXTERNAL_HELPER_NAME_LENGTH];
    ebpf_external_helper_fn *fn;
};

struct ebpf_vm {
    ebpf_external_helper_fn* helpers;
    size_t insn_cnt;
    
};

#endif
