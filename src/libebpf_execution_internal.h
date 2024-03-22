#ifndef _LIBEBPF_EXECUTION_INTERNAL_H
#define _LIBEBPF_EXECUTION_INTERNAL_H

#include "utils/spinlock.h"

#define LIBEBPF_MAX_MAP_COUNT 100

struct ebpf_execution_context {
    struct ebpf_map *maps[LIBEBPF_MAX_MAP_COUNT];
    ebpf_spinlock_t map_alloc_lock;
};

#endif
