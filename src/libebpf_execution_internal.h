#ifndef _LIBEBPF_EXECUTION_INTERNAL_H
#define _LIBEBPF_EXECUTION_INTERNAL_H

#include "libebpf_ffi.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include "utils/hashmap.h"
#include "utils/spinlock.h"

#define LIBEBPF_MAX_MAP_COUNT 100
#define LIBEBPF_MAX_FFI_COUNT 100
struct ebpf_map {
    struct ebpf_map_attr attr;
    void *map_private_data;
    struct ebpf_map_ops *ops;
    char name[100];
    int self_id;
};

struct ebpf_map_ops {
    bool used;
    int (*alloc_map)(struct ebpf_map *map, struct ebpf_map_attr *attr);
    void (*map_free)(struct ebpf_map *map);
    int (*elem_lookup)(struct ebpf_map *map, const void *key, void *value);
    int (*elem_update)(struct ebpf_map *map, const void *key, const void *value, uint64_t flags);
    int (*elem_delete)(struct ebpf_map *map, const void *key);
    int (*map_get_next_key)(struct ebpf_map *map, const void *key, void *next_key);
    void *(*elem_lookup_from_helper)(struct ebpf_map *map, const void *key);
};

struct ebpf_execution_context {
    struct ebpf_map *maps[LIBEBPF_MAX_MAP_COUNT];
    ebpf_spinlock_t map_alloc_lock;
    struct ebpf_map_ops map_ops[(int)__MAX_EBPF_MAP_TYPE];
    struct hashmap *ffi_func_name_mapper;
    struct libebpf_ffi_function* ffi_funcs;
};

extern struct ebpf_map_ops HASH_MAP_OPS;
extern struct ebpf_map_ops ARRAY_MAP_OPS;
extern struct ebpf_map_ops RINGBUF_MAP_OPS;
#endif
