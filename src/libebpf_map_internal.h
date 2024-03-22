#ifndef _LIBEBPF_MAP_INTERNAL
#define _LIBEBPF_MAP_INTERNAL

#include <stdint.h>
#include <libebpf_map.h>
#include <stdbool.h>

struct ebpf_map {
    struct ebpf_map_attr attr;
    void *map_private_data;
    struct ebpf_map_ops *ops;
    char name[100];
};

struct ebpf_map_ops {
    bool used;
    int (*alloc_map)(void **data, struct ebpf_map_attr *attr);
    void (*map_free)(void *data);
    void *(*elem_lookup)(void *data, const void *key);
    long (*elem_update)(void *data, const void *key, const void *value, uint64_t flags);
    long (*elem_delete)(void *data, const void *key);
    int (*map_get_next_key)(void *data, const void *key, void *next_key);
};

#endif
