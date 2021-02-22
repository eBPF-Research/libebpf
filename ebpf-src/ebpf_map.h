#ifndef EBPF_MAP_H_
#define EBPF_MAP_H_
#include "ebpf_types.h"

// htab_map.c
/*
https://elixir.bootlin.com/linux/v4.20.17/source/kernel/bpf/hashtab.c
https://github.com/generic-ebpf/generic-ebpf/blob/dev/sys/dev/ebpf/ebpf_map.c
https://github.com/CBackyx/eBPF-map/blob/master/hash_tab.c

1. lock
2. hashmap
3. ebpfmap
*/

void test_hashmap_pass1();

// struct ebpf_map_ops;

typedef struct ebpf_map {
	struct ebpf_map_ops *ops;
	u32 val_size;
	u32 key_size;
} ebpf_map;

// ebpf_map* ebpf_create_map();


typedef struct ebpf_map_ops {
	void* (*map_lookup_elem)(ebpf_map *map, void *key);
	int (*map_update_elem)(ebpf_map *map, void *key, void *value, u64 flags);
	int (*map_delete_elem)(ebpf_map *map, void *key);
} ebpf_map_ops;
#endif // !EBPF_MAP_H_
